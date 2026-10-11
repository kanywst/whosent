// Package mandatum is the Mandatum format adapter: it reads a Mandatum
// delegation chain, checks it with pkg/diagnose (which agrees with the
// embedded reference verifier on every run), and describes the result in the
// format-neutral model the view renders.
package mandatum

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/revoke"
	"github.com/kanywst/whosent/internal/mandatum/verify"
	"github.com/kanywst/whosent/internal/trust"
	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// ID is the format's --format name.
const ID = "mandatum"

// Adapter is the Mandatum format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

// Format describes Mandatum: rules V1 to V9 of the specification, every
// interactive feature, and a human sponsor at the root.
func (Adapter) Format() chain.Format { return format }

var format = func() chain.Format {
	f := chain.Format{
		ID:       ID,
		Name:     "Mandatum",
		RootRole: "sponsor",
		Caps:     chain.Capabilities{TimeScrub: true, RevokeSim: true, Ask: true, PerHopSignatures: true},
	}
	for _, r := range diagnose.Rules {
		f.Rules = append(f.Rules, chain.RuleInfo{ID: string(r), Title: r.Title(), Spec: "Mandatum specification section 7 " + string(r)})
	}
	return f
}()

// Detect claims an input whose links carry Mandatum's own media type, and
// considers any other input in one of the chain shapes plausible.
func (Adapter) Detect(data []byte) chain.Confidence {
	in, err := diagnose.ReadInput(data, "")
	if err != nil || len(in.Links) == 0 {
		return chain.NotMine
	}
	if headerType(in.Links[0]) == jose.Type {
		return chain.Certain
	}
	// Without the media type, only the Mandatum claims make a link look
	// like one. Every JWT is in a shape this reader accepts, and claiming
	// all of them would make an ordinary access token ambiguous between
	// this format and the JWT format.
	if hasClaim(in.Links[0], "mdt") {
		return chain.Plausible
	}
	return chain.NotMine
}

// hasClaim reports whether a compact serialization's payload carries a
// top-level claim, without verifying anything.
func hasClaim(compact []byte, name string) bool {
	parts := strings.Split(string(compact), ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	_, ok := claims[name]
	return ok
}

// headerType reads a compact serialization's `typ` without verifying
// anything. Detection must be cheap and must not decide anything a verifier
// decides, so it only looks.
func headerType(compact []byte) string {
	h, _, ok := strings.Cut(string(compact), ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return ""
	}
	var head struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return ""
	}
	return head.Typ
}

// Open reads the chain and the inputs it is checked against.
func (Adapter) Open(ctx context.Context, in chain.Inputs) (chain.Session, error) {
	input, err := diagnose.ReadInput(in.Data, in.Source)
	if err != nil {
		return nil, err
	}
	if in.Reverse {
		input.Links = diagnose.Reverse(input.Links)
		input.Info.Reversed = true
	}
	opts, err := options(ctx, in)
	if err != nil {
		return nil, err
	}
	sess := NewSession(input.Links, opts, input.Info)
	sess.ignored = chain.IgnoredInputs(in, map[string]string{
		"root-key":   "a Mandatum chain is signed by named issuers: give their keys with --trust or --jwks",
		"fact":       "Mandatum has no authorizer facts; ask about a request with whosent ask",
		"authorizer": "Mandatum has no authorizer code; ask about a request with whosent ask",
	})
	return sess, nil
}

// options turns the inputs into diagnosis options. Files that cannot be
// read are the person's to fix; a key document that is read but unusable is
// not, because an enforcement point configured with it would deny, and the
// report has to show that.
func options(ctx context.Context, in chain.Inputs) (diagnose.Options, error) {
	var o diagnose.Options
	o.At = in.At
	skew := verify.DefaultSkew
	if in.Skew != nil {
		skew = *in.Skew
	}
	if skew < 0 || skew > verify.MaxSkew {
		return o, fmt.Errorf("--skew %s is outside [0, %s]", skew, verify.MaxSkew)
	}
	o.Skew = &skew
	if in.Audience != nil {
		aud := *in.Audience
		o.Audience = &aud
	}

	var sources []trust.Source
	if in.TrustFile != "" {
		s, err := trust.ReadFile(in.TrustFile)
		if err != nil {
			return o, err
		}
		sources = append(sources, s...)
	}
	for _, v := range in.JWKS {
		s, err := trust.ParseFlag(v)
		if err != nil {
			return o, err
		}
		sources = append(sources, s)
	}
	if len(sources) > 0 {
		t, err := trust.Loader{}.Load(ctx, sources)
		if err != nil {
			return o, err
		}
		o.Trust = t
	}

	if in.RevokedIDs != "" && in.Revocations == "" {
		return o, errors.New("--revoked-jtis resolves hits in a revocation set; pass --revocations as well")
	}
	if in.Revocations != "" {
		data, err := os.ReadFile(in.Revocations)
		if err != nil {
			return o, fmt.Errorf("reading revocation set: %w", err)
		}
		set, err := revoke.ParseSet(data)
		if err != nil {
			return o, fmt.Errorf("%s: %w", in.Revocations, err)
		}
		if in.MaxAge < 0 {
			return o, fmt.Errorf("--max-age %s is negative; use 0 to accept any age", in.MaxAge)
		}
		maxAge := in.MaxAge
		o.Revocation = &diagnose.Revocation{Set: set, Source: baseName(in.Revocations), MaxAge: &maxAge}
		if in.RevokedIDs != "" {
			data, err := os.ReadFile(in.RevokedIDs)
			if err != nil {
				return o, fmt.Errorf("reading revoked jtis: %w", err)
			}
			list := diagnose.ExactList{}
			for _, line := range strings.Split(string(data), "\n") {
				if j := strings.TrimSpace(line); j != "" && !strings.HasPrefix(j, "#") {
					list[j] = true
				}
			}
			o.Revocation.Exact, o.Revocation.ExactSource = list, baseName(in.RevokedIDs)
		}
	}
	return o, nil
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Scenarios are the minted demos, each opened with every input it needs.
func (Adapter) Scenarios() []chain.Scenario {
	var out []chain.Scenario
	for _, name := range demo.Names() {
		s, err := demo.Build(name, demo.FixedBase)
		if err != nil {
			// The demos are built and self-checked by their own tests; a
			// failure here is a broken build, not something to hide.
			panic(fmt.Sprintf("mandatum demo %s: %v", name, err))
		}
		out = append(out, chain.Scenario{
			Name: s.Name, Title: s.Title, Summary: s.Summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				sc, err := demo.Build(name, base)
				if err != nil {
					return nil, err
				}
				return NewSession(sc.Links, sc.Options, diagnose.InputInfo{Source: sc.Name}), nil
			},
			Emit: func(dir string, force bool) (string, error) {
				m, err := s.Emit(dir, force)
				if err != nil {
					return "", err
				}
				return m.Command, nil
			},
		})
	}
	return out
}

// Session is a Mandatum chain with the options it is checked against.
type Session struct {
	links [][]byte
	opts  diagnose.Options
	input diagnose.InputInfo
	// ignored are the inputs given that Mandatum has no use for.
	ignored []string
}

// NewSession returns a session over links checked with opts. input
// describes where the links came from.
func NewSession(links [][]byte, opts diagnose.Options, input diagnose.InputInfo) *Session {
	return &Session{links: links, opts: opts, input: input}
}

// Info describes the session.
func (s *Session) Info() chain.Info { return chain.Info{Format: format, At: s.opts.At} }

// diagnoseFn is diagnose.Diagnose. It is a variable so a test can hand the
// adapter a report in which this tool and the reference verifier disagree,
// and check that everything downstream says so; a real disagreement cannot
// be arranged.
var diagnoseFn = diagnose.Diagnose

// Evaluate diagnoses the chain at opts.At with opts.SimRevoked simulated.
func (s *Session) Evaluate(ctx context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	r, err := s.Report(ctx, eo)
	if err != nil {
		return nil, err
	}
	c := Convert(r)
	c.Ignored = s.ignored
	return c, nil
}

// Report diagnoses the chain and returns the engine's own report.
func (s *Session) Report(ctx context.Context, eo chain.EvalOptions) (*diagnose.Report, error) {
	at := eo.At
	if at.IsZero() {
		at = s.opts.At
	}
	opts := s.opts.WithAt(at).WithSimulatedRevocations(eo.SimRevoked)
	r, err := diagnoseFn(ctx, s.links, opts)
	if err != nil {
		return nil, err
	}
	r.Input = s.input
	return r, nil
}
