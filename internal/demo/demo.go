// Package demo mints delegation chains for the demo and for tests: one
// healthy chain and a broken variant for each way a chain fails.
//
// Fixtures are minted on every run, never committed. A committed chain is a
// chain that expires, and noticing expiry is part of the job. Keys come from
// fixed seeds, so the same scenario at the same base time is byte-for-byte
// the same chain.
//
// Every scenario records the failure mandatum itself reports for it, and
// Build checks that against verify.Verify before returning, so a scenario
// can never quietly stop demonstrating what its name says.
package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/mandatum/pkg/issue"
	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/revoke"
	"github.com/kanywst/mandatum/pkg/verify"

	"github.com/kanywst/whosent/internal/trust"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// FixedBase is the base time for deterministic fixtures: 2026-09-12 08:00 UTC.
var FixedBase = time.Unix(1789200000, 0).UTC()

// The cast.
const (
	IDP       = "https://idp.example.org"
	Planner   = "spiffe://example.org/ns/agents/planner"
	Retriever = "spiffe://example.org/ns/agents/retriever"
	Fetcher   = "spiffe://example.org/ns/agents/fetcher"
	Mallory   = "spiffe://example.org/ns/agents/mallory"
	Audience  = "https://mcp.example.org"
	Sponsor   = "alice@example.org"
)

type identity struct {
	id, kid, file string
	seed          byte
}

var cast = []identity{
	{IDP, "idp-2026", "idp.json", 1},
	{Planner, "planner-1", "planner.json", 2},
	{Retriever, "retriever-1", "retriever.json", 3},
	{Fetcher, "fetcher-1", "fetcher.json", 4},
	{Mallory, "mallory-1", "mallory.json", 5},
}

// Expectation is a rule failing at a link.
type Expectation struct {
	Rule diagnose.Rule `json:"rule"`
	Link int           `json:"link"`
}

// Fixture is a scenario's supporting files, for writing out with Emit.
type Fixture struct {
	// JWKS maps a file name to a key document.
	JWKS map[string][]byte
	// TrustIssuers maps an issuer to its key document's file name.
	TrustIssuers map[string]string
	// Revocation is the encoded revocation set, or nil.
	Revocation []byte
	// RevokedJTIs is the exact list that resolves Bloom filter hits.
	RevokedJTIs []string
}

// Scenario is one demonstration chain and everything needed to check it.
type Scenario struct {
	Name    string
	Title   string
	Summary string
	Links   [][]byte
	// Options are the inputs the scenario is meant to be checked with.
	Options diagnose.Options
	// Verdict is what Diagnose concludes.
	Verdict diagnose.Verdict
	// Expect is the failure verify.Verify reports, Rule "" when it accepts.
	Expect Expectation
	// ExpectAll lists every rule that fails, at every link, which is more
	// than verify.Verify can report.
	ExpectAll []Expectation
	Fixture   Fixture
}

// Names lists the scenarios in the order the demo tours them.
func Names() []string {
	return []string{
		"healthy", "widened", "revoked", "expired", "spliced", "custody",
		"audience", "retarget", "forged", "multifault", "unchecked",
	}
}

// All builds every scenario at base.
func All(base time.Time) ([]Scenario, error) {
	var out []Scenario
	for _, n := range Names() {
		s, err := Build(n, base)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Build mints one scenario with its chain issued around base, evaluated one
// minute after it.
func Build(name string, base time.Time) (Scenario, error) {
	w := newWorld(base)
	s, err := w.scenario(name)
	if err != nil {
		return Scenario{}, err
	}
	if err := w.selfCheck(s); err != nil {
		return Scenario{}, fmt.Errorf("scenario %s: %w", name, err)
	}
	return s, nil
}

type world struct {
	base, at time.Time
	priv     map[string]ed25519.PrivateKey
	kid      map[string]string
	file     map[string]string
	jwks     map[string][]byte
}

func newWorld(base time.Time) *world {
	base = base.UTC().Truncate(time.Second)
	w := &world{
		base: base, at: base.Add(time.Minute),
		priv: map[string]ed25519.PrivateKey{}, kid: map[string]string{},
		file: map[string]string{}, jwks: map[string][]byte{},
	}
	for _, c := range cast {
		k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{c.seed}, ed25519.SeedSize))
		w.priv[c.id], w.kid[c.id], w.file[c.id] = k, c.kid, c.file
		doc, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": c.kid,
			"x": base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey)),
		}}})
		w.jwks[c.id] = doc
	}
	return w
}

func (w *world) signer(id string) issue.Signer {
	return issue.Signer{ID: id, KeyID: w.kid[id], Key: w.priv[id]}
}

// trustFor loads the key documents of the given issuers exactly as the
// command line would, so the demo and a --trust file behave the same.
func (w *world) trustFor(ids ...string) (*diagnose.Trust, Fixture, error) {
	t := &diagnose.Trust{Issuers: map[string]*diagnose.IssuerKeys{}}
	f := Fixture{JWKS: map[string][]byte{}, TrustIssuers: map[string]string{}}
	for _, id := range ids {
		keys, skipped, err := trust.ParseDocument(w.jwks[id])
		if err != nil {
			return nil, f, err
		}
		t.Issuers[id] = &diagnose.IssuerKeys{Source: w.file[id], Keys: keys, Skipped: skipped}
		f.JWKS[w.file[id]] = w.jwks[id]
		f.TrustIssuers[id] = w.file[id]
	}
	return t, f, nil
}

// revocationFor builds a published set holding jtis plus an old unrelated
// one, so that even the healthy chain is checked against a real set.
func (w *world) revocationFor(jtis ...string) (*diagnose.Revocation, []byte, []string, error) {
	all := append([]string{"dlg-retired-0099"}, jtis...)
	set, err := revoke.NewSet(all, 1e-6, 7, w.base)
	if err != nil {
		return nil, nil, nil, err
	}
	enc, err := set.Encode()
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := revoke.ParseSet(enc)
	if err != nil {
		return nil, nil, nil, err
	}
	exact := diagnose.ExactList{}
	for _, j := range all {
		exact[j] = true
	}
	return &diagnose.Revocation{
		Set: parsed, Source: "revocation.json", Exact: exact, ExactSource: "revoked-jtis.txt",
	}, enc, all, nil
}

func ptr[T any](v T) *T { return &v }

func capability(action, typ, id string, tags []string, conds map[string]mda.Condition) mda.Capability {
	return mda.Capability{
		Resource:   mda.ResourcePattern{Type: typ, ID: id, Tags: tags},
		Action:     mda.ActionPattern{Name: action},
		Conditions: conds,
	}
}

var (
	noWriteAfterRead = mda.Constraint{
		ID:     "no-write-after-external-read",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
		After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
	}
	noFetchAfterWrite = mda.Constraint{
		ID:     "no-fetch-after-mutation",
		Forbid: mda.ActionMatcher{ResourceTags: []string{"external-content"}},
		After:  mda.ActionMatcher{ResourceTags: []string{"mutating"}},
	}
	docsWrite = capability("invoke", "mcp_tool", "docs.write", []string{"mutating"}, nil)
)

func leafCaps() []mda.Capability {
	return []mda.Capability{capability("invoke", "mcp_tool", "web.fetch", []string{"external-content"},
		map[string]mda.Condition{"args.host": {Equals: ptr("docs.example.org")}})}
}

// chain mints the healthy chain: alice, through her identity provider, sends
// planner, who sends retriever, who sends fetcher. suffix distinguishes a
// sibling chain minted from the same grant.
func (w *world) chain(suffix string) ([]mda.Assertion, error) {
	sponsor := mda.Sponsor{
		Issuer: IDP, Subject: Sponsor,
		AuthenticationMethods: []string{"pwd", "hwk"},
		AuthenticatedAt:       w.base.Add(-10 * time.Minute).Unix(),
	}
	root, err := issue.Sponsor(w.signer(IDP), sponsor, issue.Grant{
		Subject: Planner, Audience: Audience, ID: "grant-alice-001" + suffix,
		IssuedAt: w.base.Add(-5 * time.Minute), Lifetime: 65 * time.Minute,
		MaxDepth: issue.Depth(3),
		Capabilities: []mda.Capability{
			capability("invoke", "mcp_tool", "search.*", nil, nil),
			capability("invoke", "mcp_tool", "web.fetch", nil, map[string]mda.Condition{"args.host": {Prefix: ptr("docs.")}}),
			docsWrite,
		},
		Sequence: &mda.Sequence{MaxInvocations: 200, Constraints: []mda.Constraint{noWriteAfterRead}},
	})
	if err != nil {
		return nil, fmt.Errorf("sponsor grant: %w", err)
	}
	mid, err := issue.Delegate(w.signer(Planner), root, issue.Grant{
		Subject: Retriever, ID: "dlg-planner-002" + suffix,
		IssuedAt: w.base.Add(-4 * time.Minute), Lifetime: 44 * time.Minute,
		MaxDepth: issue.Depth(1),
		Capabilities: []mda.Capability{
			capability("invoke", "mcp_tool", "search.query", nil, map[string]mda.Condition{"args.index": {In: []string{"public", "docs"}}}),
			capability("invoke", "mcp_tool", "web.fetch", nil, map[string]mda.Condition{"args.host": {In: []string{"docs.example.org", "docs.example.com"}}}),
		},
		Sequence: &mda.Sequence{MaxInvocations: 100, Constraints: []mda.Constraint{noWriteAfterRead, noFetchAfterWrite}},
	})
	if err != nil {
		return nil, fmt.Errorf("planner delegation: %w", err)
	}
	leaf, err := issue.Delegate(w.signer(Retriever), mid, issue.Grant{
		Subject: Fetcher, ID: "dlg-retriever-003" + suffix,
		IssuedAt: w.base.Add(-3 * time.Minute), Lifetime: 23 * time.Minute,
		MaxDepth:     issue.Depth(0),
		Capabilities: leafCaps(),
		Sequence:     &mda.Sequence{MaxInvocations: 20, Constraints: []mda.Constraint{noWriteAfterRead, noFetchAfterWrite}},
	})
	if err != nil {
		return nil, fmt.Errorf("retriever delegation: %w", err)
	}
	return []mda.Assertion{root, mid, leaf}, nil
}

// handSign signs a child of parent directly, bypassing pkg/issue, which
// refuses to produce the broken links some scenarios need. The claims start
// as a well-formed child of parent; edit changes whatever the scenario
// breaks.
func (w *world) handSign(signer string, parent mda.Assertion, edit func(*mda.Claims)) (mda.Assertion, error) {
	p := parent.Claims
	c := mda.Claims{
		Issuer: signer, Subject: Fetcher, Audience: p.Audience,
		IssuedAt: w.base.Add(-3 * time.Minute).Unix(), ExpiresAt: w.base.Add(20 * time.Minute).Unix(),
		ID: "dlg-retriever-003", Mandatum: mda.Mandatum{
			Version: mda.Version, Root: p.Mandatum.Root, Parent: mda.Digest(parent.Raw),
			Depth: p.Mandatum.Depth + 1, MaxDepth: 0, Capabilities: leafCaps(),
			Sequence: &mda.Sequence{MaxInvocations: 20, Constraints: []mda.Constraint{noWriteAfterRead, noFetchAfterWrite}},
		},
	}
	if edit != nil {
		edit(&c)
	}
	// Structurally valid, so that each scenario fails only the rule it is
	// about rather than V1 first.
	if err := c.Validate(); err != nil {
		return mda.Assertion{}, fmt.Errorf("hand-signed link is malformed: %w", err)
	}
	raw, err := jose.Sign(c, w.priv[signer], w.kid[signer])
	if err != nil {
		return mda.Assertion{}, err
	}
	return mda.Assertion{Raw: raw, Claims: c}, nil
}

func raws(as []mda.Assertion) [][]byte {
	out := make([][]byte, len(as))
	for i, a := range as {
		out[i] = a.Raw
	}
	return out
}

// full returns options supplying every input, so nothing is Unchecked.
func (w *world) full(revoked ...string) (diagnose.Options, Fixture, error) {
	t, f, err := w.trustFor(IDP, Planner, Retriever, Mallory)
	if err != nil {
		return diagnose.Options{}, f, err
	}
	rev, enc, all, err := w.revocationFor(revoked...)
	if err != nil {
		return diagnose.Options{}, f, err
	}
	f.Revocation, f.RevokedJTIs = enc, all
	return diagnose.Options{At: w.at, Audience: ptr(Audience), Trust: t, Revocation: rev}, f, nil
}

func (w *world) scenario(name string) (Scenario, error) {
	healthy, err := w.chain("")
	if err != nil {
		return Scenario{}, err
	}
	opts, fix, err := w.full()
	if err != nil {
		return Scenario{}, err
	}
	s := Scenario{Name: name, Links: raws(healthy), Options: opts, Fixture: fix, Verdict: diagnose.VerdictInvalid}
	root, mid := healthy[0], healthy[1]

	switch name {
	case "healthy":
		s.Title = "A healthy chain"
		s.Summary = "alice sends planner, planner sends retriever, retriever sends fetcher. Authority narrows at every hop and every check passes."
		s.Verdict = diagnose.VerdictValid

	case "widened":
		s.Title = "Authority from nowhere"
		s.Summary = "retriever hands fetcher docs.write, which planner had already dropped. The verifier refuses the link that widens."
		leaf, err := w.handSign(Retriever, mid, func(c *mda.Claims) {
			c.Mandatum.Capabilities = append(c.Mandatum.Capabilities, docsWrite)
		})
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, leaf})
		s.Expect = Expectation{diagnose.V5, 2}

	case "revoked":
		s.Title = "A revoked middle link"
		s.Summary = "planner's delegation to retriever is revoked. Everything below it dies with it; nothing above it is touched."
		s.Options, s.Fixture, err = w.full(mid.Claims.ID)
		if err != nil {
			return s, err
		}
		s.Expect = Expectation{diagnose.V8, 1}

	case "expired":
		s.Title = "An expired leaf"
		s.Summary = "fetcher's assertion ran out ninety minutes ago, though everything above it is still live."
		leaf, err := issue.Delegate(w.signer(Retriever), mid, issue.Grant{
			Subject: Fetcher, ID: "dlg-retriever-003",
			IssuedAt: w.base.Add(-2 * time.Hour), Lifetime: 30 * time.Minute,
			MaxDepth: issue.Depth(0), Capabilities: leafCaps(),
		})
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, leaf})
		s.Expect = Expectation{diagnose.V4, 2}

	case "spliced":
		s.Title = "A spliced link"
		s.Summary = "fetcher's link was issued under a sibling chain and pasted here. Every signature is valid; only the parent commitment gives it away."
		sibling, err := w.chain("b")
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, sibling[2]})
		s.Expect = Expectation{diagnose.V1, 2}

	case "custody":
		s.Title = "Broken custody"
		s.Summary = "mallory, a trusted agent, signs a link under retriever's grant. The signature is genuine; mallory just never held this authority."
		leaf, err := w.handSign(Mallory, mid, nil)
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, leaf})
		s.Expect = Expectation{diagnose.V2, 2}

	case "audience":
		s.Title = "The wrong resource server"
		s.Summary = "a healthy chain for mcp.example.org, presented to other.example.org."
		s.Options.Audience = ptr("https://other.example.org")
		s.Expect = Expectation{diagnose.V9, 2}

	case "retarget":
		s.Title = "A re-targeted leaf"
		s.Summary = "retriever mints fetcher a leaf for victim.example.org. The leaf names the server it is shown to, so V9 passes; section 6 rule 7 is what stops it."
		leaf, err := w.handSign(Retriever, mid, func(c *mda.Claims) { c.Audience = "https://victim.example.org" })
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, leaf})
		s.Options.Audience = ptr("https://victim.example.org")
		s.Expect = Expectation{diagnose.V5, 2}

	case "forged":
		s.Title = "A forged signature"
		s.Summary = "planner's link is signed with retriever's key. It claims to be planner's, and planner's published key says otherwise."
		forged, err := issue.Delegate(issue.Signer{ID: Planner, KeyID: w.kid[Planner], Key: w.priv[Retriever]}, root, issue.Grant{
			Subject: Retriever, ID: "dlg-planner-002",
			IssuedAt: w.base.Add(-4 * time.Minute), Lifetime: 44 * time.Minute,
			MaxDepth:     issue.Depth(1),
			Capabilities: mid.Claims.Mandatum.Capabilities,
			Sequence:     mid.Claims.Mandatum.Sequence,
		})
		if err != nil {
			return s, err
		}
		leaf, err := w.handSign(Retriever, forged, nil)
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, forged, leaf})
		s.Expect = Expectation{diagnose.V3, 1}

	case "multifault":
		s.Title = "Three faults at once"
		s.Summary = "planner's link is revoked, and fetcher's leaf is both expired and widened. The verifier reports one; this shows all three."
		leaf, err := w.handSign(Retriever, mid, func(c *mda.Claims) {
			c.IssuedAt = w.base.Add(-2 * time.Hour).Unix()
			c.ExpiresAt = w.base.Add(-90 * time.Minute).Unix()
			c.Mandatum.Capabilities = append(c.Mandatum.Capabilities, docsWrite)
		})
		if err != nil {
			return s, err
		}
		s.Links = raws([]mda.Assertion{root, mid, leaf})
		s.Options, s.Fixture, err = w.full(mid.Claims.ID)
		if err != nil {
			return s, err
		}
		s.Expect = Expectation{diagnose.V4, 2}
		s.ExpectAll = []Expectation{{diagnose.V8, 1}, {diagnose.V4, 2}, {diagnose.V5, 2}}

	case "unchecked":
		s.Title = "Nothing to check against"
		s.Summary = "the healthy chain with no keys, no revocation set and no audience. Nothing fails, and nothing is vouched for either."
		s.Options = diagnose.Options{At: w.at}
		s.Fixture = Fixture{}
		s.Verdict = diagnose.VerdictIncomplete

	default:
		return s, fmt.Errorf("unknown scenario %q; try one of %v", name, Names())
	}
	if s.ExpectAll == nil && s.Expect.Rule != "" {
		s.ExpectAll = []Expectation{s.Expect}
	}
	return s, nil
}

// selfCheck runs verify.Verify on the scenario with its own inputs and
// confirms it reports the failure the scenario promises. A scenario with no
// inputs is checked with the full ones, since the library has no notion of
// an unchecked rule.
func (w *world) selfCheck(s Scenario) error {
	opts := s.Options
	if opts.Trust == nil {
		full, _, err := w.full()
		if err != nil {
			return err
		}
		opts = full
	}
	ring := jose.NewKeyRing()
	for iss, ik := range opts.Trust.Issuers {
		for kid, k := range ik.Keys {
			if err := ring.Add(iss, kid, k); err != nil {
				return err
			}
		}
	}
	at := opts.At
	rc, err := revoke.NewChecker(opts.Revocation.Set,
		revoke.WithClock(func() time.Time { return at }), revoke.WithExact(opts.Revocation.Exact))
	if err != nil {
		return err
	}
	v, err := verify.New(ring, rc, *opts.Audience, verify.WithClock(func() time.Time { return at }))
	if err != nil {
		return err
	}
	chain := make(mda.Chain, len(s.Links))
	for i, l := range s.Links {
		chain[i] = mda.Assertion{Raw: l}
	}
	_, verr := v.Verify(context.Background(), chain)
	var ve *verify.Error
	switch {
	case verr == nil && s.Expect.Rule == "":
		return nil
	case verr == nil:
		return fmt.Errorf("mandatum accepts the chain, but the scenario expects %s at link %d", s.Expect.Rule, s.Expect.Link)
	case !errors.As(verr, &ve):
		return fmt.Errorf("mandatum refused the chain without a rule: %w", verr)
	case diagnose.Rule(ve.Rule) != s.Expect.Rule || ve.Depth != s.Expect.Link:
		return fmt.Errorf("mandatum reports %s at link %d, but the scenario expects %s at link %d: %s",
			ve.Rule, ve.Depth, s.Expect.Rule, s.Expect.Link, ve.Detail)
	}
	return nil
}

// Key returns the private key and kid the demo signs with for a principal,
// so tests can re-sign edited links as their real issuer would.
func Key(id string) (ed25519.PrivateKey, string, bool) {
	for _, c := range cast {
		if c.id == id {
			return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{c.seed}, ed25519.SeedSize)), c.kid, true
		}
	}
	return nil, "", false
}
