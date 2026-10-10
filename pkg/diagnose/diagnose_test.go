package diagnose_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/revoke"
	"github.com/kanywst/mandatum/pkg/verify"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

func scenario(t *testing.T, name string) demo.Scenario {
	t.Helper()
	s, err := demo.Build(name, demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func diag(t *testing.T, links [][]byte, opts diagnose.Options) *diagnose.Report {
	t.Helper()
	r, err := diagnose.Diagnose(context.Background(), links, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Library.Consistent {
		t.Fatalf("guard: %s", r.Library.Mismatch)
	}
	return r
}

func hasCode(fs []diagnose.Finding, code string) *diagnose.Finding {
	for i := range fs {
		if fs[i].Code == code {
			return &fs[i]
		}
	}
	return nil
}

func headerOnly(t *testing.T, header string, payload []byte) []byte {
	t.Helper()
	b := base64.RawURLEncoding
	return []byte(b.EncodeToString([]byte(header)) + "." + b.EncodeToString(payload) + ".c2ln")
}

func TestMalformedInputIsAFindingNeverAnError(t *testing.T) {
	healthy := scenario(t, "healthy")
	claims, _ := mda.ParseClaims(healthy.Links[0])
	tests := []struct {
		name     string
		links    [][]byte
		code     string
		rule     diagnose.Rule
		link     int
		severity diagnose.Severity
	}{
		{name: "an empty chain establishes nothing", links: nil,
			code: "v1.empty_chain", rule: diagnose.V1, link: -1, severity: diagnose.SeverityFail},
		{name: "an empty link has nothing to commit to", links: [][]byte{nil},
			code: "v1.empty_link", rule: diagnose.V1, link: 0, severity: diagnose.SeverityFail},
		{name: "a serialization with two parts is malformed", links: [][]byte{[]byte("a.b")},
			code: "v1.parse", rule: diagnose.V1, link: 0, severity: diagnose.SeverityFail},
		{name: "alg none is refused under V3, not V1", links: [][]byte{headerOnly(t, `{"alg":"none","typ":"mdt+jwt"}`, []byte(`{}`))},
			code: "v3.header", rule: diagnose.V3, link: 0, severity: diagnose.SeverityFail},
		{name: "a crit header is refused under V3", links: [][]byte{headerOnly(t, `{"alg":"EdDSA","typ":"mdt+jwt","crit":["x"]}`, []byte(`{}`))},
			code: "v3.header", rule: diagnose.V3, link: 0, severity: diagnose.SeverityFail},
		{name: "an unknown claim is refused rather than ignored", links: [][]byte{headerOnly(t, `{"alg":"EdDSA","typ":"mdt+jwt"}`, []byte(`{"iss":"x","surprise":1}`))},
			code: "v1.parse", rule: diagnose.V1, link: 0, severity: diagnose.SeverityFail},
		{name: "a link that parses but is structurally invalid fails V1", links: func() [][]byte {
			c := claims
			c.ID = ""
			key, kid, _ := demo.Key(demo.IDP)
			raw, _ := jose.Sign(c, key, kid)
			return [][]byte{raw}
		}(), code: "v1.invalid", rule: diagnose.V1, link: 0, severity: diagnose.SeverityFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := diag(t, tt.links, healthy.Options)
			f := hasCode(r.Findings(), tt.code)
			if f == nil {
				t.Fatalf("no %s finding in %+v", tt.code, r.Findings())
			}
			if f.Rule != tt.rule || f.Link != tt.link || f.Severity != tt.severity {
				t.Errorf("finding %s %s@%d, want %s %s@%d", f.Severity, f.Rule, f.Link, tt.severity, tt.rule, tt.link)
			}
			if r.Verdict != diagnose.VerdictInvalid {
				t.Errorf("verdict %s", r.Verdict)
			}
			if r.Library.Rule != tt.rule || r.Library.Link != tt.link {
				t.Errorf("library %s@%d", r.Library.Rule, r.Library.Link)
			}
		})
	}
}

// An unparsed link keeps its lenient payload for display, and every one of
// its other cells is skipped rather than guessed.
func TestAnUnparsedLinkIsShownButNeverTrusted(t *testing.T) {
	healthy := scenario(t, "healthy")
	payload := []byte(`{"iss":"https://idp.example.org","sub":"x","surprise":true}`)
	link := headerOnly(t, `{"alg":"EdDSA","typ":"mdt+jwt","kid":"k"}`, payload)
	r := diag(t, [][]byte{link}, healthy.Options)
	l := r.Links[0]
	if l.Claims != nil {
		t.Fatal("strict claims from a payload with an unknown member")
	}
	if l.Untrusted["surprise"] != true {
		t.Errorf("lenient payload not kept for display: %v", l.Untrusted)
	}
	if l.Header == nil || l.Header.KeyID != "k" {
		t.Errorf("header not kept for display: %+v", l.Header)
	}
	for _, c := range l.Checks {
		if c.Rule == diagnose.V1 {
			continue
		}
		if c.Status == diagnose.StatusPass {
			t.Errorf("%s passes on an unparsed link", c.Rule)
		}
	}
}

func TestSignatureOutcomesAreThreeValued(t *testing.T) {
	s := scenario(t, "healthy")
	wrongKey := map[string]*diagnose.IssuerKeys{}
	for k, v := range s.Options.Trust.Issuers {
		wrongKey[k] = v
	}
	other, _, _ := demo.Key(demo.Mallory)
	wrongKey[demo.Planner] = &diagnose.IssuerKeys{Source: "planner.json", Keys: map[string]ed25519.PublicKey{"planner-1": pub(other)}}
	unknownKid := map[string]*diagnose.IssuerKeys{}
	for k, v := range s.Options.Trust.Issuers {
		unknownKid[k] = v
	}
	pk, _, _ := demo.Key(demo.Planner)
	unknownKid[demo.Planner] = &diagnose.IssuerKeys{Source: "planner.json", Keys: map[string]ed25519.PublicKey{"planner-2": pub(pk)}}
	broken := map[string]*diagnose.IssuerKeys{}
	for k, v := range s.Options.Trust.Issuers {
		broken[k] = v
	}
	broken[demo.Planner] = &diagnose.IssuerKeys{Source: "https://keys.example.org/planner", Err: "fetching keys: HTTP 503"}
	missing := map[string]*diagnose.IssuerKeys{}
	for k, v := range s.Options.Trust.Issuers {
		if k != demo.Planner {
			missing[k] = v
		}
	}

	tests := []struct {
		name   string
		trust  map[string]*diagnose.IssuerKeys
		status diagnose.Status
		code   string
	}{
		{"the right key passes", s.Options.Trust.Issuers, diagnose.StatusPass, ""},
		{"a different key under the right kid fails", wrongKey, diagnose.StatusFail, "v3.bad_signature"},
		{"a trusted issuer without the kid fails, and says the kid is missing", unknownKid, diagnose.StatusFail, "v3.unknown_kid"},
		{"keys that could not be loaded are an error, not unchecked", broken, diagnose.StatusError, "v3.keys_unavailable"},
		{"an issuer with no anchor is unchecked, never passing", missing, diagnose.StatusUnchecked, "v3.no_anchor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := s.Options
			o.Trust = &diagnose.Trust{Issuers: tt.trust}
			r := diag(t, s.Links, o)
			c := r.Links[1].Check(diagnose.V3)
			if c.Status != tt.status {
				t.Errorf("link 1 V3 %s (%s), want %s", c.Status, c.Detail, tt.status)
			}
			if tt.code != "" && hasCode(r.Links[1].Findings, tt.code) == nil {
				t.Errorf("no %s finding", tt.code)
			}
			if tt.status == diagnose.StatusPass && r.Links[1].KeySource == "" {
				t.Error("a passing signature should name its key source")
			}
		})
	}
}

func TestRevocationEdgeCases(t *testing.T) {
	s := scenario(t, "revoked")

	t.Run("a filter hit without an exact list fails and warns it may be a false positive", func(t *testing.T) {
		o := s.Options
		rev := *o.Revocation
		rev.Exact = nil
		o.Revocation = &rev
		r := diag(t, s.Links, o)
		if hasCode(r.Links[1].Findings, "v8.bloom_hit") == nil {
			t.Error("no false-positive warning")
		}
	})

	t.Run("an exact list clears a filter hit it does not contain", func(t *testing.T) {
		o := s.Options
		rev := *o.Revocation
		rev.Exact = diagnose.ExactList{}
		o.Revocation = &rev
		r := diag(t, s.Links, o)
		if st := r.Links[1].Check(diagnose.V8).Status; st != diagnose.StatusPass {
			t.Errorf("V8 %s; the exact list is authoritative", st)
		}
	})

	t.Run("a stale set is an error at every link and the report says why", func(t *testing.T) {
		o := s.Options.WithAt(demo.FixedBase.Add(30 * time.Hour))
		r := diag(t, s.Links, o)
		if r.Revocation == nil || !r.Revocation.Stale || r.Revocation.StaleDetail == "" {
			t.Fatalf("revocation summary %+v", r.Revocation)
		}
		for _, l := range r.Links {
			if st := l.Check(diagnose.V8).Status; st != diagnose.StatusError {
				t.Errorf("link %d V8 %s, want error", l.Index, st)
			}
		}
	})

	t.Run("max age zero accepts any age, as revoke.WithMaxAge(0) does", func(t *testing.T) {
		o := s.Options.WithAt(demo.FixedBase.Add(30 * time.Hour))
		rev := *o.Revocation
		zero := time.Duration(0)
		rev.MaxAge = &zero
		o.Revocation = &rev
		r := diag(t, s.Links, o)
		if st := r.Links[0].Check(diagnose.V8).Status; st != diagnose.StatusPass {
			t.Errorf("link 0 V8 %s", st)
		}
	})

	t.Run("the set is read at the evaluation time, not the wall clock", func(t *testing.T) {
		set, err := revoke.NewSet([]string{"x"}, 1e-6, 1, demo.FixedBase)
		if err != nil {
			t.Fatal(err)
		}
		o := s.Options
		o.Revocation = &diagnose.Revocation{Set: set}
		r := diag(t, s.Links, o)
		if r.Revocation.Stale {
			t.Error("a set generated a minute before --at is not stale, however old it is today")
		}
	})
}

func TestTimeWarnings(t *testing.T) {
	s := scenario(t, "healthy")
	tests := []struct {
		name string
		at   time.Time
		code string
		link int
	}{
		{"a link inside the skew window passes with a warning", demo.FixedBase.Add(20*time.Minute + 10*time.Second), "v4.within_skew", 2},
		{"a link about to expire passes with a warning", demo.FixedBase.Add(17 * time.Minute), "v4.expiring", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := diag(t, s.Links, s.Options.WithAt(tt.at))
			if st := r.Links[tt.link].Check(diagnose.V4).Status; st != diagnose.StatusPass {
				t.Errorf("V4 %s, want pass", st)
			}
			if hasCode(r.Links[tt.link].Findings, tt.code) == nil {
				t.Errorf("no %s warning", tt.code)
			}
		})
	}
	t.Run("a skew outside the library's bounds is refused", func(t *testing.T) {
		for _, d := range []time.Duration{-time.Second, verify.MaxSkew + time.Second} {
			o := s.Options
			o.Skew = &d
			if _, err := diagnose.Diagnose(context.Background(), s.Links, o); err == nil {
				t.Errorf("skew %s accepted", d)
			}
		}
	})
}

func TestReversedChainIsFlaggedNotReordered(t *testing.T) {
	s := scenario(t, "healthy")
	r := diag(t, diagnose.Reverse(s.Links), s.Options)
	if hasCode(r.ChainFindings, "input.reversed") == nil {
		t.Error("no reversed-chain warning")
	}
	if r.Verdict != diagnose.VerdictInvalid {
		t.Error("a reversed chain must still fail; it is never silently reordered")
	}
}

// V7 cannot be reached through verify.Verify, because V5 fires first. The
// tool shows it anyway: that is the point of showing every fault.
func TestTooDeepIsReportedEvenThoughTheLibraryStopsAtV5(t *testing.T) {
	s := scenario(t, "healthy")
	edit := resign(0, func(c *mda.Claims) { c.Mandatum.MaxDepth = 1 })
	links := edit(s.Links)
	// Re-link the children to the edited grant so only depth is wrong.
	links = resign(1, func(c *mda.Claims) {
		c.Mandatum.Parent = mda.Digest(links[0])
		c.Mandatum.MaxDepth = 0
	})(links)
	links = resign(2, func(c *mda.Claims) { c.Mandatum.Parent = mda.Digest(links[1]) })(links)
	r := diag(t, links, s.Options)
	if hasCode(r.Links[2].Findings, "v7.too_deep") == nil {
		t.Errorf("no V7 finding; findings: %+v", r.Findings())
	}
	if r.Library.Rule != diagnose.V5 {
		t.Errorf("library reports %s; this test assumes it stops at V5 first", r.Library.Rule)
	}
}

func TestStatusAndKindsHaveNames(t *testing.T) {
	for _, s := range []diagnose.Status{diagnose.StatusPass, diagnose.StatusFail, diagnose.StatusError, diagnose.StatusUnchecked, diagnose.StatusSkipped, diagnose.StatusNotApplicable} {
		if s.String() == "unknown" {
			t.Errorf("status %d has no name", s)
		}
	}
	for _, r := range diagnose.Rules {
		if r.Title() == string(r) || r.Index() < 0 {
			t.Errorf("rule %s has no title or index", r)
		}
	}
	if diagnose.Rule("V10").Index() != -1 {
		t.Error("an unknown rule has an index")
	}
	for _, k := range []diagnose.CellKind{diagnose.CellAbsent, diagnose.CellHeld, diagnose.CellNarrowed, diagnose.CellWidened, diagnose.CellUnknown, diagnose.CellOrphan} {
		if k.String() == "unknown" && k != diagnose.CellUnknown {
			t.Errorf("cell kind %d has no name", k)
		}
	}
}

func TestShortNames(t *testing.T) {
	for in, want := range map[string]string{
		"spiffe://example.org/ns/agents/planner": "planner",
		"spiffe://example.org":                   "example.org",
		"https://idp.example.org/tenant?x=1":     "idp.example.org",
		"alice@example.org":                      "alice@example.org",
	} {
		if got := diagnose.Short(in); got != want {
			t.Errorf("Short(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanDurations(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:            "30s",
		41 * time.Minute:            "41m",
		2*time.Hour + 5*time.Minute: "2h05m",
		76 * time.Hour:              "3d4h",
		-90 * time.Minute:           "-1h30m",
	} {
		if got := diagnose.Human(d); got != want {
			t.Errorf("Human(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestJSONIsCompleteAndQuiet(t *testing.T) {
	s := scenario(t, "multifault")
	r := diag(t, s.Links, s.Options)
	j := r.JSON()
	if j.Schema != diagnose.SchemaVersion || j.Verdict != diagnose.VerdictInvalid || j.BreakAt != 1 {
		t.Errorf("header %+v", j)
	}
	if len(j.Links) != 3 || len(j.Hops) != 2 || len(j.Links[0].Checks) != len(diagnose.Rules) {
		t.Errorf("shape: %d links, %d hops, %d checks", len(j.Links), len(j.Hops), len(j.Links[0].Checks))
	}
	if j.Counts.Fail != 3 {
		t.Errorf("counts %+v, want 3 fails", j.Counts)
	}
	for _, f := range j.Findings {
		if strings.ContainsAny(f.Detail, "✅❌⚠✓✗") {
			t.Errorf("decoration in machine output: %q", f.Detail)
		}
	}
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
