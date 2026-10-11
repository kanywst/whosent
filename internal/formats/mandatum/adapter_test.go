package mandatum

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/internal/mandatum/verify"
	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
	"github.com/kanywst/whosent/pkg/diagnose"
)

func TestTheMandatumFormatConforms(t *testing.T) { chaintest.Run(t, New()) }

func buildReport(t *testing.T, name string) (*Session, *diagnose.Report) {
	t.Helper()
	sc, err := demo.Build(name, demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSession(sc.Links, sc.Options, diagnose.InputInfo{Source: name})
	r, err := s.Report(context.Background(), chain.EvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

// The neutral model says exactly what the engine said: the same verdict,
// break, rule outcomes and findings, for every scenario. The view and the
// command line read only the model, so anything lost here is lost to them.
func TestConvertKeepsTheEngineVerdict(t *testing.T) {
	for _, name := range demo.Names() {
		t.Run(name, func(t *testing.T) {
			_, r := buildReport(t, name)
			c := Convert(r)
			if string(c.Verdict) != string(r.Verdict) || c.BreakAt != r.BreakAt {
				t.Errorf("model %s/%d, engine %s/%d", c.Verdict, c.BreakAt, r.Verdict, r.BreakAt)
			}
			if len(c.Findings()) != len(r.Findings()) {
				t.Errorf("model has %d findings, engine %d", len(c.Findings()), len(r.Findings()))
			}
			for i, l := range r.Links {
				for k, ch := range l.Checks {
					got := c.Links[i].Checks[k]
					if got.Rule != string(ch.Rule) || int(got.Status) != int(ch.Status) {
						t.Errorf("link %d %s: model %s, engine %s", i, ch.Rule, got.Status, ch.Status)
					}
				}
				if c.Links[i].Unreached != l.Unreached || c.Links[i].Revoked != l.Revoked {
					t.Errorf("link %d: reach or revocation differs", i)
				}
			}
		})
	}
}

// The statuses and severities are converted by number, so the two
// enumerations must stay in step; this pins them.
func TestEnumerationsLineUp(t *testing.T) {
	pairs := []struct{ engine, model string }{
		{diagnose.StatusPass.String(), chain.StatusPass.String()},
		{diagnose.StatusFail.String(), chain.StatusFail.String()},
		{diagnose.StatusError.String(), chain.StatusError.String()},
		{diagnose.StatusUnchecked.String(), chain.StatusUnchecked.String()},
		{diagnose.StatusSkipped.String(), chain.StatusSkipped.String()},
		{diagnose.SeverityFail.String(), chain.SeverityFail.String()},
		{diagnose.SeverityError.String(), chain.SeverityError.String()},
		{diagnose.SeverityUnchecked.String(), chain.SeverityUnchecked.String()},
		{diagnose.SeverityWarn.String(), chain.SeverityWarn.String()},
		{diagnose.SeverityInfo.String(), chain.SeverityInfo.String()},
	}
	for _, p := range pairs {
		if p.engine != p.model {
			t.Errorf("engine %q is model %q", p.engine, p.model)
		}
	}
	if int(diagnose.StatusNotApplicable) != int(chain.StatusNotApplicable) ||
		int(diagnose.LinkBroken) != int(chain.LinkBroken) || int(diagnose.LinkIncomplete) != int(chain.LinkIncomplete) ||
		int(diagnose.CellOrphan) != int(chain.CellOrphan) || int(diagnose.CellWidened) != int(chain.CellWidened) {
		t.Error("an enumeration converted by number is out of step")
	}
}

// A disagreement with the reference verifier reaches the model as a banner
// naming both sides.
func TestAnInconsistencyBecomesABanner(t *testing.T) {
	_, r := buildReport(t, "healthy")
	r.Library.Consistent = false
	r.Library.Passed = false
	r.Library.Rule, r.Library.Link = diagnose.V3, 1
	r.Library.Mismatch = "injected"
	c := Convert(r)
	if c.Inconsistency == nil || !strings.Contains(c.Inconsistency.Banner, "V3 at link 1") || c.Inconsistency.Detail != "injected" {
		t.Errorf("%+v", c.Inconsistency)
	}
}

// "Never granted" and "granted, then dropped" send a reader to different
// people, so each is said only when it is the true story.
func TestNeverGrantedIsSaidOnlyWhenTrue(t *testing.T) {
	s, r := buildReport(t, "widened")
	c := Convert(r)
	res, err := s.Ask(context.Background(), c, map[string]string{
		FieldAction: "invoke", FieldResourceType: "mcp_tool", FieldResourceID: "docs.write", FieldTags: "mutating",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Warning, "the sponsor granted this, link 1 dropped it") {
		t.Errorf("warning %q", res.Warning)
	}
	tr := r.Ask(mustRequest(t, res.Values))
	tr.SponsorGranted = false
	if w := Answer(r, tr).Warning; !strings.Contains(w, "the sponsor never granted this") {
		t.Errorf("authority the sponsor never granted is not called out: %q", w)
	}
}

func mustRequest(t *testing.T, v map[string]string) verify.Request {
	t.Helper()
	r, err := Request(v)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDetect(t *testing.T) {
	sc, err := demo.Build("healthy", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	var links []string
	for _, l := range sc.Links {
		links = append(links, string(l))
	}
	wire, _ := json.Marshal(links)
	if got := New().Detect(wire); got != chain.Certain {
		t.Errorf("a chain with Mandatum's media type is %v, want Certain", got)
	}
	// An ordinary JWT is in a shape this reader accepts, but claiming it
	// would make every access token ambiguous with the JWT format. Only the
	// Mandatum claims make an untyped link plausible.
	plainJWT := `["eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2ln"]`
	if got := New().Detect([]byte(plainJWT)); got != chain.NotMine {
		t.Errorf("an ordinary JWT is %v, want NotMine", got)
	}
	untyped := `["eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwibWR0Ijp7fX0.c2ln"]`
	if got := New().Detect([]byte(untyped)); got != chain.Plausible {
		t.Errorf("an untyped link carrying mdt claims is %v, want Plausible", got)
	}
	for _, in := range []string{"", "not a chain", "{}", "[]"} {
		if got := New().Detect([]byte(in)); got != chain.NotMine {
			t.Errorf("%q is %v, want NotMine", in, got)
		}
	}
}

func TestAskRefusesAnIncompleteRequest(t *testing.T) {
	s, r := buildReport(t, "healthy")
	if _, err := s.Ask(context.Background(), Convert(r), map[string]string{FieldAction: "invoke"}); err == nil {
		t.Error("a request without a resource was answered")
	}
	if _, err := s.Ask(context.Background(), Convert(r), map[string]string{
		FieldAction: "invoke", FieldResourceType: "mcp_tool", FieldResourceID: "x", FieldAttributes: "novalue",
	}); err == nil || !strings.Contains(err.Error(), "key=value") {
		t.Errorf("a malformed attribute: %v", err)
	}
}
