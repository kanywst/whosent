package diagnose_test

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

func blockingSet(r *diagnose.Report) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range r.Findings() {
		if f.Derived || !f.Severity.Blocking() {
			continue
		}
		k := fmt.Sprintf("%s@%d", f.Rule, f.Link)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func expectSet(es []demo.Expectation) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, fmt.Sprintf("%s@%d", e.Rule, e.Link))
	}
	sort.Strings(out)
	return out
}

// Every scenario is diagnosed exactly as it promises, and the diagnosis
// agrees with mandatum. Run at the fixed base and at the wall clock, since
// the demo mints at "now" and a time-dependent bug would only show there.
func TestEveryScenarioIsDiagnosedAsItPromises(t *testing.T) {
	for _, base := range []time.Time{demo.FixedBase, time.Now()} {
		all, err := demo.All(base)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			t.Run(s.Name+"@"+base.Format("2006-01-02"), func(t *testing.T) {
				r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options)
				if err != nil {
					t.Fatal(err)
				}
				if !r.Library.Consistent {
					t.Fatalf("diagnosis disagrees with mandatum: %s", r.Library.Mismatch)
				}
				if r.Verdict != s.Verdict {
					t.Errorf("verdict %s, want %s", r.Verdict, s.Verdict)
				}
				if s.Expect.Rule == "" {
					if !r.Library.Passed {
						t.Errorf("mandatum refused a chain the scenario says verifies: %s at %d", r.Library.Rule, r.Library.Link)
					}
				} else if r.Library.Rule != s.Expect.Rule || r.Library.Link != s.Expect.Link {
					t.Errorf("mandatum reports %s at %d, want %s at %d", r.Library.Rule, r.Library.Link, s.Expect.Rule, s.Expect.Link)
				}
				got, want := blockingSet(r), expectSet(s.ExpectAll)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("blocking findings %v, want %v; the tool must show every fault, not only the first", got, want)
				}
				wantBreak := -1
				for _, e := range s.ExpectAll {
					if wantBreak < 0 || e.Link < wantBreak {
						wantBreak = e.Link
					}
				}
				if r.BreakAt != wantBreak {
					t.Errorf("BreakAt %d, want %d", r.BreakAt, wantBreak)
				}
				for _, l := range r.Links {
					if want := wantBreak >= 0 && l.Index > wantBreak; l.Unreached != want {
						t.Errorf("link %d unreached=%v, want %v", l.Index, l.Unreached, want)
					}
				}
				if (r.Result != nil) != (r.Verdict == diagnose.VerdictValid) {
					t.Errorf("Result set=%v for verdict %s; a result must exist exactly for a VALID chain", r.Result != nil, r.Verdict)
				}
			})
		}
	}
}

// The healthy chain must not have a single cell that is anything but pass
// or not-applicable when every input is supplied: a stray Unchecked or
// Skipped there would mean an input is silently not being used.
func TestHealthyChainPassesEveryApplicableCell(t *testing.T) {
	s, err := demo.Build("healthy", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range r.Links {
		for _, c := range l.Checks {
			if c.Status != diagnose.StatusPass && c.Status != diagnose.StatusNotApplicable {
				t.Errorf("link %d %s is %s (%s)", l.Index, c.Rule, c.Status, c.Detail)
			}
			if c.Status == diagnose.StatusPass && c.Detail == "" {
				t.Errorf("link %d %s passes with no detail; the inspector would show an empty line", l.Index, c.Rule)
			}
		}
		if l.State != diagnose.LinkOK {
			t.Errorf("link %d state %s, want ok", l.Index, l.State)
		}
	}
	applies := map[diagnose.Rule][]int{
		diagnose.V1: {0, 1, 2}, diagnose.V2: {1, 2}, diagnose.V3: {0, 1, 2}, diagnose.V4: {0, 1, 2},
		diagnose.V5: {1, 2}, diagnose.V6: {1, 2}, diagnose.V7: {2}, diagnose.V8: {0, 1, 2}, diagnose.V9: {2},
	}
	for rule, links := range applies {
		for _, i := range links {
			if st := r.Links[i].Check(rule).Status; st != diagnose.StatusPass {
				t.Errorf("link %d %s is %s, want pass", i, rule, st)
			}
		}
	}
}

// With nothing to check against, nothing may show as passing that needed an
// input: that is the whole honesty rule.
func TestUncheckedScenarioNeverShowsAnUncheckedRuleAsPassing(t *testing.T) {
	s, err := demo.Build("unchecked", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range r.Links {
		for _, rule := range []diagnose.Rule{diagnose.V3, diagnose.V8} {
			if st := l.Check(rule).Status; st != diagnose.StatusUnchecked {
				t.Errorf("link %d %s is %s without any input to check it", l.Index, rule, st)
			}
		}
		if l.State != diagnose.LinkIncomplete {
			t.Errorf("link %d state %s, want incomplete", l.Index, l.State)
		}
	}
	if st := r.Leaf().Check(diagnose.V9).Status; st != diagnose.StatusUnchecked {
		t.Errorf("leaf V9 is %s without an audience", st)
	}
	if !r.Library.StubsUsed {
		t.Error("the library run must record that it stood in for unchecked rules")
	}
	if r.Result != nil {
		t.Error("an INCOMPLETE chain must not carry a verification result")
	}
}

// The revoked scenario is the blast-radius demonstration: the revoked link
// fails, everything below is invalidated as a consequence, and nothing above
// is touched.
func TestRevocationReachesDownAndNeverUp(t *testing.T) {
	s, err := demo.Build("revoked", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Links[1].Revoked || r.Links[1].RevokedSimulated {
		t.Error("link 1 should be revoked, for real")
	}
	if r.Links[0].State != diagnose.LinkOK || r.Links[0].Unreached {
		t.Error("the link above a revocation is untouched")
	}
	var derived bool
	for _, f := range r.Links[2].Findings {
		if f.Code == "v8.ancestor_revoked" && f.Derived {
			derived = true
		}
	}
	if !derived {
		t.Error("link 2 should carry a derived finding saying its ancestor is revoked")
	}
	if !r.Links[2].Unreached || r.Links[2].UnreachedBy != 1 {
		t.Errorf("link 2 unreached=%v by %d, want true by 1", r.Links[2].Unreached, r.Links[2].UnreachedBy)
	}
	if st := r.Links[2].Check(diagnose.V8).Status; st != diagnose.StatusPass {
		t.Errorf("link 2's own jti is not revoked, so its V8 cell is %s; consequences live in findings, not cells", st)
	}
}

// Simulating a revocation is how the view shows a blast radius. The report
// must say it is a simulation, and the guard must account for it.
func TestSimulatedRevocationIsFlaggedAndConsistent(t *testing.T) {
	s, err := demo.Build("healthy", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	jti := "dlg-planner-002"
	r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options.WithSimulatedRevocations([]string{jti}))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Library.Consistent {
		t.Fatalf("guard disagrees under simulation: %s", r.Library.Mismatch)
	}
	if r.Library.Rule != diagnose.V8 || r.Library.Link != 1 {
		t.Errorf("library sees %s at %d, want V8 at 1", r.Library.Rule, r.Library.Link)
	}
	if len(r.Simulated) != 1 || r.Simulated[0] != jti {
		t.Errorf("Simulated = %v", r.Simulated)
	}
	c := r.Links[1].Check(diagnose.V8)
	if c.Status != diagnose.StatusFail || !c.Simulated {
		t.Errorf("link 1 V8 = %+v, want a simulated fail", c)
	}
	for _, f := range r.Links[2].Findings {
		if f.Code == "v8.ancestor_revoked" && !f.Simulated {
			t.Error("a consequence of a simulated revocation must be marked simulated too")
		}
	}
	if r.Verdict != diagnose.VerdictInvalid || r.Result != nil {
		t.Error("a simulated revocation must make the chain INVALID with no result")
	}
}

// Scrubbing time is a view feature built on WithAt: past the leaf's expiry
// the chain breaks at the leaf, past the middle link's it breaks there.
func TestScrubbingTimeMovesTheBreak(t *testing.T) {
	s, err := demo.Build("healthy", demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	// Revocation sets age with the clock too; give the scrub room.
	maxAge := time.Duration(0)
	s.Options.Revocation.MaxAge = &maxAge
	tests := []struct {
		name      string
		after     time.Duration
		wantBreak int
	}{
		{"before anything expires the chain holds", 10 * time.Minute, -1},
		{"after the leaf's expiry it breaks at the leaf", 25 * time.Minute, 2},
		{"after the middle link's expiry it breaks there", 45 * time.Minute, 1},
		{"after the grant's expiry it breaks at the root", 2 * time.Hour, 0},
		{"before the grant was issued it breaks at the root", -time.Hour, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options.WithAt(demo.FixedBase.Add(tt.after)))
			if err != nil {
				t.Fatal(err)
			}
			if !r.Library.Consistent {
				t.Fatalf("guard: %s", r.Library.Mismatch)
			}
			if r.BreakAt != tt.wantBreak {
				t.Errorf("BreakAt %d, want %d", r.BreakAt, tt.wantBreak)
			}
		})
	}
}
