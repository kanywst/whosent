// Package chaintest is the conformance suite every format adapter passes.
// It checks the promises the view and the command line rely on and cannot
// check themselves: that the model is internally consistent, that nothing
// unchecked is presented as checked, and that the adapter's demos open.
//
// An adapter's own test calls Run with the adapter. A failure names the
// scenario and the promise it breaks.
package chaintest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// Base is the time scenarios are minted at in the suite. It is fixed so that
// a failure reproduces.
var Base = time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)

// Run checks an adapter against every promise in this package.
func Run(t *testing.T, a chain.Adapter) {
	t.Helper()
	f := a.Format()
	t.Run("format", func(t *testing.T) { CheckFormat(t, f) })
	scenarios := a.Scenarios()
	if len(scenarios) == 0 {
		t.Fatalf("%s has no demo scenarios; a format without one cannot be shown or tested", f.ID)
	}
	names := map[string]bool{}
	for _, sc := range scenarios {
		if names[sc.Name] {
			t.Errorf("scenario %q appears twice", sc.Name)
		}
		names[sc.Name] = true
		if sc.Format != f.ID {
			t.Errorf("scenario %q says format %q, the adapter is %q", sc.Name, sc.Format, f.ID)
		}
		t.Run(sc.Name, func(t *testing.T) { CheckScenario(t, a, sc) })
	}
}

// CheckFormat checks a format descriptor.
func CheckFormat(t *testing.T, f chain.Format) {
	t.Helper()
	if f.ID == "" || f.Name == "" {
		t.Errorf("format ID %q, name %q: both are needed", f.ID, f.Name)
	}
	if strings.ToLower(f.ID) != f.ID || strings.ContainsAny(f.ID, " \t") {
		t.Errorf("format ID %q: lower case, no spaces; it is typed after --format", f.ID)
	}
	if len(f.Rules) == 0 {
		t.Error("a format with no rules has nothing to report")
	}
	seen := map[string]bool{}
	for _, r := range f.Rules {
		if r.ID == "" || r.Title == "" {
			t.Errorf("rule %+v: an ID and a title are both needed", r)
		}
		if seen[r.ID] {
			t.Errorf("rule %q appears twice", r.ID)
		}
		seen[r.ID] = true
	}
	if f.RootRole == "" {
		t.Error("RootRole is empty; the rail would label the root with nothing")
	}
}

// CheckScenario opens one demo, evaluates it at a few times, and checks
// every chain it produces.
func CheckScenario(t *testing.T, a chain.Adapter, sc chain.Scenario) {
	t.Helper()
	ctx := context.Background()
	s, err := sc.Open(Base)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	info := s.Info()
	if info.Format.ID != a.Format().ID {
		t.Errorf("session says format %q", info.Format.ID)
	}
	at := info.At
	if at.IsZero() {
		at = Base
	}
	c, err := s.Evaluate(ctx, chain.EvalOptions{At: at})
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	CheckChain(t, c)

	// A chain is rebuilt on every evaluation: the caller owns it.
	again, err := s.Evaluate(ctx, chain.EvalOptions{At: at})
	if err != nil {
		t.Fatalf("evaluating again: %v", err)
	}
	if again == c {
		t.Error("Evaluate returned the same *Chain twice; the view rewrites what it is given")
	} else if again.Verdict != c.Verdict || again.BreakAt != c.BreakAt {
		t.Errorf("the same inputs gave %s/%d, then %s/%d", c.Verdict, c.BreakAt, again.Verdict, again.BreakAt)
	}

	caps := info.Format.Caps
	if caps.TimeScrub {
		for _, d := range []time.Duration{-24 * time.Hour, time.Hour, 48 * time.Hour} {
			later, err := s.Evaluate(ctx, chain.EvalOptions{At: at.Add(d)})
			if err != nil {
				t.Fatalf("evaluating at %s: %v", d, err)
			}
			CheckChain(t, later)
		}
	}
	if caps.RevokeSim {
		revocable := false
		for _, l := range c.Links {
			if l.RevokeID == "" {
				continue
			}
			revocable = true
			sim, err := s.Evaluate(ctx, chain.EvalOptions{At: at, SimRevoked: []string{l.RevokeID}})
			if err != nil {
				t.Fatalf("simulating revocation of link %d: %v", l.Index, err)
			}
			CheckChain(t, sim)
			if sim.Verdict == chain.VerdictValid {
				t.Errorf("revoking link %d (simulated) left the chain VALID", l.Index)
			}
			if len(sim.Simulated) == 0 {
				t.Errorf("a simulated revocation of link %d is not listed in Simulated", l.Index)
			}
			break
		}
		if !revocable && len(c.Links) > 0 {
			t.Error("RevokeSim is on but no link has a RevokeID")
		}
	}
	asker, isAsker := s.(chain.Asker)
	if caps.Ask != isAsker {
		t.Errorf("Caps.Ask is %v but the session implements Asker: %v", caps.Ask, isAsker)
	}
	if isAsker {
		CheckAsk(t, asker, c)
	}

	if c.Native != nil {
		if _, err := json.Marshal(c.Native); err != nil {
			t.Errorf("Native does not marshal: %v", err)
		}
	}
	if _, err := json.Marshal(c.JSON()); err != nil {
		t.Errorf("the report does not marshal: %v", err)
	}
}

// CheckChain checks the promises one chain makes.
func CheckChain(t *testing.T, c *chain.Chain) {
	t.Helper()
	for _, p := range Problems(c) {
		t.Error(p)
	}
}

// Problems lists every promise a chain breaks; none means it keeps them all.
func Problems(c *chain.Chain) []string {
	var out []string
	errorf := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	f := c.Format
	n := len(c.Links)
	switch c.Verdict {
	case chain.VerdictValid, chain.VerdictInvalid, chain.VerdictIncomplete:
	default:
		return []string{fmt.Sprintf("verdict %q", c.Verdict)}
	}
	if c.BreakAt < -1 || c.BreakAt >= max(n, 1) {
		errorf("BreakAt %d with %d links", c.BreakAt, n)
	}
	if c.Inconsistency != nil && (c.Inconsistency.Banner == "" || c.Inconsistency.Detail == "") {
		errorf("an inconsistency without a banner or a detail cannot be reported")
	}

	blocking, unchecked := false, false
	for i, l := range c.Links {
		where := fmt.Sprintf("link %d", i)
		if l.Index != i {
			errorf("%s has Index %d", where, l.Index)
		}
		if len(l.Checks) != len(f.Rules) {
			errorf("%s has %d checks for %d rules", where, len(l.Checks), len(f.Rules))
		}
		for k, ch := range l.Checks {
			if k < len(f.Rules) && ch.Rule != f.Rules[k].ID {
				errorf("%s check %d is %q, the format's rule %d is %q", where, k, ch.Rule, k, f.Rules[k].ID)
			}
			switch {
			case ch.Status.Blocking():
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
		if l.Unreached && (l.UnreachedBy < 0 || l.UnreachedBy >= i) {
			errorf("%s is unreached by link %d, which is not above it", where, l.UnreachedBy)
		}
		if l.State == chain.LinkBroken && !anyBlocking(l) {
			errorf("%s is broken but no check of it fails", where)
		}
		if l.State == chain.LinkOK && !l.Unreached && anyBlocking(l) {
			errorf("%s is OK but a check of it fails", where)
		}
		if l.State == chain.LinkOK && !l.Unreached && anyUnchecked(l) {
			errorf("%s is OK but a check of it was not made; the view would draw it as verified", where)
		}
		if l.Remaining != 0 && l.ExpiresAt.IsZero() {
			errorf("%s has time remaining but no expiry", where)
		}
		for _, fd := range l.Findings {
			if fd.Link != i {
				errorf("%s carries a finding about link %d", where, fd.Link)
			}
		}
		for _, sec := range append(append([]chain.Section(nil), l.Sections...), l.Raw...) {
			for _, ln := range sec.Lines {
				if ln.Digest < 0 || ln.Digest > n {
					errorf("%s section %q has a digest colour for link %d of %d", where, sec.Title, ln.Digest-1, n)
				}
			}
		}
	}
	for _, fd := range c.ChainFindings {
		if fd.Link != -1 {
			errorf("a chain finding names link %d", fd.Link)
		}
	}
	for _, fd := range c.Findings() {
		if fd.Severity.Blocking() && !fd.Derived {
			blocking = true
		}
		if fd.Severity == chain.SeverityUnchecked {
			unchecked = true
		}
	}

	// The honesty rules.
	if c.Verdict == chain.VerdictValid && (blocking || unchecked) {
		errorf("VALID with a failing or unchecked rule: only a chain with every rule checked and holding is VALID")
	}
	if c.Verdict == chain.VerdictIncomplete && blocking {
		errorf("INCOMPLETE with a failing rule: a failure makes a chain INVALID")
	}
	if c.Verdict == chain.VerdictIncomplete && !unchecked {
		errorf("INCOMPLETE with nothing unchecked")
	}
	if c.Verdict == chain.VerdictInvalid && !blocking {
		errorf("INVALID with nothing failing")
	}
	if c.Verdict == chain.VerdictIncomplete && c.IncompleteReason == "" && c.Headline == "" {
		errorf("INCOMPLETE without saying what was not checked")
	}
	if c.BreakAt >= 0 {
		if c.Links[c.BreakAt].State != chain.LinkBroken && !c.Links[c.BreakAt].Revoked {
			errorf("BreakAt %d names a link that is neither broken nor revoked", c.BreakAt)
		}
		for i := c.BreakAt + 1; i < n; i++ {
			if !c.Links[i].Unreached {
				errorf("link %d is below the break at %d but not unreached", i, c.BreakAt)
			}
		}
	}

	for i, h := range c.Hops {
		if h.Parent < 0 || h.Child >= n || h.Child != h.Parent+1 {
			errorf("hop %d is %d to %d", i, h.Parent, h.Child)
		}
	}
	if m := c.Matrix; m != nil {
		if len(m.Retained) != n {
			errorf("Retained has %d entries for %d links", len(m.Retained), n)
		}
		if m.RootRows > len(m.Rows) {
			errorf("RootRows %d of %d rows", m.RootRows, len(m.Rows))
		}
		if len(m.Rows) > 0 && (m.DefaultRow < 0 || m.DefaultRow >= len(m.Rows)) {
			errorf("DefaultRow %d of %d rows", m.DefaultRow, len(m.Rows))
		}
		for _, r := range m.Rows {
			if len(r.Cells) != n {
				errorf("row %q has %d cells for %d links", r.Label, len(r.Cells), n)
			}
			for _, e := range r.Lineage {
				if e.Link < 0 || e.Link >= n {
					errorf("row %q traces link %d of %d", r.Label, e.Link, n)
				}
			}
		}
		for _, x := range m.Extra {
			if len(x.Cells) != n {
				errorf("summary row %q has %d cells for %d links", x.Label, len(x.Cells), n)
			}
		}
	}
	return out
}

func anyUnchecked(l chain.Link) bool {
	for _, c := range l.Checks {
		if c.Status == chain.StatusUnchecked {
			return true
		}
	}
	return false
}

func anyBlocking(l chain.Link) bool {
	for _, c := range l.Checks {
		if c.Status.Blocking() {
			return true
		}
	}
	return false
}

// CheckAsk asks the question the adapter itself proposes and checks the
// answer is labelled.
func CheckAsk(t *testing.T, a chain.Asker, c *chain.Chain) {
	t.Helper()
	fields := a.AskFields()
	if len(fields) == 0 {
		t.Error("an asker with no fields cannot be asked anything")
	}
	keys := map[string]bool{}
	for _, f := range fields {
		if f.Key == "" || f.Label == "" {
			t.Errorf("field %+v: a key and a label are both needed", f)
		}
		keys[f.Key] = true
	}
	row := 0
	if c.Matrix != nil {
		row = c.Matrix.DefaultRow
	}
	values := a.AskPrefill(c, row)
	res, err := a.Ask(context.Background(), c, values)
	if err != nil {
		// A prefill the asker itself refuses is a bug; an empty chain has
		// nothing to propose, so that is the one excuse.
		if len(c.Links) > 0 {
			t.Errorf("the asker refuses its own prefill %v: %v", values, err)
		}
		return
	}
	if res.Verdict == "" || res.Authority == "" {
		t.Errorf("an answer without a verdict or an authority: %+v", res)
	}
	if res.Permitted && c.Verdict == chain.VerdictInvalid {
		t.Error("an INVALID chain permitted something")
	}
	if res.Permitted && !res.Conditional && c.Verdict != chain.VerdictValid {
		t.Errorf("an unconditional permission from a %s chain", c.Verdict)
	}
	for _, s := range res.Steps {
		if s.Link < 0 || s.Link >= len(c.Links) {
			t.Errorf("a step names link %d of %d", s.Link, len(c.Links))
		}
	}
	for k := range res.Values {
		if !keys[k] && !strings.HasSuffix(k, "_json") {
			t.Errorf("the answer refills field %q, which the form does not have", k)
		}
	}
}
