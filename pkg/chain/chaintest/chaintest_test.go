package chaintest

import (
	"strings"
	"testing"

	"github.com/kanywst/whosent/pkg/chain"
)

func good() *chain.Chain {
	f := chain.Format{ID: "t", Name: "T", RootRole: "root", Rules: []chain.RuleInfo{{ID: "R1", Title: "one"}}}
	return &chain.Chain{
		Format: f, Verdict: chain.VerdictValid, BreakAt: -1,
		Links: []chain.Link{
			{Index: 0, Readable: true, Checks: []chain.Check{{Rule: "R1", Status: chain.StatusPass}}},
			{Index: 1, Readable: true, Checks: []chain.Check{{Rule: "R1", Status: chain.StatusPass}}},
		},
		Hops: []chain.Hop{{Parent: 0, Child: 1, Evaluable: true}},
	}
}

// A suite that passes everything proves nothing, so each promise is broken
// on purpose here and the suite must name it.
func TestProblemsNamesEveryBrokenPromise(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(*chain.Chain)
		want    string
	}{
		{"a valid chain with an unchecked rule", func(c *chain.Chain) { c.Links[1].Checks[0].Status = chain.StatusUnchecked }, "VALID with a failing or unchecked rule"},
		{"a valid chain with a failing rule", func(c *chain.Chain) { c.Links[1].Checks[0].Status = chain.StatusFail }, "VALID with a failing or unchecked rule"},
		{"an invalid chain with nothing failing", func(c *chain.Chain) { c.Verdict = chain.VerdictInvalid }, "INVALID with nothing failing"},
		{"an incomplete chain with nothing unchecked", func(c *chain.Chain) { c.Verdict = chain.VerdictIncomplete }, "INCOMPLETE with nothing unchecked"},
		{"checks out of the format's order", func(c *chain.Chain) { c.Links[0].Checks[0].Rule = "R9" }, "the format's rule 0"},
		{"a missing check", func(c *chain.Chain) { c.Links[0].Checks = nil }, "0 checks for 1 rules"},
		{"a link below the break that still looks reached", func(c *chain.Chain) {
			c.Verdict, c.BreakAt = chain.VerdictInvalid, 0
			c.Links[0].State = chain.LinkBroken
			c.Links[0].Checks[0].Status = chain.StatusFail
		}, "below the break"},
		{"an OK link with an unchecked rule", func(c *chain.Chain) {
			c.Verdict = chain.VerdictIncomplete
			c.IncompleteReason = "x"
			c.Links[1].Checks[0].Status = chain.StatusUnchecked
		}, "would draw it as verified"},
		{"a broken link with nothing failing", func(c *chain.Chain) { c.Links[1].State = chain.LinkBroken }, "broken but no check of it fails"},
		{"a hop that skips a link", func(c *chain.Chain) { c.Hops[0].Child = 3 }, "hop 0 is 0 to 3"},
		{"a matrix row too short", func(c *chain.Chain) {
			c.Matrix = &chain.Matrix{Retained: []int{1, 1}, Rows: []chain.Row{{Label: "x", Cells: []chain.Cell{{}}}}}
		}, "1 cells for 2 links"},
		{"an inconsistency with nothing to say", func(c *chain.Chain) { c.Inconsistency = &chain.Inconsistency{} }, "inconsistency without"},
	}
	if p := Problems(good()); len(p) != 0 {
		t.Fatalf("the good chain has problems: %v", p)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good()
			tt.breakIt(c)
			p := Problems(c)
			if !strings.Contains(strings.Join(p, "\n"), tt.want) {
				t.Errorf("the suite did not say %q; it said %v", tt.want, p)
			}
		})
	}
}
