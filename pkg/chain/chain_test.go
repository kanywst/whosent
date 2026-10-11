package chain_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// claimer is an adapter that claims every input with a fixed confidence.
type claimer struct {
	id   string
	conf chain.Confidence
}

func (c claimer) Format() chain.Format {
	return chain.Format{ID: c.id, Name: strings.ToUpper(c.id)}
}
func (c claimer) Detect([]byte) chain.Confidence { return c.conf }
func (c claimer) Open(context.Context, chain.Inputs) (chain.Session, error) {
	return nil, nil
}
func (c claimer) Scenarios() []chain.Scenario {
	return []chain.Scenario{{Name: c.id + "-demo", Format: c.id}}
}

func TestDetectPicksOneFormatOrSaysWhy(t *testing.T) {
	tests := []struct {
		name    string
		claims  []claimer
		want    string
		wantErr string
	}{
		{"one certain claim wins over plausible ones", []claimer{{"a", chain.Plausible}, {"b", chain.Certain}}, "b", ""},
		{"a lone plausible claim wins", []claimer{{"a", chain.NotMine}, {"b", chain.Plausible}}, "b", ""},
		{"two certain claims are refused", []claimer{{"a", chain.Certain}, {"b", chain.Certain}}, "", "A or B"},
		{"two plausible claims are refused", []claimer{{"a", chain.Plausible}, {"b", chain.Plausible}}, "", "pass --format"},
		{"no claim names every format", []claimer{{"a", chain.NotMine}, {"b", chain.NotMine}}, "", "not a A or B chain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var as []chain.Adapter
			for _, c := range tt.claims {
				as = append(as, c)
			}
			r, err := chain.NewRegistry(as...)
			if err != nil {
				t.Fatal(err)
			}
			a, err := r.Detect([]byte("x"))
			switch {
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %v, want one mentioning %q", err, tt.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			case a.Format().ID != tt.want:
				t.Errorf("picked %s, want %s", a.Format().ID, tt.want)
			}
		})
	}
}

func TestRegistryRefusesDuplicatesAndNamesUnknowns(t *testing.T) {
	if _, err := chain.NewRegistry(claimer{id: "a"}, claimer{id: "a"}); err == nil {
		t.Error("two formats with one ID were accepted")
	}
	r, _ := chain.NewRegistry(claimer{id: "a"}, claimer{id: "b"})
	if _, err := r.Lookup("c"); err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("unknown format: %v", err)
	}
	if _, err := r.Scenario("nope"); err == nil || !strings.Contains(err.Error(), "unknown scenario") {
		t.Errorf("unknown scenario: %v", err)
	}
	if s, err := r.Scenario("b-demo"); err != nil || s.Format != "b" {
		t.Errorf("scenario lookup: %+v %v", s, err)
	}
}

// The machine report carries every link's every rule, says which links are
// only asserted, and never drops a finding.
func TestJSONCarriesTheFacts(t *testing.T) {
	at := time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)
	c := &chain.Chain{
		Format: chain.Format{ID: "t", Rules: []chain.RuleInfo{{ID: "R1", Title: "one"}}},
		At:     at, Verdict: chain.VerdictInvalid, BreakAt: 1,
		Links: []chain.Link{
			{Index: 0, From: "a", To: "b", Readable: true, Asserted: true, Checks: []chain.Check{{Rule: "R1", Status: chain.StatusNotApplicable}}},
			{Index: 1, From: "b", To: "c", Readable: true, State: chain.LinkBroken, ExpiresAt: at,
				Checks:   []chain.Check{{Rule: "R1", Status: chain.StatusFail}},
				Findings: []chain.Finding{{Rule: "R1", Link: 1, Hop: -1, Severity: chain.SeverityFail, Detail: "no"}}},
		},
		ChainFindings: []chain.Finding{{Rule: "", Link: -1, Hop: -1, Severity: chain.SeverityWarn, Detail: "w"},
			{Rule: "R1", Link: -1, Hop: -1, Severity: chain.SeverityFail, Detail: "a consequence", Derived: true}},
		Hops: []chain.Hop{{Parent: 0, Child: 1, Evaluable: true, Changes: []chain.Change{{Kind: chain.ChangeNarrowed, Before: "x", Text: "y"}}}},
	}
	b, err := json.Marshal(c.JSON())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"schema":"whosent.chain/v1"`, `"state":"asserted"`, `"state":"broken"`, `"R1":"fail"`, `"R1":"n/a"`,
		`"before":"x"`, `"detail":"no"`, `"detail":"w"`, `"break_at":1`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON lacks %s:\n%s", want, s)
		}
	}
	if c.Counts()[chain.SeverityFail] != 1 || c.Leaf().Index != 1 {
		t.Errorf("Counts %v (a consequence is not counted) or Leaf is wrong", c.Counts())
	}
}

func TestHumanCountsDown(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45s", 12 * time.Minute: "12m", 185 * time.Minute: "3h05m", 52 * time.Hour: "2d4h", -90 * time.Second: "-1m",
	} {
		if got := chain.Human(d); got != want {
			t.Errorf("Human(%s) = %q, want %q", d, got, want)
		}
	}
}
