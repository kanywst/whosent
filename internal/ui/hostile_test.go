package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/internal/termsafe"
	"github.com/kanywst/whosent/pkg/chain"
)

// hostile is what a chain's author could put in any string field to take
// over the terminal of whoever inspects it: a screen clear and a fake
// verdict, an OSC 52 clipboard write, a carriage return that overwrites the
// line, a newline that forges one, and a bidi override that reverses text.
const hostile = "evil\x1b[2J\x1b[H\x1b[32m VALID \x1b]52;c;cm0gLXJmIH4=\x07\rok\nforged\u202egnp.exe\u2066x\u2069\x9b31m"

// hostileToken is a compact JWT whose every string is hostile, with an
// act chain two deep. It is not signed by anyone; the view must still draw
// it, and draw it safely.
func hostileToken(t *testing.T, n int) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": hostile}
	actor := map[string]any{"sub": hostile + "-a", "iss": hostile, "sub_profile": hostile,
		"act": map[string]any{"sub": hostile + "-b", "iss": hostile}}
	claims := map[string]any{
		"iss": hostile, "sub": hostile, "aud": hostile, "client_id": hostile, "scope": hostile + " " + hostile + "2",
		"iat": 1789200000, "exp": 1789203600 + n, "jti": hostile, "act": actor,
		"may_act": map[string]any{"sub": hostile, "iss": hostile},
	}
	return enc(header) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature"))
}

// TestAHostileChainCannotReachTheTerminal renders every view of a chain whose
// every string is an attack, removes the colour sequences lipgloss itself
// writes, and checks nothing a terminal would act on is left.
func TestAHostileChainCannotReachTheTerminal(t *testing.T) {
	bundle, err := json.Marshal([]string{hostileToken(t, 0), hostileToken(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	aud := hostile
	a, err := all.Registry().Lookup("jwt")
	if err != nil {
		t.Fatal(err)
	}
	jwtChain, err := a.Open(context.Background(), chain.Inputs{Data: bundle, Source: hostile, Audience: &aud, At: time.Unix(1789200060, 0)})
	if err != nil {
		t.Fatal(err)
	}
	jwtSession := Session{Name: hostile, Title: hostile, Summary: hostile, Chain: jwtChain}
	// An adapter can put anything in any field, and adapters never
	// sanitise: the view is the one place it happens. This session fills
	// every string the model has with the attack.
	adapterSession := Session{Name: hostile, Title: hostile, Summary: hostile, Chain: hostileSession{}}
	for _, s := range []Session{jwtSession, adapterSession} {
		renderHostile(t, s)
	}
}

func renderHostile(t *testing.T, s Session) {
	t.Helper()
	for _, v := range views {
		for _, sz := range [][2]int{{140, 45}, {80, 24}} {
			for _, keys := range [][]string{v.keys, append([]string{"right"}, v.keys...), append([]string{"right", "right"}, v.keys...)} {
				m := press(t, sized(t, Config{Sessions: []Session{s}}, sz[0], sz[1]), keys...)
				out := sgr.ReplaceAllString(m.View().Content, "")
				for _, line := range strings.Split(out, "\n") {
					if !utf8.ValidString(line) {
						t.Fatalf("%s %v at %dx%d: invalid UTF-8 reached the terminal in:\n%q", v.name, keys, sz[0], sz[1], line)
					}
					for _, r := range line {
						if termsafe.Unsafe(r) {
							t.Fatalf("%s %v at %dx%d: %q reached the terminal in:\n%q", v.name, keys, sz[0], sz[1], r, line)
						}
					}
				}
			}
		}
	}
}

// hostileSession is an adapter whose every string is an attack.
type hostileSession struct{}

var hostileFormat = chain.Format{
	ID: "hostile", Name: hostile, RootRole: hostile,
	Rules: []chain.RuleInfo{{ID: hostile, Title: hostile, Spec: hostile}, {ID: "H2", Title: hostile}},
	Caps:  chain.Capabilities{TimeScrub: true, RevokeSim: true, Ask: true},
}

func (hostileSession) Info() chain.Info {
	return chain.Info{Format: hostileFormat, At: time.Unix(1789200060, 0)}
}

func (hostileSession) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	h := hostile
	line := func(k chain.LineKind) chain.Line {
		return chain.Line{Kind: k, Key: h, Value: h + "\n" + h, Mark: chain.MarkFail, Digest: 1}
	}
	lines := []chain.Line{line(chain.LineKV), line(chain.LineText), line(chain.LineChange), line(chain.LineJSON), line(chain.LineCode)}
	sections := []chain.Section{{Title: h, Lines: lines}}
	c := &chain.Chain{
		Format: hostileFormat, Source: h, InputFormat: h, At: eo.At, Verdict: chain.VerdictInvalid, BreakAt: 1,
		IncompleteReason: h, Summary: []string{h, h}, Describe: h, Context: h,
		Root:          chain.Root{Name: h, Kind: h, Details: []string{h, h}},
		ChainFindings: []chain.Finding{{Rule: h, Link: -1, Hop: -1, Severity: chain.SeverityFail, Detail: h, Spec: h}},
		Matrix: &chain.Matrix{Title: h, Scope: h, RootRows: 1, Retained: []int{1, 0},
			Rows:  []chain.Row{{Label: h, Cells: []chain.Cell{{Kind: chain.CellHeld}, {Kind: chain.CellWidened}}, Lineage: []chain.LineageEntry{{Link: 0, Kind: chain.CellHeld, Texts: []string{h}}, {Link: 1, Kind: chain.CellWidened, Texts: []string{h}}}}},
			Extra: []chain.SummaryRow{{Label: h, Cells: []chain.SummaryCell{{Text: h}, {Text: h}}}}},
		CheckedAgainst: []chain.KV{{Key: h, Value: h}, {Key: "time", Value: h}},
		Missing:        []string{h},
		Simulated:      eo.SimRevoked,
		Inconsistency:  &chain.Inconsistency{Banner: h, Detail: h},
	}
	for i := 0; i < 2; i++ {
		c.Links = append(c.Links, chain.Link{
			Index: i, From: h, To: h, Readable: true, State: chain.LinkState(i * 2), Asserted: i == 0,
			Checks:   []chain.Check{{Rule: h, Status: chain.StatusFail, Detail: h}, {Rule: "H2", Status: chain.StatusUnchecked}},
			Findings: []chain.Finding{{Rule: h, Link: i, Hop: -1, Severity: chain.SeverityFail, Detail: h, Spec: h}},
			IssuedAt: eo.At.Add(-time.Hour), ExpiresAt: eo.At.Add(time.Hour), Remaining: time.Hour,
			RevokeID: h,
			Sections: sections, Raw: sections,
		})
	}
	c.Hops = []chain.Hop{{Parent: 0, Child: 1, Evaluable: true, Verdict: h,
		Changes: []chain.Change{{Kind: chain.ChangeWidened, Before: h, Text: h, Notes: []string{h}}}}}
	return c, nil
}

func (hostileSession) AskFields() []chain.AskField {
	return []chain.AskField{{Key: "a", Label: hostile, Hint: hostile}, {Key: "b", Label: hostile, Hint: hostile}}
}

func (hostileSession) AskPrefill(*chain.Chain, int) map[string]string {
	return map[string]string{"a": hostile, "b": hostile}
}

func (hostileSession) Ask(context.Context, *chain.Chain, map[string]string) (*chain.AskResult, error) {
	h := hostile
	return &chain.AskResult{
		Request: []string{h, h}, Verdict: h, Tone: chain.ToneBad, Mark: chain.MarkFail, Authority: h,
		Why: h, Reason: h, Warning: h, StepsTitle: h,
		Steps:  []chain.AskStep{{Link: 0, Outcome: chain.OutcomeRefuses, Reason: h, ShowReason: true}, {Link: 1, Outcome: chain.OutcomeCovers}},
		Values: map[string]string{"a": h, "b": h},
	}, nil
}
