package ucan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

// FuzzAnalyze feeds arbitrary bytes through everything a chain reaches:
// detection, input forms, envelope decoding, signatures, policies, the
// conversion to the neutral model and the question form. None of it may
// panic, and the chain must keep the model's promises.
func FuzzAnalyze(f *testing.F) {
	for _, sc := range New().Scenarios() {
		s, err := sc.Open(chaintest.Base)
		if err != nil {
			f.Fatal(err)
		}
		for _, tok := range s.(*Session).tokens {
			f.Add(tok.Raw)
		}
	}
	if data, err := os.ReadFile(filepath.Join("testdata", "spec", "invocation.json")); err == nil {
		var raw struct{ Valid, Invalid []json.RawMessage }
		if json.Unmarshal(data, &raw) == nil {
			for _, r := range append(raw.Valid, raw.Invalid...) {
				f.Add([]byte(r))
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = New().Detect(data)
		in, err := readInput(data)
		if err != nil {
			return
		}
		s := &Session{tokens: in.tokens, opts: Options{Revoked: map[string]bool{}}}
		at := chaintest.Base
		c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: at})
		if err != nil {
			return
		}
		for _, p := range chaintest.Problems(c) {
			t.Error(p)
		}
		for _, l := range c.Links {
			if l.RevokeID != "" {
				sim, err := s.Evaluate(context.Background(), chain.EvalOptions{At: at.Add(time.Hour), SimRevoked: []string{l.RevokeID}})
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range chaintest.Problems(sim) {
					t.Error(p)
				}
				break
			}
		}
		_, _ = s.Ask(context.Background(), c, s.AskPrefill(c, 0))
	})
}

// FuzzPolicy evaluates arbitrary policies against arbitrary arguments, both
// given as JSON. Parsing may refuse; evaluating must not panic and must
// stay within its step budget.
func FuzzPolicy(f *testing.F) {
	f.Add(`[["==", ".a", 1]]`, `{"a": 1.0}`)
	f.Add(`[["any", ".to", ["like", ".", "*@example.com"]]]`, `{"to": ["bob@example.com"]}`)
	f.Add(`[["all", ".m", ["not", ["==", ".x?", null]]]]`, `{"m": {"k": {"x": [1, 2]}}}`)
	f.Add(`[["or", [["<", ".a[-1]", 2], [">=", ".b[1:]", 0]]]]`, `{"a": [3, 1], "b": "xyz"}`)
	f.Fuzz(func(t *testing.T, pol, args string) {
		pv, err := jsonValue(pol)
		if err != nil {
			return
		}
		p, err := parsePolicy(pv)
		if err != nil {
			return
		}
		av, err := jsonValue(args)
		if err != nil {
			return
		}
		ev := &evaluation{}
		_, _, _ = p.match(av, ev)
		if ev.steps > maxSteps+1 {
			t.Errorf("%d steps, past the budget", ev.steps)
		}
		for _, s := range p {
			_ = s.String()
		}
	})
}
