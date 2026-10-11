package biscuit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/pkg/chain"
)

// FuzzAnalyze feeds arbitrary bytes through everything a token reaches:
// detection, decoding, verification, the Datalog engine, the conversion to
// the neutral model and the question form. None of it may panic, and the
// chain it produces must keep the model's promises.
func FuzzAnalyze(f *testing.F) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "samples", "*.bc"))
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil {
			f.Add(data)
		}
	}
	for _, sc := range New().Scenarios() {
		s, err := sc.Open(time.Unix(1789200000, 0))
		if err != nil {
			f.Fatal(err)
		}
		raw, err := s.(*Session).tok.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	prog, err := datalog.ParseProgram(`resource("orders"); operation("read"); allow if true;`)
	if err != nil {
		f.Fatal(err)
	}
	opts := Options{RootKeys: []Key{rootSigner.Pub}, Revoked: map[string]bool{}, Program: prog, HasAuthorizer: true,
		Limits: datalog.Limits{MaxFacts: 200, MaxIterations: 20, MaxTime: time.Second}}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = New().Detect(data)
		tok, err := Decode(data)
		if err != nil {
			return
		}
		at := time.Unix(1789200060, 0)
		s := &Session{tok: tok, opts: opts, at: at}
		c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: at})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range problems(c) {
			t.Error(p)
		}
		_, _ = s.Ask(context.Background(), c, map[string]string{askFacts: `resource("x")`, askPolicy: "allow if true"})
	})
}
