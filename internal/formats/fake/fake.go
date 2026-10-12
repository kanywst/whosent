// Package fake is a format adapter that exists only for tests. It hands the
// view shapes no real format has produced yet: links whose place in the
// chain is only asserted, a chain with no authority matrix, a format with no
// time scrub, no revocation and no questions, and inspector sections made of
// source code. If the view handles these, a new adapter that produces them
// needs no change to the view.
//
// It is never registered with the command line.
package fake

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// ID is the format's name.
const ID = "fake"

// Adapter is the fake format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

var format = chain.Format{
	ID:       ID,
	Name:     "Fake",
	RootRole: "issuer",
	Rules: []chain.RuleInfo{
		{ID: "F-SIG", Title: "signature", Spec: "fake section 1"},
		{ID: "F-TIME", Title: "time", Spec: "fake section 2"},
		{ID: "F-ACT", Title: "actor", Spec: "fake section 3"},
	},
}

// Format describes the fake format: no interactive features at all.
func (Adapter) Format() chain.Format { return format }

// Detect claims inputs that start with "fake:".
func (Adapter) Detect(data []byte) chain.Confidence {
	if len(data) >= 5 && string(data[:5]) == "fake:" {
		return chain.Certain
	}
	return chain.NotMine
}

// Open opens the "asserted" scenario for any input it claims.
func (Adapter) Open(_ context.Context, in chain.Inputs) (chain.Session, error) {
	if (Adapter{}).Detect(in.Data) != chain.Certain {
		return nil, errors.New("not a fake chain")
	}
	return session{name: "fake-asserted", at: in.At}, nil
}

// Scenarios are the shapes.
func (Adapter) Scenarios() []chain.Scenario {
	mk := func(name, title, summary string) chain.Scenario {
		return chain.Scenario{
			Name: name, Title: title, Summary: summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				return session{name: name, at: base.Add(time.Minute)}, nil
			},
		}
	}
	return []chain.Scenario{
		mk("fake-asserted", "An issuer's word for three actors",
			"one signed token names three prior actors. Only the issuer vouches for them, and nothing verifies them hop by hop."),
		mk("fake-blocks", "Blocks of checks, one forged",
			"a root key's grant narrowed by blocks of checks; the second block's signature does not verify."),
		mk("fake-long", "Ten hops",
			"a grant passed down ten agents, each narrowing it a little. More links than the matrix can show at once."),
	}
}

type session struct {
	name string
	at   time.Time
}

func (s session) Info() chain.Info { return chain.Info{Format: format, At: s.at} }

func (s session) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	switch s.name {
	case "fake-blocks":
		return blocks(eo.At), nil
	case "fake-long":
		return long(eo.At), nil
	}
	return asserted(eo.At), nil
}

func checks(sig, tm, act chain.Status) []chain.Check {
	return []chain.Check{{Rule: "F-SIG", Status: sig}, {Rule: "F-TIME", Status: tm}, {Rule: "F-ACT", Status: act}}
}

// asserted is a JWT-shaped chain: the token is signed and current, the
// actors before the current one are the issuer's say-so.
func asserted(at time.Time) *chain.Chain {
	exp := at.Add(50 * time.Minute)
	c := &chain.Chain{
		Format: format, Source: "fake-asserted", InputFormat: "fake", At: at,
		Verdict: chain.VerdictValid, BreakAt: -1,
		Headline: "The token verifies. Its three prior actors are the issuer's word, not a verified chain.",
		Summary:  []string{"1 token", "3 actors", "asserted chain"},
		Describe: "issuer https://idp.example.com",
		Context:  "at " + at.UTC().Format(time.RFC3339),
		Root:     chain.Root{Name: "idp.example.com", Kind: "issuer", Details: []string{"signed the token"}},
		CheckedAgainst: []chain.KV{
			{Key: "keys", Value: "idp.example.com  key-1"},
			{Key: "time", Value: at.UTC().Format("15:04 UTC")},
		},
	}
	names := []string{"alice", "planner", "fetcher"}
	for i, n := range names {
		from := "idp.example.com"
		if i > 0 {
			from = names[i-1]
		}
		l := chain.Link{
			Index: i, From: from, To: n, Readable: true, Asserted: i < len(names)-1,
			Checks:   checks(chain.StatusPass, chain.StatusPass, chain.StatusPass),
			IssuedAt: at.Add(-10 * time.Minute), ExpiresAt: exp, Remaining: exp.Sub(at),
			Sections: []chain.Section{{Title: "ACTOR", Lines: []chain.Line{
				{Kind: chain.LineKV, Key: "sub", Value: n},
				{Kind: chain.LineKV, Key: "sub_profile", Value: "ai_agent", Tone: chain.ToneMuted},
			}}},
			Raw: []chain.Section{{Title: "CLAIMS", Lines: []chain.Line{{Kind: chain.LineJSON, Value: "{\n  \"sub\": \"" + n + "\"\n}"}}}},
		}
		if l.Asserted {
			// Nothing could verify a prior actor, whatever was supplied, so
			// its rules do not apply rather than being unchecked; Asserted
			// is what keeps it from looking verified.
			l.Checks = checks(chain.StatusNotApplicable, chain.StatusNotApplicable, chain.StatusNotApplicable)
			l.Findings = []chain.Finding{{Rule: "F-ACT", Link: i, Hop: -1, Severity: chain.SeverityInfo,
				Detail: "a prior actor: informational, and nothing verifies it"}}
		}
		c.Links = append(c.Links, l)
		if i > 0 {
			c.Hops = append(c.Hops, chain.Hop{Parent: i - 1, Child: i, Evaluable: true,
				Changes: []chain.Change{{Kind: chain.ChangeInfo, Text: "acts for " + names[i-1]}}})
		}
	}
	return c
}

// blocks is a Biscuit-shaped chain: a root key, blocks that only add
// checks, and a matrix whose rows are checks rather than grants.
func blocks(at time.Time) *chain.Chain {
	c := &chain.Chain{
		Format: format, Source: "fake-blocks", InputFormat: "fake", At: at,
		Verdict: chain.VerdictInvalid, BreakAt: 2,
		Summary: []string{"3 blocks", "root key ed25519/1055c7"},
		Root:    chain.Root{Name: "ed25519/1055c7", Kind: "key", Details: []string{"root key"}},
		Matrix: &chain.Matrix{
			Title: "CHECKS", RootRows: 1, Retained: []int{1, 1, 1},
			Rows: []chain.Row{
				{Label: "right(file1, read)", Cells: []chain.Cell{{Kind: chain.CellHeld}, {Kind: chain.CellHeld}, {Kind: chain.CellHeld}},
					Lineage: []chain.LineageEntry{{Link: 0, Kind: chain.CellHeld, Texts: []string{`right("file1", "read")`}}}},
				{Label: "check operation(read)", Origin: 1, Cells: []chain.Cell{{}, {Kind: chain.CellNarrowed, Changed: true}, {Kind: chain.CellNarrowed}},
					Lineage: []chain.LineageEntry{{Link: 1, Kind: chain.CellNarrowed, Changed: true, Texts: []string{`check if operation("read")`}}}},
			},
		},
		CheckedAgainst: []chain.KV{{Key: "root key", Value: "ed25519/1055c7"}, {Key: "authorizer", Value: "none given: checks were not evaluated", Tone: chain.ToneWarn}},
		Missing:        []string{"an authorizer (--fact or --authorizer)"},
	}
	code := []string{
		"right(\"file1\", \"read\");",
		"check if operation(\"read\");",
		"check if time($t), $t <= 2026-09-12T09:00:00Z;",
	}
	for i := 0; i < 3; i++ {
		l := chain.Link{
			Index: i, From: "block", To: "block " + string(rune('0'+i)), Readable: true,
			State:    chain.LinkIncomplete,
			Checks:   checks(chain.StatusPass, chain.StatusUnchecked, chain.StatusNotApplicable),
			RevokeID: "rev-" + string(rune('0'+i)),
			Sections: []chain.Section{{Title: "DATALOG", Lines: []chain.Line{{Kind: chain.LineCode, Value: code[i]}}}},
			Raw:      []chain.Section{{Title: "REVOCATION ID", Lines: []chain.Line{{Kind: chain.LineKV, Key: "id", Value: "rev-" + string(rune('0'+i)), Digest: i + 1}}}},
		}
		if i == 0 {
			l.From = "root key"
		}
		if i == 2 {
			l.State = chain.LinkBroken
			l.Checks[0] = chain.Check{Rule: "F-SIG", Status: chain.StatusFail, Detail: "signature does not verify"}
			l.Findings = []chain.Finding{{Rule: "F-SIG", Link: 2, Hop: -1, Severity: chain.SeverityFail, Detail: "block 2's signature does not verify against block 1's next key"}}
		}
		c.Links = append(c.Links, l)
		if i > 0 {
			c.Hops = append(c.Hops, chain.Hop{Parent: i - 1, Child: i, Evaluable: true,
				Changes: []chain.Change{{Kind: chain.ChangeNarrowed, Text: code[i]}}})
		}
	}
	return c
}

// long is a chain with more links than the matrix has room for.
func long(at time.Time) *chain.Chain {
	const n = 10
	c := &chain.Chain{
		Format: format, Source: "fake-long", InputFormat: "fake", At: at,
		Verdict: chain.VerdictValid, BreakAt: -1,
		Summary: []string{"10 links"},
		Root:    chain.Root{Name: "alice", Kind: "human", Details: []string{"issuer"}},
		Matrix:  &chain.Matrix{Title: "AUTHORITY", RootRows: 2},
	}
	read := chain.Row{Label: "read files"}
	write := chain.Row{Label: "write files"}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("agent-%02d", i+1)
		from := "alice"
		if i > 0 {
			from = fmt.Sprintf("agent-%02d", i)
		}
		c.Links = append(c.Links, chain.Link{
			Index: i, From: from, To: name, Readable: true, State: chain.LinkOK,
			Checks: checks(chain.StatusPass, chain.StatusPass, chain.StatusPass),
		})
		read.Cells = append(read.Cells, chain.Cell{Kind: chain.CellHeld})
		w := chain.Cell{Kind: chain.CellHeld}
		if i >= n/2 {
			w = chain.Cell{Kind: chain.CellAbsent, Changed: i == n/2}
		}
		write.Cells = append(write.Cells, w)
		kept := 2
		if i >= n/2 {
			kept = 1
		}
		c.Matrix.Retained = append(c.Matrix.Retained, kept)
		if i > 0 {
			c.Hops = append(c.Hops, chain.Hop{Parent: i - 1, Child: i, Evaluable: true})
		}
	}
	c.Matrix.Rows = []chain.Row{read, write}
	return c
}
