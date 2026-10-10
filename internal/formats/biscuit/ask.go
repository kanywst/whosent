package biscuit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/pkg/chain"
)

// The question form: the request's facts, and the policy that decides.
const (
	askFacts  = "facts"
	askPolicy = "policy"
)

// AskFields are the form's fields.
func (s *Session) AskFields() []chain.AskField {
	return []chain.AskField{
		{Key: askFacts, Label: "facts", Hint: `the request, as facts: resource("orders/42"); operation("read")`},
		{Key: askPolicy, Label: "policy", Hint: `what decides: allow if true, or your own allow and deny policies`},
	}
}

// AskPrefill proposes the session's own authorizer facts, or, for a row
// that is a right("resource", "operation") fact, a request for exactly
// that right.
func (s *Session) AskPrefill(c *chain.Chain, row int) map[string]string {
	vals := map[string]string{askPolicy: "allow if true"}
	var facts []string
	for _, f := range s.opts.Program.Facts {
		if f.Predicate.NameS == "time" {
			continue
		}
		facts = append(facts, printParsedFact(f))
	}
	// A row's label is shortened for the matrix; its lineage holds the
	// fact as the token states it.
	source := func(r chain.Row) string {
		if len(r.Lineage) > 0 && len(r.Lineage[0].Texts) > 0 {
			return r.Lineage[0].Texts[0]
		}
		return ""
	}
	if len(facts) == 0 && c != nil && c.Matrix != nil && row >= 0 && row < len(c.Matrix.Rows) {
		facts = requestFor(source(c.Matrix.Rows[row]))
	}
	if len(facts) == 0 && c != nil && c.Matrix != nil {
		for _, r := range c.Matrix.Rows {
			if facts = requestFor(source(r)); len(facts) > 0 {
				break
			}
		}
	}
	vals[askFacts] = strings.Join(facts, "; ")
	return vals
}

// printParsedFact prints a fact as it was parsed: converted into a table,
// then printed with that same table.
func printParsedFact(f datalog.Fact) string {
	syms := datalog.NewSymbolTable()
	b := datalog.ConvertBlock(datalog.Block{Facts: []datalog.Fact{f}}, syms)
	return syms.PrintFact(b.Facts[0])
}

// requestFor reads `right("orders/42", "read")`, the convention for a
// right, as the request resource("orders/42"), operation("read").
func requestFor(label string) []string {
	p, err := datalog.ParseProgram(label)
	if err != nil || len(p.Facts) != 1 {
		return nil
	}
	f := p.Facts[0].Predicate
	if f.NameS != "right" || len(f.Terms) != 2 || f.Terms[0].Kind != datalog.KindString || f.Terms[1].Kind != datalog.KindString {
		return nil
	}
	return []string{fmt.Sprintf("resource(%q)", f.Terms[0].S), fmt.Sprintf("operation(%q)", f.Terms[1].S)}
}

type nativeAnswer struct {
	Schema     string                `json:"schema"`
	Authority  string                `json:"authority"`
	Permitted  bool                  `json:"permitted"`
	Policy     string                `json:"policy,omitempty"`
	Failed     []datalog.FailedCheck `json:"failed_checks"`
	Error      string                `json:"error,omitempty"`
	Facts      string                `json:"facts"`
	PolicyCode string                `json:"policy_code"`
}

// Ask runs an authorizer with the given facts and policy over the token.
func (s *Session) Ask(_ context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	factsSrc := strings.TrimSpace(values[askFacts])
	policySrc := strings.TrimSpace(values[askPolicy])
	if policySrc == "" {
		policySrc = "allow if true"
	}
	var prog datalog.Program
	if factsSrc != "" {
		p, err := datalog.ParseProgram(factsSrc)
		if err != nil {
			return nil, fmt.Errorf("facts: %w", err)
		}
		if len(p.Rules)+len(p.Checks)+len(p.Policies) > 0 {
			return nil, errors.New("facts: only facts belong here; put policies in the policy field")
		}
		prog.Append(p)
	}
	pp, err := datalog.ParseProgram(policySrc)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(pp.Policies) == 0 {
		return nil, errors.New("policy: give at least one allow or deny policy, such as allow if true")
	}
	prog.Append(pp)

	at := s.at
	if c != nil && !c.At.IsZero() {
		at = c.At
	}
	opts := s.opts
	opts.Program, opts.HasAuthorizer = prog, true
	a := analyze(s.tok, opts, at.UTC(), nil)

	res := &chain.AskResult{
		Values:     map[string]string{askFacts: factsSrc, askPolicy: policySrc},
		StepsTitle: "asked of each block's own checks",
	}
	if factsSrc != "" {
		res.Request = append(res.Request, factsSrc)
	} else {
		res.Request = append(res.Request, "no facts")
	}
	res.Request = append(res.Request, policySrc)

	// How far the answer can be relied on is decided by everything but the
	// checks themselves: the signatures, the format, the revocation list.
	authority := "AUTHORITATIVE"
	for _, br := range a.blocks {
		for _, ch := range br.checks {
			if ch.Rule == RuleChecks {
				continue
			}
			switch {
			case ch.Status.Blocking():
				authority = "HYPOTHETICAL"
			case ch.Status == chain.StatusUnchecked && authority != "HYPOTHETICAL":
				authority = "CONDITIONAL"
			}
		}
	}
	res.Authority = authority

	readable := true
	for _, br := range a.blocks {
		if !br.readable || br.block.UsesFfi() {
			readable = false
		}
	}
	native := nativeAnswer{Schema: "whosent.biscuit-ask/v1", Authority: authority, Facts: factsSrc, PolicyCode: policySrc}
	if !readable {
		res.Verdict, res.Tone, res.Mark = "CANNOT TELL", chain.ToneWarn, chain.MarkUnchecked
		res.Why = "the token cannot be evaluated: " + a.b7Reason
		if a.b7Reason == "" {
			res.Why = "the token cannot be evaluated"
		}
		for _, br := range a.blocks {
			res.Steps = append(res.Steps, chain.AskStep{Link: br.index, Outcome: chain.OutcomeUnreadable})
		}
		res.Report = []string{res.Verdict + ": " + res.Why}
		native.Error = res.Why
		res.Native = native
		return res, nil
	}

	r := datalog.Authorize(a.tokenBlocks(), withTime(prog, at.UTC()), opts.Limits)
	native.Failed = r.Failed
	failed := map[int]string{}
	for _, f := range r.Failed {
		if _, ok := failed[f.Block]; !ok {
			failed[f.Block] = f.Rule
		}
	}
	shown := false
	for _, br := range a.blocks {
		step := chain.AskStep{Link: br.index, Outcome: chain.OutcomeCovers}
		if rule, ok := failed[br.index]; ok {
			step.Outcome, step.Reason = chain.OutcomeRefuses, "fails: "+rule
			if !shown {
				step.ShowReason, shown = true, true
			}
		}
		res.Steps = append(res.Steps, step)
	}
	authorized := r.Authorized()
	switch {
	case r.Err != nil:
		res.Why = "the authorizer stopped on an error, and a stopped authorizer denies: " + r.Err.Error()
		native.Error = r.Err.Error()
	case len(r.Failed) > 0:
		res.Why = fmt.Sprintf("%d check(s) fail for this request", len(r.Failed))
		if rule, ok := failed[-1]; ok {
			res.Reason = "the authorizer's own check fails: " + rule
		}
	case r.Policy == nil:
		res.Why = "every check holds, but no policy matched, so the authorizer denies"
	case !r.Policy.Allow:
		res.Why = fmt.Sprintf("every check holds, but deny policy %d matched", r.Policy.Index)
	default:
		res.Why = fmt.Sprintf("every check holds and allow policy %d matched", r.Policy.Index)
	}
	if r.Policy != nil {
		native.Policy = fmt.Sprintf("%v %d", map[bool]string{true: "allow", false: "deny"}[r.Policy.Allow], r.Policy.Index)
	}
	switch {
	case authorized && authority == "AUTHORITATIVE":
		res.Verdict, res.Permitted, res.Tone, res.Mark = "PERMITTED", true, chain.ToneGood, chain.MarkPass
	case authorized && authority == "CONDITIONAL":
		res.Verdict, res.Permitted, res.Conditional, res.Tone, res.Mark = "PERMITTED IF", true, true, chain.ToneWarn, chain.MarkWarn
		res.Warning = "only if the rules that were not checked hold"
		if c != nil && len(c.Missing) > 0 {
			res.Warning = "only if what was not checked holds: " + strings.Join(c.Missing, ", ")
		}
	case authorized:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		res.Why = "the token does not verify, so it permits nothing. Hypothetically, if it did: " + res.Why
	default:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
	}
	native.Permitted = res.Permitted
	res.Native = native
	res.Report = append(res.Report, fmt.Sprintf("%s (%s): %s", res.Verdict, authority, res.Why))
	if res.Reason != "" {
		res.Report = append(res.Report, "    "+res.Reason)
	}
	if res.Warning != "" {
		res.Report = append(res.Report, "    "+res.Warning)
	}
	res.Report = append(res.Report, "", "  block by block")
	for _, st := range res.Steps {
		line := fmt.Sprintf("  %d  %s  ", st.Link, a.name(a.blocks[st.Link]))
		if st.Outcome == chain.OutcomeCovers {
			line += "holds"
		} else {
			line += st.Reason
		}
		res.Report = append(res.Report, line)
	}
	return res, nil
}

// withTime adds the evaluation time as the time fact, unless the program
// supplies its own.
func withTime(p datalog.Program, at interface{ Unix() int64 }) datalog.Program {
	if programHasTime(p) {
		return p
	}
	out := p
	out.Facts = append(append([]datalog.Fact(nil), p.Facts...), datalog.Fact{Predicate: datalog.Predicate{NameS: "time", Terms: []datalog.Term{datalog.Date(uint64(at.Unix()))}}})
	return out
}
