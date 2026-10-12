package ucan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kanywst/whosent/pkg/chain"
)

// AskFields are the question: a command and its arguments.
func (s *Session) AskFields() []chain.AskField {
	return []chain.AskField{
		{Key: "command", Label: "command", Hint: "the command to invoke, such as /msg/send", Required: true},
		{Key: "args", Label: "args", Hint: `the arguments as a JSON object, such as {"to": "bob@example.com"}`},
	}
}

// AskPrefill proposes the chain's own invocation, or the last delegation's
// command with no arguments.
func (s *Session) AskPrefill(c *chain.Chain, _ int) map[string]string {
	a, err := analyze(s.tokens, s.opts, s.when(c.At), nil)
	if err != nil {
		return map[string]string{}
	}
	if a.inv != nil && a.inv.readable() {
		return map[string]string{"command": a.inv.tok.Cmd, "args": dagJSON(a.inv.tok.Args, "")}
	}
	for i := len(a.links) - 1; i >= 0; i-- {
		if a.links[i].readable() {
			return map[string]string{"command": a.links[i].tok.Cmd, "args": "{}"}
		}
	}
	return map[string]string{}
}

// Ask answers whether the delegations would let their last audience invoke
// a command with given arguments.
func (s *Session) Ask(_ context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	cmd := strings.TrimSpace(values["command"])
	if cmd == "" {
		return nil, errors.New("name a command to ask about")
	}
	if err := checkCommand(cmd); err != nil {
		return nil, fmt.Errorf("command %q %v", cmd, err)
	}
	argsText := strings.TrimSpace(values["args"])
	if argsText == "" {
		argsText = "{}"
	}
	args, err := jsonValue(argsText)
	if err != nil || args.Kind != KindMap {
		return nil, fmt.Errorf("args: want a JSON object (%v)", err)
	}
	a, err := analyze(s.tokens, s.opts, s.when(c.At), c.Simulated)
	if err != nil {
		return nil, err
	}
	dlgs := a.links
	if a.inv != nil {
		dlgs = dlgs[:len(dlgs)-1]
	}
	r := &chain.AskResult{
		Request:    []string{"invoke " + cmd, "args " + dagJSON(args, ""), "on " + a.name(a.subject)},
		StepsTitle: "asked of each delegation",
		Values:     map[string]string{"command": cmd, "args": argsText},
	}
	if len(dlgs) == 0 {
		r.Verdict, r.Tone, r.Mark, r.Authority = "DENIED", chain.ToneBad, chain.MarkFail, "HYPOTHETICAL"
		r.Why = "there is no delegation to ask: only the subject may act on its own authority"
		r.Report = []string{"DENIED: " + r.Why}
		return r, nil
	}
	if last := dlgs[len(dlgs)-1]; last.readable() {
		r.Request = append(r.Request, "as "+a.name(last.tok.Aud))
	}
	blocking, unchecked := false, false
	for _, d := range dlgs {
		for _, ch := range d.checks {
			switch {
			case ch.Status.Blocking() || d.revoked:
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
	}
	covered := true
	shown := false
	for _, d := range dlgs {
		st := chain.AskStep{Link: d.index, Outcome: chain.OutcomeCovers}
		switch {
		case !d.readable():
			st.Outcome, st.Reason = chain.OutcomeUnreadable, "not supplied or not readable"
			covered = false
		case !covers(d.tok.Cmd, cmd):
			st.Outcome, st.Reason = chain.OutcomeRefuses, fmt.Sprintf("grants %s, which does not cover %s", d.tok.Cmd, cmd)
			covered = false
		default:
			ok, i, err := d.tok.Policy.match(args, &evaluation{})
			switch {
			case err != nil:
				st.Outcome, st.Reason = chain.OutcomeRefuses, err.Error()
				covered = false
			case !ok:
				st.Outcome, st.Reason = chain.OutcomeRefuses, "its policy refuses: "+d.tok.Policy[i].String()
				covered = false
			}
		}
		if st.Outcome != chain.OutcomeCovers && !shown {
			st.ShowReason, shown = true, true
		}
		r.Steps = append(r.Steps, st)
	}
	switch {
	case blocking:
		r.Authority = "HYPOTHETICAL"
	case unchecked:
		r.Authority = "CONDITIONAL"
	default:
		r.Authority = "AUTHORITATIVE"
	}
	switch {
	case covered && r.Authority == "AUTHORITATIVE":
		r.Verdict, r.Permitted, r.Tone, r.Mark = "PERMITTED", true, chain.ToneGood, chain.MarkPass
		r.Why = "every delegation covers the command and its policy holds for these arguments"
	case covered && r.Authority == "CONDITIONAL":
		r.Verdict, r.Permitted, r.Conditional, r.Tone, r.Mark = "PERMITTED IF", true, true, chain.ToneWarn, chain.MarkUnchecked
		r.Why = "every delegation covers it, if the rules that were not checked hold: " + a.incompleteReason()
	case covered:
		r.Verdict, r.Tone, r.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		r.Why = "the delegations do not verify, so they permit nothing. Hypothetically, if they did: every delegation covers it"
	default:
		r.Verdict, r.Tone, r.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		r.Why = "a delegation does not cover it"
		for _, st := range r.Steps {
			if st.Outcome != chain.OutcomeCovers {
				r.Reason = fmt.Sprintf("link %d: %s", st.Link, st.Reason)
				break
			}
		}
	}
	r.Report = append(r.Report, fmt.Sprintf("%s (%s): %s", r.Verdict, r.Authority, r.Why))
	if r.Reason != "" {
		r.Report = append(r.Report, "    "+r.Reason)
	}
	r.Report = append(r.Report, "", "  delegation by delegation")
	for _, st := range r.Steps {
		line := fmt.Sprintf("  %d  %s  ", st.Link, a.to(a.links[st.Link]))
		if st.Outcome == chain.OutcomeCovers {
			line += "covers it"
		} else {
			line += st.Reason
		}
		r.Report = append(r.Report, line)
	}
	r.Native = map[string]any{"schema": "whosent.ucan.ask/v1", "command": cmd, "permitted": r.Permitted, "authority": r.Authority, "reason": r.Reason}
	return r, nil
}

// jsonValue reads JSON into a Value. Numbers without a fraction or an
// exponent are integers.
func jsonValue(text string) (Value, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := jsonNext(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Value{}, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func jsonNext(dec *json.Decoder, depth int) (Value, error) {
	if depth > maxDepth {
		return Value{}, errors.New("nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return Value{}, err
	}
	switch t := tok.(type) {
	case nil:
		return vNull(), nil
	case bool:
		return Value{Kind: KindBool, Bool: t}, nil
	case string:
		return vStr(t), nil
	case json.Number:
		if !strings.ContainsAny(t.String(), ".eE") {
			if i, err := t.Int64(); err == nil {
				return vInt(i), nil
			}
		}
		f, err := t.Float64()
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: KindFloat, Float: f}, nil
	case json.Delim:
		switch t {
		case '[':
			var list []Value
			for dec.More() {
				v, err := jsonNext(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				list = append(list, v)
			}
			_, err := dec.Token()
			return vList(list...), err
		case '{':
			var m []Entry
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return Value{}, err
				}
				key, _ := k.(string)
				if seen[key] {
					return Value{}, fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = true
				v, err := jsonNext(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				m = append(m, entry(key, v))
			}
			_, err := dec.Token()
			// Order the entries as DAG-CBOR would, so equal maps list
			// their entries alike.
			return Value{Kind: KindMap, Map: sortedEntries(m)}, err
		}
	}
	return Value{}, fmt.Errorf("unexpected %v", tok)
}

func sortedEntries(m []Entry) []Entry {
	sort.Slice(m, func(i, j int) bool {
		a, b := m[i].Key, m[j].Key
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return a < b
	})
	return m
}
