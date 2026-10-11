package jwt

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kanywst/whosent/pkg/chain"
)

// The question form's fields.
const (
	askScope    = "scope"
	askAudience = "audience"
)

// AskFields asks for a scope and, optionally, the audience it is used at.
func (s *session) AskFields() []chain.AskField {
	return []chain.AskField{
		{Key: askScope, Label: "scope", Hint: "one scope, such as files:read", Required: true},
		{Key: askAudience, Label: "audience", Hint: "the resource server it is used at; empty skips the audience"},
	}
}

// AskPrefill proposes the selected scope row, and the audience the chain
// was checked for or the last token is addressed to.
func (s *session) AskPrefill(c *chain.Chain, row int) map[string]string {
	v := map[string]string{askScope: "", askAudience: ""}
	if c != nil && c.Matrix != nil && row >= 0 && row < len(c.Matrix.Rows) {
		v[askScope] = c.Matrix.Rows[row].Label
	}
	last := s.tokens[len(s.tokens)-1]
	if v[askScope] == "" && len(last.Scopes) > 0 {
		v[askScope] = last.Scopes[0]
	}
	if v[askScope] == "" {
		v[askScope] = "openid"
	}
	switch {
	case s.audience != nil:
		v[askAudience] = *s.audience
	case len(last.Aud) > 0:
		v[askAudience] = last.Aud[0]
	}
	return v
}

// Ask answers whether the token presented last would let its holder use a
// scope at an audience. Only a VALID chain answers authoritatively.
func (s *session) Ask(_ context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	scope := strings.TrimSpace(values[askScope])
	if scope == "" {
		return nil, errors.New("name a scope to ask about")
	}
	if strings.ContainsAny(scope, " \t") {
		return nil, errors.New("ask about one scope at a time")
	}
	aud := strings.TrimSpace(values[askAudience])
	last := s.tokens[len(s.tokens)-1]
	res := &chain.AskResult{
		Request:    []string{"scope " + scope},
		StepsTitle: "held by each link",
		Values:     map[string]string{askScope: scope, askAudience: aud},
	}
	if aud != "" {
		res.Request = append(res.Request, "at "+aud)
	}

	plans := s.plans()
	refusedAt := -1
	for i, p := range plans {
		step := chain.AskStep{Link: i}
		switch {
		case p.tok < 0:
			step.Outcome = chain.OutcomeUnreadable
			step.Reason = "a prior actor's own authority is not in the token"
		case s.tokens[p.tok].Problem != "":
			step.Outcome = chain.OutcomeUnreadable
			step.Reason = "this token cannot be read"
		case contains(s.tokens[p.tok].Scopes, scope):
			step.Outcome = chain.OutcomeCovers
		default:
			step.Outcome = chain.OutcomeRefuses
			step.Reason = "token " + fmt.Sprint(p.tok) + " does not hold " + scope
			if refusedAt < 0 {
				refusedAt = i
				step.ShowReason = true
			}
		}
		res.Steps = append(res.Steps, step)
	}

	covered := last.Problem == "" && contains(last.Scopes, scope)
	audOK := true
	if aud != "" && last.Problem == "" {
		audOK = contains(last.Aud, aud)
	}
	switch {
	case !covered:
		res.Reason = "the token presented last does not hold " + scope
	case !audOK:
		res.Reason = fmt.Sprintf("the token is addressed to %s, not %s", orNone(strings.Join(last.Aud, ", ")), aud)
	}
	ok := covered && audOK

	switch c.Verdict {
	case chain.VerdictValid:
		res.Authority = "AUTHORITATIVE"
		res.Permitted = ok
	case chain.VerdictIncomplete:
		res.Authority = "CONDITIONAL"
		res.Permitted = ok
		res.Conditional = ok
	default:
		res.Authority = "HYPOTHETICAL"
	}
	switch {
	case res.Permitted && res.Conditional:
		res.Verdict, res.Tone, res.Mark = "PERMITTED IF", chain.ToneWarn, chain.MarkUnchecked
		res.Why = "the token holds it, if the rules that were not checked pass: " + c.IncompleteReason
	case res.Permitted:
		res.Verdict, res.Tone, res.Mark = "PERMITTED", chain.ToneGood, chain.MarkPass
		res.Why = "the token presented last holds it, and every rule was checked"
	case c.Verdict == chain.VerdictInvalid && ok:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		res.Why = "the chain does not verify, so it permits nothing. Hypothetically, if it verified, the token would hold this"
	default:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		res.Why = "not held: " + res.Reason
	}
	if s.bundle() && covered {
		// Authority the presented token holds that a token before it did
		// not: it reached the leaf only through an exchange that widened.
		// Whether the first token held it decides whose mistake that is.
		for j, tj := range s.tokens[:len(s.tokens)-1] {
			if tj.Problem != "" || tj.ScopeClaim == "" || contains(tj.Scopes, scope) {
				continue
			}
			if j > 0 && contains(s.tokens[0].Scopes, scope) {
				res.Warning = fmt.Sprintf("the first token held %s, token %d dropped it, and re-adding it later does not bring it back", scope, j)
			} else {
				res.Warning = fmt.Sprintf("token %d did not hold %s: it exists only because an exchange widened scope", j, scope)
			}
			break
		}
	}
	if !s.bundle() && len(plans) > 1 {
		res.Warning = "prior actors are the issuer's word: the answer is about the token, not about what each actor was allowed"
	}

	res.Report = []string{
		fmt.Sprintf("%s (%s): %s", res.Verdict, res.Authority, res.Why),
	}
	if res.Warning != "" {
		res.Report = append(res.Report, "", "! "+res.Warning)
	}
	res.Report = append(res.Report, "", "  link by link")
	for _, st := range res.Steps {
		mark := map[chain.Outcome]string{chain.OutcomeCovers: "holds", chain.OutcomeRefuses: "lacks", chain.OutcomeUnreadable: "  ?  "}[st.Outcome]
		line := fmt.Sprintf("  %d  %-28s %s", st.Link, c.Links[st.Link].To, mark)
		if st.Reason != "" && st.Outcome != chain.OutcomeCovers {
			line += "  " + st.Reason
		}
		res.Report = append(res.Report, line)
	}
	res.Native = struct {
		Schema    string `json:"schema"`
		Scope     string `json:"scope"`
		Audience  string `json:"audience,omitempty"`
		Authority string `json:"authority"`
		Permitted bool   `json:"permitted"`
		Covered   bool   `json:"covered"`
		Reason    string `json:"reason,omitempty"`
	}{"whosent.jwt.ask/v1", scope, aud, res.Authority, res.Permitted, covered, res.Reason}
	return res, nil
}
