package macaroon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	fly "github.com/superfly/macaroon"
	"github.com/superfly/macaroon/flyio"
	"github.com/superfly/macaroon/resset"

	"github.com/kanywst/whosent/pkg/chain"
)

// The question form's fields. A Fly.io token is asked about one request,
// as Fly.io's own access check sees it; a libmacaroons macaroon about the
// predicates a verifier holds.
const (
	askOrg        = "org"
	askAction     = "action"
	askApp        = "app"
	askFeature    = "feature"
	askMachine    = "machine"
	askVolume     = "volume"
	askMutation   = "mutation"
	askPredicates = "predicates"
)

// AskFields asks for a request in Fly.io's terms, or for predicates.
func (s *session) AskFields() []chain.AskField {
	if s.b.dialect == "fly" {
		return []chain.AskField{
			{Key: askOrg, Label: "org", Hint: "the organization's numeric id", Required: true},
			{Key: askAction, Label: "action", Hint: "r, w, c, d, C or a mix, such as rw", Required: true},
			{Key: askApp, Label: "app", Hint: "the app's numeric id; empty for an org-level request"},
			{Key: askFeature, Label: "feature", Hint: "an org feature, such as wg"},
			{Key: askMachine, Label: "machine", Hint: "a machine id, with an app"},
			{Key: askVolume, Label: "volume", Hint: "a volume id, with an app"},
			{Key: askMutation, Label: "mutation", Hint: "a GraphQL mutation name"},
		}
	}
	return []chain.AskField{
		{Key: askPredicates, Label: "predicates", Hint: "what your verifier satisfies, separated by ;"},
	}
}

// AskPrefill proposes the organization a Fly.io token names, or the
// predicates already given with --fact.
func (s *session) AskPrefill(_ *chain.Chain, _ int) map[string]string {
	if s.b.dialect != "fly" {
		var fs []string
		for f := range s.facts {
			fs = append(fs, f)
		}
		sort.Strings(fs)
		return map[string]string{askPredicates: strings.Join(fs, "; ")}
	}
	v := map[string]string{askOrg: "", askAction: "r", askApp: ""}
	for _, c := range s.b.fly.root.m.UnsafeCaveats.Caveats {
		switch c := c.(type) {
		case *flyio.Organization:
			v[askOrg] = strconv.FormatUint(c.ID, 10)
		case *flyio.Apps:
			var ids []uint64
			for id := range c.Apps {
				ids = append(ids, id)
			}
			if len(ids) > 0 {
				slices.Sort(ids)
				v[askApp] = strconv.FormatUint(ids[0], 10)
			}
		}
	}
	return v
}

// Ask answers a question about the token. Only a VALID token answers
// authoritatively.
func (s *session) Ask(_ context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	if s.b.dialect == "fly" {
		return s.askFly(c, values)
	}
	return s.askLib(c, values)
}

// accessAt is a Fly.io access seen at the evaluation time, so a validity
// window is judged at the time the view shows, not the wall clock.
type accessAt struct {
	*flyio.Access
	at time.Time
}

func (a accessAt) Now() time.Time { return a.at }

func (s *session) askFly(c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	a, req, err := flyAccess(values)
	if err != nil {
		return nil, err
	}
	res := &chain.AskResult{Request: req, StepsTitle: "allowed by each caveat", Values: values}

	// The caveats Fly.io checks a request against: the permission token's
	// and its discharges', as superfly/macaroon verifies them when the key
	// is known. Third-party and binding caveats belong to verification and
	// were judged by check.
	var cavs []fly.Caveat
	verified := false
	if s.key != nil {
		var ds [][]byte
		for _, d := range s.b.fly.discharges {
			ds = append(ds, d.raw)
		}
		if set, err := s.b.fly.root.m.Verify(fly.SigningKey(s.key), ds, nil); err == nil {
			cavs, verified = set.Caveats, true
		}
	}
	if !verified {
		for _, t := range append([]*flyToken{s.b.fly.root}, s.b.fly.discharges...) {
			cavs = append(cavs, t.m.UnsafeCaveats.Caveats...)
		}
	}
	var kept []fly.Caveat
	for _, cv := range cavs {
		switch cv.(type) {
		case *fly.Caveat3P, *fly.BindToParentToken:
			continue
		}
		kept = append(kept, cv)
	}
	access := accessAt{Access: a, at: c.At}
	verr := fly.NewCaveatSet(kept...).Validate(access)

	e := &evaluation{s: s, at: c.At}
	e.fly()
	shown := false
	for i, n := range e.nodes {
		step := chain.AskStep{Link: i, Outcome: chain.OutcomeCovers}
		if n.flyCav != nil && !fly.IsAttestation(n.flyCav) {
			switch n.flyCav.(type) {
			case *fly.Caveat3P, *fly.BindToParentToken:
			default:
				if perr := n.flyCav.Prohibits(access); perr != nil {
					step.Outcome, step.Reason = chain.OutcomeRefuses, perr.Error()
					if !shown {
						step.ShowReason, shown = true, true
					}
				}
			}
		}
		res.Steps = append(res.Steps, step)
	}
	if verr != nil {
		res.Reason = verr.Error()
	}
	if s.askRefuse != nil {
		verr = s.askRefuse()
	}
	ok := verr == nil
	if !agree(verr, res.Steps) {
		// The library's answer and the caveat-by-caveat reading differ:
		// say so, and let the refusal stand.
		ok = false
		res.Warning = "superfly/macaroon's access check and the caveat-by-caveat reading disagree; the request is treated as refused"
		res.Inconsistency = &chain.Inconsistency{
			Banner: "INTERNAL INCONSISTENCY: superfly/macaroon and whosent answer this request differently",
			Detail: fmt.Sprintf("superfly/macaroon says %v, the caveats one by one say otherwise", verr),
		}
		if res.Reason == "" {
			res.Reason = "the caveat-by-caveat reading refuses it"
		}
	}
	settle(res, c, ok, "Fly.io's access check allows it, and the token verifies")
	if !verified && s.key != nil && res.Warning == "" {
		res.Warning = "the token does not verify, so its caveats were read without being vouched for"
	}
	report(res, c, "allows", "refuses")
	res.Native = struct {
		Schema    string            `json:"schema"`
		Request   map[string]string `json:"request"`
		Authority string            `json:"authority"`
		Permitted bool              `json:"permitted"`
		Reason    string            `json:"reason,omitempty"`
	}{"whosent.macaroon.ask/v1", values, res.Authority, res.Permitted, res.Reason}
	return res, nil
}

// agree reports whether the library's verdict on a request matches the
// steps: a refusal from Validate needs a caveat that refuses, and the other
// way round.
func agree(verr error, steps []chain.AskStep) bool {
	refused := false
	for _, st := range steps {
		refused = refused || st.Outcome == chain.OutcomeRefuses
	}
	return (verr != nil) == refused
}

// flyAccess reads the form into a Fly.io access, refusing what Fly.io's
// own Validate would refuse.
func flyAccess(values map[string]string) (*flyio.Access, []string, error) {
	get := func(k string) string { return strings.TrimSpace(values[k]) }
	org, err := strconv.ParseUint(get(askOrg), 10, 64)
	if err != nil {
		return nil, nil, errors.New("give the organization's numeric id")
	}
	act := get(askAction)
	if act == "" {
		return nil, nil, errors.New("give an action, such as r or rw")
	}
	a := &flyio.Access{OrgID: &org, Action: resset.ActionFromString(act)}
	req := []string{fmt.Sprintf("%s on org %d", a.Action, org)}
	if v := get(askApp); v != "" {
		app, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, nil, errors.New("the app is a numeric id")
		}
		a.AppID = &app
		req = append(req, fmt.Sprintf("app %d", app))
	}
	for _, f := range []struct {
		key string
		dst **string
	}{{askFeature, &a.Feature}, {askMachine, &a.Machine}, {askVolume, &a.Volume}, {askMutation, &a.Mutation}} {
		if v := get(f.key); v != "" {
			*f.dst = &v
			req = append(req, f.key+" "+v)
		}
	}
	if err := a.Validate(); err != nil {
		return nil, nil, fmt.Errorf("not a request Fly.io can check: %w", err)
	}
	return a, req, nil
}

// askLib checks the macaroon as a verifier holding exactly the given
// predicates would: libmacaroons accepts a macaroon only when every
// first-party caveat is satisfied.
func (s *session) askLib(c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	facts := map[string]bool{}
	var given []string
	for _, p := range strings.Split(values[askPredicates], ";") {
		if p = strings.TrimSpace(p); p != "" {
			facts[p] = true
			given = append(given, p)
		}
	}
	alt := *s
	alt.facts, alt.factsGiven = facts, true
	e := &evaluation{s: &alt, at: c.At}
	e.lib()
	got := e.chain()

	req := []string{"no predicates"}
	if len(given) > 0 {
		req = []string{strings.Join(given, "; ")}
	}
	res := &chain.AskResult{Request: req, StepsTitle: "satisfied at each caveat", Values: values}
	shown := false
	for i, l := range got.Links {
		step := chain.AskStep{Link: i, Outcome: chain.OutcomeCovers}
		if ch := l.Check(RuleCaveat); ch.Status == chain.StatusFail {
			step.Outcome, step.Reason = chain.OutcomeRefuses, l.To+": "+ch.Detail
			if !shown {
				step.ShowReason, shown = true, true
				res.Reason = step.Reason
			}
		}
		res.Steps = append(res.Steps, step)
	}
	settle(res, got, !shown, "a verifier holding these predicates accepts it, and the macaroon verifies")
	report(res, got, "satisfied", "unsatisfied")
	res.Native = struct {
		Schema     string   `json:"schema"`
		Predicates []string `json:"predicates"`
		Authority  string   `json:"authority"`
		Permitted  bool     `json:"permitted"`
		Reason     string   `json:"reason,omitempty"`
	}{"whosent.macaroon.ask/v1", given, res.Authority, res.Permitted, res.Reason}
	return res, nil
}

// settle labels an answer by how far the token itself was checked.
func settle(res *chain.AskResult, c *chain.Chain, ok bool, why string) {
	switch c.Verdict {
	case chain.VerdictValid:
		res.Authority = "AUTHORITATIVE"
		res.Permitted = ok
	case chain.VerdictIncomplete:
		res.Authority = "CONDITIONAL"
		res.Permitted, res.Conditional = ok, ok
	default:
		res.Authority = "HYPOTHETICAL"
	}
	switch {
	case res.Permitted && res.Conditional:
		res.Verdict, res.Tone, res.Mark = "PERMITTED IF", chain.ToneWarn, chain.MarkUnchecked
		res.Why = "the caveats allow it, if the rules that were not checked pass: " + c.IncompleteReason
	case res.Permitted:
		res.Verdict, res.Tone, res.Mark = "PERMITTED", chain.ToneGood, chain.MarkPass
		res.Why = why
	case c.Verdict == chain.VerdictInvalid && ok:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		res.Why = "the token does not verify, so it permits nothing. Hypothetically, if it verified, the caveats would allow this"
	default:
		res.Verdict, res.Tone, res.Mark = "DENIED", chain.ToneBad, chain.MarkFail
		res.Why = "refused: " + res.Reason
	}
}

// report is the answer as the command line prints it.
func report(res *chain.AskResult, c *chain.Chain, yes, no string) {
	res.Report = []string{fmt.Sprintf("%s (%s): %s", res.Verdict, res.Authority, res.Why)}
	if res.Warning != "" {
		res.Report = append(res.Report, "", "! "+res.Warning)
	}
	res.Report = append(res.Report, "", "  link by link")
	for _, st := range res.Steps {
		mark := yes
		if st.Outcome == chain.OutcomeRefuses {
			mark = no
		}
		line := fmt.Sprintf("  %d  %-28s %s", st.Link, c.Links[st.Link].To, mark)
		if st.Reason != "" && st.Outcome != chain.OutcomeCovers {
			line += "  " + st.Reason
		}
		res.Report = append(res.Report, line)
	}
}
