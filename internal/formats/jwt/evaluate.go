package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// plan is one link of the chain before it is checked: either a token of
// the bundle, or a prior actor a token names (asserted, never verified).
type plan struct {
	// tok is the token this link is, or -1 for an asserted actor.
	tok int
	// named is the token that names an asserted actor.
	named int
	actor actor
	// proof is the index in token named's actor_proofs of the proof that
	// covers this actor, or -1, and step the index of the Actor Chain
	// evidence step that does. signed is set when one of them is relied on,
	// so the link is the actor's own word rather than the issuer's; chained
	// says it is the evidence step.
	proof   int
	step    int
	signed  bool
	chained bool
	// cover is the coverage of the evidence a chained link stands on.
	cover string
}

// evidence is what each token carries for its prior actors: actor proofs
// (J11) and Actor Chain evidence (J12).
type evidence struct {
	proofs []proofChain
	chains []actorChain
}

// plans lays the chain out. The first token's prior actors come first, as
// asserted links: they are the issuer's word about who acted before the
// token was issued. Then one link per token, each carrying the actor that
// token makes current.
func (s *session) plans() []plan {
	var out []plan
	t0 := s.tokens[0]
	if t0.Problem == "" && t0.hasExplicitActor() {
		n := len(t0.Actors)
		for j, a := range t0.Actors[:n-1] {
			out = append(out, plan{tok: -1, named: 0, actor: a, proof: n - 1 - j, step: j})
		}
	}
	for i, t := range s.tokens {
		p := plan{tok: i, named: i, proof: -1, step: -1}
		if t.Problem == "" {
			p.actor = t.current()
		}
		out = append(out, p)
	}
	return out
}

// rootName is the subject the whole chain acts for.
func (s *session) rootName() string {
	t := s.tokens[0]
	if t.Entra != nil {
		// Entra's sub is pairwise and opaque; the user principal name is
		// the identifier a person would recognise.
		for _, k := range []string{"upn", "preferred_username"} {
			if v := str(t.Claims, k); v != "" {
				return v
			}
		}
	}
	switch {
	case t.Sub != "":
		return t.Sub
	case t.Iss != "":
		return t.Iss
	}
	return "(no subject)"
}

func (s *session) evaluate(at time.Time) *chain.Chain {
	plans := s.plans()
	ev := evidence{proofs: make([]proofChain, len(s.tokens)), chains: make([]actorChain, len(s.tokens))}
	for k := range s.tokens {
		ev.proofs[k] = s.evalProofs(k, at)
		ev.chains[k] = s.evalActorChain(k)
	}
	// A prior actor is the actor's own word only once its proof holds and
	// the token carrying it verifies: a token that fails its own validation
	// is rejected under its own rules, not read for proofs (section 7 step
	// 1). Anything short of that, unchecked included, leaves it asserted.
	if s.carrierHolds(plans, ev, at) {
		for i := range plans {
			p := &plans[i]
			switch {
			case p.tok >= 0:
			case ev.proofs[0].covers(p.proof):
				p.signed = true
			case ev.chains[0].covers(p.step):
				p.signed, p.chained, p.cover = true, true, ev.chains[0].Coverage
			}
		}
	}
	c := &chain.Chain{
		Format: format, Source: s.source, InputFormat: s.inputFormat(), At: at,
		Reversed: s.reversed, BreakAt: -1,
	}
	c.Root = s.root()

	from := c.Root.Name
	for i, p := range plans {
		l := s.link(i, p, from, at, ev)
		c.Links = append(c.Links, l)
		from = linkTo(p)
	}
	for i := 1; i < len(plans); i++ {
		c.Hops = append(c.Hops, s.hop(plans, i-1, i))
	}
	c.Matrix = s.matrix(plans)
	s.chainFindings(c)
	settle(c)
	s.describe(c, plans, ev, at)
	return c
}

// carrierHolds reports whether token 0, which names every prior actor, has
// every rule checked and holding on its own link.
func (s *session) carrierHolds(plans []plan, ev evidence, at time.Time) bool {
	for i, p := range plans {
		if p.tok != 0 {
			continue
		}
		for _, ch := range s.link(i, p, "", at, ev).Checks {
			if ch.Status != chain.StatusPass && ch.Status != chain.StatusNotApplicable {
				return false
			}
		}
		return true
	}
	return false
}

func linkTo(p plan) string {
	if p.tok >= 0 && p.actor.Sub == "" && p.actor.ClientID == "" {
		return "(unreadable token)"
	}
	return p.actor.name()
}

func (s *session) inputFormat() string {
	if s.bundle() {
		return fmt.Sprintf("bundle of %d tokens", len(s.tokens))
	}
	return "one token"
}

func (s *session) root() chain.Root {
	t := s.tokens[0]
	r := chain.Root{Name: s.rootName(), Kind: "subject"}
	if t.SubProfile != "" {
		r.Details = append(r.Details, t.SubProfile)
	} else if t.Entra != nil && t.Entra.IDType != "" {
		r.Details = append(r.Details, t.Entra.IDType)
	}
	if t.Iss != "" {
		r.Details = append(r.Details, "via "+hostOf(t.Iss))
	}
	return r
}

// link checks one link.
func (s *session) link(i int, p plan, from string, at time.Time, ev evidence) chain.Link {
	l := chain.Link{Index: i, From: from, To: linkTo(p), Readable: true}
	switch {
	case p.chained:
		return s.chainedLink(l, p, ev.chains[p.named])
	case p.signed:
		return s.signedLink(l, p, ev.proofs[p.named])
	case p.tok < 0:
		return s.assertedLink(l, p, ev.proofs[p.named], ev.chains[p.named])
	}
	t := s.tokens[p.tok]
	if t.Problem != "" {
		l.Readable = false
	}
	checks := map[string]chain.Check{}
	set := func(rule string, st chain.Status, detail string) {
		checks[rule] = chain.Check{Rule: rule, Status: st, Detail: detail}
	}
	setr := func(rule string) func(chain.Status, string) {
		return func(st chain.Status, detail string) { set(rule, st, detail) }
	}

	// J1: the token can be read, and is signed with an algorithm worth
	// checking.
	if t.Problem != "" {
		set(RuleToken, chain.StatusFail, t.Problem)
	} else {
		set(RuleToken, chain.StatusPass, t.Kind+", alg "+t.Alg)
	}

	// J2: the signature, against the keys configured for the issuer.
	sig := s.keys.verifySig(t)
	set(RuleSignature, sig.Status, sig.Detail)

	// J3: time. The last token must hold now; an earlier one must have held
	// when the next was issued, because that is when it was exchanged.
	st, detail, warn := s.timeCheck(p.tok, at)
	set(RuleTime, st, detail)

	// J4: only the token presented last is addressed to the resource
	// server being checked for.
	setr(RuleAudience)(s.audienceCheck(p.tok))

	// J5: the actor this token makes current is one.
	setr(RuleActor)(actorCheck(t))

	// J6: may_act, the token's own and the one before it.
	setr(RuleMayAct)(s.mayActCheck(p.tok))

	// J7 to J10: the exchange from the token before.
	for _, r := range []string{RuleExtends, RuleScope, RuleSubject, RuleExpiry} {
		setr(r)(s.hopRule(r, p.tok))
	}

	// J11: the actor proofs the token carries, if any.
	pc := ev.proofs[p.tok]
	set(RuleProof, pc.Status, pc.Detail)

	// J12: the Actor Chain profile the token names, if any.
	ac := ev.chains[p.tok]
	set(RuleChain, ac.Status, ac.Detail)

	for _, r := range format.Rules {
		l.Checks = append(l.Checks, checks[r.ID])
	}
	for _, ch := range l.Checks {
		if f, ok := findingFor(ch, i); ok {
			l.Findings = append(l.Findings, f)
		}
	}
	if warn != "" {
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleTime, Link: i, Hop: -1, Severity: chain.SeverityWarn, Detail: warn})
	}
	l.Findings = append(l.Findings, actorWarnings(t, i)...)
	if pc.Status == chain.StatusPass {
		for _, n := range pc.Notes {
			l.Findings = append(l.Findings, chain.Finding{Rule: RuleProof, Link: i, Hop: -1, Severity: chain.SeverityInfo, Detail: n})
		}
		for _, w := range pc.Warns {
			l.Findings = append(l.Findings, chain.Finding{Rule: RuleProof, Link: i, Hop: -1, Severity: chain.SeverityWarn, Detail: w})
		}
	}
	if ac.Status == chain.StatusPass {
		for _, n := range ac.Notes {
			l.Findings = append(l.Findings, chain.Finding{Rule: RuleChain, Link: i, Hop: -1, Severity: chain.SeverityInfo, Detail: n})
		}
		for _, w := range ac.Warns {
			l.Findings = append(l.Findings, chain.Finding{Rule: RuleChain, Link: i, Hop: -1, Severity: chain.SeverityWarn, Detail: w})
		}
	}
	if p.tok == len(s.tokens)-1 && t.Problem == "" && !t.hasExplicitActor() && t.Entra == nil {
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleActor, Link: i, Hop: -1, Severity: chain.SeverityInfo,
			Detail: fmt.Sprintf("the token names no actor (no act claim): %s %s presents it", t.holder().Role, t.holder().name())})
	}

	if t.Iat != nil {
		l.IssuedAt = *t.Iat
	}
	if t.Exp != nil {
		l.ExpiresAt = *t.Exp
		l.Remaining = t.Exp.Sub(at)
	}
	l.Sections = s.tokenSections(t, p)
	if pc.Present {
		if len(pc.Proofs) > 0 {
			// The newest proof as the chain left it: a proof that verifies
			// on its own is still not relied on when the chain fails.
			each := pc.Each[0]
			if each.Status == chain.StatusPass && pc.Status != chain.StatusPass {
				each = proofCheck{Status: pc.Status, Detail: each.Detail + "; not relied on: " + pc.Detail}
			}
			l.Sections = append(l.Sections, proofSections(pc.Proofs[0], each))
		}
		l.Sections = append(l.Sections, proofsSection(pc))
	}
	if ac.Present {
		l.Sections = append(l.Sections, chainSection(ac))
	}
	l.Raw = tokenRaw(t)
	return l
}

// signedLink is a prior actor whose own proof covers its hop: the actor
// signed that it took part, for this subject and toward a target. That is
// its evidence, so the token-level rules, checked on the token's own link,
// do not apply to it. The proof is all of its standing: when the chain of
// proofs is only unchecked, so is the link.
func (s *session) signedLink(l chain.Link, p plan, pc proofChain) chain.Link {
	each := pc.Each[p.proof]
	st, detail := each.Status, each.Detail
	for _, r := range format.Rules {
		ch := chain.Check{Rule: r.ID, Status: chain.StatusNotApplicable,
			Detail: fmt.Sprintf("a token rule, checked on token %d's own link; this actor's evidence is its proof", p.named)}
		switch r.ID {
		case RuleActor:
			ch = chain.Check{Rule: r.ID, Status: chain.StatusPass, Detail: "a well-formed actor, and the one its proof names"}
		case RuleProof:
			ch = chain.Check{Rule: r.ID, Status: st, Detail: detail}
		}
		l.Checks = append(l.Checks, ch)
	}
	if f, ok := findingFor(l.Check(RuleProof), l.Index); ok {
		l.Findings = append(l.Findings, f)
	}
	pr := pc.Proofs[p.proof]
	l.Sections = []chain.Section{actorSection(p.actor), proofSections(pr, proofCheck{Status: st, Detail: detail})}
	l.Raw = proofRaw(pr)
	return l
}

// chainedLink is a prior actor whose Actor Chain evidence step holds: the
// actor signed its request and an authorization server accepted it. Like a
// signed link, the token-level rules are checked on the token's own link.
func (s *session) chainedLink(l chain.Link, p plan, ac actorChain) chain.Link {
	st := ac.Steps[p.step]
	for _, r := range format.Rules {
		ch := chain.Check{Rule: r.ID, Status: chain.StatusNotApplicable,
			Detail: fmt.Sprintf("a token rule, checked on token %d's own link; this actor's evidence is its step proof", p.named)}
		switch r.ID {
		case RuleActor:
			ch = chain.Check{Rule: r.ID, Status: chain.StatusPass, Detail: "a well-formed actor, and the one its step proof names"}
		case RuleChain:
			ch = chain.Check{Rule: r.ID, Status: st.Check.Status, Detail: st.Check.Detail}
		}
		l.Checks = append(l.Checks, ch)
	}
	if ac.Coverage == "disclosed" {
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleChain, Link: l.Index, Hop: -1, Severity: chain.SeverityInfo,
			Detail: "the actor signed its own hop; that this hop belongs to the token's path, in this place, is the issuer's attestation"})
	}
	l.Sections = []chain.Section{actorSection(p.actor), stepSection(st, ac.Coverage)}
	l.Raw = stepRaw(st)
	return l
}

// assertedLink is a prior actor: the issuer's word, so the only rule that
// says anything about it is whether it is an actor at all.
func (s *session) assertedLink(l chain.Link, p plan, pc proofChain, ac actorChain) chain.Link {
	l.Asserted = true
	for _, r := range format.Rules {
		ch := chain.Check{Rule: r.ID, Status: chain.StatusNotApplicable,
			Detail: "a prior actor is informational (RFC 8693 section 4.1): nothing can verify it"}
		if r.ID == RuleActor {
			if p.actor.Problem != "" {
				ch = chain.Check{Rule: r.ID, Status: chain.StatusFail, Detail: "this actor " + p.actor.Problem}
			} else {
				ch = chain.Check{Rule: r.ID, Status: chain.StatusPass, Detail: "a well-formed actor, as the issuer states it"}
			}
		}
		l.Checks = append(l.Checks, ch)
	}
	if f, ok := findingFor(l.Check(RuleActor), l.Index); ok {
		l.Findings = append(l.Findings, f)
	}
	l.Findings = append(l.Findings, chain.Finding{Rule: RuleActor, Link: l.Index, Hop: -1, Severity: chain.SeverityInfo,
		Detail: whyAsserted(p, true)})
	if pc.Present && p.proof >= 0 && p.proof < len(pc.Proofs) {
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleProof, Link: l.Index, Hop: -1, Severity: chain.SeverityWarn,
			Detail: fmt.Sprintf("token %d carries a proof for this actor, but it is not relied on: %s", p.named, whyNotRelied(pc, p))})
	}
	if ac.Present && (ac.Coverage == "path" || ac.Coverage == "disclosed") && p.step >= 0 && p.step < ac.Depth && !ac.covers(p.step) {
		why := fmt.Sprintf("token %d's actor chain is %s (see its J12)", p.named, ac.Status)
		if ac.Status == chain.StatusPass {
			why = fmt.Sprintf("token %d itself does not verify", p.named)
		}
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleChain, Link: l.Index, Hop: -1, Severity: chain.SeverityWarn,
			Detail: fmt.Sprintf("token %d carries %s evidence for this actor, but it is not relied on: %s", p.named, ac.Coverage, why)})
	}
	if a := p.actor; a.Role == "" && a.Iss == "" && a.Problem == "" {
		l.Findings = append(l.Findings, chain.Finding{Rule: RuleActor, Link: l.Index, Hop: -1, Severity: chain.SeverityWarn,
			Detail: "names no iss; the actor profile draft requires one so the actor's identifier means something"})
	}
	l.Sections = []chain.Section{actorSection(p.actor), {Title: "WHY ASSERTED", Lines: []chain.Line{
		{Kind: chain.LineText, Value: whyAsserted(p, false), Tone: chain.ToneMuted},
	}}}
	if obj, err := json.MarshalIndent(p.actor.Object, "", "  "); err == nil {
		l.Raw = []chain.Section{{Title: "ACT MEMBER", Lines: []chain.Line{{Kind: chain.LineJSON, Value: string(obj)}}}}
	}
	return l
}

// whyAsserted says where an asserted link came from: a prior actor in an
// act claim, or a party the issuer names in its own claims (Entra's parent
// application).
func whyAsserted(p plan, short bool) string {
	if p.actor.Role != "" {
		if short {
			return fmt.Sprintf("the %s, named by the issuer in token %d's own claims: nothing verifies it hop by hop", p.actor.Role, p.named)
		}
		return fmt.Sprintf("Token %d names this %s in the issuer's own claims, not in an act claim. Only the issuer vouches for it, and no signature of its own is in the token.", p.named, p.actor.Role)
	}
	if short {
		return fmt.Sprintf("a prior actor named inside token %d: the issuer's word, and nothing verifies it hop by hop", p.named)
	}
	return fmt.Sprintf("Token %d names this actor inside its act claim. RFC 8693 section 4.1 makes prior actors informational: only the issuer vouches for them, and no signature of theirs is in the token.", p.named)
}

func findingFor(ch chain.Check, link int) (chain.Finding, bool) {
	var sev chain.Severity
	switch ch.Status {
	case chain.StatusFail:
		sev = chain.SeverityFail
	case chain.StatusError:
		sev = chain.SeverityError
	case chain.StatusUnchecked:
		sev = chain.SeverityUnchecked
	default:
		return chain.Finding{}, false
	}
	return chain.Finding{Rule: ch.Rule, Link: link, Hop: -1, Severity: sev, Detail: ch.Detail, Spec: format.Rule(ch.Rule).Spec}, true
}

func (s *session) timeCheck(k int, at time.Time) (chain.Status, string, string) {
	t := s.tokens[k]
	if t.Problem != "" {
		return chain.StatusSkipped, "not checked: the token cannot be read", ""
	}
	ref, when := at, "now"
	last := k == len(s.tokens)-1
	if !last {
		next := s.tokens[k+1]
		if next.Problem != "" || next.Iat == nil {
			return chain.StatusUnchecked, fmt.Sprintf("token %d has no iat, so whether this token still held when it was exchanged is unknown", k+1), ""
		}
		ref, when = *next.Iat, fmt.Sprintf("when token %d was issued", k+1)
	}
	for _, claim := range []string{"exp", "nbf", "iat"} {
		if p, bad := t.DateProblems[claim]; bad {
			return chain.StatusFail, claim + " " + p + ": a strict library refuses the token", ""
		}
	}
	if t.Iat != nil && ref.Add(s.skew).Before(*t.Iat) {
		return chain.StatusFail, fmt.Sprintf("issued at %s, which is after %s", stamp(*t.Iat), when), ""
	}
	if t.Nbf != nil && ref.Add(s.skew).Before(*t.Nbf) {
		return chain.StatusFail, fmt.Sprintf("not valid before %s, which is after %s", stamp(*t.Nbf), when), ""
	}
	if t.Exp == nil {
		if profile := expRequiredBy(t); profile != "" {
			return chain.StatusFail, "no exp, which " + profile + " requires", ""
		}
		return chain.StatusPass, "no exp", "the token has no exp: it never expires, which an enforcement point should refuse"
	}
	if !ref.Add(-s.skew).Before(*t.Exp) {
		if last {
			return chain.StatusFail, fmt.Sprintf("expired at %s", stamp(*t.Exp)), ""
		}
		return chain.StatusFail, fmt.Sprintf("expired at %s, before token %d was issued from it", stamp(*t.Exp), k+1), ""
	}
	if last {
		return chain.StatusPass, fmt.Sprintf("valid until %s", stamp(*t.Exp)), ""
	}
	return chain.StatusPass, fmt.Sprintf("still valid %s", when), ""
}

// expRequiredBy names the profile that makes exp mandatory for this
// token, or "" when exp is optional (RFC 7519 leaves it so).
func expRequiredBy(t *token) string {
	switch normType(t.Typ) {
	case typAccess:
		return "an RFC 9068 access token (at+jwt)"
	case typIDJAG:
		return "an ID-JAG"
	case typTxnToken:
		return "a Txn-Token"
	}
	return ""
}

func (s *session) audienceCheck(k int) (chain.Status, string) {
	t := s.tokens[k]
	if k != len(s.tokens)-1 {
		return chain.StatusNotApplicable, "only the token presented last is addressed to the resource server"
	}
	if t.Problem != "" {
		return chain.StatusSkipped, "not checked: the token cannot be read"
	}
	if s.audience == nil {
		if len(t.Aud) == 0 {
			return chain.StatusUnchecked, "the token names no audience; pass --audience to check it is meant for you"
		}
		return chain.StatusUnchecked, fmt.Sprintf("addressed to %s; pass --audience to check that is you", strings.Join(t.Aud, ", "))
	}
	for _, a := range t.Aud {
		if a == *s.audience {
			return chain.StatusPass, "addressed to " + a
		}
	}
	if len(t.Aud) == 0 {
		return chain.StatusFail, "the token names no audience, so it is not addressed to " + *s.audience
	}
	return chain.StatusFail, fmt.Sprintf("addressed to %s, not %s", strings.Join(t.Aud, ", "), *s.audience)
}

func actorCheck(t *token) (chain.Status, string) {
	switch {
	case t.Problem != "":
		return chain.StatusSkipped, "not checked: the token cannot be read"
	case t.ActProblem != "":
		return chain.StatusFail, t.ActProblem
	case t.hasExplicitActor() && t.current().Problem != "":
		return chain.StatusFail, "the current actor " + t.current().Problem
	case t.hasExplicitActor():
		return chain.StatusPass, "current actor " + t.current().name()
	}
	h := t.holder()
	return chain.StatusPass, fmt.Sprintf("no act claim: the %s %s holds it", h.Role, h.name())
}

// mayActCheck holds an exchanged token to the token it replaced: that
// token's may_act names who may become the actor for its subject in the
// next exchange (RFC 8693 section 4.4). A token's own may_act is about the
// exchange after it, so it says nothing about the token's own actor.
func (s *session) mayActCheck(k int) (chain.Status, string) {
	t := s.tokens[k]
	if t.Problem != "" {
		return chain.StatusSkipped, "not checked: the token cannot be read"
	}
	if k == 0 {
		return chain.StatusNotApplicable, "no token before this one names who may act"
	}
	prev := s.tokens[k-1]
	if prev.Problem == "" && prev.MayActProblem != "" {
		return chain.StatusFail, fmt.Sprintf("token %d's %s, so who may act for its subject cannot be read", k-1, prev.MayActProblem)
	}
	if prev.Problem != "" || prev.MayAct == nil {
		return chain.StatusNotApplicable, fmt.Sprintf("token %d names no may_act", k-1)
	}
	cur := t.current()
	if !cur.same(*prev.MayAct) {
		return chain.StatusFail, fmt.Sprintf("token %d lets only %s act for its subject, but %s does here", k-1, prev.MayAct.name(), cur.name())
	}
	return chain.StatusPass, cur.name() + " is the party token " + fmt.Sprint(k-1) + "'s may_act names"
}

// hopRule checks one of the exchange rules for token k against token k-1.
func (s *session) hopRule(rule string, k int) (chain.Status, string) {
	if k == 0 {
		return chain.StatusNotApplicable, "the first token is not exchanged from another"
	}
	t, prev := s.tokens[k], s.tokens[k-1]
	if t.Problem != "" || prev.Problem != "" {
		return chain.StatusSkipped, "not checked: a token of the exchange cannot be read"
	}
	switch rule {
	case RuleExtends:
		if t.ActProblem != "" || prev.ActProblem != "" {
			return chain.StatusSkipped, "not checked: an act chain cannot be read"
		}
		if len(t.Actors) != len(prev.Actors)+1 {
			return chain.StatusFail, fmt.Sprintf("names %d actor%s, token %d named %d: an exchange adds exactly one", len(t.Actors), plural(len(t.Actors)), k-1, len(prev.Actors))
		}
		for j, a := range prev.Actors {
			if !t.Actors[j].same(a) {
				return chain.StatusFail, fmt.Sprintf("actor %d is %s here but %s in token %d: this token was not exchanged from that one", j, t.Actors[j].name(), a.name(), k-1)
			}
		}
		return chain.StatusPass, "adds " + t.current().name() + " to token " + fmt.Sprint(k-1) + "'s actors"
	case RuleScope:
		switch {
		case prev.ScopeClaim == "" && t.ScopeClaim == "":
			return chain.StatusPass, "neither token names a scope"
		case prev.ScopeClaim == "":
			return chain.StatusUnchecked, fmt.Sprintf("token %d names no scope, so whether this one narrowed it cannot be judged", k-1)
		case t.ScopeClaim == "":
			// No scope claim can mean "the resource server's default",
			// which may be wider than anything token k-1 named.
			return chain.StatusUnchecked, fmt.Sprintf("names no scope, which a resource server may read as its default; whether that is within token %d's cannot be judged", k-1)
		}
		var wider []string
		for _, sc := range t.Scopes {
			if !contains(prev.Scopes, sc) {
				wider = append(wider, sc)
			}
		}
		if len(wider) > 0 {
			return chain.StatusFail, fmt.Sprintf("adds %s, which token %d did not hold", strings.Join(wider, ", "), k-1)
		}
		return chain.StatusPass, fmt.Sprintf("%d of token %d's %d scopes", len(t.Scopes), k-1, len(prev.Scopes))
	case RuleSubject:
		if t.Sub != prev.Sub {
			return chain.StatusFail, fmt.Sprintf("subject %q, but token %d's is %q: an exchange acts for the same subject", t.Sub, k-1, prev.Sub)
		}
		return chain.StatusPass, "same subject"
	case RuleExpiry:
		switch {
		case prev.DateProblems["exp"] != "":
			return chain.StatusFail, fmt.Sprintf("token %d's exp %s, so whether this one expires no later cannot hold", k-1, prev.DateProblems["exp"])
		case t.DateProblems["exp"] != "":
			return chain.StatusFail, "exp " + t.DateProblems["exp"]
		case prev.Exp == nil:
			return chain.StatusPass, fmt.Sprintf("token %d never expires", k-1)
		case t.Exp == nil:
			return chain.StatusFail, fmt.Sprintf("has no exp, but token %d expires at %s: the exchange removed the expiry", k-1, stamp(*prev.Exp))
		case t.Exp.After(*prev.Exp):
			return chain.StatusFail, fmt.Sprintf("expires %s after token %d", chain.Human(t.Exp.Sub(*prev.Exp)), k-1)
		}
		return chain.StatusPass, fmt.Sprintf("expires no later than token %d", k-1)
	}
	return chain.StatusNotApplicable, ""
}

// actorWarnings are what the actor profile draft asks of act members that
// the token leaves out. They do not break the chain.
func actorWarnings(t *token, link int) []chain.Finding {
	if t.Problem != "" || !t.hasExplicitActor() {
		return nil
	}
	cur := t.current()
	var out []chain.Finding
	if cur.Role == "" && cur.Iss == "" && cur.Problem == "" {
		out = append(out, chain.Finding{Rule: RuleActor, Link: link, Hop: -1, Severity: chain.SeverityWarn,
			Detail: "the current actor names no iss; the actor profile draft requires one"})
	}
	// An Actor Chain ActorID is exactly iss and sub, so it can never carry
	// the sub_profile the actor profile draft recommends.
	_, chained := t.Claims["actp"]
	if cur.Role == "" && cur.SubProfile == "" && cur.Problem == "" && !chained {
		out = append(out, chain.Finding{Rule: RuleActor, Link: link, Hop: -1, Severity: chain.SeverityInfo,
			Detail: "the current actor names no sub_profile, so it is unclassified (the actor profile draft recommends one)"})
	}
	return out
}

// chainFindings are about the whole input.
func (s *session) chainFindings(c *chain.Chain) {
	if s.bundle() {
		return
	}
	t := s.tokens[0]
	if t.Problem == "" && normType(t.Typ) == typWIT {
		c.ChainFindings = append(c.ChainFindings, chain.Finding{Rule: RuleToken, Link: -1, Hop: -1, Severity: chain.SeverityInfo,
			Detail: "a WIMSE workload identity token names one workload, not a delegation"})
	}
}

// settle derives states, the break, what is unreached and the verdict.
func settle(c *chain.Chain) {
	blocking, unchecked := false, false
	for i := range c.Links {
		l := &c.Links[i]
		bad, unsure := false, false
		for _, ch := range l.Checks {
			if ch.Status.Blocking() {
				bad = true
			}
			if ch.Status == chain.StatusUnchecked {
				unsure = true
			}
		}
		switch {
		case bad:
			l.State = chain.LinkBroken
			blocking = true
			if c.BreakAt < 0 {
				c.BreakAt = i
			}
		case unsure:
			l.State = chain.LinkIncomplete
			unchecked = true
		}
	}
	if c.BreakAt >= 0 {
		for i := c.BreakAt + 1; i < len(c.Links); i++ {
			c.Links[i].Unreached = true
			c.Links[i].UnreachedBy = c.BreakAt
		}
	}
	for _, f := range c.ChainFindings {
		if f.Severity.Blocking() {
			blocking = true
		}
	}
	switch {
	case blocking:
		c.Verdict = chain.VerdictInvalid
	case unchecked:
		c.Verdict = chain.VerdictIncomplete
	default:
		c.Verdict = chain.VerdictValid
	}
}

// describe writes the sentences: the summary, what was checked against,
// and what was missing.
func (s *session) describe(c *chain.Chain, plans []plan, ev evidence, at time.Time) {
	asserted, signed := 0, 0
	for _, p := range plans {
		switch {
		case p.signed:
			signed++
		case p.tok < 0:
			asserted++
		}
	}
	proofs, needActorKeys, needServerKeys := false, false, false
	for _, pc := range ev.proofs {
		proofs = proofs || pc.Present
		needActorKeys = needActorKeys || pc.NeedActorKeys
	}
	for _, ac := range ev.chains {
		proofs = proofs || len(ac.Steps) > 0
		needActorKeys = needActorKeys || ac.NeedActorKeys
		needServerKeys = needServerKeys || ac.NeedServerKeys
	}
	last := s.tokens[len(s.tokens)-1]
	if s.bundle() {
		c.Summary = []string{fmt.Sprintf("%d exchanged tokens", len(s.tokens)), "each signed", "checked hop by hop"}
	} else {
		c.Summary = []string{"1 token", fmt.Sprintf("%d actor%s", len(plans), plural(len(plans)))}
		if signed > 0 {
			c.Summary = append(c.Summary, fmt.Sprintf("%d prior actor%s signed by the actor", signed, plural(signed)))
		}
		if asserted > 0 {
			c.Summary = append(c.Summary, "prior actors asserted")
		}
	}
	if s.demo != "" {
		c.Summary = []string{s.demo}
	}
	switch {
	case c.Verdict == chain.VerdictValid && asserted > 0:
		c.Headline = fmt.Sprintf("The token verifies. Its %d prior actor%s %s the issuer's word, not a verified chain.",
			asserted, plural(asserted), map[bool]string{true: "is", false: "are"}[asserted == 1])
	case c.Verdict == chain.VerdictValid && signed > 0 && !s.bundle():
		// Only for one token: a bundle's later actors stand on the issuer's
		// signature of their own token, not on a proof of theirs.
		c.Headline = "The token verifies, and every actor in it signed its own hop."
	}

	var missing []string
	needKeys, needAud := false, false
	for _, l := range c.Links {
		if l.Check(RuleSignature).Status == chain.StatusUnchecked {
			needKeys = true
		}
		if l.Check(RuleAudience).Status == chain.StatusUnchecked {
			needAud = true
		}
	}
	if needKeys || needServerKeys {
		missing = append(missing, "the issuer's keys (--jwks ISSUER=PATH or --trust)")
	}
	if needAud {
		missing = append(missing, "the audience the token is presented to (--audience)")
	}
	if needActorKeys {
		missing = append(missing, "the actors' keys (actors in the --trust file)")
	}
	c.Missing = missing
	if c.Verdict == chain.VerdictIncomplete {
		var why []string
		if needKeys || needServerKeys {
			why = append(why, "no issuer keys given")
		}
		if needAud {
			why = append(why, "no audience given")
		}
		if needActorKeys {
			why = append(why, "no actor keys given")
		}
		for _, l := range c.Links {
			for _, ch := range l.Checks {
				// A proof unchecked for want of its actors' keys is named
				// above; any other cause is said here.
				if p := plans[l.Index]; ch.Rule == RuleProof && p.tok >= 0 && ev.proofs[p.tok].NeedActorKeys && ev.proofs[p.tok].OnlyKeys {
					continue
				}
				if p := plans[l.Index]; ch.Rule == RuleChain && p.tok >= 0 && ev.chains[p.tok].OnlyKeys {
					continue
				}
				if ch.Status == chain.StatusUnchecked && ch.Rule != RuleSignature && ch.Rule != RuleAudience {
					why = append(why, fmt.Sprintf("%s %s could not be judged", ch.Rule, format.Rule(ch.Rule).Title))
				}
			}
		}
		c.IncompleteReason = strings.Join(dedupe(why), ", ")
	}

	c.CheckedAgainst = s.keys.summary()
	if proofs {
		c.CheckedAgainst = append(c.CheckedAgainst, s.actorKeys.summary()...)
	}
	if s.audience != nil {
		c.CheckedAgainst = append(c.CheckedAgainst, chain.KV{Key: "audience", Value: *s.audience})
	} else {
		c.CheckedAgainst = append(c.CheckedAgainst, chain.KV{Key: "audience", Value: "none given", Tone: chain.ToneWarn})
	}
	c.CheckedAgainst = append(c.CheckedAgainst, chain.KV{Key: "time", Value: at.UTC().Format("2006-01-02 15:04 UTC") + ", skew " + s.skew.String()})
	c.Ignored = s.ignored

	desc := []string{}
	if last.Iss != "" {
		desc = append(desc, "issuer "+last.Iss)
	}
	desc = append(desc, last.Kind)
	c.Describe = strings.Join(desc, ", ")
	ctx := "at " + at.UTC().Format(time.RFC3339) + ", skew " + s.skew.String()
	if s.audience != nil {
		ctx += ", audience " + *s.audience
	}
	c.Context = ctx
	c.Native = s.native()
}

func (s *session) tokenSections(t *token, p plan) []chain.Section {
	if t.Problem != "" {
		return []chain.Section{{Title: "TOKEN", Lines: []chain.Line{{Kind: chain.LineText, Value: t.Problem, Tone: chain.ToneBad}}}}
	}
	tok := chain.Section{Title: "TOKEN"}
	add := func(k, v string, tone chain.Tone) {
		if v != "" {
			tok.Lines = append(tok.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
		}
	}
	add("kind", t.Kind, chain.ToneStrong)
	add("issuer", t.Iss, chain.ToneText)
	add("subject", t.Sub, chain.ToneRoot)
	add("audience", strings.Join(t.Aud, ", "), chain.ToneText)
	if t.ScopeClaim != "" {
		add(t.ScopeClaim, strings.Join(t.Scopes, " "), chain.ToneText)
		if t.ScopeNote != "" {
			add("", t.ScopeNote, chain.ToneWarn)
		}
	}
	for _, claim := range []string{"exp", "nbf", "iat"} {
		if p, bad := t.DateProblems[claim]; bad {
			add(claim, p, chain.ToneBad)
		}
	}
	if t.Iat != nil {
		add("issued", stamp(*t.Iat), chain.ToneMuted)
	}
	if t.Exp != nil {
		add("expires", stamp(*t.Exp), chain.ToneText)
	}
	add("client_id", t.ClientID, chain.ToneMuted)
	add("jti", t.JTI, chain.ToneMuted)
	add("alg", t.Alg+kidSuffix(t.Kid), chain.ToneMuted)
	out := []chain.Section{actorSection(p.actor), tok}
	if t.MayAct != nil {
		out = append(out, chain.Section{Title: "MAY ACT", Lines: []chain.Line{
			{Kind: chain.LineKV, Key: "sub", Value: t.MayAct.name()},
			{Kind: chain.LineText, Value: "RFC 8693 section 4.4: the party allowed to become the actor for this subject.", Tone: chain.ToneMuted},
		}})
	}
	if e := t.Entra; e != nil {
		sec := chain.Section{Title: "ENTRA"}
		kv := func(k, v string) {
			if v != "" {
				sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v})
			}
		}
		kv("idtyp", e.IDType)
		kv("actor facets", strings.Join(mapStrings(e.ActFacets, facetName), ", "))
		kv("subject facets", strings.Join(mapStrings(e.SubFacets, facetName), ", "))
		kv("parent app", e.ParentApp)
		kv("tenant", e.TenantID)
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Tone: chain.ToneMuted,
			Value: "Entra has no act claim: it names one acting application and the application it was made from. Only one hop is ever represented."})
		out = append(out, sec)
	}
	return out
}

func actorSection(a actor) chain.Section {
	sec := chain.Section{Title: "ACTOR"}
	add := func(k, v string, tone chain.Tone) {
		if v != "" {
			sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
		}
	}
	add("sub", a.Sub, chain.ToneStrong)
	add("role", a.Role, chain.ToneMuted)
	add("iss", a.Iss, chain.ToneText)
	add("sub_profile", a.SubProfile, chain.ToneText)
	add("client_id", a.ClientID, chain.ToneMuted)
	if a.Problem != "" {
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Value: "this actor " + a.Problem, Tone: chain.ToneBad})
	}
	return sec
}

func tokenRaw(t *token) []chain.Section {
	var out []chain.Section
	if t.Header != nil {
		out = append(out, chain.Section{Title: "HEADER", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(t.Header)}}})
	}
	if t.Claims != nil {
		out = append(out, chain.Section{Title: "CLAIMS", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(t.Claims)}}})
	}
	out = append(out, chain.Section{Title: "COMPACT", Lines: []chain.Line{{Kind: chain.LineCode, Value: t.Raw}}})
	return out
}

func pretty(v map[string]any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func kidSuffix(kid string) string {
	if kid == "" {
		return ""
	}
	return ", kid " + kid
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func hostOf(iss string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(iss, "https://"), "http://")
	if h, _, ok := strings.Cut(s, "/"); ok && h != "" {
		return h
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func mapStrings(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

// native is the adapter's own JSON for `check --json --native`.
func (s *session) native() any {
	type nativeToken struct {
		Header  map[string]any `json:"header,omitempty"`
		Claims  map[string]any `json:"claims,omitempty"`
		Problem string         `json:"problem,omitempty"`
		Kind    string         `json:"kind,omitempty"`
		Actors  []string       `json:"actors"`
	}
	out := struct {
		Schema string        `json:"schema"`
		Tokens []nativeToken `json:"tokens"`
	}{Schema: "whosent.jwt/v1"}
	for _, t := range s.tokens {
		nt := nativeToken{Header: t.Header, Claims: t.Claims, Problem: t.Problem, Kind: t.Kind, Actors: []string{}}
		for _, a := range t.Actors {
			nt.Actors = append(nt.Actors, a.name())
		}
		out.Tokens = append(out.Tokens, nt)
	}
	return out
}
