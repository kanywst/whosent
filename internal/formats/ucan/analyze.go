package ucan

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// The rules, in the order the view lists them.
const (
	RuleEnvelope   = "U1"
	RuleSignature  = "U2"
	RuleTime       = "U3"
	RulePrincipals = "U4"
	RuleSubject    = "U5"
	RuleCommand    = "U6"
	RulePolicy     = "U7"
	RuleProofs     = "U8"
	RuleRevocation = "U9"
)

var rules = []chain.RuleInfo{
	{ID: RuleEnvelope, Title: "envelope", Spec: "https://github.com/ucan-wg/spec#envelope"},
	{ID: RuleSignature, Title: "signature", Spec: "https://github.com/ucan-wg/delegation#signature-validation"},
	{ID: RuleTime, Title: "time", Spec: "https://github.com/ucan-wg/delegation#time-bounds"},
	{ID: RulePrincipals, Title: "principals", Spec: "https://github.com/ucan-wg/delegation#principal-alignment"},
	{ID: RuleSubject, Title: "subject", Spec: "https://github.com/ucan-wg/delegation#subject"},
	{ID: RuleCommand, Title: "command", Spec: "https://github.com/ucan-wg/spec#command"},
	{ID: RulePolicy, Title: "policy", Spec: "https://github.com/ucan-wg/delegation#policy"},
	{ID: RuleProofs, Title: "proofs", Spec: "https://github.com/ucan-wg/invocation#proofs"},
	{ID: RuleRevocation, Title: "revocation", Spec: "https://github.com/ucan-wg/revocation"},
}

func ruleIndex(id string) int {
	for i, r := range rules {
		if r.ID == id {
			return i
		}
	}
	panic("unknown rule " + id)
}

// Options are what a chain is checked against.
type Options struct {
	Skew time.Duration
	// Revoked holds revoked delegation CIDs in base58btc; nil when no list
	// was given.
	Revoked       map[string]bool
	RevokedSource string
	// Names label DIDs on the rail. Only demos set them.
	Names   map[string]string
	Ignored []string
}

// node is one link: a delegation, the invocation, or a proof the
// invocation names but nobody supplied.
type node struct {
	index int
	tok   *Token
	// cid is the proof's CID when tok is nil.
	cid    []byte
	inv    bool
	checks []chain.Check

	findings   []chain.Finding
	revoked    bool
	revokedSim bool
	// policyChecks are the invocation's per-statement results.
	policyChecks []policyCheck
}

type policyCheck struct {
	link  int
	stmt  string
	holds bool
}

func (n *node) missing() bool  { return n.tok == nil }
func (n *node) readable() bool { return n.tok != nil && n.tok.Err == nil }

func (n *node) set(rule string, st chain.Status, format string, a ...any) {
	n.checks[ruleIndex(rule)] = chain.Check{Rule: rule, Status: st, Detail: fmt.Sprintf(format, a...)}
}

func (n *node) status(rule string) chain.Status { return n.checks[ruleIndex(rule)].Status }

func (n *node) find(rule string, sev chain.Severity, format string, a ...any) {
	n.findings = append(n.findings, chain.Finding{Rule: rule, Link: n.index, Hop: -1, Severity: sev,
		Detail: fmt.Sprintf(format, a...), Spec: rules[ruleIndex(rule)].Spec})
}

// analysis is one evaluation of a chain.
type analysis struct {
	format    string
	opts      Options
	at        time.Time
	sim       map[string]bool
	simulated []string

	links []*node
	inv   *node
	// subject is the DID the chain is about, when anything names it.
	subject string
	ordered string

	chainFindings []chain.Finding
}

// assemble puts the tokens in chain order: with an invocation, the order
// its prf gives (root first); without one, issuer-to-audience from the
// delegation its subject issued, or the order they came in.
func assemble(tokens []*Token) (links []*node, inv *node, ordered string, unused int, err error) {
	var invs, rest []*Token
	for _, t := range tokens {
		if t.Invocation() {
			invs = append(invs, t)
		} else {
			rest = append(rest, t)
		}
	}
	switch {
	case len(invs) > 1:
		return nil, nil, "", 0, fmt.Errorf("%d invocations; give one, with its proofs", len(invs))
	case len(invs) == 0 && !anyDelegation(rest):
		if len(rest) > 0 && rest[0].Err != nil {
			return nil, nil, "", 0, fmt.Errorf("nothing decodes as a UCAN delegation or invocation: %v", rest[0].Err)
		}
		return nil, nil, "", 0, errors.New("nothing decodes as a UCAN delegation or invocation")
	}
	if len(invs) == 1 {
		used := map[*Token]bool{}
		for _, c := range invs[0].Prf {
			n := &node{cid: c}
			for _, t := range rest {
				if !used[t] && bytes.Equal(t.CID, c) {
					n.tok, used[t] = t, true
					break
				}
			}
			links = append(links, n)
		}
		inv = &node{tok: invs[0], inv: true}
		links = append(links, inv)
		for _, t := range rest {
			if !used[t] {
				unused++
			}
		}
		return number(links), inv, "the invocation's prf", unused, nil
	}
	if order, ok := byAlignment(rest); ok {
		for _, t := range order {
			links = append(links, &node{tok: t})
		}
		return number(links), nil, "issuer to audience", 0, nil
	}
	for _, t := range rest {
		links = append(links, &node{tok: t})
	}
	return number(links), nil, "as given", 0, nil
}

func anyDelegation(ts []*Token) bool {
	for _, t := range ts {
		if t.Delegation() {
			return true
		}
	}
	return false
}

func number(links []*node) []*node {
	for i, n := range links {
		n.index = i
		n.checks = make([]chain.Check, len(rules))
		for k, r := range rules {
			n.checks[k] = chain.Check{Rule: r.ID, Status: chain.StatusNotApplicable}
		}
	}
	return links
}

// byAlignment orders delegations from the one its subject issued along
// audience-to-issuer links. ok is false unless that path uses every token
// exactly once.
func byAlignment(ts []*Token) ([]*Token, bool) {
	var root *Token
	for _, t := range ts {
		if !t.Delegation() {
			return nil, false
		}
		if t.Sub != nil && principal(t.Iss) == principal(*t.Sub) {
			if root != nil {
				return nil, false
			}
			root = t
		}
	}
	if root == nil {
		return nil, false
	}
	order := []*Token{root}
	used := map[*Token]bool{root: true}
	for len(order) < len(ts) {
		cur := order[len(order)-1]
		var next *Token
		for _, t := range ts {
			if !used[t] && principal(t.Iss) == principal(cur.Aud) {
				if next != nil {
					return nil, false
				}
				next = t
			}
		}
		if next == nil {
			return nil, false
		}
		order = append(order, next)
		used[next] = true
	}
	return order, true
}

// subjectOf is the DID the chain is about: the first subject a delegation
// names, or the invocation's.
func subjectOf(links []*node, inv *node) string {
	for _, n := range links {
		if n.readable() && !n.inv && n.tok.Sub != nil {
			return *n.tok.Sub
		}
	}
	if inv != nil && inv.tok.Sub != nil {
		return *inv.tok.Sub
	}
	return ""
}

// analyze checks every link against every rule. Nothing stops at the
// first failure.
func analyze(tokens []*Token, opts Options, at time.Time, sim []string) (*analysis, error) {
	links, inv, ordered, unused, err := assemble(tokens)
	if err != nil {
		return nil, err
	}
	a := &analysis{format: ID, opts: opts, at: at, links: links, inv: inv, ordered: ordered, sim: map[string]bool{}}
	for _, id := range sim {
		a.sim[id] = true
	}
	a.subject = subjectOf(links, inv)
	if unused > 0 {
		a.chainFindings = append(a.chainFindings, chain.Finding{Rule: RuleProofs, Link: -1, Hop: -1, Severity: chain.SeverityInfo,
			Detail: fmt.Sprintf("%d token(s) not named in the invocation's prf were left out", unused), Spec: rules[ruleIndex(RuleProofs)].Spec})
	}
	for _, n := range links {
		a.envelope(n)
		a.signature(n)
		a.time(n)
		a.principals(n)
		a.subjectRule(n)
		a.command(n)
		a.proofs(n)
		a.revocation(n)
	}
	if inv != nil {
		a.policy(inv)
	}
	for _, n := range links {
		if !n.inv && n.status(RulePolicy) == chain.StatusNotApplicable && n.readable() {
			n.set(RulePolicy, chain.StatusNotApplicable, "a delegation's policy is checked against an invocation's arguments")
		}
	}
	return a, nil
}

func (a *analysis) envelope(n *node) {
	switch {
	case n.missing():
		n.set(RuleEnvelope, chain.StatusNotApplicable, "not supplied")
	case n.tok.Err != nil:
		n.set(RuleEnvelope, chain.StatusFail, "%v", n.tok.Err)
		n.find(RuleEnvelope, chain.SeverityFail, "%v", n.tok.Err)
	case n.tok.HeaderErr != nil:
		n.set(RuleEnvelope, chain.StatusFail, "%v", n.tok.HeaderErr)
		n.find(RuleEnvelope, chain.SeverityFail, "%v", n.tok.HeaderErr)
	case len(n.tok.Problems) > 0:
		d := n.tok.Problems[0]
		if len(n.tok.Problems) > 1 {
			d += fmt.Sprintf(" (and %d more)", len(n.tok.Problems)-1)
		}
		n.set(RuleEnvelope, chain.StatusFail, "%s", d)
		for _, p := range n.tok.Problems {
			n.find(RuleEnvelope, chain.SeverityFail, "%s", p)
		}
	default:
		n.set(RuleEnvelope, chain.StatusPass, "a %s, canonical DAG-CBOR", map[bool]string{true: "ucan/inv@1.0.0", false: "ucan/dlg@1.0.0"}[n.tok.Invocation()])
	}
	if n.readable() && len(n.tok.Unknown) > 0 {
		n.find(RuleEnvelope, chain.SeverityWarn, "fields neither spec defines: %v", n.tok.Unknown)
	}
}

func (a *analysis) signature(n *node) {
	if !n.readable() || n.tok.HeaderErr != nil || n.tok.Iss == "" {
		if !n.missing() {
			n.set(RuleSignature, chain.StatusSkipped, "the token could not be read")
		}
		return
	}
	key, err := parseDIDKey(n.tok.Iss)
	switch {
	case errors.Is(err, errNotDIDKey):
		n.set(RuleSignature, chain.StatusUnchecked, "issued by %s; resolving a DID of that method needs the network, and whosent checks did:key only", shortDID(n.tok.Iss))
		n.find(RuleSignature, chain.SeverityUnchecked, "the signature was not checked: %s is not a did:key", shortDID(n.tok.Iss))
		return
	case err != nil:
		n.set(RuleSignature, chain.StatusFail, "the issuer %v", err)
		n.find(RuleSignature, chain.SeverityFail, "the issuer %v", err)
		return
	}
	err = verifySig(n.tok.Header, key, n.tok.SigPayload, n.tok.Sig)
	switch {
	case errors.Is(err, errUnsupported):
		n.set(RuleSignature, chain.StatusUnchecked, "%v", err)
		n.find(RuleSignature, chain.SeverityUnchecked, "the signature was not checked: %v", err)
	case err != nil:
		n.set(RuleSignature, chain.StatusFail, "%v", err)
		n.find(RuleSignature, chain.SeverityFail, "%v", err)
	default:
		n.set(RuleSignature, chain.StatusPass, "signed by its issuer's %s key", key.Type)
	}
}

func stamp(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05 UTC") }

func (a *analysis) time(n *node) {
	if !n.readable() {
		if !n.missing() {
			n.set(RuleTime, chain.StatusSkipped, "the token could not be read")
		}
		return
	}
	t := n.tok
	skew := a.opts.Skew
	switch {
	case t.Nbf != nil && a.at.Add(skew).Before(time.Unix(*t.Nbf, 0)):
		n.set(RuleTime, chain.StatusFail, "not valid before %s", stamp(*t.Nbf))
		n.find(RuleTime, chain.SeverityFail, "not valid before %s", stamp(*t.Nbf))
	case t.Exp != nil && a.at.Add(-skew).After(time.Unix(*t.Exp, 0)):
		n.set(RuleTime, chain.StatusFail, "expired at %s", stamp(*t.Exp))
		n.find(RuleTime, chain.SeverityFail, "expired at %s", stamp(*t.Exp))
	case t.Exp == nil:
		n.set(RuleTime, chain.StatusPass, "never expires (exp: null)")
	default:
		n.set(RuleTime, chain.StatusPass, "valid until %s", stamp(*t.Exp))
	}
}

// prev is the delegation above link i, or nil.
func (a *analysis) prev(n *node) *node {
	if n.index == 0 {
		return nil
	}
	return a.links[n.index-1]
}

func (a *analysis) principals(n *node) {
	if !n.readable() {
		if !n.missing() {
			n.set(RulePrincipals, chain.StatusSkipped, "the token could not be read")
		}
		return
	}
	t, p := n.tok, a.prev(n)
	switch {
	case p == nil && n.inv:
		n.set(RulePrincipals, chain.StatusNotApplicable, "no delegation: the invoker acts on its own authority")
	case p == nil:
		if t.Sub == nil {
			n.set(RulePrincipals, chain.StatusNotApplicable, "a powerline names no subject to be issued by")
			return
		}
		if principal(t.Iss) != principal(*t.Sub) {
			n.set(RulePrincipals, chain.StatusFail, "the first delegation is issued by %s, not by its subject %s", a.name(t.Iss), a.name(*t.Sub))
			n.find(RulePrincipals, chain.SeverityFail, "the first delegation must be issued by its subject: issued by %s, subject %s", a.who(t.Iss), a.who(*t.Sub))
			return
		}
		n.set(RulePrincipals, chain.StatusPass, "issued by its subject")
	case !p.readable():
		n.set(RulePrincipals, chain.StatusSkipped, "the delegation above could not be read")
	case principal(t.Iss) != principal(p.tok.Aud):
		what := "issued"
		if n.inv {
			what = "invoked"
		}
		n.set(RulePrincipals, chain.StatusFail, "%s by %s, but the delegation above went to %s", what, a.name(t.Iss), a.name(p.tok.Aud))
		n.find(RulePrincipals, chain.SeverityFail, "%s by %s, but the delegation above was addressed to %s", what, a.who(t.Iss), a.who(p.tok.Aud))
	default:
		n.set(RulePrincipals, chain.StatusPass, "issued by the audience of the delegation above")
	}
}

func (a *analysis) subjectRule(n *node) {
	if !n.readable() {
		if !n.missing() {
			n.set(RuleSubject, chain.StatusSkipped, "the token could not be read")
		}
		return
	}
	t := n.tok
	switch {
	case t.Sub == nil && n.inv:
		// The envelope rule reports an invocation without a subject.
		n.set(RuleSubject, chain.StatusSkipped, "the invocation names no subject")
	case t.Sub == nil && n.index == 0:
		n.set(RuleSubject, chain.StatusFail, "a powerline (sub: null) cannot be the root delegation")
		n.find(RuleSubject, chain.SeverityFail, "a powerline delegation (sub: null) cannot root a chain: there is no subject before it")
	case t.Sub == nil:
		n.set(RuleSubject, chain.StatusPass, "powerline: takes the chain's subject")
	case a.subject != "" && principal(*t.Sub) != principal(a.subject):
		n.set(RuleSubject, chain.StatusFail, "about %s, the chain is about %s", a.name(*t.Sub), a.name(a.subject))
		n.find(RuleSubject, chain.SeverityFail, "names subject %s, but the chain is about %s", a.who(*t.Sub), a.who(a.subject))
	default:
		n.set(RuleSubject, chain.StatusPass, "about the chain's subject")
	}
}

func (a *analysis) command(n *node) {
	if !n.readable() || n.tok.Cmd == "" {
		if !n.missing() {
			n.set(RuleCommand, chain.StatusSkipped, "the token could not be read")
		}
		return
	}
	cmd, p := n.tok.Cmd, a.prev(n)
	switch {
	case p == nil && n.inv:
		n.set(RuleCommand, chain.StatusPass, "invokes %s on its own authority", cmd)
	case p == nil:
		n.set(RuleCommand, chain.StatusPass, "grants %s", cmd)
	case !p.readable():
		n.set(RuleCommand, chain.StatusSkipped, "the delegation above could not be read")
	case !covers(p.tok.Cmd, cmd):
		n.set(RuleCommand, chain.StatusFail, "%s is not under %s", cmd, p.tok.Cmd)
		n.find(RuleCommand, chain.SeverityFail, "%s is not under %s, which the delegation above granted", cmd, p.tok.Cmd)
	case cmd == p.tok.Cmd:
		n.set(RuleCommand, chain.StatusPass, "keeps %s", cmd)
	default:
		n.set(RuleCommand, chain.StatusPass, "narrows %s to %s", p.tok.Cmd, cmd)
	}
}

func (a *analysis) proofs(n *node) {
	switch {
	case n.missing():
		n.set(RuleProofs, chain.StatusFail, "not supplied: the invocation names %s as a proof", shortCID(n.cid))
		n.find(RuleProofs, chain.SeverityFail, "proof %s is not supplied", cidText(n.cid))
	case !n.inv:
	case !n.readable():
		n.set(RuleProofs, chain.StatusSkipped, "the invocation could not be read")
	case len(n.tok.Prf) == 0:
		if n.tok.Sub != nil && principal(n.tok.Iss) == principal(*n.tok.Sub) {
			n.set(RuleProofs, chain.StatusPass, "issued by its subject: no proof needed")
			return
		}
		n.set(RuleProofs, chain.StatusFail, "no proofs, and the invoker is not the subject")
		n.find(RuleProofs, chain.SeverityFail, "no proofs, and %s is not the subject %s", a.who(n.tok.Iss), a.who(a.subject))
	default:
		for _, l := range a.links {
			if l.missing() {
				n.set(RuleProofs, chain.StatusSkipped, "proof %d is missing", l.index)
				return
			}
		}
		n.set(RuleProofs, chain.StatusPass, "%d proof(s), all supplied", len(n.tok.Prf))
	}
}

func (a *analysis) revocation(n *node) {
	if n.inv || n.missing() {
		return
	}
	id := cidText(n.tok.CID)
	switch {
	case a.sim[id]:
		n.revoked, n.revokedSim = true, true
		n.checks[ruleIndex(RuleRevocation)] = chain.Check{Rule: RuleRevocation, Status: chain.StatusFail, Detail: "revoked (simulated)", Simulated: true}
		n.findings = append(n.findings, chain.Finding{Rule: RuleRevocation, Link: n.index, Hop: -1, Severity: chain.SeverityFail, Simulated: true,
			Detail: "revoked (simulated): " + id, Spec: rules[ruleIndex(RuleRevocation)].Spec})
		a.simulated = append(a.simulated, id)
	case a.opts.Revoked == nil:
		n.set(RuleRevocation, chain.StatusUnchecked, "no revocation list given (--revoked-jtis)")
	case a.opts.Revoked[id]:
		n.revoked = true
		n.set(RuleRevocation, chain.StatusFail, "revoked: %s", shortCID(n.tok.CID))
		n.find(RuleRevocation, chain.SeverityFail, "delegation %s is revoked", id)
	default:
		n.set(RuleRevocation, chain.StatusPass, "not on %s", a.opts.RevokedSource)
	}
}

// policy checks the invocation's arguments against every delegation's
// policy, in chain order.
func (a *analysis) policy(n *node) {
	if !n.readable() || n.tok.Args.Kind != KindMap {
		n.set(RulePolicy, chain.StatusSkipped, "the invocation's arguments could not be read")
		return
	}
	dlgs := a.links[:len(a.links)-1]
	if len(dlgs) == 0 {
		n.set(RulePolicy, chain.StatusPass, "no delegation, so no policy")
		return
	}
	for _, d := range dlgs {
		if !d.readable() || len(d.tok.Problems) > 0 {
			n.set(RulePolicy, chain.StatusSkipped, "proof %d is missing or unreadable, so not every policy is known", d.index)
			return
		}
	}
	ev := &evaluation{}
	total := 0
	var failed *policyCheck
	for _, d := range dlgs {
		for _, s := range d.tok.Policy {
			holds, err := s.eval(n.tok.Args, ev)
			if err != nil {
				n.set(RulePolicy, chain.StatusError, "%v", err)
				n.find(RulePolicy, chain.SeverityError, "%v", err)
				return
			}
			pc := policyCheck{link: d.index, stmt: s.String(), holds: holds}
			n.policyChecks = append(n.policyChecks, pc)
			total++
			if !holds && failed == nil {
				f := pc
				failed = &f
			}
		}
	}
	if failed != nil {
		n.set(RulePolicy, chain.StatusFail, "link %d's policy: %s does not hold", failed.link, failed.stmt)
		n.find(RulePolicy, chain.SeverityFail, "the arguments break link %d's policy: %s", failed.link, failed.stmt)
		return
	}
	n.set(RulePolicy, chain.StatusPass, "the arguments satisfy all %d statement(s)", total)
	if ev.unresolved {
		n.find(RulePolicy, chain.SeverityWarn, "a selector found nothing, so its statement counted as false; under not that holds, as the spec reads, though go-ucan refuses")
	}
	if ev.emptyAny {
		n.find(RulePolicy, chain.SeverityInfo, "any was asked of an empty collection and counted as false")
	}
}
