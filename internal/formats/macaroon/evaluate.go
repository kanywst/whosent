package macaroon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	fly "github.com/superfly/macaroon"

	"github.com/kanywst/whosent/pkg/chain"
)

// node is one link: a macaroon being minted (a root or a discharge), or a
// caveat added to one.
type node struct {
	kind string // "mint", "first", "third"
	mac  int    // 0 the root, i+1 discharge i
	cav  int    // the caveat's index in its macaroon, -1 for a mint

	from, to string
	checks   [6]chain.Check
	findings []chain.Finding

	// cond is a first-party caveat's predicate, loc a third party's
	// location or a macaroon's.
	cond, loc string
	// end and start are a time caveat's bounds.
	end, start time.Time
	// flyCav is a Fly.io caveat, for ask to test a request against.
	flyCav fly.Caveat

	sections []chain.Section
	raw      []chain.Section
	hop      []chain.Change
}

var ruleOrder = [6]string{RuleFormat, RuleSignature, RuleDischarge, RuleBinding, RuleTime, RuleCaveat}

func newNode(kind string, mac, cav int) *node {
	n := &node{kind: kind, mac: mac, cav: cav}
	for i, r := range ruleOrder {
		n.checks[i] = chain.Check{Rule: r, Status: chain.StatusNotApplicable}
	}
	n.set(RuleFormat, chain.StatusPass, "decoded")
	return n
}

func (n *node) set(rule string, st chain.Status, detail string) {
	for i, r := range ruleOrder {
		if r == rule {
			n.checks[i] = chain.Check{Rule: rule, Status: st, Detail: detail}
		}
	}
}

func (n *node) fail(rule string, sev chain.Severity, detail string) {
	st := chain.StatusFail
	switch sev {
	case chain.SeverityError:
		st = chain.StatusError
	case chain.SeverityUnchecked:
		st = chain.StatusUnchecked
	}
	n.set(rule, st, detail)
	n.findings = append(n.findings, chain.Finding{Rule: rule, Hop: -1, Severity: sev, Detail: detail, Spec: format.Rule(rule).Spec})
}

// evaluation is one Evaluate's working state.
type evaluation struct {
	s     *session
	at    time.Time
	nodes []*node
	cf    []chain.Finding
	inc   *chain.Inconsistency
	// unknownPreds counts first-party caveats whosent could not judge;
	// flyRestrictions counts Fly caveats that restrict a request it
	// cannot see.
	unknownPreds, flyRestrictions int
	// flyRefused is set when a caveat refused the --fact request.
	flyRefused bool
}

func (s *session) evaluate(at time.Time) *chain.Chain {
	e := &evaluation{s: s, at: at}
	if s.b.dialect == "fly" {
		e.fly()
	} else {
		e.lib()
	}
	return e.chain()
}

// lib builds the links of a libmacaroons root and its discharges.
func (e *evaluation) lib() {
	root, ds := e.s.b.lib[0], e.s.b.lib[1:]
	v := verifyLib(root, ds, e.s.key)
	var walk func(m *lmac, idx int, r macResult, fromName string)
	walk = func(m *lmac, idx int, r macResult, fromName string) {
		mint := newNode("mint", idx, -1)
		mint.loc = m.location
		mint.from = fromName
		mint.to = short(label(m.id), 20)
		if idx > 0 {
			mint.to = "discharge from " + short(host(fromName), 14)
			mint.hop = []chain.Change{{Kind: chain.ChangeInfo, Text: "the discharge from " + fromName + " answers the caveat above"}}
		}
		e.sig(mint, idx, r)
		mint.sections = e.libMintSections(m, idx)
		mint.raw = libRaw(m)
		e.add(mint)
		for i, c := range m.caveats {
			cr := cavResult{discharge: -1}
			if i < len(r.caveats) {
				cr = r.caveats[i]
			}
			n := newNode("first", idx, i)
			n.from = e.nodes[len(e.nodes)-1].to
			e.sig(n, idx, r)
			if c.thirdParty() {
				n.kind = "third"
				n.loc = c.loc
				n.to = "via " + short(host(c.loc), 16)
				e.thirdParty(n, cr, label(c.id))
				n.sections = []chain.Section{{Title: "THIRD-PARTY CAVEAT", Lines: []chain.Line{
					kv("location", orUnnamed(c.loc), chain.ToneStrong),
					kv("caveat id", label(c.id), chain.ToneText),
					kv("vid", short(hex.EncodeToString(c.vid), 40), chain.ToneMuted),
					text("a service at the location answers it with a discharge macaroon; only the root key's holder can open the verification id", chain.ToneMuted),
				}}}
				n.hop = []chain.Change{{Kind: chain.ChangeNarrowed, Text: "requires a discharge from " + orUnnamed(c.loc)}}
			} else {
				cond := string(c.id)
				n.cond = cond
				n.to = predicateLabel(cond)
				e.firstParty(n, cond)
				n.sections = []chain.Section{{Title: "CAVEAT", Lines: []chain.Line{
					{Kind: chain.LineCode, Value: label(c.id)},
					text("a first-party predicate: the verifier must find it true for the request", chain.ToneMuted),
				}}}
				n.hop = []chain.Change{{Kind: chain.ChangeNarrowed, Text: "adds " + label(c.id)}}
			}
			n.raw = []chain.Section{{Title: "CAVEAT BYTES", Lines: []chain.Line{
				kv("id", hex.EncodeToString(c.id), chain.ToneText),
				kv("vid", hex.EncodeToString(c.vid), chain.ToneMuted),
				kv("location", c.loc, chain.ToneMuted),
			}}}
			e.add(n)
			if c.thirdParty() && cr.discharge >= 0 {
				d := ds[cr.discharge]
				walk(d, cr.discharge+1, v.discharges[cr.discharge], orUnnamed(c.loc))
			}
		}
	}
	walk(root, 0, v.root, orUnnamed(root.location))
	for _, i := range v.unused {
		e.cf = append(e.cf, chain.Finding{Rule: RuleDischarge, Link: -1, Hop: -1, Severity: chain.SeverityFail,
			Detail: fmt.Sprintf("discharge %d (%s) answers no caveat; go-macaroon refuses a request that carries one", i, short(label(ds[i].id), 30)),
			Spec:   format.Rule(RuleDischarge).Spec})
	}
	if e.s.key != nil {
		e.guard(v.ok, func() error { return referenceVerify(root, ds, e.s.key) }, "go-macaroon")
	}
}

// sig sets a link's signature check from its macaroon's result.
func (e *evaluation) sig(n *node, idx int, r macResult) {
	switch {
	case e.s.key == nil && n.kind == "mint" && idx == 0:
		n.fail(RuleSignature, chain.SeverityUnchecked, "no root key: only the holder of the root key can check an HMAC chain; give it with --root-key")
	case e.s.key == nil:
		n.set(RuleSignature, chain.StatusUnchecked, "no root key")
	case !r.sigChecked:
		n.set(RuleSignature, chain.StatusSkipped, "not checked: the key for this discharge did not open, so there is nothing to check it with")
	case r.sigOK && idx > 0:
		n.set(RuleSignature, chain.StatusPass, "the discharge's chain matches, bound to the root macaroon")
	case r.sigOK:
		n.set(RuleSignature, chain.StatusPass, "the HMAC chain matches under the root key, so no caveat was removed or changed")
	case n.kind == "mint":
		n.fail(RuleSignature, chain.SeverityFail, r.sigDetail)
	default:
		n.set(RuleSignature, chain.StatusFail, "the macaroon's signature does not match; see its first link")
	}
}

func (e *evaluation) thirdParty(n *node, cr cavResult, id string) {
	switch {
	case cr.discharge >= 0:
		n.set(RuleDischarge, chain.StatusPass, fmt.Sprintf("discharge %d answers it", cr.discharge))
	case cr.dischargeNote != "":
		n.fail(RuleDischarge, chain.SeverityFail, cr.dischargeNote)
	default:
		n.fail(RuleDischarge, chain.SeverityFail, fmt.Sprintf("no discharge macaroon with id %q came with the token, and a verifier refuses a third-party caveat without one", short(id, 40)))
	}
	switch {
	case e.s.key == nil:
		n.fail(RuleBinding, chain.SeverityUnchecked, "the caveat's key is sealed under the chain: opening it needs the root key")
	case !cr.keyChecked:
		n.set(RuleBinding, chain.StatusSkipped, "not checked: this macaroon's key did not open")
	case cr.keyOK:
		n.set(RuleBinding, chain.StatusPass, "the verification id opens under the chain, so the discharge's key is the one this caveat names")
	default:
		n.fail(RuleBinding, chain.SeverityFail, cr.keyDetail)
	}
}

func (e *evaluation) firstParty(n *node, cond string) {
	if end, ok := timeCaveat(cond); ok {
		n.end = end
		if holdsBefore(end, e.at, e.s.skew) {
			n.set(RuleTime, chain.StatusPass, "holds until "+end.UTC().Format(time.RFC3339))
		} else {
			n.fail(RuleTime, chain.SeverityFail, "expired at "+end.UTC().Format(time.RFC3339))
		}
		return
	}
	switch {
	case e.s.facts[cond]:
		n.set(RuleCaveat, chain.StatusPass, "satisfied: given with --fact")
	case e.s.factsGiven:
		n.fail(RuleCaveat, chain.SeverityFail, "no --fact satisfies it, so a verifier holding exactly those predicates refuses the macaroon")
	default:
		e.unknownPreds++
		n.fail(RuleCaveat, chain.SeverityUnchecked, "an application predicate whosent cannot judge: give it with --fact if your verifier satisfies it")
	}
}

func (e *evaluation) add(n *node) { e.nodes = append(e.nodes, n) }

// guard compares whosent's verdict on the signatures and discharges with
// the reference implementation's. A disagreement is reported and the
// stricter verdict stands.
func (e *evaluation) guard(ours bool, ref func() error, name string) {
	run := ref
	if e.s.refuse != nil {
		run = e.s.refuse
	}
	err := run()
	theirs := err == nil
	if ours == theirs {
		return
	}
	detail := fmt.Sprintf("whosent says the signatures and discharges %s; %s says %s", holdWord(ours), name, holdWord(theirs))
	if err != nil {
		detail += ": " + err.Error()
	}
	e.inc = &chain.Inconsistency{Banner: "INTERNAL INCONSISTENCY: whosent and " + name + " disagree", Detail: detail}
	if !theirs {
		e.cf = append(e.cf, chain.Finding{Rule: RuleSignature, Link: -1, Hop: -1, Severity: chain.SeverityFail,
			Detail: name + " refuses the token: " + err.Error(), Spec: format.Rule(RuleSignature).Spec})
	}
}

func holdWord(ok bool) string {
	if ok {
		return "hold"
	}
	return "do not hold"
}

// fly builds the links of a Fly.io permission token and its discharges.
func (e *evaluation) fly() {
	b := e.s.b.fly
	v := verifyFly(b, e.s.key)
	walked := make([]bool, len(b.discharges))
	var walk func(t *flyToken, idx int, r flyResult, fromName string)
	walk = func(t *flyToken, idx int, r flyResult, fromName string) {
		mint := newNode("mint", idx, -1)
		mint.loc = t.m.Location
		mint.from = fromName
		mint.to = short(label(t.m.Nonce.KID), 20)
		if idx > 0 {
			mint.to = "discharge from " + short(host(t.m.Location), 14)
			mint.hop = []chain.Change{{Kind: chain.ChangeInfo, Text: "the discharge from " + fromName + " answers the caveat above"}}
		}
		e.flySig(mint, idx, r)
		mint.sections = flyMintSections(t, idx)
		mint.raw = flyRaw(t)
		e.add(mint)
		for i, c := range t.m.UnsafeCaveats.Caveats {
			cr := flyCavResult{discharge: -1}
			if i < len(r.caveats) {
				cr = r.caveats[i]
			}
			n := newNode("first", idx, i)
			n.flyCav = c
			n.from = e.nodes[len(e.nodes)-1].to
			e.flySig(n, idx, r)
			body := caveatJSON(c)
			n.to = c.Name()
			n.sections = []chain.Section{{Title: "CAVEAT", Lines: []chain.Line{
				kv("type", c.Name(), chain.ToneStrong),
				{Kind: chain.LineJSON, Value: body},
			}}}
			n.raw = n.sections
			n.hop = []chain.Change{{Kind: chain.ChangeNarrowed, Text: "adds " + c.Name() + " " + compactJSON(body)}}
			switch cav := c.(type) {
			case *fly.Caveat3P:
				n.kind = "third"
				n.loc = cav.Location
				n.to = "via " + short(host(cav.Location), 16)
				e.flyThird(n, cr)
				n.hop = []chain.Change{{Kind: chain.ChangeNarrowed, Text: "requires a discharge from " + orUnnamed(cav.Location)}}
			case *fly.ValidityWindow:
				n.start, n.end = time.Unix(cav.NotBefore, 0), time.Unix(cav.NotAfter, 0)
				switch {
				case !holdsAfter(n.start, e.at, e.s.skew):
					n.fail(RuleTime, chain.SeverityFail, "not valid before "+n.start.UTC().Format(time.RFC3339))
				case !holdsBefore(n.end, e.at, e.s.skew):
					n.fail(RuleTime, chain.SeverityFail, "expired at "+n.end.UTC().Format(time.RFC3339))
				default:
					n.set(RuleTime, chain.StatusPass, "valid until "+n.end.UTC().Format(time.RFC3339))
				}
			case *fly.BindToParentToken:
				switch {
				case cr.boundChecked && cr.bound:
					n.set(RuleBinding, chain.StatusPass, "bound to a step of the permission token's chain")
				case cr.boundChecked:
					n.fail(RuleBinding, chain.SeverityFail, "bound to another token: no step of the permission token's chain matches")
				case e.s.key == nil:
					n.fail(RuleBinding, chain.SeverityUnchecked, "checking the binding needs the permission token's chain, which needs its key")
				default:
					n.set(RuleBinding, chain.StatusSkipped, "not checked: this discharge was not reached")
				}
				n.hop = []chain.Change{{Kind: chain.ChangeInfo, Text: "binds this discharge to the permission token"}}
			default:
				switch {
				case cr.attestation != "":
					n.fail(RuleFormat, chain.SeverityFail, cr.attestation)
				case fly.IsAttestation(c):
					n.set(RuleCaveat, chain.StatusNotApplicable, "an attestation: the third party's statement, not a restriction")
					n.hop = []chain.Change{{Kind: chain.ChangeInfo, Text: "attests " + c.Name()}}
				default:
					// A restriction holds only for a request: without one
					// it is unchecked, as Fly.io checks nothing without one.
					e.flyRestrictions++
					if e.s.tokenOnly {
						n.set(RuleCaveat, chain.StatusNotApplicable, "restricts requests; ask tests this one")
						break
					}
					if e.s.flyReq == nil {
						n.fail(RuleCaveat, chain.SeverityUnchecked, "restricts requests: give one with --fact org=ID --fact action=r")
						break
					}
					if perr := c.Prohibits(accessAt{Access: e.s.flyReq, at: e.at}); perr != nil {
						e.flyRefused = true
						n.fail(RuleCaveat, chain.SeverityFail, "refuses the request: "+perr.Error())
					} else {
						n.set(RuleCaveat, chain.StatusPass, "allows the request")
					}
				}
			}
			e.add(n)
			if j := cr.discharge; j >= 0 && !walked[j] {
				walked[j] = true
				walk(b.discharges[j], j+1, v.discharges[j], orUnnamed(n.loc))
			}
		}
	}
	walk(b.root, 0, v.root, orUnnamed(b.root.m.Location))
	if len(b.others) > 0 {
		e.cf = append(e.cf, chain.Finding{Rule: RuleFormat, Link: -1, Hop: -1, Severity: chain.SeverityInfo,
			Detail: fmt.Sprintf("the header carries %d more permission token(s); Fly.io accepts a request any of them allows, and whosent shows the first", len(b.others))})
	}
	if b.skipped > 0 {
		e.cf = append(e.cf, chain.Finding{Rule: RuleFormat, Link: -1, Hop: -1, Severity: chain.SeverityInfo,
			Detail: fmt.Sprintf("%d token(s) in the header are not macaroons (fo1_ OAuth) and were passed over, as superfly/macaroon does", b.skipped)})
	}
	if e.s.key != nil {
		e.guard(v.ok, func() error { return flyReference(b, e.s.key) }, "superfly/macaroon")
	}
	if e.s.flyReq != nil && e.flyRestrictions > 0 {
		e.flyRequestGuard(b, walked)
	}
}

// flyRequestGuard compares the caveat-by-caveat reading of the request with
// superfly/macaroon's own Validate over the same caveats; a disagreement is
// reported and the refusal stands.
func (e *evaluation) flyRequestGuard(b *flyBundle, walked []bool) {
	// Only the tokens the walk judged: a discharge nothing asks for was
	// never read as part of the chain.
	toks := []*flyToken{b.root}
	for j, d := range b.discharges {
		if walked[j] {
			toks = append(toks, d)
		}
	}
	var cavs []fly.Caveat
	for _, t := range toks {
		for _, c := range t.m.UnsafeCaveats.Caveats {
			switch c.(type) {
			case *fly.Caveat3P, *fly.BindToParentToken:
				continue
			}
			if fly.IsAttestation(c) {
				continue
			}
			if _, ok := c.(*fly.ValidityWindow); ok {
				continue
			}
			cavs = append(cavs, c)
		}
	}
	verr := fly.NewCaveatSet(cavs...).Validate(accessAt{Access: e.s.flyReq, at: e.at})
	if e.s.reqRefuse != nil {
		verr = e.s.reqRefuse()
	}
	if (verr != nil) != e.flyRefused {
		detail := fmt.Sprintf("Validate says %v about the request", verr)
		if e.inc != nil {
			// The signature guard's disagreement came first; keep it.
			e.inc.Detail += "; " + detail
		} else {
			e.inc = &chain.Inconsistency{
				Banner: "INTERNAL INCONSISTENCY: superfly/macaroon's Validate and the caveats one by one judge the request differently",
				Detail: detail,
			}
		}
		if verr != nil {
			e.cf = append(e.cf, chain.Finding{Rule: RuleCaveat, Link: -1, Hop: -1, Severity: chain.SeverityFail,
				Detail: "superfly/macaroon refuses the request: " + verr.Error()})
		}
	}
}

func (e *evaluation) flySig(n *node, idx int, r flyResult) {
	switch {
	case e.s.key == nil && n.kind == "mint" && idx == 0:
		n.fail(RuleSignature, chain.SeverityUnchecked, "no signing key: only Fly.io holds it; give it with --root-key")
		return
	case e.s.key == nil:
		n.set(RuleSignature, chain.StatusUnchecked, "no signing key")
		return
	}
	e.sig(n, idx, macResult{sigChecked: r.sigChecked, sigOK: r.sigOK, sigDetail: r.sigDetail})
}

func (e *evaluation) flyThird(n *node, cr flyCavResult) {
	if cr.discharge >= 0 {
		n.set(RuleDischarge, chain.StatusPass, fmt.Sprintf("discharge %d answers it", cr.discharge))
	} else {
		n.fail(RuleDischarge, chain.SeverityFail, "no discharge token for this caveat came with the header, and Fly.io refuses the token without one")
	}
	switch {
	case e.s.key == nil:
		n.fail(RuleBinding, chain.SeverityUnchecked, "the discharge key is sealed under the chain: opening it needs the signing key")
	case !cr.keyChecked:
		n.set(RuleBinding, chain.StatusSkipped, "not checked")
	case cr.keyOK:
		n.set(RuleBinding, chain.StatusPass, "the verifier key opens under the chain")
	default:
		n.fail(RuleBinding, chain.SeverityFail, cr.keyDetail)
	}
}

// chain turns the links into the neutral model.
func (e *evaluation) chain() *chain.Chain {
	b := e.s.b
	c := &chain.Chain{
		Format:         format,
		Source:         e.s.source,
		InputFormat:    "macaroon (" + b.encoding + ")",
		Normalizations: b.norms,
		At:             e.at,
		BreakAt:        -1,
		Ignored:        e.s.ignored,
		Inconsistency:  e.inc,
	}
	c.Root = e.root()
	var expires time.Time
	for i, n := range e.nodes {
		if !n.end.IsZero() && (expires.IsZero() || n.end.Before(expires)) {
			expires = n.end
		}
		l := chain.Link{Index: i, From: n.from, To: n.to, Readable: true,
			Checks: append([]chain.Check(nil), n.checks[:]...), Sections: n.sections, Raw: n.raw}
		for _, f := range n.findings {
			f.Link = i
			l.Findings = append(l.Findings, f)
		}
		if !expires.IsZero() {
			l.ExpiresAt = expires
			l.Remaining = expires.Sub(e.at)
		}
		blocking, unchecked := false, false
		for _, ch := range l.Checks {
			switch {
			case ch.Status.Blocking():
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
		switch {
		case blocking:
			l.State = chain.LinkBroken
		case unchecked:
			l.State = chain.LinkIncomplete
		}
		if blocking && c.BreakAt < 0 {
			c.BreakAt = i
		}
		c.Links = append(c.Links, l)
	}
	if c.BreakAt >= 0 {
		for i := c.BreakAt + 1; i < len(c.Links); i++ {
			c.Links[i].Unreached = true
			c.Links[i].UnreachedBy = c.BreakAt
		}
	}
	for i := 1; i < len(e.nodes); i++ {
		c.Hops = append(c.Hops, chain.Hop{Parent: i - 1, Child: i, Evaluable: true, Changes: e.nodes[i].hop})
	}
	c.ChainFindings = e.cf
	c.Matrix = e.matrix()
	c.CheckedAgainst, c.Missing = e.checkedAgainst()
	e.verdict(c)
	c.Context = "at " + e.at.UTC().Format(time.RFC3339)
	c.Describe = e.describe()
	if e.s.demo != "" {
		c.Context += ", " + e.s.demo
	}
	return c
}

func (e *evaluation) root() chain.Root {
	b := e.s.b
	if b.dialect == "fly" {
		m := b.fly.root.m
		return chain.Root{Name: orUnnamed(m.Location), Kind: "signing key",
			Details: []string{"key id " + short(label(m.Nonce.KID), 24), "Fly.io token"}}
	}
	m := b.lib[0]
	return chain.Root{Name: orUnnamed(m.location), Kind: "root key",
		Details: []string{"id " + short(label(m.id), 30), fmt.Sprintf("v%d", m.version)}}
}

func (e *evaluation) verdict(c *chain.Chain) {
	blocking, unchecked := false, false
	for _, l := range c.Links {
		for _, ch := range l.Checks {
			switch {
			case ch.Status.Blocking():
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
	}
	for _, f := range c.Findings() {
		switch {
		case f.Severity.Blocking() && !f.Derived:
			blocking = true
		case f.Severity == chain.SeverityUnchecked:
			unchecked = true
		}
	}
	switch {
	case blocking:
		c.Verdict = chain.VerdictInvalid
	case unchecked:
		c.Verdict = chain.VerdictIncomplete
		var why []string
		if e.s.key == nil {
			why = append(why, "no root key")
		}
		if e.unknownPreds > 0 {
			why = append(why, "no predicates")
		}
		if e.s.b.dialect == "fly" && e.flyRestrictions > 0 && e.s.flyReq == nil && !e.s.tokenOnly {
			why = append(why, "no request")
		}
		c.IncompleteReason = strings.Join(why, ", ")
	default:
		c.Verdict = chain.VerdictValid
		if e.s.b.dialect == "fly" {
			c.Headline = fmt.Sprintf("The Fly.io token holds, and its caveats allow %s.", strings.Join(e.s.flyReqText, ", "))
			if e.s.flyReq == nil {
				c.Headline = "The Fly.io token holds: its signature, every discharge and every caveat checked."
			}
			return
		}
		c.Headline = fmt.Sprintf("The root key's macaroon holds through %d link%s: its signature, every discharge and every caveat checked.", len(c.Links), plural(len(c.Links)))
	}
}

func (e *evaluation) checkedAgainst() ([]chain.KV, []string) {
	var kvs []chain.KV
	var missing []string
	switch {
	case e.s.key != nil && e.s.demo != "":
		kvs = append(kvs, chain.KV{Key: "root key", Value: "demo root key"})
	case e.s.key != nil && e.s.keySource != "":
		kvs = append(kvs, chain.KV{Key: "root key", Value: e.s.keySource})
	case e.s.key != nil:
		kvs = append(kvs, chain.KV{Key: "root key", Value: "given on the command line"})
	default:
		kvs = append(kvs, chain.KV{Key: "root key", Value: "none: the signature is unchecked", Tone: chain.ToneWarn})
		missing = append(missing, "root key (--root-key)")
	}
	if e.s.b.dialect != "fly" {
		if e.s.factsGiven {
			var fs []string
			for f := range e.s.facts {
				fs = append(fs, f)
			}
			sort.Strings(fs)
			kvs = append(kvs, chain.KV{Key: "predicates", Value: strings.Join(fs, "; ")})
		} else if e.unknownPreds > 0 {
			kvs = append(kvs, chain.KV{Key: "predicates", Value: "none given: application predicates are unchecked", Tone: chain.ToneWarn})
			missing = append(missing, "the predicates your verifier satisfies (--fact)")
		}
	}
	if e.flyRestrictions > 0 {
		if e.s.flyReq != nil {
			kvs = append(kvs, chain.KV{Key: "request", Value: strings.Join(e.s.flyReqText, ", ")})
		} else {
			kvs = append(kvs, chain.KV{Key: "request", Value: fmt.Sprintf("none given: %d caveat(s) restrict requests and are unchecked", e.flyRestrictions), Tone: chain.ToneWarn})
			missing = append(missing, "a request (--fact org=ID --fact action=r)")
		}
	}
	kvs = append(kvs, chain.KV{Key: "time", Value: fmt.Sprintf("%s, skew %s", e.at.UTC().Format("2006-01-02 15:04 UTC"), e.s.skew)})
	return kvs, missing
}

func (e *evaluation) describe() string {
	b := e.s.b
	if b.dialect == "fly" {
		return fmt.Sprintf("a Fly.io token: a permission token from %s and %d discharge(s)", orUnnamed(b.fly.root.m.Location), len(b.fly.discharges))
	}
	return fmt.Sprintf("a macaroon from %s and %d discharge(s), %s", orUnnamed(b.lib[0].location), len(b.lib)-1, b.encoding)
}

// matrix shows the identifier's authority and the caveats narrowing it:
// every caveat applies from the link that added it on.
func (e *evaluation) matrix() *chain.Matrix {
	n := len(e.nodes)
	if n == 0 {
		return nil
	}
	m := &chain.Matrix{Title: "AUTHORITY", Scope: "the macaroon's grant, and the caveats narrowing it", Retained: make([]int, n)}
	grant := chain.Row{Label: "grant", Cells: make([]chain.Cell, n),
		Lineage: []chain.LineageEntry{{Link: 0, Kind: chain.CellHeld, Texts: []string{"whatever the root key's issuer lets " + e.nodes[0].to + " do"}}}}
	for i := range grant.Cells {
		grant.Cells[i] = chain.Cell{Kind: chain.CellHeld}
	}
	m.Rows = append(m.Rows, grant)
	m.RootRows = 1
	count := chain.SummaryRow{Label: "caveats", Cells: make([]chain.SummaryCell, n)}
	total := 0
	for i, nd := range e.nodes {
		if nd.kind != "mint" {
			total++
			row := chain.Row{Label: nd.to, Cells: make([]chain.Cell, n),
				Lineage: []chain.LineageEntry{{Link: i, Kind: chain.CellNarrowed, Changed: true, Texts: []string{e.nodes[i].hop[0].Text}}}}
			for k := i; k < n; k++ {
				row.Cells[k] = chain.Cell{Kind: chain.CellNarrowed, Changed: k == i}
			}
			if len(m.Rows) == 1 {
				m.DefaultRow = 1
			}
			m.Rows = append(m.Rows, row)
		}
		m.Retained[i] = 1
		count.Cells[i] = chain.SummaryCell{Text: fmt.Sprint(total)}
	}
	m.Extra = []chain.SummaryRow{count}
	return m
}

func (e *evaluation) libMintSections(m *lmac, idx int) []chain.Section {
	title := "MACAROON"
	if idx > 0 {
		title = "DISCHARGE"
	}
	lines := []chain.Line{
		kv("location", orUnnamed(m.location), chain.ToneStrong),
		kv("identifier", label(m.id), chain.ToneText),
		kv("version", fmt.Sprintf("v%d", m.version), chain.ToneMuted),
		kv("caveats", fmt.Sprint(len(m.caveats)), chain.ToneMuted),
		kv("signature", short(hex.EncodeToString(m.sig[:]), 24), chain.ToneMuted),
	}
	if idx > 0 {
		lines = append(lines, text("a third party's answer to a caveat, bound to the root macaroon it travels with", chain.ToneMuted))
	}
	return []chain.Section{{Title: title, Lines: lines}}
}

func libRaw(m *lmac) []chain.Section {
	g, err := m.toGo()
	if err != nil {
		return nil
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil
	}
	return []chain.Section{{Title: "JSON (v2)", Lines: []chain.Line{{Kind: chain.LineJSON, Value: string(data)}}}}
}

func flyMintSections(t *flyToken, idx int) []chain.Section {
	title := "PERMISSION TOKEN"
	if idx > 0 {
		title = "DISCHARGE"
	}
	return []chain.Section{{Title: title, Lines: []chain.Line{
		kv("location", orUnnamed(t.m.Location), chain.ToneStrong),
		kv("key id", short(label(t.m.Nonce.KID), 40), chain.ToneText),
		kv("proof", fmt.Sprint(t.m.Nonce.Proof), chain.ToneMuted),
		kv("caveats", fmt.Sprint(len(t.m.UnsafeCaveats.Caveats)), chain.ToneMuted),
		kv("tail", short(hex.EncodeToString(t.m.Tail), 24), chain.ToneMuted),
	}}}
}

func flyRaw(t *flyToken) []chain.Section {
	data, err := json.MarshalIndent(t.m, "", "  ")
	if err != nil {
		return nil
	}
	return []chain.Section{{Title: "JSON", Lines: []chain.Line{{Kind: chain.LineJSON, Value: string(data)}}}}
}

func caveatJSON(c fly.Caveat) string {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "(cannot render: " + err.Error() + ")"
	}
	return string(data)
}

func compactJSON(s string) string {
	return short(strings.Join(strings.Fields(s), " "), 60)
}

func kv(k, v string, t chain.Tone) chain.Line {
	return chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: t}
}

func text(v string, t chain.Tone) chain.Line {
	return chain.Line{Kind: chain.LineText, Value: v, Tone: t}
}

// host is a location's host, the part worth a rail label.
func host(loc string) string {
	if u, err := url.Parse(loc); err == nil && u.Host != "" {
		return u.Host
	}
	return orUnnamed(loc)
}

// predicateLabel names a first-party caveat on the rail: a time
// convention by its end, anything else by its text.
func predicateLabel(cond string) string {
	if end, ok := timeCaveat(cond); ok {
		return "until " + end.UTC().Format("01-02 15:04")
	}
	return short(cond, 20)
}

func orUnnamed(loc string) string {
	if loc == "" {
		return "(no location)"
	}
	return loc
}

func short(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
