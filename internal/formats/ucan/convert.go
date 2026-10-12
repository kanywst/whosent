package ucan

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// chain describes the analysis in the neutral model.
func (a *analysis) chain(source, inputFormat string) *chain.Chain {
	c := &chain.Chain{
		Format:      format,
		Source:      source,
		InputFormat: "ucan (" + inputFormat + ")",
		At:          a.at,
		BreakAt:     -1,
		Simulated:   a.simulated,
	}
	if a.ordered == "issuer to audience" {
		c.Normalizations = []string{"ordered from the subject's delegation, issuer to audience"}
	}
	c.Root = a.root()
	for _, n := range a.links {
		l := chain.Link{
			Index:            n.index,
			From:             a.from(n),
			To:               a.to(n),
			Readable:         n.readable(),
			Revoked:          n.revoked,
			RevokedSimulated: n.revokedSim,
			Checks:           append([]chain.Check(nil), n.checks...),
			Findings:         append([]chain.Finding(nil), n.findings...),
			Sections:         a.sections(n),
			Raw:              a.raw(n),
		}
		if n.readable() && !n.inv {
			l.RevokeID = cidText(n.tok.CID)
		}
		if n.readable() {
			switch {
			case n.tok.Nbf != nil:
				l.IssuedAt = time.Unix(*n.tok.Nbf, 0).UTC()
			case n.tok.Iat != nil:
				l.IssuedAt = time.Unix(*n.tok.Iat, 0).UTC()
			}
			if n.tok.Exp != nil {
				l.ExpiresAt = time.Unix(*n.tok.Exp, 0).UTC()
				l.Remaining = l.ExpiresAt.Sub(a.at)
			}
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
		if c.BreakAt < 0 && (blocking || l.Revoked) {
			c.BreakAt = n.index
		}
		c.Links = append(c.Links, l)
	}
	if c.BreakAt >= 0 {
		for i := c.BreakAt + 1; i < len(c.Links); i++ {
			c.Links[i].Unreached = true
			c.Links[i].UnreachedBy = c.BreakAt
			if c.Links[c.BreakAt].Revoked {
				c.Links[i].Findings = append(c.Links[i].Findings, chain.Finding{
					Rule: RuleRevocation, Link: i, Hop: -1, Severity: chain.SeverityFail, Derived: true,
					Simulated: c.Links[c.BreakAt].RevokedSimulated,
					Detail:    fmt.Sprintf("refused with the chain: link %d is revoked, and every chain through it is invalid", c.BreakAt),
				})
			}
		}
	}
	for i := 1; i < len(a.links); i++ {
		c.Hops = append(c.Hops, a.hop(i))
	}
	c.ChainFindings = append(c.ChainFindings, a.chainFindings...)
	c.Matrix = a.matrix()
	c.CheckedAgainst, c.Missing = a.checkedAgainst()
	c.Ignored = a.opts.Ignored
	a.verdict(c)
	c.Summary = a.summary()
	c.Describe = strings.Join(a.summary(), ", ")
	c.Context = "at " + a.at.UTC().Format(time.RFC3339)
	c.Native = a.native()
	return c
}

func (a *analysis) verdict(c *chain.Chain) {
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
		c.IncompleteReason = a.incompleteReason()
	default:
		c.Verdict = chain.VerdictValid
		dlgs := len(a.links)
		if a.inv != nil {
			dlgs--
			c.Headline = fmt.Sprintf("%s may invoke %s on %s, through %d delegation%s. Every rule was checked.",
				a.name(a.inv.tok.Iss), a.inv.tok.Cmd, a.name(a.subject), dlgs, plural(dlgs))
			return
		}
		c.Headline = fmt.Sprintf("%s's authority reaches %s through %d delegation%s. Every rule was checked.",
			a.name(a.subject), c.Links[len(c.Links)-1].To, dlgs, plural(dlgs))
	}
}

// span is a whole number of seconds as people write it: "20m", "1h5m".
func span(secs int64) string {
	s := (time.Duration(secs) * time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func (a *analysis) incompleteReason() string {
	var parts []string
	for _, n := range a.links {
		if n.status(RuleSignature) == chain.StatusUnchecked {
			parts = append(parts, "a signature whosent cannot check")
			break
		}
	}
	if a.opts.Revoked == nil {
		parts = append(parts, "no revocation list")
	}
	if len(parts) == 0 {
		return "some rules could not be checked"
	}
	return strings.Join(parts, ", ")
}

// name is what the rail calls a DID: a demo's label, or the DID cut short.
func (a *analysis) name(did string) string {
	if did == "" {
		return "unknown"
	}
	if n, ok := a.opts.Names[principal(did)]; ok {
		return n
	}
	return shortDID(did)
}

// who names a DID in a finding: the full DID, after a demo's label when
// there is one.
func (a *analysis) who(did string) string {
	if n, ok := a.opts.Names[principal(did)]; ok {
		return n + " (" + shortDID(did) + ")"
	}
	return did
}

func (a *analysis) root() chain.Root {
	r := chain.Root{Kind: "did"}
	if a.subject == "" {
		r.Name = "unknown subject"
		r.Details = []string{"no token names one"}
		return r
	}
	r.Name = a.name(a.subject)
	if r.Name != shortDID(a.subject) {
		r.Details = append(r.Details, shortDID(a.subject))
	}
	return r
}

func (a *analysis) from(n *node) string {
	if !n.readable() {
		if p := a.prev(n); p != nil && p.readable() {
			return a.name(p.tok.Aud)
		}
		return "unknown"
	}
	return a.name(n.tok.Iss)
}

func (a *analysis) to(n *node) string {
	switch {
	case n.missing():
		return "missing proof"
	case !n.readable():
		return "unreadable token"
	case n.inv && n.tok.HasAud:
		return a.name(n.tok.Aud) + " (executor)"
	case n.inv:
		return a.name(a.subject) + " (executor)"
	}
	return a.name(n.tok.Aud)
}

func (a *analysis) kind(n *node) string {
	switch {
	case n.missing():
		return "a proof the invocation names, not supplied"
	case !n.readable():
		return "a token that does not decode"
	case n.inv:
		return "invocation"
	case n.tok.Sub == nil:
		return "powerline delegation (sub: null)"
	case n.index == 0:
		return "root delegation"
	}
	return "delegation"
}

func (a *analysis) sections(n *node) []chain.Section {
	info := chain.Section{Title: "TOKEN"}
	kv := func(k, v string, tone chain.Tone) {
		info.Lines = append(info.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
	}
	kv("kind", a.kind(n), chain.ToneText)
	if n.missing() {
		kv("cid", cidText(n.cid), chain.ToneMuted)
		return []chain.Section{info}
	}
	kv("cid", cidText(n.tok.CID), chain.ToneMuted)
	if !n.readable() {
		kv("error", n.tok.Err.Error(), chain.ToneBad)
		return []chain.Section{info}
	}
	t := n.tok
	kv("issuer", t.Iss, chain.ToneText)
	switch {
	case t.HasAud:
		kv("audience", t.Aud, chain.ToneText)
	case n.inv:
		kv("audience", "none: the subject executes", chain.ToneMuted)
	}
	switch {
	case t.Sub != nil:
		kv("subject", *t.Sub, chain.ToneRoot)
	case !n.inv:
		kv("subject", "null (powerline)", chain.ToneWarn)
	}
	kv("command", t.Cmd, chain.ToneStrong)
	if t.Nbf != nil {
		kv("not before", stamp(*t.Nbf), chain.ToneText)
	}
	if t.Iat != nil {
		kv("issued", stamp(*t.Iat), chain.ToneMuted)
	}
	if t.Exp != nil {
		kv("expires", stamp(*t.Exp), chain.ToneText)
	} else {
		kv("expires", "never (exp: null)", chain.ToneWarn)
	}
	if t.HeaderErr == nil {
		kv("signature", t.Header.String(), chain.ToneMuted)
	}
	if t.HasMeta && t.Meta.Kind == KindMap {
		var keys []string
		for _, e := range t.Meta.Map {
			keys = append(keys, e.Key)
		}
		kv("meta", strings.Join(keys, ", "), chain.ToneMuted)
	}
	out := []chain.Section{info}
	if n.inv {
		out = append(out, chain.Section{Title: "ARGUMENTS", Lines: []chain.Line{{Kind: chain.LineJSON, Value: dagJSON(t.Args, "  ")}}})
		if len(n.policyChecks) > 0 {
			pc := chain.Section{Title: "POLICY CHECK"}
			for _, p := range n.policyChecks {
				l := chain.Line{Kind: chain.LineText, Value: fmt.Sprintf("link %d  %s", p.link, p.stmt)}
				if p.holds {
					l.Mark, l.Tone = chain.MarkPass, chain.ToneGood
				} else {
					l.Mark, l.Tone = chain.MarkFail, chain.ToneBad
				}
				pc.Lines = append(pc.Lines, l)
			}
			out = append(out, pc)
		}
		return out
	}
	pol := chain.Section{Title: "POLICY"}
	if len(t.Policy) == 0 {
		pol.Lines = append(pol.Lines, chain.Line{Kind: chain.LineText, Value: "none: any arguments", Tone: chain.ToneMuted})
	}
	for _, s := range t.Policy {
		pol.Lines = append(pol.Lines, chain.Line{Kind: chain.LineCode, Value: s.String()})
	}
	return append(out, pol)
}

// linkOf is the index of the link whose token has cid, or -1.
func (a *analysis) linkOf(cid []byte) int {
	for _, n := range a.links {
		if n.tok != nil && string(n.tok.CID) == string(cid) {
			return n.index
		}
	}
	return -1
}

func (a *analysis) raw(n *node) []chain.Section {
	if n.missing() {
		return []chain.Section{{Title: "NOT SUPPLIED", Lines: []chain.Line{
			{Kind: chain.LineKV, Key: "cid", Value: cidText(n.cid)},
			{Kind: chain.LineKV, Key: "base32", Value: cidBase32(n.cid), Tone: chain.ToneMuted},
		}}}
	}
	t := n.tok
	sig := chain.Section{Title: "SIGNED"}
	sig.Lines = append(sig.Lines,
		chain.Line{Kind: chain.LineKV, Key: "cid", Value: cidText(t.CID), Digest: n.index + 1},
		chain.Line{Kind: chain.LineKV, Key: "base32", Value: cidBase32(t.CID), Tone: chain.ToneMuted},
	)
	if t.Err != nil {
		sig.Lines = append(sig.Lines, chain.Line{Kind: chain.LineKV, Key: "bytes", Value: hex.EncodeToString(t.Raw), Tone: chain.ToneMuted})
		return []chain.Section{sig}
	}
	sig.Lines = append(sig.Lines,
		chain.Line{Kind: chain.LineKV, Key: "signature", Value: hex.EncodeToString(t.Sig), Tone: chain.ToneMuted},
		chain.Line{Kind: chain.LineKV, Key: "varsig", Value: hex.EncodeToString(t.HeaderBytes), Tone: chain.ToneMuted},
	)
	out := []chain.Section{sig}
	if n.inv && len(t.Prf) > 0 {
		// Each proof is drawn in the colour of the link that is that
		// proof, so a proof that matches no link stands out.
		prf := chain.Section{Title: "PROOFS (prf)"}
		for _, c := range t.Prf {
			l := chain.Line{Kind: chain.LineKV, Key: "proof", Value: cidText(c)}
			if i := a.linkOf(c); i >= 0 {
				l.Digest = i + 1
			} else {
				l.Tone = chain.ToneBad
			}
			prf.Lines = append(prf.Lines, l)
		}
		out = append(out, prf)
	}
	return append(out, chain.Section{Title: "PAYLOAD (" + t.Tag + ")", Lines: []chain.Line{{Kind: chain.LineJSON, Value: dagJSON(t.Payload, "  ")}}})
}

func (a *analysis) hop(i int) chain.Hop {
	n, p := a.links[i], a.links[i-1]
	h := chain.Hop{Parent: i - 1, Child: i, Evaluable: n.readable() && p.readable()}
	if !h.Evaluable {
		return h
	}
	t, pt := n.tok, p.tok
	switch {
	case !covers(pt.Cmd, t.Cmd):
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeWidened, Before: pt.Cmd, Text: t.Cmd, Notes: []string{"not under the command above it"}})
	case pt.Cmd == t.Cmd:
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeKept, Text: "command " + t.Cmd})
	default:
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeNarrowed, Before: pt.Cmd, Text: t.Cmd})
	}
	if n.inv {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "invokes with " + dagJSON(t.Args, "")})
		for _, pc := range n.policyChecks {
			if !pc.holds {
				h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeWidened, Text: pc.stmt, Notes: []string{fmt.Sprintf("link %d's policy, which these arguments break", pc.link)}})
			}
		}
		return h
	}
	if t.Sub == nil {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "powerline: passes on every subject the delegate holds"})
	}
	for _, s := range t.Policy {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeNarrowed, Text: "adds " + s.String()})
	}
	switch {
	case t.Exp == nil && pt.Exp != nil:
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "never expires, but the chain still ends " + stamp(*pt.Exp)})
	case t.Exp != nil && pt.Exp != nil && *t.Exp < *pt.Exp:
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeNarrowed, Text: "expires " + span(*pt.Exp-*t.Exp) + " sooner"})
	case t.Exp != nil && pt.Exp != nil && *t.Exp > *pt.Exp:
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "outlives the delegation above, so the chain still ends " + stamp(*pt.Exp)})
	}
	return h
}

// matrix shows the command each link holds and the policies that pile up
// on it. A delegation narrows by naming a longer command or adding policy
// statements; policies never come off.
func (a *analysis) matrix() *chain.Matrix {
	n := len(a.links)
	if n == 0 || !a.links[0].readable() {
		return nil
	}
	m := &chain.Matrix{Title: "AUTHORITY", Scope: "the command, and the policies narrowing it"}
	rootCmd := a.links[0].tok.Cmd
	cmdRow := chain.Row{Label: "command " + rootCmd, Cells: make([]chain.Cell, n)}
	cmdText := chain.SummaryRow{Label: "command", Cells: make([]chain.SummaryCell, n)}
	polCount := chain.SummaryRow{Label: "policy", Cells: make([]chain.SummaryCell, n)}
	expires := chain.SummaryRow{Label: "expires", Cells: make([]chain.SummaryCell, n)}
	m.Retained = make([]int, n)
	total := 0
	for i, l := range a.links {
		if !l.readable() {
			cmdRow.Cells[i] = chain.Cell{Kind: chain.CellUnknown}
			cmdText.Cells[i] = chain.SummaryCell{Text: "?", Dim: true}
			polCount.Cells[i] = chain.SummaryCell{Text: "?", Dim: true}
			expires.Cells[i] = chain.SummaryCell{Text: "?", Dim: true}
			continue
		}
		cmd := l.tok.Cmd
		kind := chain.CellHeld
		changed := i == 0
		if i > 0 && a.links[i-1].readable() {
			prev := a.links[i-1].tok.Cmd
			switch {
			case !covers(prev, cmd):
				kind, changed = chain.CellWidened, true
			case prev != cmd:
				kind, changed = chain.CellNarrowed, true
			}
		}
		cmdRow.Cells[i] = chain.Cell{Kind: kind, Changed: changed}
		cmdRow.Lineage = append(cmdRow.Lineage, chain.LineageEntry{Link: i, Kind: kind, Changed: changed, Texts: []string{cmd}})
		if covers(rootCmd, cmd) {
			m.Retained[i] = 1
		}
		cmdText.Cells[i] = chain.SummaryCell{Text: cmd}
		if !l.inv {
			total += len(l.tok.Policy)
		}
		polCount.Cells[i] = chain.SummaryCell{Text: fmt.Sprint(total)}
		if l.tok.Exp != nil {
			expires.Cells[i] = chain.SummaryCell{Text: time.Unix(*l.tok.Exp, 0).UTC().Format("15:04")}
		} else {
			expires.Cells[i] = chain.SummaryCell{Text: "never", Infinite: true}
		}
	}
	m.Rows = append(m.Rows, cmdRow)
	m.RootRows = 1
	held := map[string]bool{}
	if a.inv != nil {
		for _, pc := range a.inv.policyChecks {
			held[fmt.Sprintf("%d %s", pc.link, pc.stmt)] = pc.holds
		}
	}
	for i, l := range a.links {
		if !l.readable() || l.inv {
			continue
		}
		for _, s := range l.tok.Policy {
			row := chain.Row{Label: s.label(), Cells: make([]chain.Cell, n)}
			for k := i; k < n; k++ {
				row.Cells[k] = chain.Cell{Kind: chain.CellNarrowed, Changed: k == i}
			}
			texts := []string{s.String()}
			if holds, ok := held[fmt.Sprintf("%d %s", i, s.String())]; ok {
				texts = append(texts, map[bool]string{true: "holds for the invocation's arguments", false: "fails for the invocation's arguments"}[holds])
			}
			row.Lineage = []chain.LineageEntry{{Link: i, Kind: chain.CellNarrowed, Changed: true, Texts: texts}}
			m.Rows = append(m.Rows, row)
		}
	}
	m.Extra = []chain.SummaryRow{cmdText, polCount, expires}
	return m
}

func (a *analysis) checkedAgainst() ([]chain.KV, []string) {
	var kv []chain.KV
	var missing []string
	kv = append(kv, chain.KV{Key: "keys", Value: "each issuer's did:key, read from the token"})
	if a.opts.Revoked == nil {
		kv = append(kv, chain.KV{Key: "revocation", Value: "no list given: revocation was not checked", Tone: chain.ToneWarn})
		missing = append(missing, "a revocation list (--revoked-jtis, delegation CIDs)")
	} else {
		kv = append(kv, chain.KV{Key: "revocation", Value: fmt.Sprintf("%s, %d revoked CID(s)", a.opts.RevokedSource, len(a.opts.Revoked))})
	}
	kv = append(kv, chain.KV{Key: "time", Value: fmt.Sprintf("%s, skew %s", a.at.UTC().Format("2006-01-02 15:04 UTC"), a.opts.Skew)})
	if from, until, ok := a.window(); ok {
		kv = append(kv, chain.KV{Key: "valid", Value: from + " to " + until})
	}
	return kv, missing
}

// window is the chain's validity interval: the latest nbf to the earliest
// exp.
func (a *analysis) window() (string, string, bool) {
	var nbf, exp *int64
	for _, n := range a.links {
		if !n.readable() {
			return "", "", false
		}
		if t := n.tok.Nbf; t != nil && (nbf == nil || *t > *nbf) {
			nbf = t
		}
		if t := n.tok.Exp; t != nil && (exp == nil || *t < *exp) {
			exp = t
		}
	}
	from, until := "any time", "never"
	if nbf != nil {
		from = stamp(*nbf)
	}
	if exp != nil {
		until = stamp(*exp)
	}
	return from, until, true
}

func (a *analysis) summary() []string {
	dlgs := len(a.links)
	if a.inv != nil {
		dlgs--
	}
	out := []string{fmt.Sprintf("%d delegation%s", dlgs, plural(dlgs))}
	if a.inv != nil && a.inv.readable() {
		out = append(out, "an invocation of "+a.inv.tok.Cmd)
	}
	return out
}

type nativeReport struct {
	Schema  string        `json:"schema"`
	Subject string        `json:"subject,omitempty"`
	Tokens  []nativeToken `json:"tokens"`
}

type nativeToken struct {
	Index   int      `json:"index"`
	Kind    string   `json:"kind"`
	CID     string   `json:"cid"`
	Iss     string   `json:"iss,omitempty"`
	Aud     string   `json:"aud,omitempty"`
	Sub     *string  `json:"sub,omitempty"`
	Cmd     string   `json:"cmd,omitempty"`
	Failed  []string `json:"failed,omitempty"`
	Missing bool     `json:"missing,omitempty"`
}

func (a *analysis) native() nativeReport {
	r := nativeReport{Schema: "whosent.ucan/v1", Subject: a.subject}
	for _, n := range a.links {
		nt := nativeToken{Index: n.index, Kind: a.kind(n), Missing: n.missing()}
		if n.missing() {
			nt.CID = cidText(n.cid)
		} else {
			nt.CID = cidText(n.tok.CID)
		}
		if n.readable() {
			nt.Iss, nt.Aud, nt.Sub, nt.Cmd = n.tok.Iss, n.tok.Aud, n.tok.Sub, n.tok.Cmd
		}
		for _, ch := range n.checks {
			if ch.Status.Blocking() {
				nt.Failed = append(nt.Failed, ch.Rule+": "+ch.Detail)
			}
		}
		r.Tokens = append(r.Tokens, nt)
	}
	return r
}
