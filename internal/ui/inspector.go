package ui

import (
	"encoding/json"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// renderInspector is the selected link in full: what it grants and to whom,
// every rule's outcome, why anything failed, and how it differs from the
// link above it. r swaps it for the raw assertion.
func (m Model) renderInspector(W, H int) []string {
	r := m.report
	if r == nil || len(r.Links) == 0 {
		return m.box("LINK", []string{m.t.muted.Render("the chain is empty")}, W, H, m.t.bright)
	}
	iw := W - 4
	var lines []string
	title := fmt.Sprintf("LINK %d %s %s %s %s", m.sel, m.g.dot, m.issuerName(m.sel), m.g.arrow, m.agentName(m.sel))
	if m.raw {
		title = fmt.Sprintf("RAW %s LINK %d", m.g.dot, m.sel)
		lines = m.rawLines(iw)
	} else {
		lines = m.linkLines(iw)
	}
	if !m.wide() {
		title += "   " + m.g.dot + " tab: authority"
	}
	view := m.scrolled(lines, H-2)
	accent := m.lookStyle(linkLook(r.Links[m.sel])).Bold(true)
	return m.box(title, view, W, H, accent)
}

// scrolled is h lines of lines from the scroll offset, with the last line
// saying how much more there is rather than letting the frame cut a
// sentence off silently.
func (m Model) scrolled(lines []string, h int) []string {
	if len(lines) <= h || h <= 0 {
		return lines
	}
	scroll := clamp(m.scroll, 0, len(lines)-h)
	view := append([]string(nil), lines[scroll:scroll+h]...)
	if more := len(lines) - scroll - h; more > 0 {
		view[h-1] = m.t.slate.Render(fmt.Sprintf("%s %d more  J/K scroll", m.g.ellipsis, more+1))
	}
	return view
}

func (m Model) lookBadge(k look) lipgloss.Style {
	switch k {
	case lookOK:
		return m.t.badgeValid
	case lookUnsure:
		return m.t.badgeIncomplete
	case lookDead:
		return m.t.badgeDead
	}
	return m.t.badgeInvalid
}

func (m Model) section(name string, iw int) string {
	t, g := m.t, m.g
	label := " " + name + " "
	rule := strings.Repeat(g.h, max(iw-width(label)-2, 0))
	return t.chrome.Render(g.h+g.h) + t.muted.Bold(true).Render(label) + t.chrome.Render(rule)
}

// kv is one aligned key and value, wrapped under itself.
func (m Model) kv(key, value string, style lipgloss.Style, iw int) []string {
	const kw = 12
	lines := wrap(m.clean(value), max(iw-kw, 10))
	if len(lines) == 0 {
		lines = []string{""}
	}
	out := []string{m.t.muted.Render(m.fit(key, kw)) + style.Render(lines[0])}
	for _, l := range lines[1:] {
		out = append(out, strings.Repeat(" ", kw)+style.Render(l))
	}
	return out
}

func (m Model) linkLines(iw int) []string {
	r, t, g := m.report, m.t, m.g
	l := r.Links[m.sel]
	k := linkLook(l)
	var out []string

	// The state, as a sentence, first.
	state := m.lookBadge(k).Render(" " + strings.ToUpper(m.status(l)) + " ")
	if fs := m.flow(); !fs.settled && !fs.lit[m.sel] {
		state = t.badgeDead.Render(" " + g.ellipsis + " TRACING ")
		k = -1
	}
	switch k {
	case lookDead:
		state += t.slate.Render(fmt.Sprintf("  link %d above is broken", l.UnreachedBy))
	case lookUnsure:
		state += t.amber.Render("  not everything was checked")
	case lookRevoked:
		state += t.coral.Render("  and everything below it")
	case lookBroken:
		state += t.coral.Render("  " + m.failingRules(l))
	case lookOK:
		state += t.mint.Render("  every check held")
	}
	out = append(out, m.clip(state, iw), "")
	out = append(out, m.section("CHECKS", iw))
	out = append(out, m.checkGrid(l, iw)...)

	if fl := l.Findings; len(fl) > 0 {
		out = append(out, "", m.section("WHY", iw))
		for _, f := range fl {
			out = append(out, m.finding(f, iw)...)
		}
	}

	if m.sel == 0 && r.Sponsor != nil {
		out = append(out, "", m.section("SPONSOR", iw))
		sp := r.Sponsor
		out = append(out, m.kv("human", sp.Subject, t.gold.UnsetBold(), iw)...)
		out = append(out, m.kv("at", sp.Issuer, t.text, iw)...)
		if len(sp.AuthenticationMethods) > 0 {
			out = append(out, m.kv("amr", strings.Join(sp.AuthenticationMethods, ", "), t.text, iw)...)
		}
	}

	if m.sel > 0 && m.sel-1 < len(r.Hops) {
		out = append(out, "", m.section(fmt.Sprintf("VS LINK %d", m.sel-1), iw))
		out = append(out, m.hopLines(r.Hops[m.sel-1], iw)...)
	} else if m.sel == 0 && l.Claims != nil {
		out = append(out, "", m.section("GRANTS", iw))
		for _, c := range l.Claims.Mandatum.Capabilities {
			s := m.capLabel(c)
			if conds := diagnose.CondLabels(c); len(conds) > 0 {
				s += "  " + strings.Join(conds, "; ")
			}
			out = append(out, m.diffLine(g.diffAdded, t.teal, s, iw)...)
		}
	}

	out = append(out, "", m.section("ASSERTION", iw))
	if c := l.Claims; c != nil {
		out = append(out, m.kv("grants to", c.Subject, t.text, iw)...)
		out = append(out, m.kv("issued by", c.Issuer, t.text, iw)...)
		out = append(out, m.kv("audience", c.Audience, t.text, iw)...)
		rem, alive := remaining(l)
		exp := clockTime(l.ExpiresAt) + "  (" + rem + ")"
		es := t.text
		if !alive {
			es = t.coral
		}
		out = append(out, m.kv("expires", exp, es, iw)...)
		d := c.Mandatum.MaxDepth
		dl := fmt.Sprintf("%d more hop%s", d, plural(d))
		if d == 0 {
			dl = "no further: may act, may not delegate"
		}
		out = append(out, m.kv("delegates", dl, t.text, iw)...)
		if s := c.Mandatum.Sequence; s != nil {
			var ids []string
			for _, con := range s.Constraints {
				ids = append(ids, con.ID)
			}
			b := "unlimited"
			if s.MaxInvocations > 0 {
				b = fmt.Sprintf("%d invocations", s.MaxInvocations)
			}
			if len(ids) > 0 {
				b += "; " + strings.Join(ids, ", ")
			}
			out = append(out, m.kv("sequence", b, t.text, iw)...)
		}
		out = append(out, m.kv("jti", c.ID, t.muted, iw)...)
		if l.KeySource != "" {
			out = append(out, m.kv("key", l.KeySource, t.muted, iw)...)
		}
	} else {
		out = append(out, t.coral.Render(m.clip(g.fail+" this link does not parse", iw)))
		for _, line := range wrap(m.clean(l.ParseError), iw-2) {
			out = append(out, "  "+t.muted.Render(line))
		}
	}

	return out
}

// checkGrid is V1 to V9 in three columns, each with a glyph that says
// passed, failed, could not run, or was not checked.
func (m Model) checkGrid(l diagnose.Link, iw int) []string {
	cols := 3
	if iw < 54 {
		cols = 2
	}
	cw := iw / cols
	var out []string
	line := ""
	for i, c := range l.Checks {
		glyph, style := m.statusMark(c)
		cell := style.Render(glyph) + " " + m.t.text.Render(string(c.Rule)) + " " + m.t.muted.Render(c.Rule.Title())
		line += m.fit(cell, cw)
		if (i+1)%cols == 0 || i == len(l.Checks)-1 {
			out = append(out, line)
			line = ""
		}
	}
	return out
}

func (m Model) statusMark(c diagnose.Check) (string, lipgloss.Style) {
	t, g := m.t, m.g
	if c.Simulated && c.Status.Blocking() {
		return g.simulated, t.coral
	}
	switch c.Status {
	case diagnose.StatusPass:
		return g.pass, t.mint
	case diagnose.StatusFail:
		return g.fail, t.coral.Bold(true)
	case diagnose.StatusError:
		return g.err, t.coral.Bold(true)
	case diagnose.StatusUnchecked:
		return g.unchecked, t.amber
	case diagnose.StatusSkipped:
		return g.skipped, t.slate
	}
	return g.na, t.slate
}

// hopLines is the diff between a link and its parent, written like a diff:
// = kept, ~ narrowed, - dropped, + added, and a widening called out.
func (m Model) hopLines(h diagnose.Hop, iw int) []string {
	t, g := m.t, m.g
	if !h.Evaluable {
		return []string{t.amber.Render(m.clip(g.unchecked+" cannot compare: one of the two links does not parse", iw))}
	}
	var out []string
	for _, c := range h.Capabilities {
		mark, style := m.changeMark(c.Kind)
		out = append(out, m.diffLine(mark, style, m.capChangeText(c), iw)...)
		for _, n := range c.Notes {
			for _, line := range wrap(m.clean(n), max(iw-6, 10)) {
				out = append(out, "    "+t.muted.Render(line))
			}
		}
	}
	for _, v := range []diagnose.ValueChange{h.Expiry, h.MaxDepth, h.Audience} {
		if v.Text == "" || v.Kind == diagnose.ChangeKept && v.Text == "" {
			continue
		}
		mark, style := m.changeMark(v.Kind)
		out = append(out, m.diffLine(mark, style, v.Text, iw)...)
	}
	if s := h.Sequence; s.Text != "" || len(s.Constraints) > 0 || s.Budget.Text != "" {
		if s.Budget.Text != "" {
			mark, style := m.changeMark(s.Budget.Kind)
			out = append(out, m.diffLine(mark, style, s.Budget.Text, iw)...)
		}
		for _, c := range s.Constraints {
			mark, style := m.changeMark(c.Kind)
			out = append(out, m.diffLine(mark, style, c.Text, iw)...)
		}
		if s.Text != "" && s.Budget.Text == "" && len(s.Constraints) == 0 {
			mark, style := m.changeMark(s.Kind)
			out = append(out, m.diffLine(mark, style, s.Text, iw)...)
		}
	}
	// The structural checks between the two, only when one failed: when
	// they hold, saying so adds nothing the grid did not.
	for _, c := range []diagnose.Check{h.Commitment, h.DepthStep, h.Custody, h.Sponsor} {
		if c.Status.Blocking() {
			out = append(out, m.diffLine(g.diffWidened, t.coral, string(c.Rule)+" "+c.Detail, iw)...)
		}
	}
	if h.Verdict != "" && !m.saidAlready(h.Child, h.Verdict) {
		out = append(out, "")
		for _, line := range wrap(m.clean("mandatum: "+h.Verdict), iw-2) {
			out = append(out, "  "+t.coral.Render(line))
		}
	}
	if len(out) == 0 {
		out = append(out, t.muted.Render("identical to the link above"))
	}
	return out
}

// capChangeText says what happened to one capability across a hop, in the
// same labels the matrix uses. The engine's own sentence is the fallback
// when either side is missing.
func (m Model) capChangeText(c diagnose.CapChange) string {
	g := m.g
	switch {
	case c.Kind == diagnose.ChangeKept && c.Child != nil:
		return m.capLabel(*c.Child)
	case c.Kind == diagnose.ChangeNarrowed && c.Parent != nil && c.Child != nil:
		p, ch := m.capLabel(*c.Parent), m.capLabel(*c.Child)
		if p == ch {
			return p + "  narrowed"
		}
		return p + " " + g.arrow + " " + ch
	case c.Kind == diagnose.ChangeDropped && c.Parent != nil:
		return m.capLabel(*c.Parent) + "  dropped"
	case c.Kind == diagnose.ChangeWidened && c.Child != nil:
		return m.capLabel(*c.Child) + "  not covered by the parent's grant"
	case c.Kind == diagnose.ChangeAdded && c.Child != nil:
		return m.capLabel(*c.Child)
	}
	return c.Text
}

// saidAlready reports whether link i already has a finding carrying text,
// so the same sentence is not printed twice in one panel.
func (m Model) saidAlready(i int, text string) bool {
	if i < 0 || i >= len(m.report.Links) {
		return false
	}
	for _, f := range m.report.Links[i].Findings {
		if strings.Contains(f.Detail, text) {
			return true
		}
	}
	return false
}

func (m Model) changeMark(k diagnose.ChangeKind) (string, lipgloss.Style) {
	t, g := m.t, m.g
	switch k {
	case diagnose.ChangeKept:
		return g.diffKept, t.muted
	case diagnose.ChangeNarrowed:
		return g.diffNarrowed, t.blue
	case diagnose.ChangeDropped:
		return g.diffDropped, t.slate
	case diagnose.ChangeAdded:
		return g.diffAdded, t.teal
	case diagnose.ChangeWidened:
		return g.diffWidened, t.coral.Bold(true)
	}
	return "?", t.amber
}

func (m Model) diffLine(mark string, style lipgloss.Style, text string, iw int) []string {
	lines := wrap(m.clean(text), max(iw-2, 10))
	var out []string
	for i, l := range lines {
		lead := style.Render(mark) + " "
		if i > 0 {
			lead = "  "
		}
		out = append(out, lead+style.UnsetBold().Render(l))
	}
	return out
}

// rawLines is the assertion as it was signed: header, claims, and the two
// digests that tie it into the chain. Each link's digest has its own colour,
// and a parent commitment takes the colour of the link it names, so a
// spliced link is the one whose colour matches nothing above it.
func (m Model) rawLines(iw int) []string {
	r, t, g := m.report, m.t, m.g
	l := r.Links[m.sel]
	var out []string
	out = append(out, m.section("DIGESTS", iw))
	out = append(out, m.kv("this link", l.Digest, m.digestStyle(m.sel), iw)...)
	if c := l.Claims; c != nil && c.Mandatum.Parent != "" {
		match := -1
		for j := 0; j < m.sel; j++ {
			if r.Links[j].Digest == c.Mandatum.Parent {
				match = j
			}
		}
		if match >= 0 {
			out = append(out, m.kv("parent", c.Mandatum.Parent, m.digestStyle(match), iw)...)
			out = append(out, m.kv("", fmt.Sprintf("%s link %d", g.pass, match), m.digestStyle(match).UnsetBold(), iw)...)
		} else {
			out = append(out, m.kv("parent", c.Mandatum.Parent, t.coral.Bold(true), iw)...)
			out = append(out, m.kv("", g.fail+" matches no link above: this link was issued against another chain", t.coral, iw)...)
		}
	} else if l.Claims != nil {
		out = append(out, m.kv("parent", "none: this is the sponsor's grant", t.muted, iw)...)
	}

	out = append(out, "", m.section("HEADER", iw))
	if l.Header != nil {
		out = append(out, m.jsonLines(l.Header, iw)...)
	}
	if l.Claims != nil {
		out = append(out, "", m.section("CLAIMS", iw))
		out = append(out, m.jsonLines(l.Claims, iw)...)
	} else if l.Untrusted != nil {
		out = append(out, "", m.section("CLAIMS (UNTRUSTED: did not parse strictly)", iw))
		out = append(out, m.jsonLines(l.Untrusted, iw)...)
	}
	return out
}

func (m Model) digestStyle(i int) lipgloss.Style {
	if len(m.t.digests) == 0 {
		return m.t.bold
	}
	return m.t.digests[i%len(m.t.digests)]
}

// jsonLines pretty-prints v with keys and values in different colours.
func (m Model) jsonLines(v any, iw int) []string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []string{m.t.coral.Render(err.Error())}
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = m.clean(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := line[indent:]
		styled := m.t.text.Render(body)
		if k, rest, ok := strings.Cut(body, `": `); ok && strings.HasPrefix(k, `"`) {
			styled = m.t.blue.Render(k+`"`) + m.t.muted.Render(":") + " " + m.t.text.Render(rest)
		}
		pad := strings.Repeat(" ", indent)
		if width(pad+styled) <= iw {
			out = append(out, pad+styled)
			continue
		}
		// Too long for the panel: give up the key colour and wrap the line
		// whole, so nothing (a digest, say) is ever cut off.
		for _, w := range wrapStyledPlain(line, iw) {
			out = append(out, m.t.text.Render(w))
		}
	}
	return out
}

// wrapStyledPlain splits a long JSON line into its continuation pieces,
// indented under the value, so a long digest is never cut off.
func wrapStyledPlain(s string, n int) []string {
	if width(s) <= n || n < 10 {
		return []string{s}
	}
	var out []string
	r := []rune(s)
	first := true
	for len(r) > 0 {
		k := min(len(r), n)
		if !first {
			k = min(len(r), n-4)
		}
		piece := string(r[:k])
		if !first {
			piece = "    " + piece
		}
		out = append(out, piece)
		r = r[k:]
		first = false
	}
	return out
}
