package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/kanywst/whosent/pkg/chain"
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
	case lookUnsure, lookAsserted:
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
	case lookAsserted:
		state += t.amber.Render("  only the issuer says so")
	case lookRevoked:
		state += t.coral.Render("  and everything below it")
	case lookBroken:
		state += t.coral.Render("  " + m.failingRules(l))
	case lookOK:
		state += t.mint.Render("  every check held")
	}
	out = append(out, m.clip(state, iw), "")
	if len(l.Checks) > 0 {
		out = append(out, m.section("CHECKS", iw))
		out = append(out, m.checkGrid(l, iw)...)
	}

	if fl := l.Findings; len(fl) > 0 {
		out = append(out, "", m.section("WHY", iw))
		for _, f := range fl {
			out = append(out, m.finding(f, iw)...)
		}
	}

	if m.sel > 0 && m.sel-1 < len(r.Hops) {
		out = append(out, "", m.section(fmt.Sprintf("VS LINK %d", m.sel-1), iw))
		out = append(out, m.hopLines(r.Hops[m.sel-1], iw)...)
	}
	for _, sec := range l.Sections {
		out = append(out, "", m.section(m.clean(sec.Title), iw))
		out = append(out, m.sectionLines(sec.Lines, iw)...)
	}
	return out
}

// sectionLines draws an adapter's lines.
func (m Model) sectionLines(lines []chain.Line, iw int) []string {
	var out []string
	for _, ln := range lines {
		style := m.toneOf(ln.Tone)
		if ln.Digest > 0 {
			style = m.digestStyle(ln.Digest - 1)
		}
		value := ln.Value
		if mark := m.markGlyph(ln.Mark); mark != "" {
			value = mark + " " + value
		}
		switch ln.Kind {
		case chain.LineKV:
			out = append(out, m.kv(ln.Key, value, style, iw)...)
		case chain.LineText:
			for _, w := range wrap(m.clean(value), max(iw-ln.Indent, 10)) {
				out = append(out, strings.Repeat(" ", ln.Indent)+style.Render(w))
			}
		case chain.LineChange:
			mark, cs := m.changeMark(ln.Change)
			out = append(out, m.diffLine(mark, cs, value, iw)...)
		case chain.LineJSON:
			out = append(out, m.jsonLines(ln.Value, iw)...)
		case chain.LineCode:
			for _, src := range strings.Split(ln.Value, "\n") {
				for _, w := range wrapStyledPlain(m.clean(src), iw) {
					out = append(out, style.Render(w))
				}
			}
		case chain.LineBlank:
			out = append(out, "")
		}
	}
	return out
}

func (m Model) markGlyph(k chain.Mark) string {
	switch k {
	case chain.MarkPass:
		return m.g.pass
	case chain.MarkFail:
		return m.g.fail
	case chain.MarkUnchecked:
		return m.g.unchecked
	case chain.MarkWarn:
		return m.g.warn
	}
	return ""
}

// checkGrid is every rule in three columns, each with a glyph that says
// passed, failed, could not run, or was not checked.
func (m Model) checkGrid(l chain.Link, iw int) []string {
	cols := 3
	if iw < 54 {
		cols = 2
	}
	cw := iw / cols
	var out []string
	line := ""
	for i, c := range l.Checks {
		glyph, style := m.statusMark(c)
		title := m.report.Format.Rule(c.Rule).Title
		cell := style.Render(glyph) + " " + m.t.text.Render(m.clean(c.Rule)) + " " + m.t.muted.Render(m.clean(title))
		line += m.fit(cell, cw)
		if (i+1)%cols == 0 || i == len(l.Checks)-1 {
			out = append(out, line)
			line = ""
		}
	}
	return out
}

func (m Model) statusMark(c chain.Check) (string, lipgloss.Style) {
	t, g := m.t, m.g
	if c.Simulated && c.Status.Blocking() {
		return g.simulated, t.coral
	}
	switch c.Status {
	case chain.StatusPass:
		return g.pass, t.mint
	case chain.StatusFail:
		return g.fail, t.coral.Bold(true)
	case chain.StatusError:
		return g.err, t.coral.Bold(true)
	case chain.StatusUnchecked:
		return g.unchecked, t.amber
	case chain.StatusSkipped:
		return g.skipped, t.slate
	}
	return g.na, t.slate
}

// hopLines is the diff between a link and its parent, written like a diff:
// = kept, ~ narrowed, - dropped, + added, and a widening called out.
func (m Model) hopLines(h chain.Hop, iw int) []string {
	t, g := m.t, m.g
	if !h.Evaluable {
		return []string{t.amber.Render(m.clip(g.unchecked+" cannot compare: one of the two links does not parse", iw))}
	}
	var out []string
	for _, c := range h.Changes {
		mark, style := m.changeMark(c.Kind)
		text := m.clean(c.Text)
		if c.Before != "" {
			text = m.clean(c.Before) + " " + g.arrow + " " + text
		}
		out = append(out, m.diffLine(mark, style, text, iw)...)
		for _, n := range c.Notes {
			for _, line := range wrap(m.clean(n), max(iw-6, 10)) {
				out = append(out, "    "+t.muted.Render(line))
			}
		}
	}
	if h.Verdict != "" {
		out = append(out, "")
		for _, line := range wrap(m.clean(h.Verdict), iw-2) {
			out = append(out, "  "+t.coral.Render(line))
		}
	}
	if len(out) == 0 {
		out = append(out, t.muted.Render("identical to the link above"))
	}
	return out
}

func (m Model) changeMark(k chain.ChangeKind) (string, lipgloss.Style) {
	t, g := m.t, m.g
	switch k {
	case chain.ChangeKept:
		return g.diffKept, t.muted
	case chain.ChangeNarrowed:
		return g.diffNarrowed, t.blue
	case chain.ChangeDropped:
		return g.diffDropped, t.slate
	case chain.ChangeAdded:
		return g.diffAdded, t.teal
	case chain.ChangeWidened:
		return g.diffWidened, t.coral.Bold(true)
	case chain.ChangeInfo:
		return g.info, t.muted
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

// rawLines is the link as it was signed, decoded: whatever sections the
// format has for it (digests, header, claims, source code).
func (m Model) rawLines(iw int) []string {
	l := m.report.Links[m.sel]
	if len(l.Raw) == 0 {
		return []string{m.t.muted.Render("nothing raw to show for this link")}
	}
	var out []string
	for i, sec := range l.Raw {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, m.section(m.clean(sec.Title), iw))
		out = append(out, m.sectionLines(sec.Lines, iw)...)
	}
	return out
}

func (m Model) digestStyle(i int) lipgloss.Style {
	if len(m.t.digests) == 0 {
		return m.t.bold
	}
	return m.t.digests[i%len(m.t.digests)]
}

// jsonLines draws an indented JSON document with keys and values in
// different colours.
func (m Model) jsonLines(doc string, iw int) []string {
	var out []string
	for _, line := range strings.Split(doc, "\n") {
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
