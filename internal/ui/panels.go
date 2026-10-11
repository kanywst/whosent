package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/kanywst/whosent/pkg/chain"
)

// renderPanels lays out the lower half: the authority matrix and findings
// beside the link inspector when the terminal is wide, or one panel at a
// time, switched with tab, when it is not.
func (m Model) renderPanels(W, H int) []string {
	if !m.wide() {
		if m.lower == panelLink || m.raw {
			return m.renderInspector(W, H)
		}
		return m.renderAuthority(W, H, true)
	}
	leftW := max(W*11/20, 60)
	rightW := W - leftW
	if m.report.Matrix == nil {
		// Nothing to tabulate: the findings have the whole column.
		return hjoin(m.renderFindings(leftW, H), m.renderInspector(rightW, H))
	}
	auth := append(m.matrixLines(leftW-4), m.lineage(leftW-4)...)
	authH := min(len(auth)+2, H*3/5)
	findH := H - authH
	var left []string
	if findH >= 5 {
		left = append(m.box(m.authorityTitle(), auth, leftW, authH, m.t.bright), m.renderFindings(leftW, findH)...)
	} else {
		left = m.renderAuthority(leftW, H, false)
	}
	return hjoin(left, m.renderInspector(rightW, H))
}

func (m Model) authorityTitle() string {
	mx := m.report.Matrix
	if mx == nil {
		return "AUTHORITY"
	}
	title := m.clean(mx.Title)
	if title == "" {
		title = "AUTHORITY"
	}
	if mx.Scope != "" {
		return title + " " + m.g.dot + " " + m.clean(mx.Scope)
	}
	return title
}

func (m Model) renderAuthority(W, H int, stacked bool) []string {
	if m.report.Matrix == nil {
		lines := append(append(m.findingLines(W-4), ""), m.inputLines(W-4)...)
		title := "FINDINGS"
		if stacked {
			title += "   " + m.g.dot + " tab: link"
		}
		return m.box(title, m.scrolled(lines, H-2), W, H, m.t.bright)
	}
	lines := m.matrixLines(W - 4)
	if stacked {
		// One panel has to carry the findings too, and they matter more
		// than the selected row's lineage, so they come first.
		lines = append(append(lines, m.section("FINDINGS", W-4)), m.findingLines(W-4)...)
		lines = append(append(lines, ""), m.lineage(W-4)...)
		lines = append(append(lines, ""), m.inputLines(W-4)...)
		title := m.authorityTitle() + "   " + m.g.dot + " tab: link"
		return m.box(title, m.scrolled(lines, H-2), W, H, m.t.bright)
	}
	lines = append(lines, m.lineage(W-4)...)
	return m.box(m.authorityTitle(), m.window(lines, H-2, m.authorityFocus()), W, H, m.t.bright)
}

// authorityFocus is the line the selected row is on, so a long matrix
// scrolls to keep it in view.
func (m Model) authorityFocus() int { return 1 + m.row }

// window returns h lines of lines, scrolled so that line focus is visible.
func (m Model) window(lines []string, h, focus int) []string {
	if len(lines) <= h || h <= 0 {
		return lines
	}
	start := clamp(focus-h/2, 0, len(lines)-h)
	return lines[start : start+h]
}

// matrixLines is the matrix: one row per grant the sponsor made (plus
// any authority that appeared from nowhere), one column per agent, and in
// each cell what that agent holds of it.
func (m Model) matrixLines(iw int) []string {
	r, t, g := m.report, m.t, m.g
	n := len(r.Links)
	fs := m.flow()
	if m.rows() == 0 {
		return []string{t.muted.Render("no capabilities to show")}
	}
	mx := r.Matrix

	// The label column is as wide as the longest label; the agent columns
	// share the rest, up to a width past which they only spread the
	// heatmap thin.
	longest := 0
	for _, row := range mx.Rows {
		longest = max(longest, width(m.clean(row.Label)))
	}
	nameW := 4
	for i := range r.Links {
		nameW = max(nameW, min(width(m.agentName(i)), 12))
	}
	labelW := min(longest+4, max(iw-n*(nameW+2), 12))
	colW := clamp((iw-labelW)/max(n, 1), 4, nameW+4)

	var out []string
	head := strings.Repeat(" ", labelW)
	for i := range r.Links {
		name := m.clip(m.agentName(i), colW-1)
		s := t.muted
		switch {
		case i == m.sel:
			s = t.bright.Underline(true)
		case m.void(i) && fs.settled:
			s = t.slate
		}
		head += center(s.Render(name), colW)
		head = m.fit(head, labelW+(i+1)*colW)
	}
	out = append(out, head)

	for ri, row := range mx.Rows {
		labelStyle := t.text
		prefix := "  "
		if row.Origin > 0 {
			labelStyle = t.coral
			prefix = t.coral.Render(g.widened[:len(g.widened)/2]) + " "
			if g.ascii {
				prefix = t.coral.Render("^") + " "
			}
		}
		label := prefix + labelStyle.Render(m.clip(m.clean(row.Label), labelW-3))
		line := m.fit(label, labelW)
		for i := range r.Links {
			line += center(m.cell(row, i, fs), colW)
			line = m.fit(line, labelW+(i+1)*colW)
		}
		if ri == m.row {
			line = m.highlightRow(row, labelW, colW, fs)
		}
		out = append(out, line)
	}

	out = append(out, "")
	anyVoid := false
	for i := range r.Links {
		anyVoid = anyVoid || (m.void(i) && fs.settled)
	}
	retained := func(i int) int {
		if i < len(mx.Retained) {
			return mx.Retained[i]
		}
		return 0
	}
	out = append(out, m.summaryRow("reach", labelW, colW, func(i int) (string, lipgloss.Style) {
		if mx.RootRows == 0 {
			return "-", t.slate
		}
		if r.Links[i].Asserted {
			// An asserted link's authority is not stated anywhere, so
			// "0/n" would claim it holds nothing.
			return "?", t.amber
		}
		if m.void(i) && fs.settled {
			return fmt.Sprintf("0/%d", mx.RootRows), t.coral
		}
		k := retained(i)
		s := t.teal
		if k < mx.RootRows {
			s = t.blue
		}
		if k == 0 {
			s = t.slate
		}
		return fmt.Sprintf("%d/%d", k, mx.RootRows), s
	}))
	if anyVoid {
		// What a void link claims, kept in sight but kept apart from what
		// it holds.
		out = append(out, m.summaryRow("claims", labelW, colW, func(i int) (string, lipgloss.Style) {
			if !m.void(i) || !fs.settled {
				return "", t.slate
			}
			return fmt.Sprintf("%d/%d", retained(i), mx.RootRows), t.slate
		}))
	}
	for _, extra := range mx.Extra {
		out = append(out, m.summaryRow(m.clean(extra.Label), labelW, colW, func(i int) (string, lipgloss.Style) {
			if i >= len(extra.Cells) {
				return "", t.slate
			}
			c := extra.Cells[i]
			text := m.clean(c.Text)
			if c.Infinite {
				text = "∞"
				if g.ascii {
					text = "inf"
				}
			}
			if c.Dim || (m.void(i) && fs.settled) {
				return text, t.slate
			}
			return text, t.muted
		}))
	}
	out = append(out, "")
	out = append(out, m.legend(iw), "")
	return out
}

// highlightRow redraws a row on the selection background, keeping each
// cell's own colour so the selection never hides what a cell says.
func (m Model) highlightRow(row chain.Row, labelW, colW int, fs flowState) string {
	t, g := m.t, m.g
	sel := t.selected
	labelStyle := t.bright
	prefix := "  "
	if row.Origin > 0 {
		labelStyle = t.coral.Bold(true)
		prefix = "^ "
		if !g.ascii {
			prefix = "▲ "
		}
	}
	line := sel.Render(m.fit(labelStyle.Render(prefix+m.clip(m.clean(row.Label), labelW-3)), labelW))
	for i := range m.report.Links {
		cell := m.cell(row, i, fs)
		pad := colW - width(cell)
		left := pad / 2
		line += sel.Render(strings.Repeat(" ", left)) + sel.Render(cell) + sel.Render(strings.Repeat(" ", pad-left))
	}
	return line
}

// void reports whether agent i holds nothing, whatever its link claims: its
// own link fails, or one above it does. Its column still shows the claims,
// dimmed, because what a broken link claims is evidence; it is never drawn
// as authority.
func (m Model) void(i int) bool {
	if m.report == nil || i >= len(m.report.Links) {
		return false
	}
	switch linkLook(m.report.Links[i]) {
	case lookBroken, lookRevoked, lookDead:
		return true
	}
	return false
}

// cell draws what agent i holds of a row.
func (m Model) cell(row chain.Row, i int, fs flowState) string {
	t, g := m.t, m.g
	if i >= len(row.Cells) {
		return ""
	}
	if !fs.lit[i] && (!fs.breaking || i != m.report.BreakAt) {
		return "  "
	}
	dead := m.void(i) && fs.settled
	c := row.Cells[i]
	switch c.Kind {
	case chain.CellHeld:
		if dead {
			return t.slate.Render(g.held)
		}
		return t.teal.Render(g.held)
	case chain.CellNarrowed:
		if dead {
			return t.slate.Render(g.narrowed)
		}
		return t.blue.Render(g.narrowed)
	case chain.CellWidened:
		return t.coral.Bold(true).Render(g.widened)
	case chain.CellUnknown:
		return t.amber.Render(g.unknown)
	case chain.CellOrphan:
		return t.amber.Render(g.orphan)
	}
	if c.Changed {
		return t.slate.Render(g.dropped)
	}
	return "  "
}

func (m Model) summaryRow(label string, labelW, colW int, f func(int) (string, lipgloss.Style)) string {
	line := m.fit("  "+m.t.muted.Render(label), labelW)
	for i := range m.report.Links {
		s, st := f(i)
		line += center(st.Render(m.clip(s, colW-1)), colW)
		line = m.fit(line, labelW+(i+1)*colW)
	}
	return line
}

func (m Model) legend(iw int) string {
	t, g := m.t, m.g
	parts := []string{
		t.teal.Render(g.held) + t.muted.Render(" held"),
		t.blue.Render(g.narrowed) + t.muted.Render(" narrowed"),
		t.slate.Render(g.dropped) + t.muted.Render(" dropped"),
		t.coral.Bold(true).Render(g.widened) + t.muted.Render(" widened"),
	}
	for _, row := range m.report.Matrix.Rows {
		for _, c := range row.Cells {
			if c.Kind == chain.CellUnknown || c.Kind == chain.CellOrphan {
				label := "unreadable"
				if l := m.report.Matrix.UnknownLabel; l != "" {
					label = m.clean(l)
				}
				parts = append(parts, t.amber.Render(g.unknown)+t.muted.Render(" "+label))
				return "  " + m.clip(strings.Join(parts, "   "), iw-2)
			}
		}
	}
	return "  " + m.clip(strings.Join(parts, "   "), iw-2)
}

// lineage follows the selected row down the chain: what each agent holds of
// it, conditions and all. It is the matrix's cell, read out in full.
func (m Model) lineage(iw int) []string {
	r, t, g := m.report, m.t, m.g
	if m.row >= m.rows() {
		return nil
	}
	row := r.Matrix.Rows[m.row]
	out := []string{t.muted.Render("  "+g.arrow+" ") + t.bright.Render(m.clip(m.clean(row.Label), iw-4))}
	nameW := 0
	for i := range r.Links {
		nameW = max(nameW, min(width(m.agentName(i)), 12))
	}
	for _, e := range row.Lineage {
		i := e.Link
		if i < row.Origin || i >= len(r.Links) {
			continue
		}
		lead := "    " + m.fit(t.muted.Render(m.agentName(i)), nameW) + "  "
		var text []string
		style := t.text
		switch e.Kind {
		case chain.CellAbsent:
			if !e.Changed {
				continue
			}
			text, style = []string{"dropped here"}, t.slate
		case chain.CellUnknown:
			text, style = []string{"link does not parse"}, t.amber
		default:
			for _, s := range e.Texts {
				text = append(text, m.clean(s))
			}
			switch e.Kind {
			case chain.CellNarrowed:
				style = t.blue
			case chain.CellWidened:
				style = t.coral
			case chain.CellHeld:
				style = t.teal
			}
			if m.void(i) && e.Kind != chain.CellWidened {
				// Claimed, not held: say so in words as well as in grey.
				style = t.slate
				for k := range text {
					text[k] += "  (claimed; holds nothing)"
				}
			}
		}
		for k, s := range text {
			for j, w := range wrap(s, max(iw-width(lead), 10)) {
				if k == 0 && j == 0 {
					out = append(out, lead+style.Render(w))
				} else {
					out = append(out, strings.Repeat(" ", width(lead))+style.Render(w))
				}
			}
		}
	}
	return out
}

// renderFindings lists everything the engine had to say, worst first.
func (m Model) renderFindings(W, H int) []string {
	c := m.report.Counts()
	title := "FINDINGS"
	var parts []string
	if n := c[chain.SeverityFail] + c[chain.SeverityError]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d failing", n))
	}
	if n := c[chain.SeverityUnchecked]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d unchecked", n))
	}
	if n := c[chain.SeverityWarn]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d warning%s", n, plural(n)))
	}
	if len(parts) > 0 {
		title += " " + m.g.dot + " " + strings.Join(parts, ", ")
	}
	lines := append(append(m.findingLines(W-4), ""), m.inputLines(W-4)...)
	return m.box(title, m.window(lines, H-2, 0), W, H, m.t.bright)
}

func (m Model) findingLines(iw int) []string {
	r, t := m.report, m.t
	all := r.Findings()
	var primary, derived []chain.Finding
	for _, f := range all {
		if f.Derived {
			derived = append(derived, f)
		} else {
			primary = append(primary, f)
		}
	}
	rank := func(s chain.Severity) int { return int(s) }
	// Stable by severity, keeping the engine's order within each.
	for i := 1; i < len(primary); i++ {
		for j := i; j > 0 && rank(primary[j].Severity) < rank(primary[j-1].Severity); j-- {
			primary[j], primary[j-1] = primary[j-1], primary[j]
		}
	}
	if len(primary) == 0 && len(derived) == 0 {
		return []string{t.mint.Render(m.g.pass + " nothing to report: every rule held for every link")}
	}
	var out []string
	for _, f := range append(primary, derived...) {
		out = append(out, m.finding(f, iw)...)
	}
	return out
}

// finding draws one finding with a hanging indent.
func (m Model) finding(f chain.Finding, iw int) []string {
	t := m.t
	glyph, style := m.severityMark(f.Severity)
	where := "chain"
	if f.Link >= 0 {
		where = fmt.Sprintf("link %d", f.Link)
	}
	head := m.clean(f.Rule)
	if head == "" {
		head = "input"
	}
	tag := head + " " + where
	detail := m.clean(f.Detail)
	if f.Simulated && !strings.Contains(detail, "simulated") {
		detail += " (simulated)"
	}
	textStyle := t.text
	if f.Derived {
		textStyle = t.slate
		style = t.slate
		tag += " (consequence)"
	}
	if f.Severity == chain.SeverityInfo {
		textStyle = t.muted
	}
	lead := style.Render(glyph) + " " + t.muted.Render(tag) + "  "
	const indent = 2
	first := iw - width(lead)
	var out []string
	if first < 12 {
		out = append(out, lead)
		for _, l := range wrap(detail, max(iw-indent, 10)) {
			out = append(out, strings.Repeat(" ", indent)+textStyle.Render(l))
		}
		return out
	}
	for i, l := range wrapHanging(detail, first, max(iw-indent, 10)) {
		if i == 0 {
			out = append(out, lead+textStyle.Render(l))
			continue
		}
		out = append(out, strings.Repeat(" ", indent)+textStyle.Render(l))
	}
	return out
}

func (m Model) severityMark(s chain.Severity) (string, lipgloss.Style) {
	t, g := m.t, m.g
	switch s {
	case chain.SeverityFail:
		return g.fail, t.coral
	case chain.SeverityError:
		return g.err, t.coral.Bold(true)
	case chain.SeverityUnchecked:
		return g.unchecked, t.amber
	case chain.SeverityWarn:
		return g.warn, t.amber
	}
	return g.info, t.muted
}

// inputLines says what the chain was checked against. A verdict is only as
// good as its inputs, and an absent input is exactly what makes a rule
// unchecked, so it is said in the same place as the findings.
func (m Model) inputLines(iw int) []string {
	r, g := m.report, m.g
	out := []string{m.section("CHECKED AGAINST", iw)}
	for _, kv := range r.CheckedAgainst {
		v := kv.Value
		if kv.Key == "time" && m.offset != 0 {
			v += " " + g.dot + " scrubbed " + m.timeLabel()
		}
		out = append(out, m.kv(kv.Key, v, m.toneOf(kv.Tone), iw)...)
	}
	for _, ig := range r.Ignored {
		out = append(out, m.kv("ignored", ig, m.toneOf(chain.ToneMuted), iw)...)
	}
	return out
}

// toneOf is the style a tone is drawn in.
func (m Model) toneOf(k chain.Tone) lipgloss.Style {
	t := m.t
	switch k {
	case chain.ToneMuted:
		return t.muted
	case chain.ToneStrong:
		return t.bright
	case chain.ToneRoot:
		return t.gold.UnsetBold()
	case chain.ToneGood:
		return t.mint
	case chain.ToneWarn:
		return t.amber
	case chain.ToneBad:
		return t.coral
	case chain.ToneBadStrong:
		return t.coral.Bold(true)
	case chain.ToneDim:
		return t.slate
	case chain.ToneAdded:
		return t.teal
	case chain.ToneNarrowed:
		return t.blue
	}
	return t.text
}
