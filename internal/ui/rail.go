package ui

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/kanywst/whosent/pkg/chain"
)

// The rail is the chain drawn as what it is: a human at the left, the agents
// authority was handed to, and between each pair the link that handed it
// over. A link is an arrow, so a broken link is a broken arrow, and every
// agent past it is drawn hollow and grey: no authority reaches them. That
// one picture answers most of what anyone opens the tool to ask.

// look is how a link, and the agent it grants to, is drawn.
type look int

const (
	lookOK      look = iota // every rule checked and held
	lookUnsure              // nothing failed, something was not checked
	lookBroken              // a rule failed or could not be evaluated
	lookRevoked             // revoked, or its revocation is being simulated
	lookDead                // below a break: no authority reaches it
	// lookAsserted: nothing failed, but the link's place in the chain is
	// only someone else's say-so. It is drawn like an unverified link,
	// amber and dashed, and never like a verified one.
	lookAsserted
)

func linkLook(l chain.Link) look {
	switch {
	case l.Unreached:
		return lookDead
	case l.Revoked || l.RevokedSimulated:
		return lookRevoked
	case l.State == chain.LinkBroken:
		return lookBroken
	case l.Asserted:
		return lookAsserted
	case l.State == chain.LinkIncomplete:
		return lookUnsure
	}
	return lookOK
}

func (m Model) lookStyle(k look) lipgloss.Style {
	switch k {
	case lookOK:
		return m.t.teal
	case lookUnsure, lookAsserted:
		return m.t.amber
	case lookBroken, lookRevoked:
		return m.t.coral
	}
	return m.t.slate
}

func (m Model) agentGlyph(k look) string {
	switch k {
	case lookOK:
		return m.g.agent
	case lookUnsure, lookAsserted:
		return m.g.hollow
	case lookBroken:
		return m.g.broken
	case lookRevoked:
		return m.g.revoked
	}
	return m.g.dead
}

// status is the one-word state of an agent, under its name.
func (m Model) status(l chain.Link) string {
	g := m.g
	switch linkLook(l) {
	case lookOK:
		return g.pass + " verified"
	case lookUnsure:
		return g.unchecked + " unverified"
	case lookAsserted:
		return g.unchecked + " asserted"
	case lookBroken:
		return g.fail + " broken"
	case lookRevoked:
		if l.RevokedSimulated {
			return g.revoked + " revoked (sim)"
		}
		return g.revoked + " revoked"
	}
	return g.dead + " unreached"
}

// ruleMarks lists the rules a link fails, or failing that the ones left
// unchecked, compactly: "✗ V4 V5".
func (m Model) ruleMarks(l chain.Link) (string, lipgloss.Style) {
	var bad, unsure []string
	for _, c := range l.Checks {
		switch {
		case c.Status.Blocking():
			bad = append(bad, m.clean(c.Rule))
		case c.Status == chain.StatusUnchecked:
			unsure = append(unsure, m.clean(c.Rule))
		}
	}
	switch {
	case len(bad) > 0:
		return m.g.fail + " " + strings.Join(bad, " "), m.t.coral
	case len(unsure) > 0:
		return m.g.unchecked + " " + strings.Join(unsure, " "), m.t.amber
	}
	return m.g.pass, m.t.mint
}

// vitals is an agent's remaining delegation depth as pips, and its time left.
func (m Model) vitals(l chain.Link) string {
	g, t := m.g, m.t
	if !l.Readable {
		return t.slate.Render("unreadable")
	}
	var parts []string
	if d := l.Depth; d != nil {
		left := min(d.Left, d.Total)
		parts = append(parts, t.gold.UnsetBold().Render(strings.Repeat(g.pipOn, max(left, 0)))+
			t.slate.Render(strings.Repeat(g.pipOff, max(d.Total-left, 0))))
	}
	switch {
	case l.ExpiresAt.IsZero():
	case l.Remaining <= 0:
		parts = append(parts, t.coral.Render("expired"))
	default:
		parts = append(parts, t.muted.Render(chain.Human(l.Remaining)))
	}
	return strings.Join(parts, " ")
}

// renderRail picks the horizontal rail when the whole chain fits across the
// screen, and a vertical one otherwise.
func (m Model) renderRail(W, H int) []string {
	r := m.report
	if r == nil {
		return nil
	}
	if lines, ok := m.railAcross(W); ok {
		return lines
	}
	return m.railDown(W, H)
}

// railAcross lays the chain out left to right, four rows deep. Each column
// is as wide as what it says, and the arrows share whatever is left, so a
// short name never leaves a hole between itself and its arrow.
func (m Model) railAcross(W int) ([]string, bool) {
	r := m.report
	n := len(r.Links)
	if n == 0 {
		return nil, false
	}
	avail := W - 4
	widths := make([]int, n+1)
	natural := func(capW int) int {
		sum := 0
		for j := range widths {
			widths[j] = min(m.nodeWidth(j), capW)
			sum += widths[j]
		}
		return sum
	}
	const minEdge, maxEdge = 9, 20
	sum := natural(24)
	for capW := 23; avail-sum < n*minEdge && capW >= 12; capW-- {
		sum = natural(capW)
	}
	if avail-sum < n*minEdge {
		return nil, false
	}
	ew := min((avail-sum)/n, maxEdge)
	margin := 2 + (avail-sum-n*ew)/2

	fs := m.flow()
	rows := make([]string, 4)
	for j := 0; j <= n; j++ {
		node := m.nodeAcross(j, widths[j], fs)
		for k := range rows {
			rows[k] += node[k]
		}
		if j < n {
			edge := m.edgeAcross(j, ew, fs)
			for k := range rows {
				rows[k] += edge[k]
			}
		}
	}
	pad := strings.Repeat(" ", margin)
	for k := range rows {
		rows[k] = m.fit(pad+rows[k], W)
	}
	return rows, true
}

// nodeWidth is how wide node j's column wants to be.
func (m Model) nodeWidth(j int) int {
	r := m.report
	if j == 0 {
		w := max(width(m.sponsorName())+2, width(m.rootRole()))
		for _, d := range r.Root.Details {
			w = max(w, width(m.clean(d)))
		}
		return w
	}
	l := r.Links[j-1]
	return max(width(m.agentName(j-1))+2, width(m.status(l)), width(m.vitals(l)), 10)
}

// nodeAcross is one agent's column: name, state, vitals, life bar. Node 0 is
// the sponsor; node j is the subject of link j-1.
func (m Model) nodeAcross(j, cw int, fs flowState) [4]string {
	t, g := m.t, m.g
	var out [4]string
	if j == 0 {
		r := m.report
		out[0] = m.fit(t.gold.Render(g.sponsor+" "+m.clip(m.sponsorName(), cw-2)), cw)
		out[1] = m.fit(t.muted.Render(m.rootRole()), cw)
		out[2], out[3] = m.fit("", cw), m.fit("", cw)
		for k, d := range r.Root.Details {
			if k < 2 {
				out[2+k] = m.fit(t.slate.Render(m.clean(d)), cw)
			}
		}
		return out
	}
	i := j - 1
	l := m.report.Links[i]
	k := linkLook(l)
	style := m.lookStyle(k)
	lit := fs.lit[i]
	if !lit {
		style = t.chrome
	}
	if !fs.settled && k == lookDead {
		// Until the flow-in finishes, an unreached agent is merely not yet
		// reached; it greys out only once the pulse has stopped short of it.
		style = t.chrome
	}
	name := m.clip(m.agentName(i), cw-2)
	glyph := m.agentGlyph(k)
	if !lit {
		glyph = g.dead
	}
	nameStyle := t.text
	switch {
	case k == lookDead && fs.settled:
		nameStyle = t.slate
	case !lit:
		nameStyle = t.chrome
	}
	cell := style.Render(glyph) + " " + nameStyle.Render(name)
	if i == m.sel {
		cell = t.selected.Render(style.Bold(true).Render(glyph) + " " + nameStyle.Bold(true).Underline(true).Render(name))
	}
	if m.flashing(i) {
		cell = style.Reverse(true).Bold(true).Render(" " + glyph + " " + name + " ")
	}
	out[0] = m.fit(cell, cw)
	if !lit || (!fs.settled && k == lookDead) {
		out[1], out[2], out[3] = m.fit("", cw), m.fit("", cw), m.fit("", cw)
		return out
	}
	out[1] = m.fit(m.lookStyle(k).Render(m.status(l)), cw)
	out[2] = m.fit(m.vitals(l), cw)
	barStyle := t.teal
	if f := lifeFraction(l); f < 0.25 {
		barStyle = t.amber
	}
	if k == lookDead {
		barStyle = t.slate
	}
	if l.Readable && !l.ExpiresAt.IsZero() {
		out[3] = m.fit(m.bar(lifeFraction(l), min(cw, 10), barStyle), cw)
	} else {
		out[3] = m.fit("", cw)
	}
	return out
}

// edgeAcross is link i: an arrow from the agent that issued it to the one it
// grants to, with its number and verdict underneath.
func (m Model) edgeAcross(i, ew int, fs flowState) [4]string {
	t := m.t
	l := m.report.Links[i]
	k := linkLook(l)
	inner := ew - 2
	var out [4]string
	out[0] = " " + m.arrow(i, k, inner, fs) + " "

	label := fmt.Sprintf("link %d", i)
	labelStyle := t.muted
	if i == m.sel {
		labelStyle = t.bright
	}
	marks, ms := m.ruleMarks(l)
	shown := fs.settled || fs.lit[i] || (fs.breaking && i == m.report.BreakAt)
	if !shown {
		out[1] = strings.Repeat(" ", ew)
		out[2] = strings.Repeat(" ", ew)
	} else {
		out[1] = " " + m.fit(center(labelStyle.Render(label), inner), inner) + " "
		if k == lookDead {
			ms = t.slate
		}
		if marks == m.g.pass {
			// A link that passes says so through its arrow and its agent;
			// a tick here too would only be noise between them.
			marks = ""
		}
		out[2] = " " + m.fit(center(ms.Render(m.clip(marks, inner)), inner), inner) + " "
	}
	out[3] = strings.Repeat(" ", ew)
	return out
}

// center pads s on the left so that it sits in the middle of n cells.
func center(s string, n int) string {
	if w := width(s); w < n {
		return strings.Repeat(" ", (n-w)/2) + s
	}
	return s
}

// arrow draws one link's arrow, n cells wide, as it looks at this frame of
// the flow-in.
func (m Model) arrow(i int, k look, n int, fs flowState) string {
	t, g := m.t, m.g
	body := n - 1
	pending := t.chrome.Render(strings.Repeat(g.edgeDead, body) + g.headDead)

	if !fs.settled {
		switch {
		case fs.pulse == i:
			// The pulse is crossing: what it has crossed takes the link's
			// colour, the pulse itself is bright, the rest waits.
			pos := int(fs.at*float64(body-1) + 0.5)
			style := m.lookStyle(k)
			if k == lookBroken || k == lookRevoked {
				// A broken link carries the pulse as far as the break, and
				// no further.
				style = t.coral
				pos = int(fs.at*float64(body/2) + 0.5)
			}
			return style.Render(strings.Repeat(g.edge, pos)) + t.bright.Render(g.pulse) +
				t.chrome.Render(strings.Repeat(g.edgeDead, max(body-pos-1, 0))+g.headDead)
		case fs.breaking && i == m.report.BreakAt:
			s := m.brokenArrow(n, k)
			if fs.on {
				return t.coral.Reverse(true).Bold(true).Render(stripStyles(s))
			}
			return s
		case !fs.lit[i]:
			return pending
		}
	}

	style := m.lookStyle(k)
	if m.flashing(i) {
		style = style.Reverse(true).Bold(true)
	}
	switch k {
	case lookOK:
		return style.Render(strings.Repeat(g.edge, body) + g.head)
	case lookUnsure, lookAsserted:
		return style.Render(strings.Repeat(g.edgeUnchecked, body) + g.head)
	case lookBroken, lookRevoked:
		if m.flashing(i) {
			return style.Render(stripStyles(m.brokenArrow(n, k)))
		}
		return m.brokenArrow(n, k)
	}
	return t.slate.Render(strings.Repeat(g.edgeDead, body) + g.headDead)
}

// brokenArrow is an arrow that never arrives: solid up to the break, then
// dashes.
func (m Model) brokenArrow(n int, k look) string {
	t, g := m.t, m.g
	body := n - 1
	mid := body / 2
	mark := g.breakMark
	if k == lookRevoked {
		mark = g.revokeMark
	}
	return t.coral.Render(strings.Repeat(g.edge, mid)) + t.coral.Bold(true).Render(mark) +
		t.slate.Render(strings.Repeat(g.edgeDead, max(body-mid-1, 0))+g.headDead)
}

// railDown lays the chain out top to bottom, for terminals too narrow for
// the whole chain across. Each link is the connector between two agents.
// When even that is too tall it drops the connectors, and when a long chain
// still does not fit it shows a window around the selected link.
func (m Model) railDown(W, H int) []string {
	r := m.report
	t, g := m.t, m.g
	n := len(r.Links)
	fs := m.flow()
	budget := max(H/3, 4)
	connectors := 2*n+1 <= budget

	nameW := width(m.sponsorName())
	for i := range r.Links {
		nameW = max(nameW, width(m.agentName(i)))
	}
	nameW = min(nameW, max(W/3, 12))

	var rows []string
	sp := "  " + t.gold.Render(g.sponsor+" "+m.fit(m.sponsorName(), nameW)) + "  " + t.muted.Render(m.rootRole())
	for _, d := range r.Root.Details {
		sp += t.slate.Render(" " + g.dot + " " + m.clean(d))
	}
	rows = append(rows, m.fit(sp, W))

	for i, l := range r.Links {
		k := linkLook(l)
		style := m.lookStyle(k)
		lit := fs.lit[i]
		settledDead := k == lookDead && fs.settled
		if !lit || (k == lookDead && !fs.settled) {
			style = t.chrome
		}
		marks, ms := m.ruleMarks(l)
		if settledDead || !lit {
			ms = t.slate
		}
		linkLabel := fmt.Sprintf("link %d", i)
		if i == m.sel {
			linkLabel = t.bright.Render(linkLabel)
		} else {
			linkLabel = t.muted.Render(linkLabel)
		}
		if connectors {
			v := g.vEdge
			switch {
			case !lit || settledDead:
				v = g.vEdgeDead
			case k == lookUnsure || k == lookAsserted:
				v = g.vEdgeUnchecked
			case k == lookBroken:
				v = g.breakMark
			case k == lookRevoked:
				v = g.revokeMark
			}
			conn := "  " + style.Render(v) + " " + linkLabel
			if lit || fs.settled {
				conn += "  " + ms.Render(marks)
			}
			rows = append(rows, m.fit(conn, W))
		}
		glyph := m.agentGlyph(k)
		if !lit {
			glyph = g.dead
		}
		nameStyle := t.text
		if settledDead {
			nameStyle = t.slate
		} else if !lit {
			nameStyle = t.chrome
		}
		node := style.Render(glyph) + " " + nameStyle.Render(m.fit(m.agentName(i), nameW))
		if i == m.sel {
			node = t.selected.Render(style.Bold(true).Render(glyph) + " " + nameStyle.Bold(true).Render(m.fit(m.agentName(i), nameW)))
		}
		if m.flashing(i) {
			node = style.Reverse(true).Bold(true).Render(glyph + " " + m.fit(m.agentName(i), nameW))
		}
		line := "  " + node
		if lit || fs.settled {
			line += "  " + m.lookStyle(k).Render(m.fit(m.status(l), 16)) + " " + m.vitals(l)
			if !connectors {
				line += "  " + linkLabel + " " + ms.Render(marks)
			}
		}
		rows = append(rows, m.fit(line, W))
	}

	if len(rows) <= budget {
		return rows
	}
	// A window around the selection, with the sponsor always on top.
	per := 1
	if connectors {
		per = 2
	}
	selRow := 1 + per*m.sel + per - 1
	start := clamp(selRow-(budget-1)/2, 1, len(rows)-(budget-1))
	out := []string{rows[0]}
	out = append(out, rows[start:start+budget-1]...)
	if start > 1 {
		out[1] = m.fit("  "+t.slate.Render(g.ellipsis+fmt.Sprintf(" %d more above", start-1)), W)
	}
	if start+budget-1 < len(rows) {
		out[len(out)-1] = m.fit("  "+t.slate.Render(g.ellipsis+fmt.Sprintf(" %d more below", len(rows)-(start+budget-1))), W)
	}
	return out
}

// stripStyles removes escapes, so a span can be restyled as one piece.
func stripStyles(s string) string { return ansiStrip(s) }
