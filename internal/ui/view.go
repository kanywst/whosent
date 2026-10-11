package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/kanywst/whosent/pkg/chain"
)

// Minimum terminal size. Below it the view says so instead of drawing a
// screen too cramped to read.
const (
	minWidth  = 60
	minHeight = 18
	// wideWidth is where the authority matrix and the link inspector fit
	// side by side; narrower, they share one panel and tab switches it.
	wideWidth = 120
)

// View draws the screen. It is pure: it reads the model and returns text.
func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

func (m Model) render() string {
	if !m.ready {
		return ""
	}
	if m.width < minWidth || m.height < minHeight {
		msg := fmt.Sprintf("terminal too small\n\nneeds %dx%d, this is %dx%d", minWidth, minHeight, m.width, m.height)
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.t.amber.Render(msg))
	}
	lines := m.screen()
	switch m.overlay {
	case overlayHelp:
		lines = m.place(lines, m.renderHelp(min(76, m.width-4)))
	case overlayAsk:
		lines = m.place(lines, m.renderAsk(min(72, m.width-4)))
	case overlayAnswer:
		if m.answer != nil {
			lines = m.place(lines, m.renderAnswer(min(76, m.width-4)))
		}
	}
	return strings.Join(lines, "\n")
}

func (m Model) wide() bool { return m.width >= wideWidth }

// screen is the main screen: exactly m.height lines of exactly m.width cells.
func (m Model) screen() []string {
	W, H := m.width, m.height
	var top []string
	top = append(top, m.renderHeader(W))
	if m.err != nil {
		top = append(top, m.t.coral.Render(m.fit(m.g.fail+" "+m.clean(m.err.Error()), W)))
		return m.pad(top, H, m.renderFooter(W))
	}
	top = append(top, m.renderBanner(W)...)
	top = append(top, strings.Repeat(" ", W))
	top = append(top, m.renderRail(W, H)...)
	if m.clock {
		top = append(top, strings.Repeat(" ", W))
		top = append(top, m.renderTimeline(W)...)
	}
	top = append(top, strings.Repeat(" ", W))

	panelH := H - len(top) - 1
	if panelH >= 5 {
		top = append(top, m.renderPanels(W, panelH)...)
	}
	return m.pad(top, H, m.renderFooter(W))
}

// pad fills the screen to h lines and puts the footer on the last one.
func (m Model) pad(lines []string, h int, footer string) []string {
	if len(lines) > h-1 {
		lines = lines[:h-1]
	}
	for len(lines) < h-1 {
		lines = append(lines, strings.Repeat(" ", m.width))
	}
	for i := range lines {
		lines[i] = m.fit(lines[i], m.width)
	}
	return append(lines, m.fit(footer, m.width))
}

// place draws box centred over lines.
func (m Model) place(lines, box []string) []string {
	if len(box) == 0 {
		return lines
	}
	bw := width(box[0])
	x := max((m.width-bw)/2, 0)
	y := max((len(lines)-len(box))/2, 0)
	out := append([]string(nil), lines...)
	for i, b := range box {
		if y+i >= len(out) {
			break
		}
		row := out[y+i]
		left := ansi.Truncate(row, x, "")
		right := ansi.TruncateLeft(row, x+bw, "")
		out[y+i] = m.fit(left+b+right, m.width)
	}
	return out
}

// tone is the meaning a colour carries.
type tone int

const (
	toneGood tone = iota
	toneBad
	toneUnsure
)

func (m Model) badge(k tone) lipgloss.Style {
	switch k {
	case toneGood:
		return m.t.badgeValid
	case toneUnsure:
		return m.t.badgeIncomplete
	}
	return m.t.badgeInvalid
}

func (m Model) toneStyle(k tone) lipgloss.Style {
	switch k {
	case toneGood:
		return m.t.mint
	case toneUnsure:
		return m.t.amber
	}
	return m.t.coral
}

func (m Model) renderHeader(W int) string {
	t, g := m.t, m.g
	s := m.session()
	left := " " + t.gold.Render(g.sponsor+" whosent") + "  "
	name := s.Name
	if name == "" && m.report != nil {
		name = m.report.Source
	}
	left += t.bright.Render(m.clean(name))
	if s.Title != "" {
		left += t.muted.Render(" " + g.dot + " " + m.clean(s.Title))
	}

	var right []string
	if m.offset != 0 || m.clock {
		right = append(right, t.amber.Render(g.clock+" "+m.timeLabel()))
	}
	if len(m.sims) > 0 {
		right = append(right, t.coral.Render(fmt.Sprintf("%s simulating %d revocation%s", g.revoked, len(m.sims), plural(len(m.sims)))))
	}
	if c := len(m.cfg.Sessions); c > 1 {
		right = append(right, t.muted.Render(fmt.Sprintf("%d/%d", m.cur+1, c))+" "+t.slate.Render("n/p"))
	}
	right = append(right, t.key.Render("?")+t.muted.Render(" help "))
	r := strings.Join(right, "   ")
	room := W - width(r) - 1
	return m.fit(m.clip(left, room), room) + " " + r
}

// timeLabel says when the chain is being evaluated, relative to when it was
// opened, and as a wall-clock time.
func (m Model) timeLabel() string {
	at := m.base.Add(m.offset).UTC()
	rel := "now"
	switch {
	case m.offset > 0:
		rel = "+" + chain.Human(m.offset)
	case m.offset < 0:
		rel = "-" + chain.Human(-m.offset)
	}
	return rel + " " + at.Format("15:04")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// renderBanner is the verdict, in one sentence, with whatever context the
// session brings on the line below.
func (m Model) renderBanner(W int) []string {
	r, t := m.report, m.t
	var out []string
	if r.Inconsistency != nil {
		out = append(out, t.badgeAlarm.Render(m.fit(" "+m.clean(r.Inconsistency.Banner)+" ", W)))
	}
	k, label, sentence := m.verdict()
	badge := m.badge(k).Render(" " + label + " ")
	if m.anim.kind == animFlowIn && m.anim.running() {
		// The verdict arrives when authority has finished flowing, so the
		// eye follows the pulse instead of reading the ending first. Any
		// key skips straight to it.
		badge = t.badgeDead.Render(" " + m.g.ellipsis + " TRACING ")
		sentence = "following " + m.sponsorName() + "'s authority down the chain"
	}
	lead := width(badge) + 3
	// The verdict is the one sentence that must never be cut off, so it
	// wraps, under itself, onto a second line when it has to.
	text := wrap(m.clean(sentence), W-lead-1)
	for i, l := range text {
		if i == 2 {
			break
		}
		if i == 0 {
			out = append(out, m.fit(" "+badge+"  "+t.text.Render(l), W))
			continue
		}
		if i == 1 && len(text) > 2 {
			l = m.clip(l+" "+strings.Join(text[2:], " "), W-lead-1)
		}
		out = append(out, m.fit(strings.Repeat(" ", lead)+t.text.Render(l), W))
	}

	s := m.session()
	ctx := s.Summary
	if ctx == "" {
		ctx = m.inputLine()
	}
	// The scenario's own description is true of the chain as minted. Once
	// the clock moves or a revocation is simulated it may no longer be, and
	// a line under the verdict must never contradict it, so it gives way.
	switch {
	case len(m.sims) > 0 && m.offset != 0:
		ctx = fmt.Sprintf("simulated revocation at %s: nothing was revoked. x toggles, X clears, 0 returns to now.", m.timeLabel())
	case len(m.sims) > 0:
		ctx = "simulated: what revoking the marked link would cut off. Nothing was revoked. x toggles, X clears."
	case m.offset != 0:
		ctx = fmt.Sprintf("scrubbed to %s: the chain as it would stand then, not now. 0 returns to now.", m.timeLabel())
	}
	ctxLines := wrap(m.clean(ctx), W-2)
	keep := 1
	if m.height >= 28 {
		keep = 2
	}
	for i, l := range ctxLines {
		if i == keep {
			break
		}
		if i == keep-1 && len(ctxLines) > keep {
			l = strings.Join(ctxLines[i:], " ")
		}
		out = append(out, " "+t.muted.Render(m.fit(l, W-1)))
	}
	return out
}

// inputLine says what was checked and how, for a chain with no summary of
// its own.
func (m Model) inputLine() string {
	return strings.Join(m.report.Summary, " "+m.g.dot+" ")
}

// verdict is the banner: what the chain amounts to, said the way a person
// would say it.
func (m Model) verdict() (tone, string, string) {
	r, g := m.report, m.g
	if r.Headline != "" {
		switch r.Verdict {
		case chain.VerdictValid:
			return toneGood, g.pass + " VALID", r.Headline
		case chain.VerdictIncomplete:
			return toneUnsure, g.unchecked + " INCOMPLETE", r.Headline
		}
		return toneBad, g.fail + " INVALID", r.Headline
	}
	sponsor := "the " + m.rootRole()
	if r.Root.Name != "" {
		sponsor = m.clean(r.Root.Name)
	}
	leaf := "the leaf"
	if n := len(r.Links); n > 0 {
		leaf = m.agentName(n - 1)
	}
	switch r.Verdict {
	case chain.VerdictValid:
		return toneGood, g.pass + " VALID", fmt.Sprintf("%s's authority reaches %s through %d link%s. Every rule was checked.",
			sponsor, leaf, len(r.Links), plural(len(r.Links)))
	case chain.VerdictIncomplete:
		why := r.IncompleteReason
		if why == "" {
			why = "some rules were not checked"
		}
		return toneUnsure, g.unchecked + " INCOMPLETE", fmt.Sprintf("Nothing failed, but it is not verified: %s.", why)
	}
	if r.BreakAt >= 0 && r.BreakAt < len(r.Links) {
		l := r.Links[r.BreakAt]
		rules := m.failingRules(l)
		who := m.agentName(r.BreakAt)
		below := fmt.Sprintf(" %s holds nothing.", who)
		if r.BreakAt < len(r.Links)-1 {
			below = fmt.Sprintf(" %s and below hold nothing.", who)
		}
		return toneBad, g.fail + " INVALID", fmt.Sprintf("Breaks at link %d (%s %s %s): %s.%s",
			r.BreakAt, m.issuerName(r.BreakAt), g.arrow, who, rules, below)
	}
	for _, f := range r.ChainFindings {
		if f.Severity.Blocking() {
			return toneBad, g.fail + " INVALID", fmt.Sprintf("%s: %s", f.Rule, f.Detail)
		}
	}
	return toneBad, g.fail + " INVALID", "The chain does not verify."
}

// rootRole is what the format calls the root of a chain.
func (m Model) rootRole() string {
	if m.report != nil && m.report.Format.RootRole != "" {
		return m.clean(m.report.Format.RootRole)
	}
	return "root"
}

// ruleTitle is a rule's id and its title, such as "V4 time".
func (m Model) ruleTitle(id string) string {
	if m.report == nil {
		return id
	}
	if t := m.report.Format.Rule(id).Title; t != "" {
		return m.clean(id + " " + t)
	}
	return m.clean(id)
}

// failingRules names the rules a link fails, by their titles.
func (m Model) failingRules(l chain.Link) string {
	var parts []string
	for _, c := range l.Checks {
		if c.Status.Blocking() {
			s := m.ruleTitle(c.Rule)
			if c.Simulated {
				s += " (sim)"
			}
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "it does not parse"
	}
	return strings.Join(parts, ", ")
}

// agentName is the short name of whoever link i grants to.
func (m Model) agentName(i int) string {
	r := m.report
	if r == nil || i < 0 || i >= len(r.Links) {
		return "?"
	}
	if l := r.Links[i]; l.To != "" {
		return m.clean(l.To)
	}
	return fmt.Sprintf("link %d", i)
}

// issuerName is the short name of whoever handed link i over.
func (m Model) issuerName(i int) string {
	r := m.report
	if r == nil || i < 0 || i >= len(r.Links) {
		return "?"
	}
	if l := r.Links[i]; l.From != "" {
		return m.clean(l.From)
	}
	return "?"
}

func (m Model) sponsorName() string {
	if r := m.report; r != nil && r.Root.Name != "" {
		return m.clean(r.Root.Name)
	}
	return m.rootRole()
}

// hints renders key hints, dropping from the end until they fit.
func (m Model) hints(w int, pairs [][2]string) string {
	sep := m.t.chrome.Render("  ")
	for n := len(pairs); n > 0; n-- {
		var parts []string
		for _, p := range pairs[:n] {
			parts = append(parts, m.t.key.Render(p[0])+" "+m.t.muted.Render(p[1]))
		}
		s := strings.Join(parts, sep)
		if width(s) <= w {
			return s
		}
	}
	return ""
}

func (m Model) renderFooter(W int) string {
	var pairs [][2]string
	caps := m.caps()
	_, canAsk := m.asker()
	switch {
	case m.clock:
		step, big := m.scrubSteps()
		pairs = [][2]string{
			{"←→", "±" + chain.Human(step)}, {"[ ]", "±" + chain.Human(big)}, {"0", "back to now"},
			{"h l", "link"},
		}
		if caps.RevokeSim {
			pairs = append(pairs, [2]string{"x", "revoke"})
		}
		pairs = append(pairs, [2]string{"t", "done"}, [2]string{"q", "quit"})
	default:
		pairs = [][2]string{{"←→", "link"}}
		if m.rows() > 0 {
			pairs = append(pairs, [2]string{"↑↓", "authority"})
		}
		if caps.TimeScrub {
			pairs = append(pairs, [2]string{"t", "time"})
		}
		if caps.RevokeSim {
			pairs = append(pairs, [2]string{"x", "revoke"})
		}
		if canAsk {
			pairs = append(pairs, [2]string{"a", "ask"})
		}
		if m.offset != 0 {
			// Scrubbed and out of time mode: the way back has to stay in
			// sight, or the header's +20m is a state with no exit.
			pairs = append([][2]string{{"0", "back to now"}}, pairs...)
		}
		if !m.wide() {
			pairs = append(pairs, [2]string{"tab", "panel"})
		}
		pairs = append(pairs, [2]string{"r", "raw"})
		if len(m.cfg.Sessions) > 1 {
			pairs = append(pairs, [2]string{"n p", "scenario"})
		}
		pairs = append(pairs, [2]string{"space", "replay"}, [2]string{"q", "quit"})
	}
	if m.g.ascii {
		for i := range pairs {
			pairs[i][0] = strings.NewReplacer("←→", "<>", "↑↓", "^v").Replace(pairs[i][0])
			pairs[i][1] = strings.ReplaceAll(pairs[i][1], "±", "+-")
		}
	}
	return " " + m.hints(W-1, pairs)
}

// lifeFraction is how much of a link's lifetime is left.
func lifeFraction(l chain.Link) float64 {
	life := l.ExpiresAt.Sub(l.IssuedAt)
	if life <= 0 {
		return 0
	}
	return float64(l.Remaining) / float64(life)
}
