package ui

import (
	"image/color"
	"os"

	"charm.land/lipgloss/v2"
)

// palette is every colour the view uses. Nothing outside this file names a
// colour, so a state can only ever be drawn in the colour its role has.
type palette struct {
	gold    color.Color // the human sponsor
	teal    color.Color // authority that is held and verified
	blue    color.Color // authority that was narrowed
	coral   color.Color // a violation, a break, a failure
	mint    color.Color // a check that passed
	amber   color.Color // something that was not checked
	slate   color.Color // dropped, unreached, does not apply
	chrome  color.Color // borders and rules
	muted   color.Color // labels
	text    color.Color // body text
	bright  color.Color // emphasis
	onBadge color.Color // text on a coloured badge
	sel     color.Color // the selected row's background
	digests []color.Color
}

func newPalette(dark bool) palette {
	if dark {
		return palette{
			gold:    lipgloss.Color("#F5C26B"),
			teal:    lipgloss.Color("#2DD4BF"),
			blue:    lipgloss.Color("#60A5FA"),
			coral:   lipgloss.Color("#FB7185"),
			mint:    lipgloss.Color("#4ADE80"),
			amber:   lipgloss.Color("#E0A458"),
			slate:   lipgloss.Color("#5B6577"),
			chrome:  lipgloss.Color("#4B5A70"),
			muted:   lipgloss.Color("#94A3B8"),
			text:    lipgloss.Color("#E2E8F0"),
			bright:  lipgloss.Color("#F8FAFC"),
			onBadge: lipgloss.Color("#0B1220"),
			sel:     lipgloss.Color("#1E293B"),
			digests: []color.Color{
				lipgloss.Color("#F472B6"), lipgloss.Color("#A78BFA"), lipgloss.Color("#38BDF8"),
				lipgloss.Color("#34D399"), lipgloss.Color("#FACC15"), lipgloss.Color("#FB923C"),
			},
		}
	}
	return palette{
		gold:    lipgloss.Color("#A16207"),
		teal:    lipgloss.Color("#0F766E"),
		blue:    lipgloss.Color("#1D4ED8"),
		coral:   lipgloss.Color("#BE123C"),
		mint:    lipgloss.Color("#15803D"),
		amber:   lipgloss.Color("#B45309"),
		slate:   lipgloss.Color("#94A3B8"),
		chrome:  lipgloss.Color("#CBD5E1"),
		muted:   lipgloss.Color("#64748B"),
		text:    lipgloss.Color("#1E293B"),
		bright:  lipgloss.Color("#020617"),
		onBadge: lipgloss.Color("#FFFFFF"),
		sel:     lipgloss.Color("#E2E8F0"),
		digests: []color.Color{
			lipgloss.Color("#BE185D"), lipgloss.Color("#6D28D9"), lipgloss.Color("#0369A1"),
			lipgloss.Color("#047857"), lipgloss.Color("#A16207"), lipgloss.Color("#C2410C"),
		},
	}
}

// theme is the set of styles the renderers draw with. In colourless mode
// every style keeps its text attributes (bold, faint, reverse) and loses its
// colours, which is what NO_COLOR asks for: the glyphs still carry every
// state, because no state is ever signalled by colour alone.
type theme struct {
	color bool

	gold, teal, blue, coral, mint, amber, slate lipgloss.Style
	chrome, muted, text, bright                 lipgloss.Style
	bold, faint                                 lipgloss.Style

	badgeValid, badgeInvalid, badgeIncomplete, badgeAlarm, badgeDead lipgloss.Style
	selected                                                         lipgloss.Style
	key                                                              lipgloss.Style

	digests []lipgloss.Style
}

func newTheme(dark, useColor bool) theme {
	p := newPalette(dark)
	fg := func(c color.Color) lipgloss.Style {
		if !useColor {
			return lipgloss.NewStyle()
		}
		return lipgloss.NewStyle().Foreground(c)
	}
	badge := func(c color.Color) lipgloss.Style {
		if !useColor {
			return lipgloss.NewStyle().Bold(true).Reverse(true)
		}
		return lipgloss.NewStyle().Bold(true).Foreground(p.onBadge).Background(c)
	}
	t := theme{
		color:  useColor,
		gold:   fg(p.gold).Bold(true),
		teal:   fg(p.teal),
		blue:   fg(p.blue),
		coral:  fg(p.coral),
		mint:   fg(p.mint),
		amber:  fg(p.amber),
		slate:  fg(p.slate),
		chrome: fg(p.chrome),
		muted:  fg(p.muted),
		text:   fg(p.text),
		bright: fg(p.bright).Bold(true),
		bold:   lipgloss.NewStyle().Bold(true),
		faint:  lipgloss.NewStyle().Faint(true),

		badgeValid:      badge(p.mint),
		badgeInvalid:    badge(p.coral),
		badgeIncomplete: badge(p.amber),
		badgeAlarm:      badge(p.coral).Blink(false),
		badgeDead:       badge(p.slate),
		key:             fg(p.bright).Bold(true),
	}
	if useColor {
		t.selected = lipgloss.NewStyle().Background(p.sel)
		t.slate = t.slate.Faint(false)
	} else {
		t.selected = lipgloss.NewStyle().Reverse(true)
		t.slate = t.slate.Faint(true)
	}
	for _, c := range p.digests {
		t.digests = append(t.digests, fg(c).Bold(true))
	}
	return t
}

// colorFromEnv reports whether colour is allowed. NO_COLOR set to anything
// non-empty turns it off, as https://no-color.org asks.
func colorFromEnv() bool { return os.Getenv("NO_COLOR") == "" }

// glyphs is the whole symbol vocabulary. Every state has its own glyph so
// that a colour-blind reader, or a terminal with no colour at all, loses
// nothing.
type glyphs struct {
	ascii bool

	sponsor, agent, hollow, broken, dead, revoked string
	edge, edgeUnchecked, edgeDead                 string
	vEdge, vEdgeUnchecked, vEdgeDead              string
	warn, info                                    string
	head, headDead, breakMark, revokeMark, pulse  string

	pass, fail, err, unchecked, skipped, na, simulated string

	barOn, barOff string

	held, narrowed, dropped, absent, widened, unknown, orphan string

	tl, tr, bl, br, h, v, teeL, teeR string

	ellipsis, dot, arrow, cursor, clock, vline                  string
	diffKept, diffNarrowed, diffDropped, diffAdded, diffWidened string
}

func newGlyphs(ascii bool) glyphs {
	if ascii {
		return glyphs{
			ascii:   true,
			sponsor: "@", agent: "*", hollow: "o", broken: "X", dead: ".", revoked: "/",
			edge: "=", edgeUnchecked: "-", edgeDead: ".",
			vEdge: "|", vEdgeUnchecked: ":", vEdgeDead: ".", warn: "^", info: "i",
			head: ">", headDead: ">", breakMark: "X", revokeMark: "/", pulse: "o",
			pass: "+", fail: "x", err: "!", unchecked: "?", skipped: "-", na: ".", simulated: "/",
			barOn: "#", barOff: "-",
			held: "##", narrowed: "==", dropped: "__", absent: "  ", widened: "^^", unknown: "??", orphan: "~~",
			tl: "+", tr: "+", bl: "+", br: "+", h: "-", v: "|", teeL: "+", teeR: "+",
			ellipsis: "~", dot: "-", arrow: "->", cursor: "_", clock: "@", vline: "|",
			diffKept: "=", diffNarrowed: "~", diffDropped: "-", diffAdded: "+", diffWidened: "!",
		}
	}
	return glyphs{
		sponsor: "◉", agent: "◆", hollow: "◇", broken: "✗", dead: "◌", revoked: "⊘",
		edge: "━", edgeUnchecked: "┅", edgeDead: "╌",
		vEdge: "┃", vEdgeUnchecked: "┇", vEdgeDead: "╎", warn: "△", info: "i",
		head: "▸", headDead: "▹", breakMark: "╳", revokeMark: "⊘", pulse: "●",
		pass: "✓", fail: "✗", err: "!", unchecked: "○", skipped: "–", na: "·", simulated: "⊘",
		barOn: "▰", barOff: "▱",
		held: "▆▆", narrowed: "▃▃", dropped: "▁▁", absent: "  ", widened: "▲▲", unknown: "??", orphan: "◌◌",
		tl: "╭", tr: "╮", bl: "╰", br: "╯", h: "─", v: "│", teeL: "├", teeR: "┤",
		ellipsis: "…", dot: "·", arrow: "→", cursor: "▏", clock: "◷", vline: "│",
		diffKept: "=", diffNarrowed: "~", diffDropped: "-", diffAdded: "+", diffWidened: "✗",
	}
}
