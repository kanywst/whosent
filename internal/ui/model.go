package ui

import (
	"context"
	"slices"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// overlay is what, if anything, is drawn over the main screen.
type overlay int

const (
	overlayNone overlay = iota
	overlayHelp
	overlayAsk
	overlayAnswer
)

// panel is which lower panel shows when there is room for only one.
type panel int

const (
	panelAuthority panel = iota
	panelLink
)

// Model is the whole interactive view. It is a value: every helper returns a
// new Model rather than mutating, so Update reads as a sequence of steps.
type Model struct {
	cfg  Config
	cur  int // the session on screen
	ctx  context.Context
	t    theme
	g    glyphs
	dark bool

	// base is the evaluation time the session opened at; offset is how far
	// the time scrub has moved from it.
	base   time.Time
	offset time.Duration
	// sims are the jtis whose revocation is being simulated.
	sims []string

	report *diagnose.Report
	err    error

	sel    int // the selected link
	row    int // the selected authority row
	scroll int // the inspector's scroll offset
	raw    bool
	clock  bool // time mode: the timeline is shown and arrows scrub
	lower  panel

	overlay overlay
	ask     askForm
	answer  *diagnose.Trace

	width, height int
	ready         bool

	motion bool
	anim   anim
}

// New builds the view for cfg. The first session is diagnosed immediately,
// so a model is never on screen without a report.
func New(cfg Config) Model {
	m := Model{
		cfg:    cfg,
		ctx:    context.Background(),
		dark:   true,
		motion: cfg.Motion,
		g:      newGlyphs(cfg.ASCII),
		lower:  panelAuthority,
	}
	m.t = newTheme(m.dark, colorFromEnv() && !cfg.NoColor)
	return m.open(0)
}

// session is the session on screen.
func (m Model) session() Session {
	if len(m.cfg.Sessions) == 0 {
		return Session{}
	}
	return m.cfg.Sessions[m.cur]
}

// open switches to session i, resets everything that belonged to the last
// one, and starts the flow-in.
func (m Model) open(i int) Model {
	m.cur = i
	s := m.session()
	m.base = s.Options.At
	if m.base.IsZero() {
		m.base = time.Now()
	}
	m.offset, m.sims = 0, nil
	m.sel, m.row, m.scroll = 0, 0, 0
	m.raw, m.clock = false, false
	m.overlay, m.answer = overlayNone, nil
	m = m.diagnose()
	if r := m.report; r != nil && r.BreakAt >= 0 {
		// Open on the link that broke: it is the first thing anyone asks.
		m.sel = r.BreakAt
	}
	if r := m.report; r != nil {
		m.row = defaultRow(r)
	}
	m.anim = m.flowIn()
	return m
}

// diagnose re-runs the engine at the current time with the current
// simulations. The time scrub and the revocation simulation both come
// through here, so they always show exactly what `whosent check` would say
// with the same inputs.
//
// The scrub is bounded to the chain's own lifetime (see scrubRange), so a
// demo's revocation set, minted at the demo's base time, never ages past its
// 24h limit inside the range; no MaxAge override is needed, and none is made.
// For a real chain the set's age at the scrubbed time is a genuine fact and
// is shown as one.
func (m Model) diagnose() Model {
	s := m.session()
	opts := s.Options.WithAt(m.base.Add(m.offset)).WithSimulatedRevocations(m.sims)
	r, err := diagnose.Diagnose(m.ctx, s.Links, opts)
	m.report, m.err = r, err
	if r != nil {
		r.Input = s.Input
		m.sel = clamp(m.sel, 0, max(len(r.Links)-1, 0))
		m.row = clamp(m.row, 0, max(len(r.Matrix.Rows)-1, 0))
	}
	return m
}

// redo re-diagnoses after the time or the simulations changed, and flashes
// every link whose state moved, so the consequence of the change is where
// the eye already is.
func (m Model) redo() Model {
	before := m.report
	m = m.diagnose()
	changed := map[int]bool{}
	if before != nil && m.report != nil && len(before.Links) == len(m.report.Links) {
		for i := range m.report.Links {
			a, b := before.Links[i], m.report.Links[i]
			if a.State != b.State || a.Unreached != b.Unreached || a.Revoked != b.Revoked ||
				a.RevokedSimulated != b.RevokedSimulated {
				changed[i] = true
			}
		}
	}
	m.anim = m.flash(changed)
	return m
}

// Init starts the flow-in and asks the terminal for its background colour,
// so the palette can follow a light theme.
func (m Model) Init() tea.Cmd {
	return tea.Batch(tea.RequestBackgroundColor, m.tick())
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	return min(max(v, lo), hi)
}

// toggleSim adds or removes a simulated revocation of the selected link.
func (m Model) toggleSim() Model {
	r := m.report
	if r == nil || m.sel >= len(r.Links) || r.Links[m.sel].Claims == nil {
		return m
	}
	jti := r.Links[m.sel].Claims.ID
	if i := slices.Index(m.sims, jti); i >= 0 {
		m.sims = slices.Delete(slices.Clone(m.sims), i, i+1)
	} else {
		m.sims = append(slices.Clone(m.sims), jti)
	}
	return m.redo()
}

// defaultRow is the authority row to open on: authority that appeared from
// nowhere if any did, since that is the story; otherwise the first grant
// that reaches the leaf, so that asking about the selected row (a) asks
// about something the chain was actually built to do.
func defaultRow(r *diagnose.Report) int {
	for i, row := range r.Matrix.Rows {
		if row.Origin > 0 {
			return i
		}
	}
	leaf := len(r.Links) - 1
	for i, row := range r.Matrix.Rows {
		if leaf >= 0 && leaf < len(row.Cells) {
			if k := row.Cells[leaf].Kind; k == diagnose.CellHeld || k == diagnose.CellNarrowed {
				return i
			}
		}
	}
	return 0
}
