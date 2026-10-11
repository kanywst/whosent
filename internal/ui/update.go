package ui

import (
	"time"

	tea "charm.land/bubbletea/v2"
)

// Update routes a message. Keys go to the overlay when one is open, and to
// the main screen otherwise.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height, m.ready = msg.Width, msg.Height, true
		m.scroll = 0
		return m, nil

	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		m.t = newTheme(m.dark, m.t.color)
		return m, nil

	case tickMsg:
		if msg.gen != m.anim.gen || !m.anim.running() {
			return m, nil
		}
		m.anim.frame++
		return m, m.tick()

	case tea.MouseWheelMsg:
		if m.overlay != overlayNone {
			return m, nil
		}
		switch msg.Button {
		case tea.MouseWheelUp:
			m.scroll = max(m.scroll-3, 0)
		case tea.MouseWheelDown:
			m.scroll += 3
		}
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if msg.Mod == tea.ModAlt && msg.Code != tea.KeyEscape {
			// Esc followed quickly by a key arrives as one alt+key event
			// (a fast typist, a paste, a recording tool). Nothing here is
			// bound to alt, so read it as what was meant: esc, then the
			// key. Without this, "esc q" never quits.
			next, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape}))
			if cmd != nil {
				return next, cmd
			}
			k := msg.Key()
			k.Mod = 0
			if k.Text == "" && k.Code >= ' ' && k.Code < tea.KeyExtended {
				k.Text = string(k.Code)
			}
			return next.(Model).Update(tea.KeyPressMsg(k))
		}
		switch m.overlay {
		case overlayHelp:
			m.overlay = overlayNone
			if msg.String() == "q" {
				return m, tea.Quit
			}
			return m, nil
		case overlayAsk:
			return m.updateAsk(msg)
		case overlayAnswer:
			return m.updateAnswer(msg)
		}
		// Any key ends a running animation first; the key still acts, so a
		// fast user is never made to wait for the show.
		m = m.skip()
		return m.updateMain(msg)
	}
	return m, nil
}

func (m Model) updateMain(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	n := 0
	if m.report != nil {
		n = len(m.report.Links)
	}
	rows := m.rows()
	step, big := m.scrubSteps()
	caps := m.caps()

	switch k := msg.String(); k {
	case "q":
		return m, tea.Quit
	case "?":
		m.overlay = overlayHelp
	case "esc":
		switch {
		case m.clock:
			m.clock = false
		case m.raw:
			m.raw = false
		}

	case "left", "right":
		if m.clock && caps.TimeScrub {
			d := step
			if k == "left" {
				d = -d
			}
			m = m.scrubBy(d)
			return m, m.tick()
		}
		m = m.selectLink(k == "right", n)
	case "h":
		m = m.selectLink(false, n)
	case "l":
		m = m.selectLink(true, n)
	case "shift+left", "[":
		if caps.TimeScrub {
			m = m.scrubBy(-big)
			return m, m.tick()
		}
	case "shift+right", "]":
		if caps.TimeScrub {
			m = m.scrubBy(big)
			return m, m.tick()
		}
	case "0":
		if m.offset != 0 {
			m.offset = 0
			m = m.redo()
			return m, m.tick()
		}
	case "t":
		if caps.TimeScrub {
			m.clock = !m.clock
		}

	case "up", "k":
		m.row = max(m.row-1, 0)
	case "down", "j":
		m.row = clamp(m.row+1, 0, rows-1)
	case "K", "pgup", "ctrl+u":
		m.scroll = max(m.scroll-m.pageSize(), 0)
	case "J", "pgdown", "ctrl+d":
		m.scroll += m.pageSize()
	case "g", "home":
		m.scroll = 0

	case "tab":
		if m.lower == panelAuthority {
			m.lower = panelLink
		} else {
			m.lower = panelAuthority
		}
		m.scroll = 0
	case "r":
		m.raw = !m.raw
		m.scroll = 0
		if !m.wide() {
			m.lower = panelLink
		}

	case "x":
		m = m.toggleSim()
		return m, m.tick()
	case "X":
		if len(m.sims) > 0 {
			m.sims = nil
			m = m.redo()
			return m, m.tick()
		}

	case "a":
		if _, ok := m.asker(); ok {
			m.ask = m.newAsk()
			m.overlay = overlayAsk
		}

	case "n", "p":
		if len(m.cfg.Sessions) > 1 {
			c := len(m.cfg.Sessions)
			next := (m.cur + 1) % c
			if k == "p" {
				next = (m.cur - 1 + c) % c
			}
			m = m.open(next)
			return m, m.tick()
		}
	case "space", " ":
		m.anim = m.flowIn()
		if m.motion {
			m.anim.frame = 0
		}
		return m, m.tick()
	}
	return m, nil
}

func (m Model) selectLink(next bool, n int) Model {
	if next {
		m.sel = clamp(m.sel+1, 0, n-1)
	} else {
		m.sel = max(m.sel-1, 0)
	}
	m.scroll = 0
	return m
}

// scrubBy moves the evaluation time, within the chain's own lifetime.
func (m Model) scrubBy(d time.Duration) Model {
	lo, hi := m.scrubRange()
	off := m.offset + d
	if t := m.base.Add(off); t.Before(lo) {
		off = lo.Sub(m.base)
	} else if t.After(hi) {
		off = hi.Sub(m.base)
	}
	if off == m.offset {
		return m
	}
	m.offset = off
	m.clock = true
	return m.redo()
}

// scrubRange is the span the time scrub may cover: from shortly before the
// earliest link was issued to shortly after the last one expires. Outside it
// nothing about the chain changes, so there is nothing to see.
func (m Model) scrubRange() (time.Time, time.Time) {
	lo, hi := m.base, m.base
	if m.report != nil {
		for _, l := range m.report.Links {
			if !l.IssuedAt.IsZero() && l.IssuedAt.Before(lo) {
				lo = l.IssuedAt
			}
			if !l.ExpiresAt.IsZero() && l.ExpiresAt.After(hi) {
				hi = l.ExpiresAt
			}
		}
	}
	pad := max(hi.Sub(lo)/20, time.Minute)
	return lo.Add(-pad), hi.Add(pad)
}

// scrubSteps picks a step that crosses the chain's lifetime in about sixty
// presses, rounded to a whole minute, and a big step ten times that.
func (m Model) scrubSteps() (time.Duration, time.Duration) {
	lo, hi := m.scrubRange()
	step := (hi.Sub(lo) / 60).Round(time.Minute)
	step = max(step, time.Minute)
	return step, 10 * step
}

func (m Model) pageSize() int { return max(m.height/3, 3) }
