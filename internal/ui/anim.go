package ui

import (
	"time"

	tea "charm.land/bubbletea/v2"
)

// Motion is a frame counter, not a clock. Every frame is a pure function of
// its number, so a test can render frame 12 and get the same picture every
// time, and the screen only redraws while something is actually moving: once
// an animation ends no tick is scheduled, and an idle view costs nothing.

const (
	frameInterval = 33 * time.Millisecond // about 30 frames a second
	edgeFrames    = 9                     // frames for authority to cross one link
	breakFrames   = 12                    // frames the break flashes
	flashFrames   = 14                    // frames a changed link flashes
)

type animKind int

const (
	animNone animKind = iota
	animFlowIn
	animFlash
)

type anim struct {
	kind  animKind
	frame int
	total int
	// gen tells this animation's ticks from a superseded one's, so starting
	// a new animation never makes an old tick advance it.
	gen int
	// changed is the set of links a flash highlights.
	changed map[int]bool
}

type tickMsg struct{ gen int }

func (a anim) running() bool { return a.kind != animNone && a.frame < a.total }

// flowIn is authority travelling down the chain: one link at a time, the
// pulse crossing each edge and lighting the agent it reaches, stopping at
// the first broken link with a flash.
func (m Model) flowIn() anim {
	a := anim{kind: animFlowIn, gen: m.anim.gen + 1}
	if m.report == nil {
		return anim{gen: a.gen}
	}
	n := len(m.report.Links)
	reach := n
	if m.report.BreakAt >= 0 {
		reach = m.report.BreakAt + 1
	}
	a.total = reach * edgeFrames
	if m.report.BreakAt >= 0 {
		a.total += breakFrames
	}
	a.total += 2
	if !m.motion {
		a.frame = a.total
	}
	return a
}

// flash highlights the links a change affected.
func (m Model) flash(changed map[int]bool) anim {
	a := anim{kind: animFlash, total: flashFrames, gen: m.anim.gen + 1, changed: changed}
	if !m.motion || len(changed) == 0 {
		a.frame = a.total
	}
	return a
}

// tick schedules the next frame, if there is one to draw.
func (m Model) tick() tea.Cmd {
	if !m.anim.running() {
		return nil
	}
	gen := m.anim.gen
	return tea.Tick(frameInterval, func(time.Time) tea.Msg { return tickMsg{gen: gen} })
}

// skip ends any running animation at its final frame.
func (m Model) skip() Model {
	m.anim.frame = m.anim.total
	return m
}

// flowState is what the flow-in has reached at the current frame.
type flowState struct {
	// lit[i] is whether agent i (the subject of link i) has been reached.
	lit []bool
	// pulse is the link the pulse is crossing, and at is how far across it
	// is, from 0 to 1. pulse is -1 when nothing is crossing.
	pulse int
	at    float64
	// breaking is true while the break flashes, and on is its phase.
	breaking, on bool
	// settled is true once the flow-in has finished: the downstream fade
	// and every final colour apply only then.
	settled bool
}

func (m Model) flow() flowState {
	n := 0
	if m.report != nil {
		n = len(m.report.Links)
	}
	fs := flowState{lit: make([]bool, n), pulse: -1}
	if m.anim.kind != animFlowIn || !m.anim.running() {
		for i := range fs.lit {
			fs.lit[i] = true
		}
		fs.settled = true
		return fs
	}
	f := m.anim.frame
	reach := n
	if m.report.BreakAt >= 0 {
		reach = m.report.BreakAt + 1
	}
	for i := 0; i < reach; i++ {
		if f >= (i+1)*edgeFrames {
			fs.lit[i] = true
		}
	}
	if f < reach*edgeFrames {
		fs.pulse = f / edgeFrames
		fs.at = float64(f%edgeFrames) / float64(edgeFrames-1)
		return fs
	}
	if m.report.BreakAt >= 0 {
		bf := f - reach*edgeFrames
		if bf < breakFrames {
			fs.breaking = true
			fs.on = (bf/3)%2 == 0
		}
	}
	return fs
}

// flashing reports whether link i is in the bright phase of a change flash.
func (m Model) flashing(i int) bool {
	if m.anim.kind != animFlash || !m.anim.running() || !m.anim.changed[i] {
		return false
	}
	return (m.anim.frame/3)%2 == 0
}
