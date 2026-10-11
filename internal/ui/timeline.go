package ui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// renderTimeline draws each link's lifetime on one shared axis, with the
// evaluation time as a cursor through all of them. Scrubbing moves the
// cursor, and a link turns coral the moment the cursor passes its expiry:
// "when does this chain die" becomes something you can watch.
func (m Model) renderTimeline(W int) []string {
	r, t, g := m.report, m.t, m.g
	if r == nil || len(r.Links) == 0 {
		return nil
	}
	lo, hi := m.scrubRange()
	at := m.base.Add(m.offset)

	labelW := 4
	for i := range r.Links {
		labelW = max(labelW, min(width(m.agentName(i)), 14)+5)
	}
	bw := W - labelW - 4
	if bw < 10 {
		return nil
	}
	span := hi.Sub(lo)
	col := func(x time.Time) int {
		if span <= 0 {
			return 0
		}
		c := int(float64(x.Sub(lo)) / float64(span) * float64(bw-1))
		return clamp(c, 0, bw-1)
	}
	cur := col(at)

	type cell struct {
		s     string
		style lipgloss.Style
	}
	render := func(cells []cell) string {
		var b strings.Builder
		for _, c := range cells {
			b.WriteString(c.style.Render(c.s))
		}
		return b.String()
	}

	var out []string
	// The axis: start and end times, and the cursor's own label above it.
	axis := make([]cell, bw)
	for i := range axis {
		axis[i] = cell{g.h, t.chrome}
	}
	axis[cur] = cell{"┴", t.amber}
	if g.ascii {
		axis[cur] = cell{"+", t.amber}
	}
	loL, hiL := lo.UTC().Format("15:04"), hi.UTC().Format("15:04")
	head := m.fit("  "+t.muted.Render("time"), labelW) + "  " + render(axis)
	out = append(out, m.fit(head, W))
	label := g.clock + " " + m.timeLabel()
	lpos := clamp(cur-width(label)/2, 0, max(bw-width(label), 0))
	for i, l := range r.Links {
		cells := make([]cell, bw)
		for k := range cells {
			cells[k] = cell{" ", t.text}
		}
		if !l.ExpiresAt.IsZero() {
			// A link whose format records no issue time (a Biscuit block
			// carries only checks on the time) is drawn from the start of
			// the axis: alive since before anything here, until it expires.
			a, b := 0, col(l.ExpiresAt)
			if !l.IssuedAt.IsZero() {
				a = col(l.IssuedAt)
			}
			style := t.teal
			switch {
			case !at.Before(l.ExpiresAt):
				style = t.coral
			case !l.IssuedAt.IsZero() && at.Before(l.IssuedAt):
				style = t.chrome
			}
			if linkLook(l) == lookDead {
				style = t.slate
			}
			for k := a; k <= b && k < bw; k++ {
				cells[k] = cell{g.edge, style}
			}
			if b < bw {
				end := "▏"
				if g.ascii {
					end = "|"
				}
				cells[b] = cell{end, style}
			}
		}
		cursor := g.vline
		cells[cur] = cell{cursor, t.amber.Bold(true)}
		name := m.agentName(i)
		ls := t.muted
		if i == m.sel {
			ls = t.bright
		}
		line := m.fit("  "+ls.Render(fmt.Sprintf("%d ", i)+m.clip(name, labelW-5)), labelW) + "  " + render(cells)
		out = append(out, m.fit(line, W))
	}
	// Under the bars: the start, the cursor's time beneath it, the end.
	lpos = max(lpos, len(loL)+1)
	foot := t.slate.Render(loL) + strings.Repeat(" ", lpos-len(loL)) + t.amber.Render(label)
	if gap := bw - lpos - width(label) - len(hiL); gap >= 1 {
		foot += strings.Repeat(" ", gap) + t.slate.Render(hiL)
	}
	out = append(out, m.fit(m.fit("", labelW)+"  "+foot, W))
	return out
}
