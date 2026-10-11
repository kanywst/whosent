package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kanywst/whosent/pkg/chain"
)

// The ask form is a handful of single-line fields the format names. It is
// built here rather than from a form library because it needs nothing a form
// library adds, and a field that does not blink is one a test can render
// twice and get the same text.

type askForm struct {
	fields []chain.AskField
	values []string
	focus  int
	err    string
}

// newAsk prefills the form with something worth asking: the last question
// when there was one, otherwise whatever the format proposes for the chain
// and the selected authority row.
func (m Model) newAsk() askForm {
	a, ok := m.asker()
	if !ok {
		return askForm{}
	}
	f := askForm{fields: append([]chain.AskField(nil), a.AskFields()...)}
	scrub(&f.fields)
	f.values = make([]string, len(f.fields))
	var prefill map[string]string
	if m.answer != nil {
		prefill = m.answer.Values
	} else {
		prefill = a.AskPrefill(m.report, m.row)
	}
	for i, fd := range f.fields {
		f.values[i] = prefill[fd.Key]
	}
	return f
}

// valueMap is the form as the asker reads it.
func (f askForm) valueMap() map[string]string {
	v := make(map[string]string, len(f.fields))
	for i, fd := range f.fields {
		v[fd.Key] = f.values[i]
	}
	return v
}

func (m Model) updateAsk(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	f := &m.ask
	n := len(f.fields)
	if n == 0 {
		m.overlay = overlayNone
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.overlay = overlayNone
	case "tab", "down":
		f.focus = (f.focus + 1) % n
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + n) % n
	case "enter":
		a, ok := m.asker()
		if !ok || m.report == nil {
			m.overlay = overlayNone
			return m, nil
		}
		res, err := a.Ask(m.ctx, m.report, f.valueMap())
		if err != nil {
			// An error can quote what was typed, or the chain.
			f.err = m.clean(err.Error())
			return m, nil
		}
		scrub(res)
		m.answer = res
		m.overlay = overlayAnswer
	case "backspace":
		v := []rune(f.values[f.focus])
		if len(v) > 0 {
			f.values[f.focus] = string(v[:len(v)-1])
		}
		f.err = ""
	case "ctrl+u":
		f.values[f.focus] = ""
		f.err = ""
	default:
		if t := msg.Key().Text; t != "" {
			f.values[f.focus] += t
			f.err = ""
		}
	}
	return m, nil
}

func (m Model) updateAnswer(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "e", "a", "enter":
		m.ask = m.newAsk()
		m.overlay = overlayAsk
	case "q":
		return m, tea.Quit
	default:
		m.overlay = overlayNone
	}
	return m, nil
}

// renderAsk draws the form.
func (m Model) renderAsk(w int) []string {
	t, g := m.t, m.g
	inner := w - 4
	labelW := 15
	var body []string
	body = append(body, t.muted.Render(m.clip("would this chain let its leaf do this?", inner)), "")
	for i, fd := range m.ask.fields {
		label := t.muted.Render(m.fit(m.clean(fd.Label), labelW))
		val := m.clean(m.ask.values[i])
		room := inner - labelW - 1
		if i == m.ask.focus {
			label = t.bright.Render(m.fit(m.clean(fd.Label), labelW))
			shown := val
			if width(shown) > room-1 {
				// Keep the end in view: it is where the typing happens.
				r := []rune(shown)
				for width(string(r)) > room-1 && len(r) > 0 {
					r = r[1:]
				}
				shown = string(r)
			}
			body = append(body, label+" "+t.text.Render(shown)+t.teal.Render(g.cursor))
			body = append(body, strings.Repeat(" ", labelW+1)+t.slate.Render(m.clip(m.clean(fd.Hint), room)))
			continue
		}
		body = append(body, label+" "+t.text.Render(m.clip(val, room)))
	}
	body = append(body, "")
	if m.ask.err != "" {
		body = append(body, t.coral.Render(m.clip(g.fail+" "+m.ask.err, inner)))
	}
	body = append(body, m.hints(inner, [][2]string{{"tab", "next field"}, {"enter", "ask"}, {"esc", "cancel"}}))
	return m.frame("ASK", body, w, len(body)+2, t.teal.Bold(true), t.teal)
}

// renderAnswer draws the verdict for the last question, and the same
// question asked of every link on the way down.
func (m Model) renderAnswer(w int) []string {
	t, g, a := m.t, m.g, m.answer
	inner := w - 4
	var body []string
	for _, part := range a.Request {
		for _, line := range wrap(m.clean(part), inner) {
			body = append(body, t.bright.Render(line))
		}
	}
	body = append(body, "")

	k := toneBad
	switch a.Tone {
	case chain.ToneGood:
		k = toneGood
	case chain.ToneWarn:
		k = toneUnsure
	}
	glyph := m.markGlyph(a.Mark)
	if glyph == "" {
		glyph = g.fail
	}
	badge := m.badge(k).Render(" " + glyph + " " + m.clean(a.Verdict) + " ")
	body = append(body, badge+"  "+t.muted.Render(m.clean(a.Authority)))
	for _, line := range wrap(m.clean(a.Why), inner) {
		body = append(body, t.text.Render(line))
	}
	if a.Reason != "" {
		for _, line := range wrap(m.clean(a.Reason), inner-2) {
			body = append(body, "  "+t.muted.Render(line))
		}
	}
	if a.Warning != "" {
		body = append(body, "")
		for _, line := range wrap(g.fail+" "+m.clean(a.Warning), inner) {
			body = append(body, t.coral.Render(line))
		}
	}

	if len(a.Steps) > 0 {
		body = append(body, "", t.muted.Render(m.clip(m.clean(a.StepsTitle), inner)))
	}
	for _, s := range a.Steps {
		name := m.agentName(s.Link)
		var mark string
		switch s.Outcome {
		case chain.OutcomeUnreadable:
			mark = t.amber.Render(g.unchecked + " unreadable")
		case chain.OutcomeCovers:
			mark = t.mint.Render(g.pass + " covers it")
		default:
			mark = t.coral.Render(g.fail + " refuses")
		}
		head := t.muted.Render(fmt.Sprintf("%2d ", s.Link)) + m.fit(t.text.Render(name), 14) + " " + mark
		body = append(body, m.clip(head, inner))
		if s.ShowReason && s.Reason != "" {
			for _, line := range wrap(m.clean(s.Reason), inner-6) {
				body = append(body, "      "+t.slate.Render(line))
			}
		}
	}
	body = append(body, "", m.hints(inner, [][2]string{{"e", "edit the question"}, {"esc", "close"}}))
	return m.frame("ANSWER", body, w, len(body)+2, m.toneStyle(k).Bold(true), m.toneStyle(k))
}
