package ui

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// The ask form is five single-line fields. It is built here rather than from
// a form library because it needs nothing a form library adds, and a field
// that does not blink is one a test can render twice and get the same text.

const (
	fieldAction = iota
	fieldType
	fieldID
	fieldTags
	fieldAttrs
	fieldCount
)

var fieldLabels = [fieldCount]string{"action", "resource type", "resource id", "tags", "attributes"}

var fieldHints = [fieldCount]string{
	"what is attempted, such as invoke",
	"such as mcp_tool",
	"the literal resource, such as web.fetch",
	"comma separated",
	"key=value, comma separated; values are read as JSON when they parse",
}

type askForm struct {
	values [fieldCount]string
	focus  int
	err    string
}

// newAsk prefills the form with something worth asking. An MCP tools/call
// input names its own tool; otherwise the leaf's first grant is turned into
// a concrete request it would cover, so pressing enter straight away shows
// a real answer, and changing one field shows what that changes.
func (m Model) newAsk() askForm {
	f := askForm{}
	f.values[fieldAction] = "invoke"
	f.values[fieldType] = "mcp_tool"
	if m.answer != nil {
		return formFromRequest(m.answer.Request)
	}
	r := m.report
	if r == nil {
		return f
	}
	if tc := r.Input.ToolCall; tc != nil && tc.Name != "" {
		f.values[fieldID] = tc.Name
		return f
	}
	// The selected authority row, as the deepest link that holds it holds
	// it: select a row, press a, and the question is about that row.
	var caps []mda.Capability
	if m.row < len(r.Matrix.Rows) {
		row := r.Matrix.Rows[m.row]
		for i := len(row.Cells) - 1; i >= 0 && caps == nil; i-- {
			cell, claims := row.Cells[i], r.Links[i].Claims
			if claims == nil || len(cell.Caps) == 0 || cell.Kind == diagnose.CellAbsent {
				continue
			}
			if ci := cell.Caps[0]; ci < len(claims.Mandatum.Capabilities) {
				caps = claims.Mandatum.Capabilities[ci : ci+1]
			}
		}
	}
	for i := len(r.Links) - 1; i >= 0 && caps == nil; i-- {
		if c := r.Links[i].Claims; c != nil && len(c.Mandatum.Capabilities) > 0 {
			caps = c.Mandatum.Capabilities
		}
	}
	if len(caps) == 0 {
		return f
	}
	c := caps[0]
	f.values[fieldAction] = c.Action.Name
	f.values[fieldType] = c.Resource.Type
	id := c.Resource.ID
	if strings.HasSuffix(id, "*") {
		id = strings.TrimSuffix(id, "*") + "example"
	}
	f.values[fieldID] = id
	f.values[fieldTags] = strings.Join(c.Resource.Tags, ", ")
	var attrs []string
	for _, k := range sortedKeys(c.Conditions) {
		if v, ok := sampleValue(c.Conditions[k]); ok {
			attrs = append(attrs, k+"="+v)
		}
	}
	f.values[fieldAttrs] = strings.Join(attrs, ", ")
	return f
}

func formFromRequest(req verify.Request) askForm {
	f := askForm{}
	f.values[fieldAction] = req.Action
	f.values[fieldType] = req.ResourceType
	f.values[fieldID] = req.ResourceID
	f.values[fieldTags] = strings.Join(req.ResourceTags, ", ")
	var attrs []string
	for _, k := range sortedKeys(req.Attributes) {
		v, _ := json.Marshal(req.Attributes[k])
		s := string(v)
		if str, ok := req.Attributes[k].(string); ok && !strings.ContainsAny(str, ", =") {
			s = str
		}
		attrs = append(attrs, k+"="+s)
	}
	f.values[fieldAttrs] = strings.Join(attrs, ", ")
	return f
}

// sampleValue is a value the condition accepts.
func sampleValue(c mda.Condition) (string, bool) {
	switch {
	case c.Equals != nil:
		return *c.Equals, true
	case len(c.In) > 0:
		return c.In[0], true
	case c.Prefix != nil:
		return *c.Prefix + "example", true
	case c.Min != nil:
		return fmt.Sprint(*c.Min), true
	case c.Max != nil:
		return fmt.Sprint(*c.Max), true
	}
	return "", false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// request turns the form into a request, or says which field is wrong.
func (f askForm) request() (verify.Request, error) {
	req := verify.Request{
		Action:       strings.TrimSpace(f.values[fieldAction]),
		ResourceType: strings.TrimSpace(f.values[fieldType]),
		ResourceID:   strings.TrimSpace(f.values[fieldID]),
		Attributes:   map[string]any{},
	}
	if req.Action == "" || req.ResourceType == "" || req.ResourceID == "" {
		return req, fmt.Errorf("action, resource type and resource id are all needed")
	}
	for _, t := range strings.Split(f.values[fieldTags], ",") {
		if t = strings.TrimSpace(t); t != "" {
			req.ResourceTags = append(req.ResourceTags, t)
		}
	}
	for _, kv := range strings.Split(f.values[fieldAttrs], ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return req, fmt.Errorf("attribute %q: want key=value", kv)
		}
		v = strings.TrimSpace(v)
		var parsed any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			req.Attributes[k] = parsed
		} else {
			req.Attributes[k] = v
		}
	}
	return req, nil
}

func (m Model) updateAsk(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	f := &m.ask
	switch msg.String() {
	case "esc":
		m.overlay = overlayNone
	case "tab", "down":
		f.focus = (f.focus + 1) % fieldCount
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + fieldCount) % fieldCount
	case "enter":
		req, err := f.request()
		if err != nil {
			f.err = err.Error()
			return m, nil
		}
		if m.report != nil {
			tr := m.report.Ask(req)
			m.answer = &tr
			m.overlay = overlayAnswer
		}
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
	for i := 0; i < fieldCount; i++ {
		label := t.muted.Render(m.fit(fieldLabels[i], labelW))
		val := m.clean(m.ask.values[i])
		room := inner - labelW - 1
		if i == m.ask.focus {
			label = t.bright.Render(m.fit(fieldLabels[i], labelW))
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
			body = append(body, strings.Repeat(" ", labelW+1)+t.slate.Render(m.clip(fieldHints[i], room)))
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
	t, g, tr := m.t, m.g, m.answer
	inner := w - 4
	var body []string
	for _, part := range strings.Split(describeRequest(tr.Request), "\n") {
		for _, line := range wrap(m.clean(part), inner) {
			body = append(body, t.bright.Render(line))
		}
	}
	body = append(body, "")

	verdict, tone, why := answerVerdict(tr)
	badge := m.badge(tone).Render(" " + m.verdictGlyph(tr) + " " + verdict + " ")
	authority := t.muted.Render(string(tr.Authority))
	body = append(body, badge+"  "+authority)
	for _, line := range wrap(why, inner) {
		body = append(body, t.text.Render(line))
	}
	if !tr.Covered && tr.Reason != "" {
		for _, line := range wrap(m.clean(tr.Reason), inner-2) {
			body = append(body, "  "+t.muted.Render(line))
		}
	}
	if tr.OnlyThroughWidening {
		body = append(body, "")
		// Two different stories, sent to two different people: authority
		// the sponsor never granted, and authority the sponsor granted that
		// a link in between dropped and a later one re-added.
		msg := fmt.Sprintf("%s the sponsor never granted this: it exists only because link %d widened authority",
			g.fail, tr.WideningAt)
		if tr.SponsorGranted {
			msg = fmt.Sprintf("%s the sponsor granted this, link %d dropped it, and re-adding it at link %d does not bring it back",
				g.fail, tr.FirstRefused, tr.WideningAt)
		}
		for _, line := range wrap(m.clean(msg), inner) {
			body = append(body, t.coral.Render(line))
		}
	}

	body = append(body, "", t.muted.Render("asked of each link's own grant"))
	r := m.report
	for _, s := range tr.Steps {
		name := ""
		if r != nil && s.Link < len(r.Links) {
			name = m.agentName(s.Link)
		}
		var mark string
		switch {
		case !s.Evaluable:
			mark = t.amber.Render(g.unchecked + " unreadable")
		case s.Permitted:
			mark = t.mint.Render(g.pass + " covers it")
		default:
			mark = t.coral.Render(g.fail + " refuses")
		}
		head := t.muted.Render(fmt.Sprintf("%2d ", s.Link)) + m.fit(t.text.Render(m.clean(name)), 14) + " " + mark
		body = append(body, m.clip(head, inner))
		if !s.Permitted && s.Reason != "" && s.Link == tr.FirstRefused {
			for _, line := range wrap(m.clean(s.Reason), inner-6) {
				body = append(body, "      "+t.slate.Render(line))
			}
		}
	}
	body = append(body, "", m.hints(inner, [][2]string{{"e", "edit the question"}, {"esc", "close"}}))
	return m.frame("ANSWER", body, w, len(body)+2, m.toneStyle(tone).Bold(true), m.toneStyle(tone))
}

func (m Model) verdictGlyph(tr *diagnose.Trace) string {
	if tr.Permitted {
		return m.g.pass
	}
	if tr.Authority == diagnose.Conditional && tr.Covered {
		return m.g.unchecked
	}
	return m.g.fail
}

// answerVerdict words the answer by how far it can be relied on. A chain that
// does not verify permits nothing, whatever its leaf claims, so that is said
// first and the leaf's claim second.
func answerVerdict(tr *diagnose.Trace) (string, tone, string) {
	switch tr.Authority {
	case diagnose.Authoritative:
		if tr.Permitted {
			return "PERMITTED", toneGood, "the chain verified with every input, and the leaf's grant covers this request"
		}
		return "DENIED", toneBad, "the chain verified, but the leaf's grant does not cover this request"
	case diagnose.Conditional:
		if tr.Covered {
			return "PERMITTED IF", toneUnsure, "the leaf's grant covers this request, but only holds if the rules that were not checked pass"
		}
		return "DENIED", toneBad, "the leaf's grant does not cover this request (some rules were also not checked)"
	case diagnose.Hypothetical:
		if tr.Covered {
			return "DENIED", toneBad, "the chain does not verify, so it permits nothing. Hypothetically, if it verified, the leaf's grant would cover this request"
		}
		return "DENIED", toneBad, "the chain does not verify, and even if it did, the leaf's grant would not cover this request"
	}
	return "NOT EVALUABLE", toneBad, "the leaf does not parse, so it claims nothing that can be read"
}

func describeRequest(req verify.Request) string {
	s := req.Action + " " + req.ResourceType + ":" + req.ResourceID
	for _, t := range req.ResourceTags {
		s += " #" + t
	}
	var parts []string
	for _, k := range sortedKeys(req.Attributes) {
		parts = append(parts, fmt.Sprintf("%s=%v", k, req.Attributes[k]))
	}
	if len(parts) > 0 {
		s += "\n" + strings.Join(parts, "  ")
	}
	return s
}
