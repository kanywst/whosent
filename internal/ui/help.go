package ui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// keyHelp is the whole key map, in the order the help overlay lists it.
var keyHelp = []struct{ group, keys, what string }{
	{"move", "← → h l", "select a link (an arrow on the rail)"},
	{"move", "↑ ↓ k j", "select a row of authority"},
	{"move", "J K pgup pgdn", "scroll the link panel"},
	{"move", "tab", "switch panel, when they do not fit side by side"},
	{"see", "r", "the raw assertion: header, claims, digests"},
	{"see", "space", "replay authority flowing down the chain"},
	{"what if", "t", "time mode: the timeline, and ← → move the clock"},
	{"what if", "[ ] shift+← →", "move the clock in big steps"},
	{"what if", "0", "back to the time the chain was opened at"},
	{"what if", "x", "simulate revoking the selected link; again to undo"},
	{"what if", "X", "clear every simulated revocation"},
	{"what if", "a", "ask whether the chain would permit a request"},
	{"session", "n p", "next or previous scenario, in the demo tour"},
	{"session", "? q esc", "help, quit, back"},
}

func (m Model) renderHelp(w int) []string {
	t, g := m.t, m.g
	inner := w - 4
	var body []string
	group := ""
	for _, k := range keyHelp {
		if k.group != group {
			if group != "" {
				body = append(body, "")
			}
			group = k.group
			body = append(body, t.muted.Bold(true).Render(strings.ToUpper(group)))
		}
		keys := m.clean(k.keys)
		body = append(body, "  "+t.key.Render(m.fit(keys, 18))+t.text.Render(m.clip(m.clean(k.what), inner-20)))
	}
	body = append(body, "", t.muted.Bold(true).Render("READING IT"))
	legend := []struct{ glyph, style, what string }{
		{g.agent, "teal", "verified: every rule checked and held"},
		{g.hollow, "amber", "unverified: nothing failed, something was not checked"},
		{g.broken, "coral", "broken: a rule failed, or could not be evaluated"},
		{g.revoked, "coral", "revoked, or its revocation is being simulated"},
		{g.dead, "slate", "unreached: a link above it is broken"},
	}
	for _, l := range legend {
		st := map[string]lipgloss.Style{"teal": t.teal, "amber": t.amber, "coral": t.coral, "slate": t.slate}[l.style]
		body = append(body, "  "+st.Render(l.glyph)+"  "+t.text.Render(m.clip(m.clean(l.what), inner-5)))
	}
	body = append(body, "  "+t.gold.UnsetBold().Render(g.pipOn+g.pipOn)+t.slate.Render(g.pipOff)+"  "+
		t.text.Render(m.clip("delegations it may still make, then time left and a life bar", inner-7)))
	body = append(body, "", "  "+t.mint.Render(g.pass)+" pass  "+t.coral.Render(g.fail)+" fail  "+
		t.coral.Render(g.err)+" could not run  "+t.amber.Render(g.unchecked)+" not checked  "+
		t.slate.Render(g.skipped)+" skipped  "+t.slate.Render(g.na)+" n/a")
	body = append(body, "", t.slate.Render(m.clip("any key closes this", inner)))
	h := min(len(body)+2, m.height-2)
	if len(body) > h-2 {
		// Cut from the bottom, where the legend is, and say so: the keys
		// come first and go last.
		body = append(body[:h-3], t.slate.Render(m.clip(g.ellipsis+" taller terminal for the legend", inner)))
	}
	return m.frame("HELP", body, w, h, t.bright, t.muted)
}
