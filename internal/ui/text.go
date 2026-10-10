package ui

import (
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/kanywst/whosent/internal/termsafe"
)

// width is the number of terminal cells s occupies, ignoring escapes.
func width(s string) int { return lipgloss.Width(s) }

// fit makes s exactly n cells wide: truncated with an ellipsis when it is too
// long, padded with spaces when it is too short. Every line the view draws
// goes through it (or through a helper that does), which is what keeps a
// line from ever spilling past the terminal edge.
func (m Model) fit(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if w := width(s); w > n {
		s = ansi.Truncate(s, n, m.g.ellipsis)
	}
	if w := width(s); w < n {
		s += strings.Repeat(" ", n-w)
	}
	return s
}

// clip truncates s to at most n cells without padding.
func (m Model) clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if width(s) > n {
		return ansi.Truncate(s, n, m.g.ellipsis)
	}
	return s
}

// clean is the one door every string from a chain comes through on its
// way to the screen. Everything in a chain was written by whoever minted it:
// a subject carrying an escape sequence could repaint the screen or write
// the clipboard, and one carrying a bidi override could make "mallory" read
// as someone else. termsafe renders all of those visibly instead, in every
// mode, before anything is styled.
//
// In ASCII mode every other non-ASCII rune is transliterated or replaced
// too, so --ascii holds even for text the engine or the chain wrote.
func (m Model) clean(s string) string {
	s = termsafe.Text(s)
	if !m.g.ascii {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r > unicode.MaxASCII {
			b.WriteString(asciiFor(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func asciiFor(r rune) string {
	switch r {
	case '→':
		return "->"
	case '←':
		return "<-"
	case '…':
		return "..."
	case '·', '•':
		return "-"
	case '✓':
		return "+"
	case '✗':
		return "x"
	case '‘', '’':
		return "'"
	case '“', '”':
		return `"`
	case '–', '‑':
		return "-"
	case '≤':
		return "<="
	case '≥':
		return ">="
	case '∞':
		return "inf"
	case '§':
		return "S"
	}
	return "?"
}

// wrap breaks plain text into lines at most n cells wide, at spaces where it
// can and mid-word where a single word is longer than a line.
func wrap(s string, n int) []string {
	if n <= 0 {
		return nil
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := ""
		for _, w := range words {
			for ansi.StringWidth(w) > n {
				if line != "" {
					out = append(out, line)
					line = ""
				}
				head := ansi.Truncate(w, n, "")
				out = append(out, head)
				w = w[len(head):]
			}
			switch {
			case line == "":
				line = w
			case ansi.StringWidth(line)+1+ansi.StringWidth(w) <= n:
				line += " " + w
			default:
				out = append(out, line)
				line = w
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// wrapHanging wraps s with a first line of first cells and the rest of rest
// cells, for text that follows a label on its first line.
func wrapHanging(s string, first, rest int) []string {
	lines := wrap(s, first)
	if len(lines) <= 1 || first == rest {
		return lines
	}
	head := lines[0]
	tail := strings.TrimSpace(strings.TrimPrefix(strings.Join(strings.Fields(s), " "), head))
	return append([]string{head}, wrap(tail, rest)...)
}

// box draws a rounded frame of exactly w by h cells around body, with title
// set into the top edge. Body lines are fitted to the inner width; extra
// lines are dropped and missing ones are blank, so the frame never changes
// size with its content.
func (m Model) box(title string, body []string, w, h int, accent lipgloss.Style) []string {
	return m.frame(title, body, w, h, accent, m.t.chrome)
}

// frame is box with the border drawn in a style of the caller's choosing;
// an overlay draws its border in its accent, so it stands off the screen
// behind it.
func (m Model) frame(title string, body []string, w, h int, accent, border lipgloss.Style) []string {
	if w < 4 || h < 2 {
		return nil
	}
	g := m.g
	t := struct{ chrome lipgloss.Style }{border}
	inner := w - 4
	top := g.tl + g.h
	if title != "" {
		top += " " + accent.Render(m.clip(title, w-7)) + " "
	}
	top = t.chrome.Render(g.tl+g.h) + strings.TrimPrefix(top, g.tl+g.h)
	if fill := w - 1 - width(top); fill > 0 {
		top += t.chrome.Render(strings.Repeat(g.h, fill))
	}
	top += t.chrome.Render(g.tr)

	out := []string{m.fit(top, w)}
	side := t.chrome.Render(g.v)
	for i := 0; i < h-2; i++ {
		line := ""
		if i < len(body) {
			line = body[i]
		}
		out = append(out, side+" "+m.fit(line, inner)+" "+side)
	}
	out = append(out, t.chrome.Render(g.bl+strings.Repeat(g.h, w-2)+g.br))
	return out
}

// hjoin places blocks side by side. Each block's lines must already be the
// block's width; a block shorter than the tallest is padded with blank lines
// of its own width.
func hjoin(blocks ...[]string) []string {
	rows := 0
	for _, b := range blocks {
		rows = max(rows, len(b))
	}
	out := make([]string, rows)
	for _, b := range blocks {
		bw := 0
		if len(b) > 0 {
			bw = width(b[0])
		}
		for i := 0; i < rows; i++ {
			if i < len(b) {
				out[i] += b[i]
			} else {
				out[i] += strings.Repeat(" ", bw)
			}
		}
	}
	return out
}

// bar draws a meter of n cells, filled for the fraction f.
func (m Model) bar(f float64, n int, on lipgloss.Style) string {
	if n <= 0 {
		return ""
	}
	f = min(max(f, 0), 1)
	k := int(f*float64(n) + 0.5)
	if f > 0 && k == 0 {
		k = 1
	}
	return on.Render(strings.Repeat(m.g.barOn, k)) + m.t.slate.Render(strings.Repeat(m.g.barOff, n-k))
}

// ansiStrip removes every escape sequence from s.
func ansiStrip(s string) string { return ansi.Strip(s) }
