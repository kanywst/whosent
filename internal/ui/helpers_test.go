package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/internal/formats/fake"
)

// demoSessions mints every registered format's demo scenarios at the fixed
// base time, so every test sees the same chains, timestamps and verdicts,
// plus the fake format's, which exist to give the view shapes no real
// format has yet.
func demoSessions(t *testing.T) []Session {
	t.Helper()
	var out []Session
	scenarios := all.Registry().Scenarios()
	scenarios = append(scenarios, fake.New().Scenarios()...)
	for _, sc := range scenarios {
		s, err := sc.Open(demo.FixedBase)
		if err != nil {
			t.Fatalf("minting %s: %v", sc.Name, err)
		}
		out = append(out, Session{Name: sc.Name, Title: sc.Title, Summary: sc.Summary, Chain: s})
	}
	return out
}

func scenario(t *testing.T, name string) Session {
	t.Helper()
	for _, s := range demoSessions(t) {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no scenario %q", name)
	return Session{}
}

// sized is a model with a terminal of w by h, motion off, ready to draw.
func sized(t *testing.T, cfg Config, w, h int) Model {
	t.Helper()
	m := New(cfg)
	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(Model)
}

func open(t *testing.T, name string, w, h int) Model {
	t.Helper()
	return sized(t, Config{Sessions: []Session{scenario(t, name)}}, w, h)
}

// keyPress is a key as the terminal would deliver it.
func keyPress(k string) tea.KeyPressMsg {
	switch k {
	case "left":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft})
	case "right":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyRight})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape})
	case "backspace":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyBackspace})
	case "space":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "})
	}
	r := []rune(k)[0]
	return tea.KeyPressMsg(tea.Key{Code: r, Text: k})
}

// press feeds keys to the model in order and returns where it ends up.
// Commands are not run: every key acts synchronously, and ticks are tested
// on their own.
func press(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		next, _ := m.Update(keyPress(k))
		m = next.(Model)
	}
	return m
}

func plain(m Model) string { return ansi.Strip(m.View().Content) }

// TestDump writes renders to a directory for a person to look at. It does
// nothing unless WHOSENT_DUMP names the directory.
func TestDump(t *testing.T) {
	dir := os.Getenv("WHOSENT_DUMP")
	if dir == "" {
		t.Skip("set WHOSENT_DUMP=dir to write renders")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	type shot struct {
		name, scenario string
		keys           []string
	}
	shots := []shot{
		{"healthy", "healthy", nil},
		{"multifault", "multifault", nil},
		{"unchecked", "unchecked", nil},
		{"widened", "widened", nil},
		{"spliced-raw", "spliced", []string{"r"}},
		{"expired-scrubbed", "healthy", []string{"t", "right", "right", "right", "]", "]"}},
		{"revoke-sim", "healthy", []string{"right", "x"}},
		{"ask", "healthy", []string{"a"}},
		{"answer", "healthy", []string{"a", "enter"}},
		{"answer-widened", "widened", []string{"a", "enter"}},
		{"help", "healthy", []string{"?"}},
		{"stacked-link", "multifault", []string{"tab"}},
	}
	sizes := [][2]int{{140, 45}, {90, 30}, {200, 60}, {60, 18}}
	for _, s := range shots {
		for _, sz := range sizes {
			m := open(t, s.scenario, sz[0], sz[1])
			m = press(t, m, s.keys...)
			base := filepath.Join(dir, s.name+"-"+itoa(sz[0])+"x"+itoa(sz[1]))
			_ = os.WriteFile(base+".txt", []byte(plain(m)), 0o644)
			_ = os.WriteFile(base+".ansi", []byte(m.View().Content), 0o644)
		}
	}
	_ = time.Now
	_ = strings.Contains
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + func() string { return fmtInt(n) }())
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
