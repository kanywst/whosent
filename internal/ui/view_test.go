package ui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/chain"
)

// views are the screens a person can reach, as the keys that reach them.
var views = []struct {
	name string
	keys []string
}{
	{"main", nil},
	{"next link", []string{"right"}},
	{"raw", []string{"r"}},
	{"time mode, scrubbed", []string{"t", "right", "right", "]"}},
	{"revocation simulated", []string{"x"}},
	{"help", []string{"?"}},
	{"ask form", []string{"a"}},
	{"answer", []string{"a", "enter"}},
	{"other panel", []string{"tab"}},
	{"last row selected", []string{"down", "down", "down", "down", "down"}},
}

var sizes = [][2]int{
	{60, 18}, {64, 20}, {72, 22}, {80, 24}, {90, 30}, {100, 32}, {119, 40}, {120, 40}, {140, 45}, {160, 50}, {200, 60},
}

// TestEveryLineFitsTheTerminal draws every scenario, in every view, at every
// size, and checks that no line spills past the right edge and that the
// screen is exactly as tall as the terminal. A line one cell too wide wraps,
// and a wrapped line pushes everything under it down: the whole screen tears.
func TestEveryLineFitsTheTerminal(t *testing.T) {
	sessions := demoSessions(t)
	for _, s := range sessions {
		for _, v := range views {
			for _, sz := range sizes {
				name := fmt.Sprintf("%s/%s/%dx%d", s.Name, v.name, sz[0], sz[1])
				t.Run(name, func(t *testing.T) {
					m := press(t, sized(t, Config{Sessions: []Session{s}}, sz[0], sz[1]), v.keys...)
					lines := strings.Split(m.View().Content, "\n")
					if len(lines) != sz[1] {
						t.Errorf("drew %d lines on a %d line terminal", len(lines), sz[1])
					}
					for i, l := range lines {
						if w := ansi.StringWidth(l); w > sz[0] {
							t.Errorf("line %d is %d cells on a %d cell terminal:\n%s", i, w, sz[0], ansi.Strip(l))
						}
					}
				})
			}
		}
	}
}

// TestEachScenarioSaysWhatIsWrongWithIt checks the facts a person opens the
// tool to learn are on the first screen: the verdict, where the chain
// breaks, the rules that failed, and that nothing below a break looks alive.
func TestEachScenarioSaysWhatIsWrongWithIt(t *testing.T) {
	for _, name := range demo.Names() {
		t.Run(name, func(t *testing.T) {
			sc, err := demo.Build(name, demo.FixedBase)
			if err != nil {
				t.Fatal(err)
			}
			m := open(t, name, 160, 50)
			got := plain(m)
			r := m.report

			if !strings.Contains(got, string(r.Verdict)) {
				t.Errorf("the screen never says %s", r.Verdict)
			}
			if string(r.Verdict) != string(sc.Verdict) {
				t.Errorf("the view diagnosed %s, the scenario is %s", r.Verdict, sc.Verdict)
			}
			if r.BreakAt >= 0 {
				want := fmt.Sprintf("Breaks at link %d", r.BreakAt)
				if !strings.Contains(got, want) {
					t.Errorf("the banner does not say %q:\n%s", want, got)
				}
			}
			for _, e := range sc.ExpectAll {
				want := fmt.Sprintf("%s link %d", e.Rule, e.Link)
				if !strings.Contains(got, want) {
					t.Errorf("the findings do not mention %q", want)
				}
			}
			unreached := 0
			for _, l := range r.Links {
				if l.Unreached {
					unreached++
				}
			}
			if unreached > 0 && !strings.Contains(got, "unreached") {
				t.Error("links below the break are not marked unreached")
			}
			if r.Verdict == chain.VerdictValid && strings.Contains(got, "unreached") {
				t.Error("a valid chain shows an unreached link")
			}
		})
	}
}

// TestUncheckedNeverLooksVerified is the honesty rule: a signature nobody had
// a key for must not be drawn the way a verified one is.
func TestUncheckedNeverLooksVerified(t *testing.T) {
	m := open(t, "unchecked", 160, 50)
	got := plain(m)
	for _, unwanted := range []string{"✓ verified", "✓ V3", "✓ V8", "✓ V9", "✓ VALID"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("an unchecked chain shows %q", unwanted)
		}
	}
	for _, want := range []string{"INCOMPLETE", "○ unverified", "○ V3", "no keys for 3 issuers", "none given"} {
		if !strings.Contains(got, want) {
			t.Errorf("an unchecked chain does not show %q", want)
		}
	}
}

// TestFlowInIsAFunctionOfTheFrame renders frames of the opening animation
// twice and checks they match, and that it ends on exactly the picture a
// view with motion off shows from the start.
func TestFlowInIsAFunctionOfTheFrame(t *testing.T) {
	cfg := Config{Sessions: []Session{scenario(t, "multifault")}, Motion: true}
	m := sized(t, cfg, 140, 45)
	if !m.anim.running() {
		t.Fatal("motion is on but nothing animates")
	}
	total := m.anim.total
	for f := 0; f <= total; f++ {
		m.anim.frame = f
		a, b := m.View().Content, m.View().Content
		if a != b {
			t.Fatalf("frame %d renders differently twice", f)
		}
	}
	m.anim.frame = 0
	first := plain(m)
	if strings.Contains(first, "✓ verified") {
		t.Error("frame 0 shows an agent verified before authority reached it")
	}
	m.anim.frame = total
	still := sized(t, Config{Sessions: cfg.Sessions}, 140, 45)
	if plain(m) != plain(still) {
		t.Error("the last frame is not the still picture")
	}
	if m.tick() != nil {
		t.Error("a finished animation still schedules ticks; an idle screen must not redraw")
	}
}

// TestAKeySkipsTheAnimation: a fast user is never made to wait.
func TestAKeySkipsTheAnimation(t *testing.T) {
	m := sized(t, Config{Sessions: []Session{scenario(t, "healthy")}, Motion: true}, 140, 45)
	m = press(t, m, "right")
	if m.anim.running() {
		t.Error("the animation is still running after a key")
	}
	if m.sel != 1 {
		t.Errorf("the key that skipped the animation did not also act: selection is %d", m.sel)
	}
}

func TestStaleTicksAreIgnored(t *testing.T) {
	m := sized(t, Config{Sessions: []Session{scenario(t, "healthy")}, Motion: true}, 140, 45)
	gen := m.anim.gen
	m = press(t, m, "space")
	next, cmd := m.Update(tickMsg{gen: gen})
	if next.(Model).anim.frame != 0 || cmd != nil {
		t.Error("a tick from a replaced animation advanced the new one")
	}
}

func TestKeysDriveTheView(t *testing.T) {
	cfg := Config{Sessions: demoSessions(t)}
	m := sized(t, cfg, 140, 45)

	if m = press(t, m, "right"); m.sel != 1 {
		t.Errorf("right selects link %d, want 1", m.sel)
	}
	if m = press(t, m, "left", "left"); m.sel != 0 {
		t.Errorf("left past the first link selects %d, want 0", m.sel)
	}
	row := m.row
	if m = press(t, m, "down"); m.row != row+1 {
		t.Errorf("down selects row %d, want %d", m.row, row+1)
	}
	if m = press(t, m, "t"); !m.clock {
		t.Error("t does not enter time mode")
	}
	if m = press(t, m, "right"); m.offset <= 0 {
		t.Error("right in time mode does not move the clock forward")
	}
	if m = press(t, m, "0"); m.offset != 0 {
		t.Error("0 does not bring the clock back")
	}
	if m = press(t, m, "esc"); m.clock {
		t.Error("esc does not leave time mode")
	}
	if m = press(t, m, "r"); !m.raw {
		t.Error("r does not show the raw assertion")
	}
	if m = press(t, m, "?"); m.overlay != overlayHelp {
		t.Error("? does not open help")
	}
	if m = press(t, m, "j"); m.overlay != overlayNone {
		t.Error("a key does not close help")
	}
	if m = press(t, m, "n"); m.cur != 1 {
		t.Errorf("n opens session %d, want 1", m.cur)
	}
	if m = press(t, m, "p", "p"); m.cur != len(cfg.Sessions)-1 {
		t.Errorf("p from the first session opens %d, want the last", m.cur)
	}
	_, cmd := m.Update(keyPress("q"))
	if cmd == nil {
		t.Fatal("q returns no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("q does not quit")
	}
}

// TestScrubbingPastTheLeafsExpiryBreaksTheChain is the time scrub doing what
// it is for: showing when the chain dies.
func TestScrubbingPastTheLeafsExpiryBreaksTheChain(t *testing.T) {
	m := open(t, "healthy", 140, 45)
	if m.report.Verdict != chain.VerdictValid {
		t.Fatalf("healthy starts %s", m.report.Verdict)
	}
	leaf := len(m.report.Links) - 1
	for i := 0; i < 200 && m.report.Verdict == chain.VerdictValid; i++ {
		m = press(t, m, "]")
	}
	r := m.report
	if r.Verdict != chain.VerdictInvalid {
		t.Fatal("scrubbing forward never expired anything")
	}
	if r.BreakAt != leaf || r.Links[leaf].Check("V4").Status != chain.StatusFail {
		t.Errorf("the first thing to expire is link %d, want the leaf (%d) failing V4", r.BreakAt, leaf)
	}
	if got := plain(m); !strings.Contains(got, "V4") || !strings.Contains(got, "expired") {
		t.Error("the screen does not say the leaf expired")
	}
	if m = press(t, m, "0"); m.report.Verdict != chain.VerdictValid {
		t.Error("0 does not bring the chain back to valid")
	}
}

func TestScrubStaysWithinTheChainsLifetime(t *testing.T) {
	m := open(t, "healthy", 140, 45)
	for i := 0; i < 500; i++ {
		m = press(t, m, "]")
	}
	_, hi := m.scrubRange()
	if at := m.base.Add(m.offset); at.After(hi) {
		t.Errorf("the scrub went to %s, past the end of its range %s", at, hi)
	}
}

// TestRevokingALinkKillsWhatIsBelowItAndNothingAbove is the blast radius.
func TestRevokingALinkKillsWhatIsBelowItAndNothingAbove(t *testing.T) {
	m := open(t, "healthy", 140, 45)
	m = press(t, m, "right", "x")
	r := m.report
	if len(m.sims) != 1 {
		t.Fatalf("x simulated %d revocations, want 1", len(m.sims))
	}
	if !r.Links[1].RevokedSimulated {
		t.Error("the selected link is not marked as a simulated revocation")
	}
	if r.Links[0].Unreached || r.Links[0].State != chain.LinkOK {
		t.Error("revoking link 1 touched link 0 above it")
	}
	for i := 2; i < len(r.Links); i++ {
		if !r.Links[i].Unreached {
			t.Errorf("link %d below the revoked one is still reached", i)
		}
	}
	got := plain(m)
	for _, want := range []string{"simulating 1 revocation", "revoked (sim)", "Nothing was revoked"} {
		if !strings.Contains(got, want) {
			t.Errorf("a simulated revocation does not say %q", want)
		}
	}
	if m = press(t, m, "x"); len(m.sims) != 0 || m.report.Verdict != chain.VerdictValid {
		t.Error("x again does not undo the simulation")
	}
	if m = press(t, m, "x", "X"); len(m.sims) != 0 {
		t.Error("X does not clear the simulations")
	}
}

// TestAskLabelsHowFarTheAnswerCanBeTrusted runs the ask flow end to end.
func TestAskLabelsHowFarTheAnswerCanBeTrusted(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		want     []string
	}{
		{name: "a verified chain answers authoritatively", scenario: "healthy",
			want: []string{"PERMITTED", "AUTHORITATIVE"}},
		{name: "an unchecked chain answers conditionally", scenario: "unchecked",
			want: []string{"PERMITTED IF", "CONDITIONAL"}},
		{name: "authority the sponsor granted, a link dropped and a later one re-added is called out as such", scenario: "widened",
			want: []string{"DENIED", "HYPOTHETICAL", "the sponsor granted this, link 1 dropped it", "does not bring it back"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := press(t, open(t, tt.scenario, 140, 45), "a", "enter")
			if m.overlay != overlayAnswer || m.answer == nil {
				t.Fatal("enter on the ask form gave no answer")
			}
			got := plain(m)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("the answer does not say %q:\n%s", w, got)
				}
			}
		})
	}
}

func TestAskFormRefusesAnIncompleteRequest(t *testing.T) {
	m := press(t, open(t, "healthy", 140, 45), "a", "tab", "tab")
	for i := 0; i < 40; i++ {
		m = press(t, m, "backspace")
	}
	m = press(t, m, "enter")
	if m.overlay != overlayAsk || m.ask.err == "" {
		t.Error("an empty resource id was asked about instead of refused")
	}
}

// sgr matches the colour and attribute sequences lipgloss itself writes.
var sgr = regexp.MustCompile("\x1b\\[[0-9;:]*m")

func TestNoColorDrawsNoColour(t *testing.T) {
	colour := regexp.MustCompile(`\x1b\[[0-9;]*(3[0-9]|4[0-9]|9[0-7]|10[0-7])[;m]`)
	for _, s := range demoSessions(t) {
		for _, v := range views {
			m := press(t, sized(t, Config{Sessions: []Session{s}, NoColor: true}, 140, 45), v.keys...)
			if loc := colour.FindStringIndex(m.View().Content); loc != nil {
				t.Errorf("%s/%s: NoColor output has a colour escape %q", s.Name, v.name, m.View().Content[loc[0]:loc[1]])
			}
		}
	}
}

func TestASCIIModeDrawsOnlyASCII(t *testing.T) {
	for _, s := range demoSessions(t) {
		for _, v := range views {
			m := press(t, sized(t, Config{Sessions: []Session{s}, ASCII: true}, 140, 45), v.keys...)
			for _, r := range plain(m) {
				if r > unicode.MaxASCII {
					t.Errorf("%s/%s: --ascii output has %q", s.Name, v.name, r)
					break
				}
			}
		}
	}
}

func TestATerminalTooSmallSaysSo(t *testing.T) {
	m := open(t, "healthy", 50, 15)
	if got := plain(m); !strings.Contains(got, "terminal too small") || !strings.Contains(got, "60x18") {
		t.Errorf("a 50x15 terminal is not told it is too small:\n%s", got)
	}
}

// TestAnInconsistencyIsImpossibleToMiss: if the tool and the library ever
// disagree, the screen must say so before anything else.
func TestAnInconsistencyIsImpossibleToMiss(t *testing.T) {
	m := open(t, "healthy", 140, 45)
	r := *m.report
	r.Inconsistency = &chain.Inconsistency{
		Banner: "!! INTERNAL INCONSISTENCY  whosent says the chain verifies, mandatum says V3 at link 1. Trust the library, and report this.",
		Detail: "injected",
	}
	m.report = &r
	lines := strings.Split(plain(m), "\n")
	if !strings.Contains(lines[1], "INTERNAL INCONSISTENCY") || !strings.Contains(lines[1], "V3 at link 1") {
		t.Errorf("an inconsistency is not the first thing under the header:\n%s", lines[1])
	}
}

// TestQuitWorksFromEveryView drives each view and overlay to q (or esc then
// q where q is text, as in the ask form) and checks the program is told to
// quit. A view that swallows q leaves a person with only ctrl+c.
func TestQuitWorksFromEveryView(t *testing.T) {
	tests := []struct {
		name string
		keys []string
	}{
		{"main", nil},
		{"raw", []string{"r"}},
		{"help", []string{"?"}},
		{"time mode", []string{"t", "]"}},
		{"scrubbed, out of time mode", []string{"t", "]", "esc"}},
		{"revocation simulated", []string{"x"}},
		{"ask form, after esc", []string{"a", "esc"}},
		{"answer", []string{"a", "enter"}},
		{"answer, after esc", []string{"a", "enter", "esc"}},
		{"other panel", []string{"tab"}},
		{"raw, after esc", []string{"r", "esc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, sz := range [][2]int{{140, 45}, {90, 30}} {
				m := press(t, open(t, "spliced", sz[0], sz[1]), tt.keys...)
				_, cmd := m.Update(keyPress("q"))
				if cmd == nil {
					t.Fatalf("%dx%d: q returned no command", sz[0], sz[1])
				}
				if _, ok := cmd().(tea.QuitMsg); !ok {
					t.Errorf("%dx%d: q does not quit", sz[0], sz[1])
				}
			}
		})
	}
}

// TestEscAndAKeyInOneBurstAreBothRead: esc followed fast by a key arrives as
// alt+key. "esc q" from the ask form must close the form and quit, not
// leave the form open with nothing typed.
func TestEscAndAKeyInOneBurstAreBothRead(t *testing.T) {
	m := press(t, open(t, "healthy", 140, 45), "a")
	next, cmd := m.Update(tea.KeyPressMsg(tea.Key{Code: 'q', Mod: tea.ModAlt}))
	if next.(Model).overlay != overlayNone {
		t.Error("alt+q left the ask form open")
	}
	if cmd == nil {
		t.Fatal("alt+q from the ask form did not quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("alt+q from the ask form did not quit")
	}
	m = press(t, open(t, "healthy", 140, 45), "r")
	next, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: '?', Mod: tea.ModAlt}))
	if n := next.(Model); n.raw || n.overlay != overlayHelp {
		t.Error("alt+? from raw did not leave raw and open help")
	}
}

// TestAVoidLinkHoldsNothing: a link that fails, and everything below it,
// holds no authority whatever it claims. The matrix must not draw its
// claims as holdings, and reach must read zero.
func TestAVoidLinkHoldsNothing(t *testing.T) {
	m := open(t, "healthy", 140, 45)
	for i := 0; i < 200 && m.report.Verdict == chain.VerdictValid; i++ {
		m = press(t, m, "]")
	}
	got := plain(m)
	if !strings.Contains(got, "0/3") || !strings.Contains(got, "claims") {
		t.Errorf("an expired leaf's column does not read 0/3 with its claims apart:\n%s", got)
	}
	if strings.Contains(got, "every check passes") {
		t.Error("the scenario summary still says every check passes after the chain broke")
	}
	if !strings.Contains(got, "scrubbed to") {
		t.Error("the context line does not say the clock was moved")
	}

	m = press(t, open(t, "healthy", 140, 45), "x")
	for i := range m.report.Links {
		if !m.void(i) {
			t.Errorf("revoking link 0 leaves link %d holding authority", i)
		}
	}
	if got := plain(m); strings.Count(got, "0/3") != len(m.report.Links) {
		t.Errorf("with the first link revoked every column should read 0/3:\n%s", got)
	}
}

func TestAScrubbedClockShowsTheWayBack(t *testing.T) {
	m := press(t, open(t, "healthy", 140, 45), "t", "]", "esc")
	lines := strings.Split(plain(m), "\n")
	if footer := lines[len(lines)-1]; !strings.Contains(footer, "0 back to now") {
		t.Errorf("scrubbed but out of time mode, the footer does not say how to return:\n%s", footer)
	}
}

// TestTheHeadlinesFitAtFullWidth: at 120 columns and up the verdict and
// each link's state are one line, never cut off.
func TestTheHeadlinesFitAtFullWidth(t *testing.T) {
	for _, keys := range [][]string{nil, {"right", "x"}, {"t", "]", "]"}} {
		for _, s := range demoSessions(t) {
			m := press(t, sized(t, Config{Sessions: []Session{s}}, 140, 45), keys...)
			lines := strings.Split(plain(m), "\n")
			if strings.HasPrefix(lines[2], "              ") {
				t.Errorf("%s %v: the verdict wraps at 140 columns:\n%s\n%s", s.Name, keys, lines[1], lines[2])
			}
			for _, l := range lines {
				if strings.Contains(l, "VERIFIED") || strings.Contains(l, "REVOKED") || strings.Contains(l, "UNVERIFIED") {
					if strings.Contains(l, "…") {
						t.Errorf("%s %v: the link state line is cut off:\n%s", s.Name, keys, l)
					}
				}
			}
		}
	}
}

// TestNeverGrantedIsSaidOnlyWhenTrue: "the sponsor never granted this" sends
// a reader to a different person than "a link dropped it", so each must be
// said only when it is the true story. The wording is the adapter's (its own
// test covers the other branch); the view must carry it through intact.
func TestNeverGrantedIsSaidOnlyWhenTrue(t *testing.T) {
	m := press(t, open(t, "widened", 140, 45), "a", "enter")
	if m.answer == nil || !strings.Contains(m.answer.Warning, "the sponsor granted this, link 1 dropped it") {
		t.Fatal("widened's default question is not one the sponsor granted and a hop re-added")
	}
	got := plain(m)
	if strings.Contains(got, "never granted") {
		t.Error("the answer says never granted for authority the sponsor did grant")
	}
	if !strings.Contains(got, "the sponsor granted this") {
		t.Errorf("the warning does not reach the screen:\n%s", got)
	}
}

// TestRawViewKeepsItsLines: the raw view is a JSON document, one member per
// line. Scrubbing what an adapter hands over must not flatten it into one
// line of escaped newlines.
func TestRawViewKeepsItsLines(t *testing.T) {
	m := press(t, open(t, "healthy", 140, 45), "r")
	got := plain(m)
	if strings.Contains(got, `\x0a`) {
		t.Errorf("the raw view shows escaped newlines:\n%s", got)
	}
	for _, want := range []string{`"alg": "EdDSA",`, `"typ": "mdt+jwt"`, "DIGESTS", "HEADER", "CLAIMS"} {
		if !strings.Contains(got, want) {
			t.Errorf("the raw view lacks %q:\n%s", want, got)
		}
	}
}

// TestConsequencesAreNotCountedAsFailures: one revoked link is one failure,
// however many links hang below it.
func TestConsequencesAreNotCountedAsFailures(t *testing.T) {
	if got := plain(open(t, "multifault", 140, 45)); !strings.Contains(got, "FINDINGS · 3 failing") {
		t.Errorf("multifault's three faults are not counted as three:\n%s", got)
	}
}

// TestAssertedAuthorityIsUnknownNotZero: a prior actor named inside a JWT
// has no stated authority. Its reach must not read "0/n", which would say
// it holds nothing, and the legend must not call it unreadable.
func TestAssertedAuthorityIsUnknownNotZero(t *testing.T) {
	m := open(t, "jwt-okta-style", 140, 45)
	got := plain(m)
	var reach string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "reach") {
			reach = l
		}
	}
	if strings.Contains(reach, "0/2") || strings.Count(reach, "?") < 2 {
		t.Errorf("the asserted actors' reach should read ?, not 0/2:\n%s", reach)
	}
	if !strings.Contains(got, "not in the token") || strings.Contains(got, "unreadable") {
		t.Errorf("the legend should say the authority is not in the token:\n%s", got)
	}
}

// TestAnAssertedLinkNeverGetsATick: in the vertical rail every link shows
// its marks; an asserted one passed nothing that verified it.
func TestAnAssertedLinkNeverGetsATick(t *testing.T) {
	ticked := regexp.MustCompile(`link [01]\s+✓`)
	for _, size := range [][2]int{{90, 30}, {70, 24}, {140, 45}} {
		m := open(t, "jwt-okta-style", size[0], size[1])
		if l := ticked.FindString(plain(m)); l != "" {
			t.Errorf("%dx%d: an asserted link is ticked as verified: %q", size[0], size[1], l)
		}
	}
}
