package ui

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kanywst/whosent/internal/termsafe"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// hostile is what a chain's author could put in any string field to take
// over the terminal of whoever inspects it: a screen clear and a fake
// verdict, an OSC 52 clipboard write, a carriage return that overwrites the
// line, a newline that forges one, and a bidi override that reverses text.
const hostile = "evil\x1b[2J\x1b[H\x1b[32m VALID \x1b]52;c;cm0gLXJmIH4=\x07\rok\nforged\u202egnp.exe\u2066x\u2069\x9b31m"

// hostileLink is a compact serialization whose every string is hostile. It is
// not signed by anyone; the view must still draw it, and draw it safely.
func hostileLink(t *testing.T, depth int, parent string) []byte {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := map[string]any{"alg": "EdDSA", "typ": "mdt+jwt", "kid": hostile}
	mdt := map[string]any{
		"v":         1,
		"root":      map[string]any{"iss": hostile, "sub": hostile, "amr": []string{hostile}},
		"depth":     depth,
		"max_depth": 3 - depth,
		"cap": []map[string]any{{
			"resource":   map[string]any{"type": hostile, "id": hostile + "*", "tags": []string{hostile}},
			"action":     map[string]any{"name": hostile},
			"conditions": map[string]any{hostile: map[string]any{"eq": hostile, "in": nil}},
		}},
		"seq": map[string]any{"max_invocations": 5, "constraints": []map[string]any{{
			"id":     hostile,
			"forbid": map[string]any{"action": hostile},
			"after":  map[string]any{"resource.tags": []string{hostile}},
		}}},
	}
	if parent != "" {
		mdt["parent"] = parent
	}
	claims := map[string]any{
		"iss": hostile, "sub": hostile + "-" + string(rune('a'+depth)), "aud": hostile,
		"iat": 1789200000, "exp": 1789203600, "jti": hostile, "mdt": mdt,
	}
	return []byte(enc(header) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not a signature")))
}

// TestAHostileChainCannotReachTheTerminal renders every view of a chain whose
// every string is an attack, removes the colour sequences lipgloss itself
// writes, and checks nothing a terminal would act on is left.
func TestAHostileChainCannotReachTheTerminal(t *testing.T) {
	l0 := hostileLink(t, 0, "")
	l1 := hostileLink(t, 1, diagnose.Short("sha-256:"+hostile))
	aud := hostile
	s := Session{
		Name: hostile, Title: hostile, Summary: hostile,
		Links:   [][]byte{l0, l1, []byte(hostile)},
		Options: diagnose.Options{Audience: &aud},
		Input:   diagnose.InputInfo{Source: hostile, Format: hostile, ToolCall: &diagnose.ToolCall{Name: hostile}},
	}
	for _, v := range views {
		for _, sz := range [][2]int{{140, 45}, {80, 24}} {
			for _, keys := range [][]string{v.keys, append([]string{"right"}, v.keys...), append([]string{"right", "right"}, v.keys...)} {
				m := press(t, sized(t, Config{Sessions: []Session{s}}, sz[0], sz[1]), keys...)
				out := sgr.ReplaceAllString(m.View().Content, "")
				for _, line := range strings.Split(out, "\n") {
					if !utf8.ValidString(line) {
						t.Fatalf("%s %v at %dx%d: invalid UTF-8 reached the terminal in:\n%q", v.name, keys, sz[0], sz[1], line)
					}
					for _, r := range line {
						if termsafe.Unsafe(r) {
							t.Fatalf("%s %v at %dx%d: %q reached the terminal in:\n%q", v.name, keys, sz[0], sz[1], r, line)
						}
					}
				}
			}
		}
	}
}
