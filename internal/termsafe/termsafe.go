// Package termsafe makes untrusted text safe to print to a terminal.
//
// Everything whosent shows about a chain comes from the chain: subjects,
// issuers, jtis, resource ids, condition values, and library error text that
// quotes them back. A chain is attacker-supplied, so printing those strings
// raw hands the attacker the terminal. An ESC sequence can clear the screen
// and draw a fake "VALID" over the real verdict, OSC 52 writes the clipboard
// on terminals that honour it, a carriage return overwrites the start of a
// line, and a bidi override reorders what a line appears to say without
// changing a byte of it.
//
// Text renders every such character visibly instead, so the reader sees that
// it was there rather than what it would have done.
package termsafe

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Unsafe reports whether r must not reach a terminal raw: C0 and C1
// controls, DEL, the bidi embedding, override, isolate and mark characters,
// and the Unicode line and paragraph separators (which some viewers break a
// line on, so they can forge a line as well as a newline can).
func Unsafe(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

// Text returns s with every unsafe character, and every byte that is not
// valid UTF-8, replaced by a visible escape: `\x1b` for a control below
// U+0080 or an invalid byte, `\u202e` for the rest. Everything else,
// including emoji and non-Latin scripts, is left as it is.
//
// An invalid byte is escaped rather than replaced with U+FFFD because a lone
// 0x9b is CSI on a terminal running 8-bit controls, and because the person
// reading the report should see the bytes that were sent.
func Text(s string) string {
	if !needs(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x80 && Unsafe(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case Unsafe(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// needs is the fast path: most strings are printable ASCII and come back
// unchanged without allocating.
func needs(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
		if c >= 0x80 {
			for _, r := range s[i:] {
				if r == utf8.RuneError || Unsafe(r) {
					return true
				}
			}
			return false
		}
	}
	return false
}

// Contains reports whether s holds anything Text would escape. Tests use it
// to assert that output is clean.
func Contains(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if Unsafe(r) {
			return true
		}
	}
	return false
}

// JSON escapes, as \uXXXX, every unsafe character encoding/json leaves raw
// in its output: DEL, the C1 controls, the bidi characters and anything else
// Unsafe names above U+007E. encoding/json already escapes the C0 controls
// and U+2028/U+2029, but `whosent check --json` is printed to terminals as
// often as it is piped, and a bidi override in a subject reorders what the
// reader sees there just as it does in the human report.
//
// The input must be the output of a JSON encoder. Outside strings JSON is
// ASCII, so every rune replaced here is inside a string, where \uXXXX
// decodes back to the same character: the document means exactly what it
// meant before.
func JSON(b []byte) []byte {
	if !needsJSON(b) {
		return b
	}
	out := make([]byte, 0, len(b)+16)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if (r >= 0x80 || r == 0x7f) && Unsafe(r) {
			out = fmt.Appendf(out, `\u%04x`, r)
		} else {
			out = append(out, b[i:i+size]...)
		}
		i += size
	}
	return out
}

func needsJSON(b []byte) bool {
	for i := 0; i < len(b); {
		if b[i] == 0x7f {
			return true
		}
		if b[i] < 0x80 {
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if Unsafe(r) {
			return true
		}
		i += size
	}
	return false
}
