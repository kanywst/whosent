package termsafe

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain ASCII comes back unchanged", in: "spiffe://example.org/ns/agents/planner", want: "spiffe://example.org/ns/agents/planner"},
		{name: "non-Latin scripts and emoji are not escaped", in: "アリス ✅ 🤖 é", want: "アリス ✅ 🤖 é"},
		{name: "an ESC sequence is shown, not run", in: "alice\x1b[2J\x1b[H", want: `alice\x1b[2J\x1b[H`},
		{name: "OSC 52 with its BEL terminator is shown", in: "\x1b]52;c;aGk=\x07", want: `\x1b]52;c;aGk=\x07`},
		{name: "a carriage return cannot rewrite the line", in: "ok\rVALID", want: `ok\x0dVALID`},
		{name: "a newline cannot forge a line", in: "a\nb", want: `a\x0ab`},
		{name: "a tab is escaped so columns stay honest", in: "a\tb", want: `a\x09b`},
		{name: "DEL is escaped", in: "a\x7fb", want: `a\x7fb`},
		{name: "a C1 control encoded as UTF-8 is escaped", in: "a\u009b31mb", want: `a\u009b31mb`},
		{name: "a lone 0x9b byte (8-bit CSI) is escaped", in: "a\x9b31mb", want: `a\x9b31mb`},
		{name: "invalid UTF-8 is escaped byte by byte", in: "a\xff\xfeb", want: `a\xff\xfeb`},
		{name: "a bidi override cannot reorder the line", in: "user\u202egnp.exe", want: `user\u202egnp.exe`},
		{name: "bidi isolates are escaped", in: "\u2066x\u2069", want: `\u2066x\u2069`},
		{name: "bidi marks are escaped", in: "\u200e\u200f\u061c", want: `\u200e\u200f\u061c`},
		{name: "line and paragraph separators are escaped", in: "a\u2028b\u2029", want: `a\u2028b\u2029`},
		{name: "the zero width joiner inside an emoji is left alone", in: "\U0001F469\u200d\U0001F4BB", want: "\U0001F469\u200d\U0001F4BB"},
		{name: "the empty string stays empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Text(tt.in)
			if got != tt.want {
				t.Errorf("Text(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if Contains(got) {
				t.Errorf("Text(%q) = %q still holds something a terminal would act on", tt.in, got)
			}
		})
	}
}

func TestContains(t *testing.T) {
	if Contains("plain ✅ text") {
		t.Error("clean text reported as unsafe")
	}
	for _, s := range []string{"\x1b", "\u202e", "\x9b", "a\nb"} {
		if !Contains(s) {
			t.Errorf("Contains(%q) = false; the clean-output assertions would pass vacuously", s)
		}
	}
}

func FuzzText(f *testing.F) {
	for _, s := range []string{"", "plain", "\x1b[31mred", "\x1b]52;c;x\x07", "\u202e", "\xff", "\x9b", "\U0001F469\u200d\U0001F4BB", "\r\n\t"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Text(s)
		if Contains(got) {
			t.Fatalf("Text(%q) = %q, which still holds an unsafe character", s, got)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("Text(%q) = %q is not valid UTF-8", s, got)
		}
		if !Contains(s) && got != s {
			t.Fatalf("Text changed clean input %q to %q", s, got)
		}
		// Nothing printable may be lost: every safe rune of the input is in
		// the output, in order.
		var kept strings.Builder
		for _, r := range s {
			if r != utf8.RuneError && !Unsafe(r) {
				kept.WriteRune(r)
			}
		}
		rest := got
		for _, r := range kept.String() {
			i := strings.IndexRune(rest, r)
			if i < 0 {
				t.Fatalf("Text(%q) = %q dropped %q", s, got, r)
			}
			rest = rest[i+utf8.RuneLen(r):]
		}
	})
}

func BenchmarkTextClean(b *testing.B) {
	s := "spiffe://example.org/ns/agents/retriever"
	for b.Loop() {
		_ = Text(s)
	}
}

func TestJSON(t *testing.T) {
	in := map[string]string{"sub": "alice\u202eevil\u009b31m\u2066x\u200f", "plain": "アリス ✅"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got := JSON(raw)
	if Contains(string(got)) {
		t.Fatalf("JSON left an unsafe character in %s", got)
	}
	var back map[string]string
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("JSON broke the document: %v\n%s", err, got)
	}
	if back["sub"] != in["sub"] || back["plain"] != in["plain"] {
		t.Errorf("JSON changed what the document means: %q", back)
	}
	clean := []byte(`{"a":"b ✅"}`)
	if string(JSON(clean)) != string(clean) {
		t.Error("JSON changed a clean document")
	}
}

func FuzzJSON(f *testing.F) {
	f.Add("alice\u202e", "\u009b")
	f.Fuzz(func(t *testing.T, k, v string) {
		raw, err := json.Marshal(map[string]any{k: v, "list": []string{v, k}})
		if err != nil {
			return
		}
		got := JSON(raw)
		if Contains(string(got)) {
			t.Fatalf("unsafe character left in %q", got)
		}
		var a, b any
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got, &b); err != nil {
			t.Fatalf("JSON broke the document: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("JSON changed the meaning: %v vs %v", a, b)
		}
	})
}
