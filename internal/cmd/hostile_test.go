package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/internal/termsafe"
)

// hostile is what an attacker writes into every string of a chain: clear
// the screen and draw a fake verdict, write the clipboard (OSC 52), rewrite
// the line with a carriage return, forge a new line, reverse the text that
// follows (bidi override), and an 8-bit CSI as a C1 code point.
// hostileWord is hostile without its spaces, for a value read as one word
// (a scope).
var hostileWord = strings.ReplaceAll(hostile, " ", "")

const hostile = "\x7f\x1b[2J\x1b[H✅ VALID: every rule checked\x1b[8m\x1b]52;c;aGk=\x07\rOK\nforged line\u202eevil\u009b31m\u2028"

// hostileChain mints a bundle of two exchanged JWTs whose every
// attacker-chosen string is hostile, and which fails enough rules (the
// second exchange splices in a stranger and gains a scope) that error text
// quoting those strings reaches every section of the report.
func hostileChain(t *testing.T, dir string) []string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	h := func(s string) string { return s + hostile }
	iss, kid := h("https://idp"), h("kid")
	mint := func(claims map[string]any) string {
		hdr, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "typ": "at+jwt"})
		body, _ := json.Marshal(claims)
		input := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
		return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
	}
	actor := func(sub string, inner map[string]any) map[string]any {
		a := map[string]any{"sub": h(sub), "iss": iss, "sub_profile": h("ai_agent")}
		if inner != nil {
			a["act"] = inner
		}
		return a
	}
	t0 := mint(map[string]any{
		"iss": iss, "sub": h("alice"), "aud": h("aud"), "jti": h("jti-0"), "client_id": h("chat"),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"scope": h("files:read"), "act": actor("planner", nil), "may_act": map[string]any{"sub": h("fetcher"), "iss": iss},
	})
	t1 := mint(map[string]any{
		"iss": iss, "sub": h("alice"), "aud": h("aud"), "jti": h("jti-1"), "client_id": h("fetcher"),
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(2 * time.Hour).Unix(),
		"scope": h("files:read") + " " + h("admin"), "act": actor("fetcher", actor("mallory", nil)),
	})

	tokens, _ := json.Marshal([]string{t0, t1})
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
	write("jwks.json", jwks)
	// A trust file rather than --jwks: the hostile issuer contains "=",
	// which is where --jwks splits.
	trustFile, _ := json.Marshal(map[string]any{"issuers": map[string]any{iss: map[string]string{"jwks_file": "jwks.json"}}})
	return []string{
		write("tokens.json", tokens),
		"--format", "jwt",
		"--trust", write("trust.json", trustFile),
		"--audience", "https://elsewhere",
	}
}

// assertClean fails if any line of out holds a character a terminal acts
// on. Newlines are the report's own, so the check is per line.
func assertClean(t *testing.T, label, out string) {
	t.Helper()
	for i, line := range strings.Split(out, "\n") {
		if termsafe.Contains(line) {
			t.Errorf("%s line %d carries a raw control or bidi character: %q", label, i+1, line)
		}
	}
}

// A chain is attacker-supplied, and nearly everything a report prints comes
// from it. If any of it reached the terminal raw, the attacker could clear
// the screen and draw "VALID" over the real verdict, or write the reader's
// clipboard. Every human output path is run against a chain that tries all
// of it, and against every demo scenario.
func TestHumanOutputNeverCarriesRawControlCharacters(t *testing.T) {
	dir := t.TempDir()
	args := hostileChain(t, dir)
	runs := map[string][]string{
		"check":      append([]string{"check"}, args...),
		"check-bare": {"check", args[0], "--format", "jwt"},
		"ask":        append([]string{"ask", "--scope", "admin" + hostileWord}, args...),
		"ask-bare":   {"ask", args[0], "--format", "jwt", "--scope", "files:read" + hostileWord},
	}
	for name, a := range runs {
		t.Run(name, func(t *testing.T) {
			_, out, errOut := runCmd(t, "", a...)
			if !strings.Contains(out, `\x1b`) {
				t.Fatalf("the hostile strings never reached the report, so this test proves nothing:\n%s", out)
			}
			assertClean(t, "stdout", out)
			assertClean(t, "stderr", errOut)
		})
	}

	// The hostile report must still say what the chain really is.
	_, out, _ := runCmd(t, "", append([]string{"check"}, args...)...)
	if !strings.Contains(out, "INVALID") {
		t.Errorf("the real verdict is missing:\n%s", out)
	}

	for _, sc := range all.Registry().Scenarios() {
		if sc.Emit == nil {
			continue
		}
		t.Run("demo/"+sc.Name, func(t *testing.T) {
			a := emitScenario(t, sc.Name)
			for _, cmd := range [][]string{{"check"}, {"ask"}} {
				_, out, errOut := runCmd(t, "", append(cmd, a...)...)
				assertClean(t, "stdout", out)
				assertClean(t, "stderr", errOut)
			}
		})
	}
}

// JSON output is escaped by encoding/json; this pins that, so a future
// change to a hand-built encoder cannot quietly undo it.
func TestJSONOutputEscapesHostileStrings(t *testing.T) {
	dir := t.TempDir()
	args := hostileChain(t, dir)
	for _, a := range [][]string{
		append([]string{"check", "--json"}, args...),
		append([]string{"ask", "--json", "--scope", "admin" + hostileWord}, args...),
	} {
		_, out, _ := runCmd(t, "", a...)
		if !json.Valid([]byte(out)) {
			t.Fatalf("%s: not JSON:\n%s", a[0], out)
		}
		if !strings.Contains(out, `\u001b`) {
			t.Fatalf("%s: the hostile strings never reached the JSON, so this test proves nothing", a[0])
		}
		assertClean(t, a[0]+" --json", out)
	}
}

// An error message can quote its input back; a hostile file name or a
// hostile byte in malformed JSON must not reach the terminal raw either.
func TestErrorsNeverCarryRawControlCharacters(t *testing.T) {
	dir := t.TempDir()
	for _, a := range [][]string{
		{"check", "--jwks", "\x1b[2Jno-equals-sign"},
		{"check", filepath.Join(dir, "missing\x1b]52;c;aGk=\x07")},
		{"check", "--at", "\x1b[2J"},
	} {
		code, out, errOut := runCmd(t, "", a...)
		if code != ExitUsage {
			t.Errorf("%q: exit %d, want %d", a, code, ExitUsage)
		}
		if !strings.Contains(errOut, `\x1b`) {
			t.Errorf("%q: the hostile bytes never reached the error, so this case proves nothing: %q", a, errOut)
		}
		assertClean(t, "stdout", out)
		assertClean(t, "stderr", errOut)
	}
}
