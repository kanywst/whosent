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

	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/revoke"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/internal/termsafe"
)

// hostile is what an attacker writes into every string of a chain: clear
// the screen and draw a fake verdict, write the clipboard (OSC 52), rewrite
// the line with a carriage return, forge a new line, reverse the text that
// follows (bidi override), and an 8-bit CSI as a C1 code point.
const hostile = "\x7f\x1b[2J\x1b[H✅ VALID: every rule checked\x1b[8m\x1b]52;c;aGk=\x07\rOK\nforged line\u202eevil\u009b31m\u2028"

// hostileChain mints a two-link chain whose every attacker-chosen string is
// hostile, and which fails enough rules (V5, V6, V8, V9) that the library's
// error text, quoting those strings, reaches every section of the report.
func hostileChain(t *testing.T, dir string) []string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	h := func(s string) string { return s + hostile }
	capOf := func(id string) mda.Capability {
		return mda.Capability{
			Resource:   mda.ResourcePattern{Type: h("mcp_tool"), ID: h(id), Tags: []string{h("tag")}},
			Action:     mda.ActionPattern{Name: h("invoke")},
			Conditions: map[string]mda.Condition{h("args.host"): {In: []string{h("docs"), h("www")}}},
		}
	}
	root := mda.Sponsor{Issuer: h("https://idp"), Subject: h("alice"), AuthenticationMethods: []string{h("pwd")}}
	c0 := mda.Claims{
		Issuer: h("idp"), Subject: h("planner"), Audience: h("aud"),
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ID: h("jti-0"),
		Mandatum: mda.Mandatum{
			Version: mda.Version, Root: root, MaxDepth: 2, Capabilities: []mda.Capability{capOf("search")},
			Sequence: &mda.Sequence{MaxInvocations: 10, Constraints: []mda.Constraint{{
				ID: h("rule"), Forbid: mda.ActionMatcher{ResourceTags: []string{h("w")}}, After: mda.ActionMatcher{ResourceTags: []string{h("r")}},
			}}},
		},
	}
	raw0, err := jose.Sign(c0, priv, h("kid"))
	if err != nil {
		t.Fatal(err)
	}
	other := root
	other.Subject = h("mallory")
	c1 := mda.Claims{
		Issuer: c0.Subject, Subject: h("fetcher"), Audience: c0.Audience,
		IssuedAt: c0.IssuedAt, ExpiresAt: now.Add(30 * time.Minute).Unix(), ID: h("jti-1"),
		Mandatum: mda.Mandatum{
			Version: mda.Version, Root: other, Parent: mda.Digest(raw0), Depth: 1, MaxDepth: 0,
			Capabilities: []mda.Capability{capOf("search"), capOf("wipe")},
			Sequence:     &mda.Sequence{MaxInvocations: 5, Constraints: []mda.Constraint{{ID: h("added"), Forbid: mda.ActionMatcher{Action: h("x")}, After: mda.ActionMatcher{Action: h("y")}}}},
		},
	}
	raw1, err := jose.Sign(c1, priv, h("kid"))
	if err != nil {
		t.Fatal(err)
	}

	chain, _ := json.Marshal([]string{string(raw0), string(raw1)})
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
	write("jwks.json", jwks)
	// A trust file rather than --jwks: the hostile issuer contains "=",
	// which is where --jwks splits.
	trustFile, _ := json.Marshal(map[string]any{"issuers": map[string]any{c0.Issuer: map[string]string{"jwks_file": "jwks.json"}}})
	set, err := revoke.NewSet([]string{c0.ID}, 0.001, 1, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := set.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		write("chain.json", chain),
		"--trust", write("trust.json", trustFile),
		"--revocations", write("revocation.json", enc),
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
		"check-bare": {"check", args[0]},
		"ask":        append([]string{"ask", "--resource-type", "mcp_tool" + hostile, "--resource-id", "search" + hostile, "--attr", "args.host=docs" + hostile}, args...),
		"ask-bare":   {"ask", args[0], "--resource-id", "wipe" + hostile},
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

	for _, n := range demo.Names() {
		t.Run("demo/"+n, func(t *testing.T) {
			_, a := emit(t, n)
			_, out, errOut := runCmd(t, "", append([]string{"check"}, a...)...)
			assertClean(t, "stdout", out)
			assertClean(t, "stderr", errOut)
			_, out, errOut = runCmd(t, "", append([]string{"ask", "--resource-id", "web.fetch"}, a...)...)
			assertClean(t, "stdout", out)
			assertClean(t, "stderr", errOut)
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
		append([]string{"ask", "--json", "--resource-id", "search" + hostile}, args...),
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
