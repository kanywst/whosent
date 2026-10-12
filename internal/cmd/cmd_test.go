package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/pkg/chain"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCheckExitCodesFollowTheVerdict(t *testing.T) {
	want := map[chain.Verdict]int{
		chain.VerdictValid: ExitValid, chain.VerdictInvalid: ExitInvalid, chain.VerdictIncomplete: ExitIncomplete,
	}
	for _, sc := range all.Registry().Scenarios() {
		if sc.Emit == nil {
			continue
		}
		t.Run(sc.Name, func(t *testing.T) {
			args := append([]string{"check"}, emitScenario(t, sc.Name)...)
			_, js, _ := runCmd(t, "", append(args, "--json")...)
			var r chain.JSONChain
			if err := json.Unmarshal([]byte(js), &r); err != nil {
				t.Fatalf("%v\n%s", err, js)
			}
			code, out, errOut := runCmd(t, "", args...)
			if code != want[r.Verdict] {
				t.Errorf("exit %d, want %d for %s\n%s\n%s", code, want[r.Verdict], r.Verdict, out, errOut)
			}
			if !strings.Contains(out, string(r.Verdict)) {
				t.Errorf("report does not state the verdict:\n%s", out)
			}
		})
	}
}

func TestStrictTurnsIncompleteIntoFailure(t *testing.T) {
	args := emitScenario(t, "jwt-unchecked")
	if code, _, _ := runCmd(t, "", append([]string{"check", "--strict"}, args...)...); code != ExitInvalid {
		t.Errorf("exit %d, want %d", code, ExitInvalid)
	}
}

// Machine output is the whole of stdout, and carries no decoration. A
// script piping --json into jq must never meet an emoji.
func TestCheckJSONStdoutIsOnlyJSON(t *testing.T) {
	for _, name := range []string{"jwt-bundle-healthy", "jwt-unchecked", "biscuit-denied", "ucan-widened"} {
		t.Run(name, func(t *testing.T) {
			args := emitScenario(t, name)
			_, out, _ := runCmd(t, "", append([]string{"check", "--json"}, args...)...)
			var r chain.JSONChain
			dec := json.NewDecoder(strings.NewReader(out))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil {
				t.Fatalf("stdout is not one JSON report: %v\n%s", err, out)
			}
			if dec.More() {
				t.Error("trailing output after the JSON report")
			}
			assertUndecorated(t, out)
			if r.Schema != chain.SchemaVersion || r.Format == "" {
				t.Errorf("schema %q, format %q", r.Schema, r.Format)
			}

			// --native is the format's own report, just as strict.
			_, out, _ = runCmd(t, "", append([]string{"check", "--json", "--native"}, args...)...)
			var nr map[string]any
			dec = json.NewDecoder(strings.NewReader(out))
			if err := dec.Decode(&nr); err != nil || dec.More() {
				t.Fatalf("--native stdout is not one JSON document: %v\n%s", err, out)
			}
			assertUndecorated(t, out)
		})
	}
}

func assertUndecorated(t *testing.T, out string) {
	t.Helper()
	for _, banned := range []string{"✅", "❌", "⚠", "✓", "✗", "===", "‼"} {
		if strings.Contains(out, banned) {
			t.Errorf("machine output contains %q", banned)
		}
	}
}

func TestCheckHumanReportShowsTheBreak(t *testing.T) {
	_, out, _ := runCmd(t, "", append([]string{"check"}, emitScenario(t, "jwt-bundle-widened")...)...)
	for _, want := range []string{"INVALID", "breaks at link 2", "J8 link 2", "files:write", "How authority narrows"} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not mention %q:\n%s", want, out)
		}
	}
}

func TestCheckSaysWhatWasNotChecked(t *testing.T) {
	_, out, _ := runCmd(t, "", append([]string{"check"}, emitScenario(t, "jwt-unchecked")...)...)
	if !strings.Contains(out, "Not checked: the issuer's keys") || !strings.Contains(out, "(--audience)") {
		t.Errorf("report:\n%s", out)
	}
}

func TestCheckReadsStdinAndReverse(t *testing.T) {
	args := emitScenario(t, "jwt-bundle-healthy")
	tokens, err := os.ReadFile(args[0])
	if err != nil {
		t.Fatal(err)
	}
	rest := args[1:]
	if code, out, _ := runCmd(t, string(tokens), append([]string{"check", "-"}, rest...)...); code != ExitValid {
		t.Errorf("stdin: exit %d\n%s", code, out)
	}
	var list []string
	if err := json.Unmarshal(tokens, &list); err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	rev, _ := json.Marshal(list)
	if code, out, _ := runCmd(t, string(rev), append([]string{"check", "-", "--reverse"}, rest...)...); code != ExitValid {
		t.Errorf("--reverse: exit %d\n%s", code, out)
	}
	if code, out, _ := runCmd(t, string(rev), append([]string{"check", "-"}, rest...)...); code != ExitInvalid {
		t.Errorf("reversed without --reverse: exit %d\n%s", code, out)
	}
}

func TestUsageErrorsExitThree(t *testing.T) {
	args := emitScenario(t, "jwt-bundle-healthy")
	tokens := args[0]
	dir := filepath.Dir(tokens)
	tests := []struct {
		name    string
		args    []string
		mention string
	}{
		{"a missing chain file", []string{"check", filepath.Join(dir, "nope.json")}, "nope.json"},
		{"an unknown flag", []string{"check", tokens, "--nope"}, "unknown flag"},
		{"a skew beyond the bound", []string{"check", tokens, "--skew", "6m"}, "outside"},
		{"an unreadable --at", []string{"check", tokens, "--at", "tomorrow"}, "--at"},
		{"a missing key file", []string{"check", tokens, "--jwks", "iss=" + filepath.Join(dir, "missing.json")}, "reading keys"},
		{"a malformed --jwks", []string{"check", tokens, "--jwks", "nope"}, "ISSUER=PATH"},
		{"an unknown format", []string{"check", tokens, "--format", "nope"}, "nope"},
		{"two chains", []string{"check", tokens, tokens}, "accepts at most 1"},
		{"ask without a scope", append([]string{"ask"}, args...), "--scope"},
		{"--emit without a scenario", []string{"demo", "--emit", t.TempDir()}, "name it"},
		{"an unknown scenario", []string{"demo", "--emit", t.TempDir(), "nope"}, "unknown scenario"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCmd(t, "", tt.args...)
			if code != ExitUsage {
				t.Errorf("exit %d, want %d", code, ExitUsage)
			}
			if !strings.Contains(errOut, tt.mention) {
				t.Errorf("stderr %q does not mention %q", errOut, tt.mention)
			}
		})
	}
}

func TestInteractiveCommandsRefuseWithoutATerminal(t *testing.T) {
	args := emitScenario(t, "jwt-bundle-healthy")
	for _, a := range [][]string{args[:1], {"demo"}} {
		code, _, errOut := runCmd(t, "", a...)
		if code != ExitUsage || !strings.Contains(errOut, "terminal") {
			t.Errorf("%v: exit %d, stderr %q", a, code, errOut)
		}
	}
}

func TestAskExitCodesAndLabels(t *testing.T) {
	tests := []struct {
		scenario string
		extra    []string
		code     int
		mention  string
	}{
		{"jwt-bundle-healthy", []string{"--scope", "files:read"}, ExitValid, "PERMITTED (AUTHORITATIVE)"},
		{"jwt-bundle-healthy", []string{"--scope", "files:write"}, ExitInvalid, "DENIED"},
		{"jwt-unchecked", []string{"--scope", "files:read"}, ExitIncomplete, "CONDITIONAL"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario+" "+tt.extra[1], func(t *testing.T) {
			code, out, _ := runCmd(t, "", append(append([]string{"ask"}, emitScenario(t, tt.scenario)...), tt.extra...)...)
			if code != tt.code {
				t.Errorf("exit %d, want %d\n%s", code, tt.code, out)
			}
			if !strings.Contains(out, tt.mention) {
				t.Errorf("answer does not mention %q:\n%s", tt.mention, out)
			}
		})
	}
	t.Run("--strict refuses a conditional answer", func(t *testing.T) {
		args := append(append([]string{"ask", "--strict"}, emitScenario(t, "jwt-unchecked")...), "--scope", "files:read")
		if code, _, _ := runCmd(t, "", args...); code != ExitInvalid {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("json answers are only JSON", func(t *testing.T) {
		args := append(append([]string{"ask", "--json"}, emitScenario(t, "jwt-bundle-healthy")...), "--scope", "files:read")
		_, out, _ := runCmd(t, "", args...)
		var doc map[string]any
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if doc["authority"] != "AUTHORITATIVE" || doc["permitted"] != true {
			t.Errorf("%v", doc)
		}
		assertUndecorated(t, out)
	})
}

func TestAtParsing(t *testing.T) {
	now := time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"", now, true},
		{"now", now, true},
		{"+25m", now.Add(25 * time.Minute), true},
		{"-1h", now.Add(-time.Hour), true},
		{"1789200000", time.Unix(1789200000, 0).UTC(), true},
		{"2026-09-12T08:00:00Z", now, true},
		{"2026-09-12T17:00:00+09:00", now, true},
		{"+soon", time.Time{}, false},
		{"yesterday", time.Time{}, false},
	}
	for _, tt := range tests {
		got, err := parseAt(tt.in, now)
		if (err == nil) != tt.ok || (tt.ok && !got.Equal(tt.want)) {
			t.Errorf("parseAt(%q) = %v, %v", tt.in, got, err)
		}
	}
}

func TestExitCodeForAnInconsistentReport(t *testing.T) {
	r := &chain.Chain{Verdict: chain.VerdictValid, Inconsistency: &chain.Inconsistency{Detail: "x"}}
	if c := exitCode(r, false); c != ExitInconsistent {
		t.Errorf("exit %d, want %d: a disagreement with a reference implementation must never exit 0", c, ExitInconsistent)
	}
}

func TestDemoListAndEmit(t *testing.T) {
	code, out, _ := runCmd(t, "", "demo", "--list")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, sc := range all.Registry().Scenarios() {
		if !strings.Contains(out, sc.Name) {
			t.Errorf("--list does not name %s", sc.Name)
		}
	}
	dir := t.TempDir()
	code, out, _ = runCmd(t, "", "demo", "--emit", dir, "jwt-bundle-healthy")
	if code != 0 || !strings.Contains(out, "whosent check tokens.json") {
		t.Errorf("exit %d\n%s", code, out)
	}
	for _, f := range []string{"tokens.json", "trust.json", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCmd(t, "", "version")
	if code != 0 || !strings.HasPrefix(out, "whosent ") {
		t.Errorf("exit %d %q", code, out)
	}
}

func TestCompletionIsGenerated(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		code, out, _ := runCmd(t, "", "completion", sh)
		if code != 0 || len(out) < 100 {
			t.Errorf("%s: exit %d, %d bytes", sh, code, len(out))
		}
	}
}

// A disagreement with a reference implementation must reach the person and
// the script: a banner in the report, a line on stderr, and exit 70 from
// every command, in every output form.
func TestEveryCommandExitsSeventyOnADisagreement(t *testing.T) {
	orig := evaluateFn
	evaluateFn = func(ctx context.Context, s chain.Session, eo chain.EvalOptions) (*chain.Chain, error) {
		c, err := orig(ctx, s, eo)
		if err == nil {
			c.Inconsistency = &chain.Inconsistency{Banner: "injected", Detail: "injected disagreement"}
		}
		return c, err
	}
	t.Cleanup(func() { evaluateFn = orig })

	args := emitScenario(t, "jwt-bundle-healthy")
	for _, a := range [][]string{
		append([]string{"check"}, args...),
		append([]string{"check", "--json"}, args...),
		append([]string{"ask", "--scope", "files:read"}, args...),
		append([]string{"ask", "--json", "--scope", "files:read"}, args...),
	} {
		code, out, errOut := runCmd(t, "", a...)
		if code != ExitInconsistent {
			t.Errorf("%v: exit %d, want %d", a[:2], code, ExitInconsistent)
		}
		if !strings.Contains(errOut, "injected disagreement") {
			t.Errorf("%v: stderr does not report the disagreement: %q", a[:2], errOut)
		}
		if a[1] != "--json" && a[0] == "check" && !strings.Contains(out, "INTERNAL INCONSISTENCY") {
			t.Errorf("the report carries no banner:\n%s", out)
		}
	}
}

func TestAnEmptyAudienceIsAUsageError(t *testing.T) {
	args := emitScenario(t, "jwt-bundle-healthy")
	for _, aud := range []string{"", "  "} {
		code, _, errOut := runCmd(t, "", append(append([]string{"check"}, args...), "--audience", aud)...)
		if code != ExitUsage || !strings.Contains(errOut, "--audience is empty") {
			t.Errorf("--audience %q: exit %d, %q", aud, code, errOut)
		}
	}
}
