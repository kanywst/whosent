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

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// emit writes a scenario's fixtures and returns the check arguments its
// manifest names, with paths made absolute.
func emit(t *testing.T, name string) (string, []string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	s, err := demo.Build(name, demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Emit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(m.Command)[2:] // drop "whosent check"
	for i, f := range fields {
		if strings.HasSuffix(f, ".json") || strings.HasSuffix(f, ".txt") {
			fields[i] = filepath.Join(dir, f)
		}
	}
	return dir, fields
}

func TestCheckExitCodesFollowTheVerdict(t *testing.T) {
	for _, name := range demo.Names() {
		t.Run(name, func(t *testing.T) {
			s, err := demo.Build(name, demo.FixedBase)
			if err != nil {
				t.Fatal(err)
			}
			_, args := emit(t, name)
			code, out, errOut := runCmd(t, "", append([]string{"check"}, args...)...)
			want := map[diagnose.Verdict]int{
				diagnose.VerdictValid: ExitValid, diagnose.VerdictInvalid: ExitInvalid, diagnose.VerdictIncomplete: ExitIncomplete,
			}[s.Verdict]
			if code != want {
				t.Errorf("exit %d, want %d\n%s\n%s", code, want, out, errOut)
			}
			if !strings.Contains(out, string(s.Verdict)) {
				t.Errorf("report does not state the verdict:\n%s", out)
			}
		})
	}
}

func TestStrictTurnsIncompleteIntoFailure(t *testing.T) {
	_, args := emit(t, "unchecked")
	if code, _, _ := runCmd(t, "", append([]string{"check", "--strict"}, args...)...); code != ExitInvalid {
		t.Errorf("exit %d, want %d", code, ExitInvalid)
	}
}

// Machine output is the whole of stdout, and carries no decoration. A
// script piping --json into jq must never meet an emoji.
func TestCheckJSONStdoutIsOnlyJSON(t *testing.T) {
	for _, name := range []string{"healthy", "multifault", "unchecked"} {
		t.Run(name, func(t *testing.T) {
			_, args := emit(t, name)
			_, out, _ := runCmd(t, "", append([]string{"check", "--json"}, args...)...)
			var r diagnose.JSONReport
			dec := json.NewDecoder(strings.NewReader(out))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil {
				t.Fatalf("stdout is not one JSON report: %v\n%s", err, out)
			}
			if dec.More() {
				t.Error("trailing output after the JSON report")
			}
			for _, banned := range []string{"✅", "❌", "⚠", "✓", "✗", "===", "‼"} {
				if strings.Contains(out, banned) {
					t.Errorf("machine output contains %q", banned)
				}
			}
			if r.Schema != diagnose.SchemaVersion {
				t.Errorf("schema %q", r.Schema)
			}
		})
	}
}

func TestCheckHumanReportShowsEveryFault(t *testing.T) {
	_, args := emit(t, "multifault")
	_, out, _ := runCmd(t, "", append([]string{"check"}, args...)...)
	for _, want := range []string{
		"INVALID", "breaks at link 1", "V8 link 1", "V4 link 2", "V5 link 2",
		"docs.write", "How authority narrows", "(no authority reaches here)", "consequence",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not mention %q:\n%s", want, out)
		}
	}
}

func TestCheckSaysWhatWasNotChecked(t *testing.T) {
	_, args := emit(t, "unchecked")
	_, out, _ := runCmd(t, "", append([]string{"check"}, args...)...)
	if !strings.Contains(out, "Not checked: signatures (--trust or --jwks), revocation (--revocations), audience (--audience)") {
		t.Errorf("report:\n%s", out)
	}
}

func TestCheckReadsStdinAndReverse(t *testing.T) {
	dir, args := emit(t, "healthy")
	chain, err := os.ReadFile(filepath.Join(dir, "chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	rest := args[1:] // the flags after chain.json
	if code, out, _ := runCmd(t, string(chain), append([]string{"check", "-"}, rest...)...); code != ExitValid {
		t.Errorf("stdin: exit %d\n%s", code, out)
	}
	var links []string
	_ = json.Unmarshal(chain, &links)
	for i, j := 0, len(links)-1; i < j; i, j = i+1, j-1 {
		links[i], links[j] = links[j], links[i]
	}
	rev, _ := json.Marshal(links)
	if code, out, _ := runCmd(t, string(rev), append([]string{"check", "-", "--reverse"}, rest...)...); code != ExitValid {
		t.Errorf("--reverse: exit %d\n%s", code, out)
	}
	if code, out, _ := runCmd(t, string(rev), append([]string{"check", "-"}, rest...)...); code != ExitInvalid || !strings.Contains(out, "looks reversed") {
		t.Errorf("reversed without --reverse: exit %d\n%s", code, out)
	}
}

func TestUsageErrorsExitThree(t *testing.T) {
	dir, args := emit(t, "healthy")
	chain := filepath.Join(dir, "chain.json")
	tests := []struct {
		name    string
		args    []string
		mention string
	}{
		{"a missing chain file", []string{"check", filepath.Join(dir, "nope.json")}, "no such file"},
		{"an unknown flag", []string{"check", chain, "--nope"}, "unknown flag"},
		{"a skew beyond the library's bound", []string{"check", chain, "--skew", "6m"}, "outside"},
		{"an unreadable --at", []string{"check", chain, "--at", "tomorrow"}, "--at"},
		{"exact jtis without a set", []string{"check", chain, "--revoked-jtis", chain}, "--revocations"},
		{"a revocation file that is not a set", []string{"check", chain, "--revocations", chain}, "revoke"},
		{"a missing key file", []string{"check", chain, "--jwks", "iss=" + filepath.Join(dir, "missing.json")}, "reading keys"},
		{"a malformed --jwks", []string{"check", chain, "--jwks", "nope"}, "ISSUER=PATH"},
		{"a negative max age", append([]string{"check", chain, "--max-age", "-1h"}, args[1:]...), "negative"},
		{"two chains", []string{"check", chain, chain}, "accepts at most 1"},
		{"ask without a resource", append([]string{"ask"}, args...), "--resource-id"},
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
	_, args := emit(t, "healthy")
	for _, a := range [][]string{args[:1], {"demo"}} {
		code, _, errOut := runCmd(t, "", a...)
		if code != ExitUsage || !strings.Contains(errOut, "terminal") {
			t.Errorf("%v: exit %d, stderr %q", a, code, errOut)
		}
	}
}

func TestAskExitCodesAndLabels(t *testing.T) {
	req := []string{"--resource-id", "web.fetch", "--tag", "external-content", "--attr", "args.host=docs.example.org"}
	tests := []struct {
		scenario string
		extra    []string
		code     int
		mention  string
	}{
		{"healthy", req, ExitValid, "PERMITTED (AUTHORITATIVE)"},
		{"healthy", []string{"--resource-id", "docs.write", "--tag", "mutating"}, ExitInvalid, "DENIED"},
		{"unchecked", req, ExitIncomplete, "CONDITIONAL"},
		{"expired", req, ExitInvalid, "hypothetically"},
		{"widened", []string{"--resource-id", "docs.write", "--tag", "mutating"}, ExitInvalid, "the sponsor granted it, link 1 dropped it"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario+" "+tt.extra[1], func(t *testing.T) {
			_, args := emit(t, tt.scenario)
			code, out, _ := runCmd(t, "", append(append([]string{"ask"}, args...), tt.extra...)...)
			if code != tt.code {
				t.Errorf("exit %d, want %d\n%s", code, tt.code, out)
			}
			if !strings.Contains(out, tt.mention) {
				t.Errorf("answer does not mention %q:\n%s", tt.mention, out)
			}
		})
	}
	t.Run("--strict refuses a conditional answer", func(t *testing.T) {
		_, args := emit(t, "unchecked")
		if code, _, _ := runCmd(t, "", append(append([]string{"ask", "--strict"}, args...), req...)...); code != ExitInvalid {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("json answers are only JSON", func(t *testing.T) {
		_, args := emit(t, "healthy")
		_, out, _ := runCmd(t, "", append(append([]string{"ask", "--json"}, args...), req...)...)
		var tr diagnose.JSONTrace
		if err := json.Unmarshal([]byte(out), &tr); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if tr.Authority != diagnose.Authoritative || !tr.Permitted || len(tr.Steps) != 3 {
			t.Errorf("%+v", tr)
		}
	})
}

// A tools/call request names its tool, so ask needs nothing else, and
// --attr-from-args maps the arguments with a warning that it is an
// assumption.
func TestAskReadsAToolCall(t *testing.T) {
	dir, args := emit(t, "healthy")
	chain, _ := os.ReadFile(filepath.Join(dir, "chain.json"))
	var links []string
	_ = json.Unmarshal(chain, &links)
	call, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{
		"name": "web.fetch", "arguments": map[string]any{"host": "docs.example.org"},
		"_meta": map[string]any{diagnose.ChainMetaKey: links},
	}})
	code, out, errOut := runCmd(t, string(call), append([]string{"ask", "-", "--attr-from-args", "--tag", "external-content"}, args[1:]...)...)
	if code != ExitValid {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "assumption") {
		t.Errorf("no warning that the argument mapping is an assumption: %q", errOut)
	}
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
	r := &diagnose.Report{Verdict: diagnose.VerdictValid}
	r.Library.Consistent = false
	if c := exitCode(r, false); c != ExitInconsistent {
		t.Errorf("exit %d, want %d: a disagreement with mandatum must never exit 0", c, ExitInconsistent)
	}
}

func TestDemoListAndEmit(t *testing.T) {
	code, out, _ := runCmd(t, "", "demo", "--list")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, n := range demo.Names() {
		if !strings.Contains(out, n) {
			t.Errorf("--list does not name %s", n)
		}
	}
	dir := t.TempDir()
	code, out, _ = runCmd(t, "", "demo", "--emit", dir, "spliced")
	if code != 0 || !strings.Contains(out, "whosent check chain.json") {
		t.Errorf("exit %d\n%s", code, out)
	}
	for _, f := range []string{"chain.json", "trust.json", "revocation.json", "revoked-jtis.txt", "manifest.json", "jwks/idp.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := runCmd(t, "", "version")
	if code != 0 || !strings.HasPrefix(out, "whosent ") || !strings.Contains(out, "mandatum") {
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

// A disagreement with mandatum must reach the person and the script: a
// banner in the report, a line on stderr, and exit 70 from every command,
// in every output form.
func TestEveryCommandExitsSeventyOnADisagreement(t *testing.T) {
	orig := diagnoseFn
	diagnoseFn = func(ctx context.Context, links [][]byte, o diagnose.Options) (*diagnose.Report, error) {
		r, err := orig(ctx, links, o)
		if err == nil {
			r.Library.Consistent = false
			r.Library.Mismatch = "injected disagreement"
		}
		return r, err
	}
	t.Cleanup(func() { diagnoseFn = orig })

	_, args := emit(t, "healthy")
	for _, a := range [][]string{
		append([]string{"check"}, args...),
		append([]string{"check", "--json"}, args...),
		append([]string{"ask", "--resource-id", "web.fetch", "--attr", "args.host=docs.example.org"}, args...),
		append([]string{"ask", "--json", "--resource-id", "web.fetch", "--attr", "args.host=docs.example.org"}, args...),
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
	_, args := emit(t, "healthy")
	for _, aud := range []string{"", "  "} {
		code, _, errOut := runCmd(t, "", append(append([]string{"check"}, args...), "--audience", aud)...)
		if code != ExitUsage || !strings.Contains(errOut, "--audience is empty") {
			t.Errorf("--audience %q: exit %d, %q", aud, code, errOut)
		}
	}
}
