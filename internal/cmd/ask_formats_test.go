package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/pkg/chain"
)

// emitScenario writes any format's scenario and returns the check command's
// arguments, with paths to the files it wrote made absolute.
func emitScenario(t *testing.T, name string) []string {
	t.Helper()
	sc, err := all.Registry().Scenario(name)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), name)
	command, err := sc.Emit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		t.Errorf("%s wrote no manifest.json, which demo --help promises: %v", name, err)
	}
	fields := strings.Fields(command)[2:]
	for i, f := range fields {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil && !strings.HasPrefix(f, "-") {
			fields[i] = filepath.Join(dir, f)
		}
	}
	return fields
}

// ask used to send Mandatum's question to every format: a JWT could not be
// asked anything, and a Biscuit token was asked nothing at all and decided
// by "allow if true". Each format now gets its own question, a flag it has
// no use for is refused, and nothing is filled in from a default.
func TestAskSpeaksEachFormatsQuestion(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		extra    []string
		code     int
		says     string
	}{
		{"a JWT is asked about a scope it holds", "jwt-bundle-healthy", []string{"--scope", "files:read"}, ExitValid, "PERMITTED"},
		{"a JWT is asked about a scope it lacks", "jwt-bundle-healthy", []string{"--scope", "admin"}, ExitInvalid, "DENIED"},
		{"a JWT question needs a scope", "jwt-bundle-healthy", nil, ExitUsage, "--scope"},
		{"a resource flag does not apply to a JWT", "jwt-bundle-healthy", []string{"--scope", "files:read", "--tag", "x"}, ExitUsage, "--tag"},
		{"a Biscuit token runs its own authorizer", "biscuit-healthy", nil, ExitValid, "PERMITTED"},
		{"a Biscuit request becomes facts", "biscuit-healthy", []string{"--resource-id", "orders", "--action", "delete"}, ExitInvalid, "DENIED"},
		{"the authorizer's request is what the denied scenario asks", "biscuit-denied", nil, ExitInvalid, "DENIED"},
		{"a policy the asker gives is not the deployment's", "biscuit-denied", []string{"--policy", "allow if resource($r)", "--resource-id", "orders", "--action", "read"}, ExitIncomplete, "CONDITIONAL"},
		{"--scope does not apply to a Biscuit token", "biscuit-healthy", []string{"--scope", "x"}, ExitUsage, "--scope"},
		{"--field sets a field by name", "biscuit-healthy", []string{"--field", `facts=resource("orders"); operation("write")`}, ExitInvalid, "DENIED"},
		{"--field refuses a field the format lacks", "biscuit-healthy", []string{"--field", "scope=x"}, ExitUsage, "no field"},
		{"a Fly.io request is judged by its caveats", "macaroon-fly", []string{"--field", "org=4242", "--field", "app=123", "--action", "r"}, ExitValid, "PERMITTED"},
		{"a Fly.io action outside the mask is denied", "macaroon-fly", []string{"--field", "org=4242", "--field", "app=123", "--action", "d"}, ExitInvalid, "DENIED"},
		{"a Fly.io question needs an organization", "macaroon-fly", []string{"--action", "r"}, ExitUsage, "org"},
		{"--policy does not apply to Mandatum", "healthy", []string{"--resource-id", "web.fetch", "--policy", "x"}, ExitUsage, "--policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"ask"}, emitScenario(t, tt.scenario)...)
			args = append(args, tt.extra...)
			code, out, errOut := runCmd(t, "", args...)
			if code != tt.code || !strings.Contains(out+errOut, tt.says) {
				t.Errorf("exit %d, want %d mentioning %q\nstdout: %s\nstderr: %s", code, tt.code, tt.says, out, errOut)
			}
		})
	}
}

// An input flag a format has no use for used to be reported by Biscuit
// alone, and only in some places: a JWT given --revocations said nothing,
// which reads as if a revocation list had been checked. Every format now
// says so, in check's human output and its JSON.
func TestEveryFormatSaysWhichInputsItIgnored(t *testing.T) {
	tests := []struct {
		scenario string
		extra    []string
		flag     string
	}{
		{"jwt-bundle-healthy", []string{"--revocations", "x.json"}, "--revocations"},
		{"jwt-bundle-healthy", []string{"--fact", `operation("read")`}, "--fact"},
		{"biscuit-healthy", []string{"--audience", "https://api"}, "--audience"},
		{"healthy", []string{"--authorizer", "authz.datalog"}, "--authorizer"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario+" "+tt.flag, func(t *testing.T) {
			args := append(append([]string{"check"}, emitScenario(t, tt.scenario)...), tt.extra...)
			_, out, errOut := runCmd(t, "", args...)
			if !strings.Contains(out, "Ignored: "+tt.flag) {
				t.Errorf("human output does not say %s was ignored\nstdout: %s\nstderr: %s", tt.flag, out, errOut)
			}
			_, js, _ := runCmd(t, "", append(args, "--json")...)
			if !strings.Contains(js, `"ignored"`) || !strings.Contains(js, tt.flag) {
				t.Errorf("JSON output does not list %s as ignored: %s", tt.flag, js)
			}
		})
	}
}

// A token that verifies but names prior actors in its act claim is VALID,
// yet nothing checked those actors. The report must not say every link was
// checked, or a CI gate reading it would vouch for links nobody verified.
func TestValidWithAssertedActorsSaysSo(t *testing.T) {
	args := append([]string{"check"}, emitScenario(t, "jwt-okta-style")...)
	code, out, errOut := runCmd(t, "", args...)
	if code != ExitValid {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, ExitValid, out, errOut)
	}
	if strings.Contains(out, "every rule checked for every link") {
		t.Errorf("claims every link was checked although prior actors are only asserted:\n%s", out)
	}
	if !strings.Contains(out, "2 prior actors are the issuer's word") {
		t.Errorf("does not say the prior actors are only asserted:\n%s", out)
	}
}

// The macaroon guard records a disagreement with go-macaroon or
// superfly/macaroon as an Inconsistency (pinned in that package); the
// command must turn it into exit 70 for macaroons too, in both forms.
func TestAMacaroonDisagreementExitsSeventy(t *testing.T) {
	orig := evaluateFn
	evaluateFn = func(ctx context.Context, s chain.Session, eo chain.EvalOptions) (*chain.Chain, error) {
		c, err := orig(ctx, s, eo)
		if err == nil {
			c.Inconsistency = &chain.Inconsistency{Banner: "injected", Detail: "injected disagreement"}
		}
		return c, err
	}
	t.Cleanup(func() { evaluateFn = orig })

	sc, err := all.Registry().Scenario("macaroon-healthy")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := sc.Emit(dir, true); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", filepath.Join(dir, "token.txt"), "--format", "macaroon",
		"--root-key", filepath.Join(dir, "root.key"), "--at", "2026-09-12T08:01:00Z"}
	for _, a := range [][]string{args, append(args, "--json")} {
		code, _, errOut := runCmd(t, "", a...)
		if code != ExitInconsistent || !strings.Contains(errOut, "injected disagreement") {
			t.Errorf("%v: exit %d, stderr %q", a[len(a)-1], code, errOut)
		}
	}
}

// A Fly.io token's caveats restrict requests, so without one the token is
// INCOMPLETE; with one, check judges the caveats as Fly.io would.
func TestFlyCaveatsNeedARequest(t *testing.T) {
	base := append([]string{"check"}, emitScenario(t, "macaroon-fly")...)
	tests := []struct {
		name  string
		extra []string
		code  int
		want  string
	}{
		{"no request leaves the caveats unchecked", nil, ExitIncomplete, "restricts requests"},
		{"a request the caveats allow is VALID", []string{"--fact", "org=4242", "--fact", "app=123", "--fact", "action=r"}, ExitValid, "VALID"},
		{"a request a caveat refuses is INVALID", []string{"--fact", "org=4242", "--fact", "app=123", "--fact", "action=d"}, ExitInvalid, "refuses the request"},
		{"a fact that is not KEY=VALUE is a usage error", []string{"--fact", "org"}, ExitUsage, "KEY=VALUE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCmd(t, "", append(append([]string{}, base...), tt.extra...)...)
			if code != tt.code || !strings.Contains(out+errOut, tt.want) {
				t.Errorf("exit %d (want %d), want %q\nstdout: %s\nstderr: %s", code, tt.code, tt.want, out, errOut)
			}
		})
	}
}
