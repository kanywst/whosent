package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/formats/all"
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
