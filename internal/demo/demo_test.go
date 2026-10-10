package demo

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The same scenario at the same base time is the same chain, byte for byte.
// That is what makes emitted fixtures and recorded demos reproducible.
func TestScenariosAreDeterministic(t *testing.T) {
	for _, n := range Names() {
		a, err := Build(n, FixedBase)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Build(n, FixedBase)
		if err != nil {
			t.Fatal(err)
		}
		for i := range a.Links {
			if !bytes.Equal(a.Links[i], b.Links[i]) {
				t.Errorf("%s link %d differs between two builds", n, i)
			}
		}
	}
}

func TestEveryScenarioBuildsAtAnyBase(t *testing.T) {
	for _, base := range []time.Time{FixedBase, time.Now(), time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := All(base); err != nil {
			t.Errorf("base %s: %v", base, err)
		}
	}
}

func TestUnknownScenarioNamesTheChoices(t *testing.T) {
	if _, err := Build("nope", FixedBase); err == nil {
		t.Error("accepted")
	}
}

func TestEmitWritesAReproducibleFixture(t *testing.T) {
	dir := t.TempDir()
	s, err := Build("revoked", FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Emit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk Manifest
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Expect == nil || onDisk.Expect.Rule != "V8" || onDisk.Expect.Link != 1 {
		t.Errorf("manifest expect %+v", onDisk.Expect)
	}
	if onDisk.Command != m.Command || onDisk.At != FixedBase.Add(time.Minute) {
		t.Errorf("manifest %+v", onDisk)
	}
	var links []string
	b, _ = os.ReadFile(filepath.Join(dir, "chain.json"))
	if err := json.Unmarshal(b, &links); err != nil || len(links) != 3 {
		t.Errorf("chain.json: %v, %d links", err, len(links))
	}
	info, err := os.Stat(filepath.Join(dir, "chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits: Go reports every writable file as
	// 0666 there, so the mode says nothing about what Emit asked for.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("chain.json mode %v", info.Mode())
	}
}

func TestKeyIsTheSigningKey(t *testing.T) {
	if _, _, ok := Key("nobody"); ok {
		t.Error("a key for a principal outside the cast")
	}
	k, kid, ok := Key(Planner)
	if !ok || kid != "planner-1" || len(k) == 0 {
		t.Errorf("Key(Planner) = %v %q %v", len(k), kid, ok)
	}
}

// Emitting into a shared directory must not be a way to overwrite someone
// else's file: a symlink planted at one of the names is replaced, and what
// it points at is left alone.
func TestEmitNeverWritesThroughASymlink(t *testing.T) {
	s, err := Build("healthy", FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(dir, "chain.json")); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Emit(dir, false); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("emitting into a non-empty directory without force: %v", err)
	}
	if _, err := s.Emit(dir, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("the symlink's target was overwritten: %q", b)
	}
	fi, err := os.Lstat(filepath.Join(dir, "chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("chain.json is %v, want a regular 0600 file", fi.Mode())
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".whosent-*"))
	if len(leftovers) > 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestEmitRefusesASymlinkedKeyDirectory(t *testing.T) {
	s, err := Build("healthy", FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "jwks")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Emit(dir, true); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a symlinked jwks/ was written through: %v", err)
	}
}
