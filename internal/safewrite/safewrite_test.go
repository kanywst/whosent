package safewrite

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDir(t *testing.T) {
	base := t.TempDir()
	fresh := filepath.Join(base, "a", "b")
	if err := Dir(fresh, false); err != nil {
		t.Fatalf("a missing directory is not created: %v", err)
	}
	// Windows has no Unix permission bits, so the mode says nothing there.
	if fi, err := os.Stat(fresh); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700) {
		t.Errorf("created directory: %v %v", fi.Mode(), err)
	}
	if err := Dir(fresh, false); err != nil {
		t.Errorf("an empty directory is refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Dir(fresh, false); err == nil {
		t.Error("a non-empty directory is accepted without force")
	}
	if err := Dir(fresh, true); err != nil {
		t.Errorf("force does not accept a non-empty directory: %v", err)
	}
	if err := Dir(filepath.Join(fresh, "x"), true); err == nil {
		t.Error("a file is accepted as a directory")
	}
}

func TestFileNeverWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out.json")
	if err := os.Symlink(victim, target); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if err := File(target, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("the symlink's target was overwritten: %q", b)
	}
	fi, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("out.json is %v, want a regular 0600 file", fi.Mode())
	}
	if b, _ := os.ReadFile(target); string(b) != "data" {
		t.Errorf("content %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".whosent-*")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}
