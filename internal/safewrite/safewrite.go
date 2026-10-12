// Package safewrite writes demo fixtures without trusting what is already
// on disk: a directory that holds something is refused without force, and
// every file is written to a temporary name and renamed into place at 0600,
// so a symlink planted at the name is replaced rather than written through.
package safewrite

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir creates dir 0700, or accepts an existing empty one. A directory that
// already holds something is refused without force.
func Dir(dir string, force bool) error {
	fi, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 && !force {
		return fmt.Errorf("%s is not empty; pass --force to write the fixture into it anyway", dir)
	}
	return nil
}

// File writes data to path through a temporary file in the same directory
// and a rename, so the result is a fresh 0600 file whatever was at path
// before, and a symlink at path is replaced rather than followed.
func File(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".whosent-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
