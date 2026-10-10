package demo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/trust"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// Manifest describes an emitted fixture: what it is, how to check it, and
// what checking it must report.
type Manifest struct {
	Name      string           `json:"name"`
	Title     string           `json:"title"`
	Summary   string           `json:"summary"`
	At        time.Time        `json:"at"`
	Audience  string           `json:"audience,omitempty"`
	Verdict   diagnose.Verdict `json:"verdict"`
	Expect    *Expectation     `json:"expect"`
	ExpectAll []Expectation    `json:"expect_all"`
	Command   string           `json:"command"`
}

// Emit writes the scenario's files into dir: chain.json (the wire form),
// jwks/*.json, trust.json, revocation.json, revoked-jtis.txt and
// manifest.json. Files are written 0600 and directories 0700; nothing here
// is secret, but there is no reason for a fixture to be world-writable.
//
// dir must be missing or empty unless force is set, so a mistyped directory
// is never quietly overwritten. Each file is written to a temporary name and
// renamed into place, which replaces whatever was at the name rather than
// writing through it: a symlink planted in a shared directory is replaced,
// and the file it pointed at is left alone.
func (s Scenario) Emit(dir string, force bool) (Manifest, error) {
	if err := prepareDir(dir, force); err != nil {
		return Manifest{}, err
	}
	jwksDir := filepath.Join(dir, "jwks")
	if fi, err := os.Lstat(jwksDir); err == nil && !fi.IsDir() {
		// A symlinked jwks/ would send the key documents wherever it
		// points; rename protects a file, not the directory above it.
		return Manifest{}, fmt.Errorf("%s exists and is not a directory; refusing to write through it", jwksDir)
	}
	if err := os.MkdirAll(jwksDir, 0o700); err != nil {
		return Manifest{}, err
	}
	links := make([]string, len(s.Links))
	for i, l := range s.Links {
		links[i] = string(l)
	}
	if err := writeJSON(filepath.Join(dir, "chain.json"), links); err != nil {
		return Manifest{}, err
	}

	cmd := []string{"whosent", "check", "chain.json"}
	if len(s.Fixture.TrustIssuers) > 0 {
		names := make([]string, 0, len(s.Fixture.JWKS))
		for n := range s.Fixture.JWKS {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if err := writeFile(filepath.Join(dir, "jwks", n), s.Fixture.JWKS[n]); err != nil {
				return Manifest{}, err
			}
		}
		tf := trust.File{Issuers: map[string]trust.FileIssuer{}}
		for iss, n := range s.Fixture.TrustIssuers {
			tf.Issuers[iss] = trust.FileIssuer{JWKSFile: filepath.Join("jwks", n)}
		}
		if err := writeJSON(filepath.Join(dir, "trust.json"), tf); err != nil {
			return Manifest{}, err
		}
		cmd = append(cmd, "--trust", "trust.json")
	}
	if s.Fixture.Revocation != nil {
		if err := writeFile(filepath.Join(dir, "revocation.json"), s.Fixture.Revocation); err != nil {
			return Manifest{}, err
		}
		cmd = append(cmd, "--revocations", "revocation.json")
		if len(s.Fixture.RevokedJTIs) > 0 {
			body := strings.Join(s.Fixture.RevokedJTIs, "\n") + "\n"
			if err := writeFile(filepath.Join(dir, "revoked-jtis.txt"), []byte(body)); err != nil {
				return Manifest{}, err
			}
			cmd = append(cmd, "--revoked-jtis", "revoked-jtis.txt")
		}
	}
	m := Manifest{
		Name: s.Name, Title: s.Title, Summary: s.Summary, At: s.Options.At.UTC(),
		Verdict: s.Verdict, ExpectAll: s.ExpectAll,
	}
	if m.ExpectAll == nil {
		m.ExpectAll = []Expectation{}
	}
	if s.Expect.Rule != "" {
		e := s.Expect
		m.Expect = &e
	}
	if s.Options.Audience != nil {
		m.Audience = *s.Options.Audience
		cmd = append(cmd, "--audience", m.Audience)
	}
	cmd = append(cmd, "--at", m.At.Format(time.RFC3339))
	m.Command = strings.Join(cmd, " ")
	if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", filepath.Base(path), err)
	}
	return writeFile(path, append(b, '\n'))
}

// prepareDir creates dir 0700, or accepts an existing empty one. A
// directory that already holds something is refused without force.
func prepareDir(dir string, force bool) error {
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

// writeFile writes data to path through a temporary file in the same
// directory and a rename, so the result is a fresh 0600 file whatever was
// at path before, and a symlink at path is replaced rather than followed.
func writeFile(path string, data []byte) error {
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
