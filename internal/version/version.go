// Package version reports what build this is.
package version

import (
	"fmt"
	"runtime/debug"
)

// Set at build time with -ldflags "-X github.com/kanywst/whosent/internal/version.Version=...".
var (
	Version   = "dev"
	GitCommit = ""
	BuildDate = ""
)

// Info is the build's identity.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"commit"`
	BuildDate string `json:"date"`
	Mandatum  string `json:"mandatum"`
}

// Get returns the build's identity. A `go install` build carries no ldflags,
// so the module version and VCS stamp from the build info stand in for them.
func Get() Info {
	i := Info{Version: Version, GitCommit: GitCommit, BuildDate: BuildDate, Mandatum: "unknown"}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return i
	}
	if i.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		i.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if i.GitCommit == "" {
				i.GitCommit = s.Value
			}
		case "vcs.time":
			if i.BuildDate == "" {
				i.BuildDate = s.Value
			}
		}
	}
	for _, d := range bi.Deps {
		if d.Path == "github.com/kanywst/mandatum" {
			i.Mandatum = d.Version
			if d.Replace != nil {
				i.Mandatum = d.Replace.Version + " (replaced)"
			}
		}
	}
	return i
}

// String is the one-line form `whosent version` prints.
func (i Info) String() string {
	s := "whosent " + i.Version
	if i.GitCommit != "" {
		c := i.GitCommit
		if len(c) > 12 {
			c = c[:12]
		}
		s += " (" + c + ")"
	}
	if i.BuildDate != "" {
		s += " built " + i.BuildDate
	}
	return s + fmt.Sprintf(", mandatum %s", i.Mandatum)
}
