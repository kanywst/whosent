package cmd

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/internal/ui"
	"github.com/kanywst/whosent/internal/version"
	"github.com/kanywst/whosent/pkg/chain"
)

// fixedBase is the base time --fixed mints at, the same one emitted fixtures
// use: 2026-09-12 08:00 UTC.
var fixedBase = time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)

func newDemo(f *flags, reg *chain.Registry, stdout io.Writer) *cobra.Command {
	var emit string
	var fixed, list, force bool
	names := func() []string {
		var out []string
		for _, s := range reg.Scenarios() {
			out = append(out, s.Name)
		}
		return out
	}
	c := &cobra.Command{
		Use:   "demo [SCENARIO]",
		Short: "Mint example chains and open them, or write them out as fixtures",
		Long: `demo mints delegation chains with throwaway keys and opens them in the
interactive view. With no scenario it tours them all; n and p switch between
them. Each scenario brings its own keys, revocation list and audience, so the
input flags do not apply.

With --emit DIR it writes one scenario's files instead, with a manifest.json
naming the scenario and holding the exact whosent check command. Emitted
fixtures use a fixed base time, so they are the same bytes on every run.

Scenarios: ` + fmt.Sprint(names()),
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return names(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if list {
				// The columns are as wide as the longest name, so a format
				// with long scenario names does not push its titles out of
				// line.
				nameW, formatW := 0, 0
				for _, s := range reg.Scenarios() {
					nameW, formatW = max(nameW, len(s.Name)), max(formatW, len(s.Format))
				}
				for _, s := range reg.Scenarios() {
					_, _ = fmt.Fprintf(stdout, "%-*s  %-*s  %s\n", nameW, s.Name, formatW, s.Format, s.Title)
				}
				return nil
			}
			if emit != "" {
				if len(args) == 0 {
					return errors.New("--emit writes one scenario; name it, such as `whosent demo --emit out widened`")
				}
				s, err := reg.Scenario(args[0])
				if err != nil {
					return err
				}
				if s.Emit == nil {
					return fmt.Errorf("the %s scenario has no fixture files to write", s.Name)
				}
				command, err := s.Emit(emit, force)
				if err != nil {
					return err
				}
				printer(stdout)("wrote %s to %s\ncheck it with:\n  cd %s && %s\n", s.Name, emit, emit, command)
				return nil
			}

			if !isTerminal(stdout) {
				return errors.New("the demo needs a terminal; use `whosent demo --emit DIR SCENARIO` and `whosent check` instead")
			}
			base := time.Now()
			if fixed {
				base = fixedBase
			}
			scenarios := reg.Scenarios()
			if len(args) == 1 {
				s, err := reg.Scenario(args[0])
				if err != nil {
					return err
				}
				scenarios = []chain.Scenario{s}
			}
			var sessions []ui.Session
			for _, sc := range scenarios {
				sess, err := sc.Open(base)
				if err != nil {
					return fmt.Errorf("minting %s: %w", sc.Name, err)
				}
				sessions = append(sessions, ui.Session{Name: sc.Name, Title: sc.Title, Summary: sc.Summary, Chain: sess})
			}
			return ui.Run(ui.Config{Sessions: sessions, Motion: !f.noMotion, ASCII: f.ascii || asciiFromEnv()})
		},
	}
	c.Flags().StringVar(&emit, "emit", "", "write the scenario's fixture files into this directory instead of opening it")
	c.Flags().BoolVar(&fixed, "fixed", false, "mint at the fixed base time rather than now, for reproducible recordings")
	c.Flags().BoolVar(&list, "list", false, "list the scenarios")
	c.Flags().BoolVar(&force, "force", false, "with --emit, write into a directory that is not empty")
	return c
}

func newVersion(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, _ = fmt.Fprintln(stdout, versionString())
			return nil
		},
	}
}

func versionString() string { return version.Get().String() }
