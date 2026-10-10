package cmd

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/internal/ui"
	"github.com/kanywst/whosent/internal/version"
)

func newDemo(f *flags, stdout io.Writer) *cobra.Command {
	var emit string
	var fixed, list, force bool
	c := &cobra.Command{
		Use:   "demo [SCENARIO]",
		Short: "Mint example chains and open them, or write them out as fixtures",
		Long: `demo mints delegation chains with throwaway keys and opens them in the
interactive view. With no scenario it tours them all; n and p switch between
them. Each scenario brings its own keys, revocation set and audience, so the
input flags do not apply.

With --emit DIR it writes one scenario's files instead: chain.json, jwks/,
trust.json, revocation.json, revoked-jtis.txt, and a manifest.json holding
the exact whosent check command and what it must report. Emitted fixtures use
a fixed base time, so they are the same bytes on every run.

Scenarios: ` + fmt.Sprint(demo.Names()),
		Args: cobra.MaximumNArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return demo.Names(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if list {
				for _, n := range demo.Names() {
					s, err := demo.Build(n, demo.FixedBase)
					if err != nil {
						return err
					}
					_, _ = fmt.Fprintf(stdout, "%-11s %s\n", n, s.Title)
				}
				return nil
			}
			if emit != "" {
				if len(args) == 0 {
					return errors.New("--emit writes one scenario; name it, such as `whosent demo --emit out widened`")
				}
				s, err := demo.Build(args[0], demo.FixedBase)
				if err != nil {
					return err
				}
				m, err := s.Emit(emit, force)
				if err != nil {
					return err
				}
				printer(stdout)("wrote %s to %s\ncheck it with:\n  cd %s && %s\n", s.Name, emit, emit, m.Command)
				return nil
			}

			if !isTerminal(stdout) {
				return errors.New("the demo needs a terminal; use `whosent demo --emit DIR SCENARIO` and `whosent check` instead")
			}
			base := time.Now()
			if fixed {
				base = demo.FixedBase
			}
			names := demo.Names()
			if len(args) == 1 {
				names = []string{args[0]}
			}
			var sessions []ui.Session
			for _, n := range names {
				s, err := demo.Build(n, base)
				if err != nil {
					return err
				}
				sessions = append(sessions, ui.Session{
					Name: s.Name, Title: s.Title, Summary: s.Summary, Links: s.Links, Options: s.Options,
				})
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
