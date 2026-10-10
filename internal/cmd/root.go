// Package cmd is the command line surface.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kanywst/mandatum/pkg/revoke"
	"github.com/kanywst/mandatum/pkg/verify"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kanywst/whosent/internal/trust"
	"github.com/kanywst/whosent/internal/ui"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// Exit codes. Only a chain that verified with every input supplied exits 0,
// so a script cannot mistake "nothing was checked" for "everything passed".
const (
	ExitValid        = 0
	ExitInvalid      = 1
	ExitIncomplete   = 2
	ExitUsage        = 3
	ExitInconsistent = 70
)

// maxInput bounds how much of a file or stdin is read: mandatum's MCP
// enforcement point reads at most this much of a request (its
// DefaultMaxBodyBytes), so a larger chain is one no enforcement point using
// it ever sees. A real chain is a few kilobytes.
const maxInput = 1 << 20

// exitError carries an exit code out of a command without printing anything:
// the command has already said what it had to.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// Execute runs the command line and returns the process exit code.
func Execute() int {
	return run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRoot(stdin, stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	var ee exitError
	switch {
	case err == nil:
		return ExitValid
	case errors.As(err, &ee):
		return ee.code
	}
	// An error can quote the input back (a JSON syntax error, a file name),
	// so it goes through the same printer as the report.
	printer(stderr)("whosent: %s\n", err)
	return ExitUsage
}

// flags are the inputs every command that reads a chain shares.
type flags struct {
	trust       string
	jwks        []string
	revocations string
	revokedJTIs string
	maxAge      time.Duration
	audience    string
	at          string
	skew        time.Duration
	reverse     bool
	noMotion    bool
	ascii       bool
}

func newRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	f := &flags{}
	root := &cobra.Command{
		Use:   "whosent [FILE|-]",
		Short: "Who sent this agent, and what is it still allowed to do?",
		Long: `whosent opens a Mandatum delegation chain and shows the human it is rooted in,
how authority narrows at every hop, and exactly where trust breaks.

The chain is read from FILE, or from stdin with "-" or when stdin is a pipe. It
may be a JSON array of compact serializations (the wire form), an MCP
tools/call request carrying one, or one serialization per line.

Rules that need an input you did not give (keys, a revocation set, an
audience) are reported as unchecked, never as passing.`,
		Example: `  whosent demo                       take the tour
  whosent chain.json --trust trust.json --revocations revocation.json --audience https://mcp.example.org
  whosent check chain.json --json    a report for scripts
  whosent ask chain.json --resource-id web.fetch --attr args.host=docs.example.org`,
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isTerminal(stdout) {
				return errors.New("the interactive view needs a terminal; use `whosent check` for a report")
			}
			in, opts, err := f.load(cmd, args, stdin)
			if err != nil {
				return err
			}
			s := ui.Session{Name: in.Info.Source, Links: in.Links, Options: opts, Input: in.Info}
			return ui.Run(ui.Config{Sessions: []ui.Session{s}, Motion: !f.noMotion, ASCII: f.ascii || asciiFromEnv()})
		},
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w (see whosent --help)", err)
	})

	p := root.PersistentFlags()
	p.StringVar(&f.trust, "trust", "", "trust file mapping issuers to their key documents")
	p.StringArrayVar(&f.jwks, "jwks", nil, "an issuer's keys, as ISSUER=PATH or ISSUER=https://URL (repeatable)")
	p.StringVar(&f.revocations, "revocations", "", "published revocation set (compact Bloom filter, section 7.1)")
	p.StringVar(&f.revokedJTIs, "revoked-jtis", "", "exact list of revoked jtis, one per line, to resolve filter hits")
	p.DurationVar(&f.maxAge, "max-age", diagnose.DefaultMaxAge, "oldest revocation set accepted; 0 accepts any age")
	p.StringVar(&f.audience, "audience", "", "the resource server the chain is presented to (checks V9)")
	p.StringVar(&f.at, "at", "", "evaluate at this time: RFC 3339, unix seconds, or relative like +25m or -1h")
	p.DurationVar(&f.skew, "skew", verify.DefaultSkew, "clock skew tolerance, at most "+verify.MaxSkew.String())
	p.BoolVar(&f.reverse, "reverse", false, "the chain was handed over leaf first; reverse it before checking")
	p.BoolVar(&f.noMotion, "no-motion", false, "no animation")
	p.BoolVar(&f.ascii, "ascii", false, "ASCII glyphs only (also WHOSENT_ASCII=1)")

	root.AddCommand(newCheck(f, stdin, stdout, stderr))
	root.AddCommand(newAsk(f, stdin, stdout, stderr))
	root.AddCommand(newDemo(f, stdout))
	root.AddCommand(newVersion(stdout))
	return root
}

func asciiFromEnv() bool {
	v := os.Getenv("WHOSENT_ASCII")
	return v != "" && v != "0"
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readChain reads the chain from the named file, or stdin.
func readChain(args []string, stdin io.Reader) (diagnose.Input, error) {
	name := "-"
	if len(args) > 0 {
		name = args[0]
	}
	var r io.Reader
	source := name
	if name == "-" {
		if f, ok := stdin.(*os.File); ok && len(args) == 0 && term.IsTerminal(int(f.Fd())) {
			return diagnose.Input{}, errors.New("no chain given: pass a file, pipe one in, or run `whosent demo`")
		}
		r, source = stdin, "stdin"
	} else {
		f, err := os.Open(name)
		if err != nil {
			return diagnose.Input{}, fmt.Errorf("reading chain: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return diagnose.Input{}, fmt.Errorf("reading %s: %w", source, err)
	}
	if len(data) > maxInput {
		return diagnose.Input{}, fmt.Errorf("%s is larger than %d bytes; that is not a delegation chain", source, maxInput)
	}
	return diagnose.ReadInput(data, source)
}

// parseAt reads --at against a single captured now.
func parseAt(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "now":
		return now, nil
	case s[0] == '+' || s[0] == '-':
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, fmt.Errorf("--at %q: a relative time is a signed duration like +25m or -1h", s)
		}
		return now.Add(d), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--at %q: want RFC 3339 (2026-09-12T08:00:00Z), unix seconds, or +25m/-1h", s)
	}
	return t, nil
}

// options turns the flags into diagnosis options. Files that cannot be read
// are usage errors; a key document that is read but unusable is not, because
// an enforcement point configured with it would deny, and the report has to
// show that.
func (f *flags) options(ctx context.Context, cmd *cobra.Command) (diagnose.Options, error) {
	var o diagnose.Options
	at, err := parseAt(f.at, time.Now())
	if err != nil {
		return o, err
	}
	o.At = at
	if f.skew < 0 || f.skew > verify.MaxSkew {
		return o, fmt.Errorf("--skew %s is outside [0, %s]", f.skew, verify.MaxSkew)
	}
	skew := f.skew
	o.Skew = &skew
	if cmd.Flags().Changed("audience") {
		// An empty audience is never a resource server's identity: mandatum's
		// verifier refuses to be built with one. It is most often an unset
		// variable in `--audience "$AUD"`, which deserves a usage error rather
		// than a report about a chain checked against nothing.
		if strings.TrimSpace(f.audience) == "" {
			return o, errors.New("--audience is empty; name the resource server the chain is presented to, or leave the flag out to skip V9")
		}
		aud := f.audience
		o.Audience = &aud
	}

	var sources []trust.Source
	if f.trust != "" {
		s, err := trust.ReadFile(f.trust)
		if err != nil {
			return o, err
		}
		sources = append(sources, s...)
	}
	for _, v := range f.jwks {
		s, err := trust.ParseFlag(v)
		if err != nil {
			return o, err
		}
		sources = append(sources, s)
	}
	if len(sources) > 0 {
		t, err := trust.Loader{}.Load(ctx, sources)
		if err != nil {
			return o, err
		}
		o.Trust = t
	}

	if f.revokedJTIs != "" && f.revocations == "" {
		return o, errors.New("--revoked-jtis resolves hits in a revocation set; pass --revocations as well")
	}
	if f.revocations != "" {
		data, err := os.ReadFile(f.revocations)
		if err != nil {
			return o, fmt.Errorf("reading revocation set: %w", err)
		}
		set, err := revoke.ParseSet(data)
		if err != nil {
			return o, fmt.Errorf("%s: %w", f.revocations, err)
		}
		if f.maxAge < 0 {
			return o, fmt.Errorf("--max-age %s is negative; use 0 to accept any age", f.maxAge)
		}
		maxAge := f.maxAge
		o.Revocation = &diagnose.Revocation{Set: set, Source: baseName(f.revocations), MaxAge: &maxAge}
		if f.revokedJTIs != "" {
			data, err := os.ReadFile(f.revokedJTIs)
			if err != nil {
				return o, fmt.Errorf("reading revoked jtis: %w", err)
			}
			list := diagnose.ExactList{}
			for _, line := range strings.Split(string(data), "\n") {
				if j := strings.TrimSpace(line); j != "" && !strings.HasPrefix(j, "#") {
					list[j] = true
				}
			}
			o.Revocation.Exact, o.Revocation.ExactSource = list, baseName(f.revokedJTIs)
		}
	}
	return o, nil
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// load reads the chain and the options, and diagnoses it.
func (f *flags) load(cmd *cobra.Command, args []string, stdin io.Reader) (diagnose.Input, diagnose.Options, error) {
	in, err := readChain(args, stdin)
	if err != nil {
		return in, diagnose.Options{}, err
	}
	if f.reverse {
		in.Links = diagnose.Reverse(in.Links)
		in.Info.Reversed = true
	}
	opts, err := f.options(cmd.Context(), cmd)
	return in, opts, err
}

// diagnoseFn is diagnose.Diagnose. It is a variable so a test can hand the
// commands a report in which this tool and mandatum disagree, and check the
// commands say so and exit 70; a real disagreement cannot be arranged.
var diagnoseFn = diagnose.Diagnose

func diagnoseInput(ctx context.Context, in diagnose.Input, opts diagnose.Options) (*diagnose.Report, error) {
	r, err := diagnoseFn(ctx, in.Links, opts)
	if err != nil {
		return nil, err
	}
	r.Input = in.Info
	return r, nil
}
