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

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kanywst/whosent/internal/formats/all"
	"github.com/kanywst/whosent/internal/ui"
	"github.com/kanywst/whosent/pkg/chain"
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

// maxInput bounds how much of a file or stdin is read. Mandatum's MCP
// enforcement point reads at most this much of a request (its
// DefaultMaxBodyBytes), and a token of any format this tool reads is a few
// kilobytes, so a larger input is not a delegation chain.
const maxInput = 1 << 20

// defaultSkew and maxSkew bound --skew. An adapter may narrow them for its
// format; none may widen them, because a large skew silently extends the
// life of every token it is applied to.
const (
	defaultSkew = 30 * time.Second
	maxSkew     = 5 * time.Minute
)

// defaultMaxAge is the oldest revocation set accepted unless --max-age says
// otherwise.
const defaultMaxAge = 24 * time.Hour

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
	format      string
	trust       string
	jwks        []string
	rootKeys    []string
	revocations string
	revokedJTIs string
	maxAge      time.Duration
	audience    string
	facts       []string
	authorizer  string
	at          string
	skew        time.Duration
	reverse     bool
	noMotion    bool
	ascii       bool
}

func newRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	f := &flags{}
	reg := all.Registry()
	root := &cobra.Command{
		Use:   "whosent [FILE|-]",
		Short: "Who sent this agent, and what is it still allowed to do?",
		Long: `whosent opens a delegation chain and shows who it is rooted in, how
authority narrows at every hop, and exactly where trust breaks.

Formats: ` + strings.Join(reg.IDs(), ", ") + `. The format is recognised from
the input; --format says it when the input could be more than one.

The chain is read from FILE, or from stdin with "-" or when stdin is a pipe.

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
			sess, source, err := f.load(cmd, reg, args, stdin)
			if err != nil {
				return err
			}
			s := ui.Session{Name: source, Chain: sess}
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
	p.StringVar(&f.format, "format", "", "the chain's format: "+strings.Join(reg.IDs(), ", ")+" (default: recognised from the input)")
	p.StringVar(&f.trust, "trust", "", "trust file mapping issuers to their key documents")
	p.StringArrayVar(&f.jwks, "jwks", nil, "an issuer's keys, as ISSUER=PATH or ISSUER=https://URL (repeatable)")
	p.StringArrayVar(&f.rootKeys, "root-key", nil, "a root key: a public key a chain may be rooted in, or a macaroon's secret; hex or a file (repeatable)")
	p.StringVar(&f.revocations, "revocations", "", "published revocation set")
	p.StringVar(&f.revokedJTIs, "revoked-jtis", "", "exact list of revoked identifiers, one per line, to resolve filter hits")
	p.DurationVar(&f.maxAge, "max-age", defaultMaxAge, "oldest revocation set accepted; 0 accepts any age")
	p.StringVar(&f.audience, "audience", "", "the party the chain is presented to (checks the audience rule)")
	p.StringArrayVar(&f.facts, "fact", nil, "a fact an authorizer supplies, such as 'operation(\"read\")', or a macaroon predicate a verifier satisfies (repeatable)")
	p.StringVar(&f.authorizer, "authorizer", "", "a file of authorizer code to evaluate the chain's checks against")
	p.StringVar(&f.at, "at", "", "evaluate at this time: RFC 3339, unix seconds, or relative like +25m or -1h")
	p.DurationVar(&f.skew, "skew", defaultSkew, "clock skew tolerance, at most "+maxSkew.String())
	p.BoolVar(&f.reverse, "reverse", false, "the chain was handed over leaf first; reverse it before checking")
	p.BoolVar(&f.noMotion, "no-motion", false, "no animation")
	p.BoolVar(&f.ascii, "ascii", false, "ASCII glyphs only (also WHOSENT_ASCII=1)")

	root.AddCommand(newCheck(f, reg, stdin, stdout, stderr))
	root.AddCommand(newAsk(f, reg, stdin, stdout, stderr))
	root.AddCommand(newDemo(f, reg, stdout))
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

// readChain reads the chain from the named file, or stdin, and returns its
// bytes and a name for it.
func readChain(args []string, stdin io.Reader) ([]byte, string, error) {
	name := "-"
	if len(args) > 0 {
		name = args[0]
	}
	var r io.Reader
	source := name
	if name == "-" {
		if f, ok := stdin.(*os.File); ok && len(args) == 0 && term.IsTerminal(int(f.Fd())) {
			return nil, "", errors.New("no chain given: pass a file, pipe one in, or run `whosent demo`")
		}
		r, source = stdin, "stdin"
	} else {
		f, err := os.Open(name)
		if err != nil {
			return nil, "", fmt.Errorf("reading chain: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return nil, "", fmt.Errorf("reading %s: %w", source, err)
	}
	if len(data) > maxInput {
		return nil, "", fmt.Errorf("%s is larger than %d bytes; that is not a delegation chain", source, maxInput)
	}
	return data, source, nil
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

// inputs turns the flags into what an adapter reads. Only the checks every
// format shares happen here; each adapter checks the rest itself.
func (f *flags) inputs(cmd *cobra.Command, data []byte, source string) (chain.Inputs, error) {
	in := chain.Inputs{
		Data: data, Source: source,
		TrustFile: f.trust, JWKS: f.jwks, RootKeys: f.rootKeys,
		Revocations: f.revocations, RevokedIDs: f.revokedJTIs, MaxAge: f.maxAge,
		Facts: f.facts, Authorizer: f.authorizer, Reverse: f.reverse,
	}
	at, err := parseAt(f.at, time.Now())
	if err != nil {
		return in, err
	}
	in.At = at
	if f.skew < 0 || f.skew > maxSkew {
		return in, fmt.Errorf("--skew %s is outside [0, %s]", f.skew, maxSkew)
	}
	skew := f.skew
	in.Skew = &skew
	for _, v := range f.jwks {
		// The shape is the same for every format that takes issuer keys;
		// what the keys must be is the adapter's to check.
		if iss, loc, ok := strings.Cut(v, "="); !ok || iss == "" || loc == "" {
			return in, fmt.Errorf("--jwks %q: want ISSUER=PATH or ISSUER=https://URL", v)
		}
	}
	if cmd.Flags().Changed("audience") {
		// An empty audience is never a party's identity: Mandatum's
		// verifier refuses to be built with one. It is most often an unset
		// variable in `--audience "$AUD"`, which deserves a usage error
		// rather than a report about a chain checked against nothing.
		if strings.TrimSpace(f.audience) == "" {
			return in, errors.New("--audience is empty; name the party the chain is presented to, or leave the flag out to skip the audience rule")
		}
		aud := f.audience
		in.Audience = &aud
	}
	return in, nil
}

// load reads the chain, picks its format, and opens it with the inputs.
func (f *flags) load(cmd *cobra.Command, reg *chain.Registry, args []string, stdin io.Reader) (chain.Session, string, error) {
	data, source, err := readChain(args, stdin)
	if err != nil {
		return nil, "", err
	}
	// Flags first: a malformed flag is the person's to fix whatever the
	// input turns out to be.
	in, err := f.inputs(cmd, data, source)
	if err != nil {
		return nil, "", err
	}
	var a chain.Adapter
	if f.format != "" {
		a, err = reg.Lookup(f.format)
	} else {
		a, err = reg.Detect(data)
	}
	if err != nil {
		return nil, "", err
	}
	s, err := a.Open(cmd.Context(), in)
	return s, source, err
}

// evaluateFn evaluates a session. It is a variable so a test can hand the
// commands a chain in which an adapter and its reference implementation
// disagree, and check the commands say so and exit 70; a real disagreement
// cannot be arranged.
var evaluateFn = func(ctx context.Context, s chain.Session, eo chain.EvalOptions) (*chain.Chain, error) {
	return s.Evaluate(ctx, eo)
}

// evaluate checks a session once, at the time it was opened for.
func evaluate(ctx context.Context, s chain.Session) (*chain.Chain, error) {
	at := s.Info().At
	if at.IsZero() {
		at = time.Now()
	}
	return evaluateFn(ctx, s, chain.EvalOptions{At: at})
}
