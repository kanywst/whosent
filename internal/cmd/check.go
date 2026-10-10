package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/pkg/diagnose"
)

func newCheck(f *flags, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var asJSON, strict bool
	c := &cobra.Command{
		Use:   "check [FILE|-]",
		Short: "Report on a chain without the interactive view",
		Long: `check evaluates every rule for every link and prints a report.

Exit status:
  0   VALID: every rule was checked for every link, and holds
  1   INVALID: a rule failed, or could not be evaluated (an enforcement point denies)
  2   INCOMPLETE: nothing failed, but something was not checked (1 with --strict)
  3   the command line or an input file is wrong
  70  this tool and mandatum disagree about the chain (a bug in whosent; please report it)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, opts, err := f.load(cmd, args, stdin)
			if err != nil {
				return err
			}
			r, err := diagnoseInput(cmd.Context(), in, opts)
			if err != nil {
				return err
			}
			if asJSON {
				if err := writeJSON(stdout, r.JSON()); err != nil {
					return err
				}
			} else {
				writeReport(stdout, r)
			}
			if !r.Library.Consistent {
				printer(stderr)("whosent: internal inconsistency: %s\n", r.Library.Mismatch)
			}
			return exitError{exitCode(r, strict)}
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON (schema "+diagnose.SchemaVersion+")")
	c.Flags().BoolVar(&strict, "strict", false, "treat INCOMPLETE as a failure (exit 1)")
	return c
}

func exitCode(r *diagnose.Report, strict bool) int {
	switch {
	case !r.Library.Consistent:
		return ExitInconsistent
	case r.Verdict == diagnose.VerdictValid:
		return ExitValid
	case r.Verdict == diagnose.VerdictIncomplete && !strict:
		return ExitIncomplete
	}
	return ExitInvalid
}

// glyph is a check's mark in the human report. Every status has its own
// mark, so the report reads the same without colour.
func glyph(s diagnose.Status) string {
	switch s {
	case diagnose.StatusPass:
		return "✓"
	case diagnose.StatusFail:
		return "✗"
	case diagnose.StatusError:
		return "!"
	case diagnose.StatusUnchecked:
		return "?"
	case diagnose.StatusSkipped:
		return "-"
	}
	return "·"
}

func severityGlyph(s diagnose.Severity) string {
	switch s {
	case diagnose.SeverityFail:
		return "✗"
	case diagnose.SeverityError:
		return "!"
	case diagnose.SeverityUnchecked:
		return "?"
	case diagnose.SeverityWarn:
		return "▲"
	}
	return "i"
}

func verdictLine(r *diagnose.Report) string {
	switch r.Verdict {
	case diagnose.VerdictValid:
		return "✅ VALID: every rule checked for every link, and the chain holds"
	case diagnose.VerdictIncomplete:
		return "⚠️  INCOMPLETE: nothing failed, but some rules were not checked, so nothing is vouched for"
	}
	if r.BreakAt >= 0 {
		return fmt.Sprintf("❌ INVALID: the chain breaks at link %d, and no authority reaches below it", r.BreakAt)
	}
	return "❌ INVALID: the chain grants nothing"
}

func principal(id string) string {
	if s := diagnose.Short(id); s != id {
		return s
	}
	return id
}

func writeReport(w io.Writer, r *diagnose.Report) {
	p := printer(w)

	head := fmt.Sprintf("=== %s · %d links", r.Input.Source, len(r.Links))
	if len(r.Links) == 1 {
		head = fmt.Sprintf("=== %s · 1 link", r.Input.Source)
	}
	if s := r.Sponsor; s != nil {
		head += fmt.Sprintf(" · sponsor %s via %s", s.Subject, s.Issuer)
		if len(s.AuthenticationMethods) > 0 {
			head += " (" + strings.Join(s.AuthenticationMethods, "+") + ")"
		}
	}
	p("%s\n", head)
	aud := "not checked"
	if r.AudienceChecked {
		aud = r.Audience
	}
	p("    at %s · skew %s · audience %s\n", r.At.UTC().Format(time.RFC3339), r.Skew, aud)
	if len(r.Simulated) > 0 {
		p("    ⊘ simulating revocation of %s\n", strings.Join(r.Simulated, ", "))
	}
	if r.Input.Reversed {
		p("    reversed on request (--reverse)\n")
	}
	p("\n%s\n", verdictLine(r))
	if !r.Library.Consistent {
		p("\n‼️  INTERNAL INCONSISTENCY: %s\n    mandatum's verdict stands; this is a bug in whosent.\n", r.Library.Mismatch)
	}

	if len(r.Links) > 0 {
		p("\n  #  %-34s", "issuer → subject")
		for _, rule := range diagnose.Rules {
			p(" %s", rule)
		}
		p("\n")
		for _, l := range r.Links {
			name := "(does not parse)"
			if l.Claims != nil {
				name = principal(l.Claims.Issuer) + " → " + principal(l.Claims.Subject)
			}
			if len([]rune(name)) > 34 {
				name = string([]rune(name)[:33]) + "…"
			}
			p("  %d  %-34s", l.Index, name)
			for _, c := range l.Checks {
				p("  %s", glyph(c.Status))
			}
			switch {
			case l.Unreached:
				p("   (no authority reaches here)")
			case l.Revoked && l.RevokedSimulated:
				p("   ⊘ revoked (simulated)")
			}
			p("\n")
		}
		p("     ✓ pass  ✗ fail  ! could not evaluate  ? not checked  - skipped  · does not apply\n")
	}

	findings := r.Findings()
	if len(findings) > 0 {
		p("\nFindings\n")
		for _, f := range findings {
			where := "chain"
			if f.Link >= 0 {
				where = fmt.Sprintf("link %d", f.Link)
			}
			rule := string(f.Rule)
			if rule == "" {
				rule = "input"
			}
			tag := ""
			if f.Derived {
				tag = " (consequence)"
			}
			if f.Simulated {
				tag += " (simulated)"
			}
			spec := ""
			if f.Spec != "" {
				spec = " [" + f.Spec + "]"
			}
			p("  %s %s %s%s: %s%s\n", severityGlyph(f.Severity), rule, where, tag, f.Detail, spec)
		}
	}

	if len(r.Hops) > 0 {
		p("\nHow authority narrows\n")
		for _, h := range r.Hops {
			from, to := "?", "?"
			if c := r.Links[h.Parent].Claims; c != nil {
				from = principal(c.Subject)
			}
			if c := r.Links[h.Child].Claims; c != nil {
				to = principal(c.Subject)
			}
			p("  %d → %d  %s → %s\n", h.Parent, h.Child, from, to)
			if !h.Evaluable {
				p("      cannot compare: a link of this pair does not parse\n")
				continue
			}
			for _, c := range h.Capabilities {
				p("      %s %s\n", changeMark(c.Kind), c.Text)
				for _, n := range c.Notes {
					p("          %s\n", n)
				}
			}
			for _, v := range []diagnose.ValueChange{h.Expiry, h.MaxDepth, h.Sequence.Budget} {
				if v.Text != "" {
					p("      %s %s\n", changeMark(v.Kind), v.Text)
				}
			}
			for _, c := range h.Sequence.Constraints {
				if c.Kind != diagnose.ChangeKept {
					p("      %s %s\n", changeMark(c.Kind), c.Text)
				}
			}
			if h.Audience.Kind == diagnose.ChangeWidened {
				p("      %s %s\n", changeMark(h.Audience.Kind), h.Audience.Text)
			}
		}
		p("      = kept  ~ narrowed  - dropped  + added  ✗ widened (violation)\n")
	}

	var missing []string
	cnt := r.Counts()
	if cnt[diagnose.SeverityUnchecked] > 0 {
		seen := map[diagnose.Rule]bool{}
		for _, f := range findings {
			if f.Severity == diagnose.SeverityUnchecked {
				seen[f.Rule] = true
			}
		}
		if seen[diagnose.V3] {
			missing = append(missing, "signatures (--trust or --jwks)")
		}
		if seen[diagnose.V8] {
			missing = append(missing, "revocation (--revocations)")
		}
		if seen[diagnose.V9] {
			missing = append(missing, "audience (--audience)")
		}
	}
	if len(missing) > 0 {
		p("\nNot checked: %s\n", strings.Join(missing, ", "))
	}
}

func changeMark(k diagnose.ChangeKind) string {
	switch k {
	case diagnose.ChangeKept:
		return "="
	case diagnose.ChangeNarrowed:
		return "~"
	case diagnose.ChangeDropped:
		return "-"
	case diagnose.ChangeAdded:
		return "+"
	case diagnose.ChangeWidened:
		return "✗"
	}
	return "?"
}
