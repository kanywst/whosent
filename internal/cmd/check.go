package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/pkg/chain"
)

func newCheck(f *flags, reg *chain.Registry, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var asJSON, native, strict bool
	c := &cobra.Command{
		Use:   "check [FILE|-]",
		Short: "Report on a chain without the interactive view",
		Long: `check evaluates every rule for every link and prints a report.

Exit status:
  0   VALID: every rule was checked for every link, and holds
  1   INVALID: a rule failed, or could not be evaluated (an enforcement point denies)
  2   INCOMPLETE: nothing failed, but something was not checked (1 with --strict)
  3   the command line or an input file is wrong
  70  this tool and the format's reference implementation disagree about the chain
      (a bug in whosent; please report it)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if native && !asJSON {
				return fmt.Errorf("--native picks the JSON document; pass --json as well")
			}
			s, _, err := f.load(cmd, reg, args, stdin)
			if err != nil {
				return err
			}
			c, err := evaluate(cmd.Context(), s)
			if err != nil {
				return err
			}
			switch {
			case asJSON && native:
				if c.Native == nil {
					return fmt.Errorf("the %s format has no report of its own beyond %s", c.Format.Name, chain.SchemaVersion)
				}
				if err := writeJSON(stdout, c.Native); err != nil {
					return err
				}
			case asJSON:
				if err := writeJSON(stdout, c.JSON()); err != nil {
					return err
				}
			default:
				writeReport(stdout, c)
			}
			if c.Inconsistency != nil {
				printer(stderr)("whosent: internal inconsistency: %s\n", c.Inconsistency.Detail)
			}
			return exitError{exitCode(c, strict)}
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON (schema "+chain.SchemaVersion+")")
	c.Flags().BoolVar(&native, "native", false, "with --json, print the format's own report instead, such as Mandatum's whosent.report/v1")
	c.Flags().BoolVar(&strict, "strict", false, "treat INCOMPLETE as a failure (exit 1)")
	return c
}

func exitCode(c *chain.Chain, strict bool) int {
	switch {
	case c.Inconsistency != nil:
		return ExitInconsistent
	case c.Verdict == chain.VerdictValid:
		return ExitValid
	case c.Verdict == chain.VerdictIncomplete && !strict:
		return ExitIncomplete
	}
	return ExitInvalid
}

// glyph is a check's mark in the human report. Every status has its own
// mark, so the report reads the same without colour.
func glyph(s chain.Status) string {
	switch s {
	case chain.StatusPass:
		return "✓"
	case chain.StatusFail:
		return "✗"
	case chain.StatusError:
		return "!"
	case chain.StatusUnchecked:
		return "?"
	case chain.StatusSkipped:
		return "-"
	}
	return "·"
}

func severityGlyph(s chain.Severity) string {
	switch s {
	case chain.SeverityFail:
		return "✗"
	case chain.SeverityError:
		return "!"
	case chain.SeverityUnchecked:
		return "?"
	case chain.SeverityWarn:
		return "▲"
	}
	return "i"
}

func verdictLine(c *chain.Chain) string {
	switch c.Verdict {
	case chain.VerdictValid:
		// A JWT names its prior actors only on the issuer's word (RFC 8693
		// section 4.1), so "every link was checked" would be false for
		// them. Exit 0 still holds: the token itself verifies, and only
		// its current actor is authoritative.
		if n := assertedLinks(c); n > 0 {
			return fmt.Sprintf("✅ VALID: every checkable rule holds, but %d prior %s the issuer's word, not verified hop by hop",
				n, plural(n, "actor is", "actors are"))
		}
		return "✅ VALID: every rule checked for every link, and the chain holds"
	case chain.VerdictIncomplete:
		return "⚠️  INCOMPLETE: nothing failed, but some rules were not checked, so nothing is vouched for"
	}
	if c.BreakAt >= 0 {
		return fmt.Sprintf("❌ INVALID: the chain breaks at link %d, and no authority reaches below it", c.BreakAt)
	}
	return "❌ INVALID: the chain grants nothing"
}

// assertedLinks counts the links only the issuer vouches for.
func assertedLinks(c *chain.Chain) int {
	n := 0
	for _, l := range c.Links {
		if l.Asserted {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// linkName is "from → to", or what to say when the link was unreadable.
func linkName(l chain.Link) string {
	if !l.Readable {
		return "(does not parse)"
	}
	from, to := l.From, l.To
	if from == "" {
		from = "?"
	}
	if to == "" {
		to = "?"
	}
	return from + " → " + to
}

func writeReport(w io.Writer, c *chain.Chain) {
	p := printer(w)

	head := fmt.Sprintf("=== %s · %d links", c.Source, len(c.Links))
	if len(c.Links) == 1 {
		head = fmt.Sprintf("=== %s · 1 link", c.Source)
	}
	if c.Format.Name != "" {
		head += " · " + c.Format.Name
	}
	if c.Describe != "" {
		head += " · " + c.Describe
	}
	p("%s\n", head)
	if c.Context != "" {
		p("    %s\n", c.Context)
	}
	if len(c.Simulated) > 0 {
		p("    ⊘ simulating revocation of %s\n", strings.Join(c.Simulated, ", "))
	}
	if c.Reversed {
		p("    reversed on request (--reverse)\n")
	}
	p("\n%s\n", verdictLine(c))
	if c.Inconsistency != nil {
		p("\n‼️  INTERNAL INCONSISTENCY: %s\n    the %s reference implementation's verdict stands; this is a bug in whosent.\n",
			c.Inconsistency.Detail, c.Format.Name)
	}

	if len(c.Links) > 0 {
		p("\n  #  %-34s", "issuer → subject")
		for _, r := range c.Format.Rules {
			p(" %s", r.ID)
		}
		p("\n")
		for _, l := range c.Links {
			name := linkName(l)
			if len([]rune(name)) > 34 {
				name = string([]rune(name)[:33]) + "…"
			}
			p("  %d  %-34s", l.Index, name)
			for _, r := range c.Format.Rules {
				// Each mark sits under the end of its rule's name.
				p(" %s%s", strings.Repeat(" ", max(len([]rune(r.ID))-1, 0)), glyph(l.Check(r.ID).Status))
			}
			switch {
			case l.Unreached:
				p("   (no authority reaches here)")
			case l.Revoked && l.RevokedSimulated:
				p("   ⊘ revoked (simulated)")
			case l.Asserted && l.State != chain.LinkBroken:
				p("   (asserted by the issuer, not verified)")
			}
			p("\n")
		}
		p("     ✓ pass  ✗ fail  ! could not evaluate  ? not checked  - skipped  · does not apply\n")
	}

	findings := c.Findings()
	if len(findings) > 0 {
		p("\nFindings\n")
		for _, f := range findings {
			where := "chain"
			if f.Link >= 0 {
				where = fmt.Sprintf("link %d", f.Link)
			}
			rule := f.Rule
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

	if len(c.Hops) > 0 {
		p("\nHow authority narrows\n")
		for _, h := range c.Hops {
			from, to := "?", "?"
			if h.Parent >= 0 && h.Parent < len(c.Links) && c.Links[h.Parent].To != "" {
				from = c.Links[h.Parent].To
			}
			if h.Child >= 0 && h.Child < len(c.Links) && c.Links[h.Child].To != "" {
				to = c.Links[h.Child].To
			}
			p("  %d → %d  %s → %s\n", h.Parent, h.Child, from, to)
			if !h.Evaluable {
				p("      cannot compare: a link of this pair does not parse\n")
				continue
			}
			changes := h.Summary
			if changes == nil {
				changes = h.Changes
			}
			for _, ch := range changes {
				text := ch.Text
				if ch.Before != "" {
					text = ch.Before + " → " + text
				}
				p("      %s %s\n", changeMark(ch.Kind), text)
				for _, n := range ch.Notes {
					p("          %s\n", n)
				}
			}
		}
		p("      = kept  ~ narrowed  - dropped  + added  ✗ widened (violation)\n")
	}

	if len(c.Missing) > 0 {
		p("\nNot checked: %s\n", strings.Join(c.Missing, ", "))
	}
	for _, ig := range c.Ignored {
		p("Ignored: %s\n", ig)
	}
}

func changeMark(k chain.ChangeKind) string {
	switch k {
	case chain.ChangeKept:
		return "="
	case chain.ChangeNarrowed:
		return "~"
	case chain.ChangeDropped:
		return "-"
	case chain.ChangeAdded:
		return "+"
	case chain.ChangeWidened:
		return "✗"
	case chain.ChangeInfo:
		return "i"
	}
	return "?"
}
