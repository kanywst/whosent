package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/pkg/chain"
)

type askFlags struct {
	resourceID string
	action     string
	scope      string
	policy     string
	fields     []string
	asJSON     bool
	strict     bool
}

func newAsk(f *flags, reg *chain.Registry, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	a := &askFlags{}
	c := &cobra.Command{
		Use:   "ask [FILE|-]",
		Short: "Would this chain permit an action?",
		Long: `ask checks a request against the chain with its format's own matcher, at
every link, so you can see where authority for it ends, or where it appears
from nowhere.

The answer is labelled for how far it can be relied on:
  AUTHORITATIVE  the chain verified with every input supplied
  CONDITIONAL    nothing failed, but some rules were not checked
  HYPOTHETICAL   the chain does not verify, so it permits nothing; this is what the leaf claims

Exit status:
  0   permitted by a VALID chain
  1   not permitted (including any request against an INVALID chain)
  2   permitted, CONDITIONAL on rules that were not checked (1 with --strict)
  3   the command line or an input file is wrong
  70  this tool and the format's reference implementation disagree about the
      chain (a bug in whosent)`,
		Example: `  whosent ask token.jwt --jwks ISS=jwks.json --audience https://api --scope files:read
  whosent ask token.b64 --root-key root.pub --authorizer authz.datalog --resource-id orders --action read
  whosent ask token.b64 --root-key root.pub --field 'facts=resource("orders"); operation("read")' --policy 'allow if true'

Which flags apply depends on the format: a JWT asks about a
scope (--scope, and --audience for where it is used); a Biscuit token runs
its authorizer (--authorizer and --fact) for a request (--resource-id and
--action become resource(...) and operation(...) facts) and decides with the
authorizer's policies unless --policy gives others; a UCAN chain about a
command (--action) and its arguments (--field args=JSON). --field KEY=VALUE sets
any of the format's question fields directly. A flag the format does not
use is refused, and nothing a question needs is filled in from a default.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, _, err := f.load(cmd, reg, args, stdin)
			if err != nil {
				return err
			}
			asker, ok := s.(chain.Asker)
			if !ok || !s.Info().Format.Caps.Ask {
				return fmt.Errorf("the %s format cannot answer questions yet", s.Info().Format.Name)
			}
			c, err := evaluate(cmd.Context(), s)
			if err != nil {
				return err
			}
			values, warnings, err := a.values(cmd, asker.AskFields(), f)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				printer(stderr)("whosent: %s\n", w)
			}
			res, err := asker.Ask(cmd.Context(), c, values)
			if err != nil {
				return err
			}
			if a.asJSON {
				doc := res.Native
				if doc == nil {
					doc = res
				}
				if err := writeJSON(stdout, doc); err != nil {
					return err
				}
			} else {
				p := printer(stdout)
				for _, line := range res.Report {
					p("%s\n", line)
				}
			}
			if c.Inconsistency != nil {
				printer(stderr)("whosent: internal inconsistency: %s\n", c.Inconsistency.Detail)
				return exitError{ExitInconsistent}
			}
			if res.Inconsistency != nil {
				printer(stderr)("whosent: internal inconsistency: %s\n", res.Inconsistency.Detail)
				return exitError{ExitInconsistent}
			}
			switch {
			case res.Permitted && !res.Conditional:
				return exitError{ExitValid}
			case res.Permitted && !a.strict:
				return exitError{ExitIncomplete}
			}
			return exitError{ExitInvalid}
		},
	}
	fl := c.Flags()
	fl.StringVar(&a.resourceID, "resource-id", "", "Biscuit: the resource, as a resource(...) fact")
	fl.StringVar(&a.action, "action", "", "the action: Biscuit's operation(...) fact, UCAN's command, Fly.io's action")
	fl.StringVar(&a.scope, "scope", "", "JWT: the scope to ask about")
	fl.StringVar(&a.policy, "policy", "", "Biscuit: the policies that decide, instead of the authorizer's own")
	fl.StringArrayVar(&a.fields, "field", nil, "set one of the format's question fields, KEY=VALUE (repeatable)")
	fl.BoolVar(&a.asJSON, "json", false, "print the answer as JSON, in the format's own schema")
	fl.BoolVar(&a.strict, "strict", false, "treat a CONDITIONAL answer as not permitted")
	return c
}

// values turns the flags into the format's question. Each format names its
// own fields; the flags that map onto them are used, a flag the format has no
// field for is refused (rather than quietly ignored, which would answer a
// question nobody asked), and a required field left empty is refused too.
func (a *askFlags) values(cmd *cobra.Command, fields []chain.AskField, gf *flags) (map[string]string, []string, error) {
	changed := cmd.Flags().Changed
	has := map[string]bool{}
	var keys []string
	for _, fd := range fields {
		has[fd.Key] = true
		keys = append(keys, fd.Key)
	}
	values := map[string]string{}
	var warnings []string
	refuse := func(fl string) error {
		return fmt.Errorf("--%s does not apply to this format's questions (its fields: %s)", fl, strings.Join(keys, ", "))
	}
	if changed("scope") {
		if !has["scope"] {
			return nil, nil, refuse("scope")
		}
		values["scope"] = a.scope
	}
	if has["audience"] && gf.audience != "" {
		values["audience"] = gf.audience
	}
	if changed("policy") {
		if !has["policy"] {
			return nil, nil, refuse("policy")
		}
		values["policy"] = a.policy
	}
	if has["command"] && changed("action") {
		values["command"] = a.action
	}
	if has["action"] && changed("action") {
		values["action"] = a.action
	}
	if changed("resource-id") || (changed("action") && !has["command"] && !has["action"]) {
		if !has["facts"] {
			if changed("resource-id") {
				return nil, nil, refuse("resource-id")
			}
			return nil, nil, refuse("action")
		}
		var facts []string
		if changed("resource-id") {
			facts = append(facts, fmt.Sprintf("resource(%s)", datalogString(a.resourceID)))
		}
		if changed("action") {
			facts = append(facts, fmt.Sprintf("operation(%s)", datalogString(a.action)))
		}
		values["facts"] = strings.Join(facts, "; ")
	}
	for _, kv := range a.fields {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, nil, fmt.Errorf("--field %q: want KEY=VALUE", kv)
		}
		if !has[k] {
			return nil, nil, fmt.Errorf("--field %q: this format's question has no field %q (its fields: %s)", kv, k, strings.Join(keys, ", "))
		}
		values[k] = v
	}
	for _, fd := range fields {
		if fd.Required && strings.TrimSpace(values[fd.Key]) == "" {
			return nil, nil, fmt.Errorf("the question needs its %s: give it with %s", fd.Label, flagFor(fd.Key))
		}
	}
	return values, warnings, nil
}

// flagFor names the flag that sets a question field.
func flagFor(key string) string {
	switch key {
	case "scope":
		return "--scope"
	case "policy":
		return "--policy"
	case "command", "action":
		return "--action"
	}
	return "--field " + key + "=..."
}

// datalogString writes a Datalog string literal, escaping what the
// parser requires escaped.
func datalogString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
