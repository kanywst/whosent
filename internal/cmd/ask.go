package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/pkg/chain"
)

// The defaults mandatum's MCP enforcement point uses.
const (
	defaultResourceType = "mcp_tool"
	defaultAction       = "invoke"
)

type askFlags struct {
	resourceType string
	resourceID   string
	tags         []string
	action       string
	attrs        []string
	request      string
	fromArgs     bool
	scope        string
	policy       string
	fields       []string
	asJSON       bool
	strict       bool
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
		Example: `  whosent ask chain.json --resource-id web.fetch --attr args.host=docs.example.org
  whosent ask call.json --attr-from-args       # a tools/call request names the tool and its arguments
  whosent ask token.jwt --jwks ISS=jwks.json --audience https://api --scope files:read
  whosent ask token.b64 --root-key root.pub --authorizer authz.datalog --resource-id orders --action read
  whosent ask token.b64 --root-key root.pub --field 'facts=resource("orders"); operation("read")' --policy 'allow if true'

Which flags apply depends on the format: Mandatum asks about a resource
(--resource-id, --action, --resource-type, --tag, --attr); a JWT about a
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
			values, warnings, err := a.values(cmd, asker.AskFields(), c.Call, f)
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
	fl.StringVar(&a.resourceType, "resource-type", defaultResourceType, "the resource's type")
	fl.StringVar(&a.resourceID, "resource-id", "", "the resource, such as a tool name (default: the tool a tools/call request names)")
	fl.StringArrayVar(&a.tags, "tag", nil, "a tag the deployment attaches to the resource (repeatable)")
	fl.StringVar(&a.action, "action", defaultAction, "the action attempted")
	fl.StringArrayVar(&a.attrs, "attr", nil, "an attribute conditions are evaluated against, KEY=VALUE; VALUE is read as JSON when it parses (repeatable)")
	fl.StringVar(&a.request, "request", "", "read the request from a JSON file instead")
	fl.BoolVar(&a.fromArgs, "attr-from-args", false, "map a tools/call request's arguments to args.<name> attributes")
	fl.StringVar(&a.scope, "scope", "", "JWT: the scope to ask about")
	fl.StringVar(&a.policy, "policy", "", "Biscuit: the policies that decide, instead of the authorizer's own")
	fl.StringArrayVar(&a.fields, "field", nil, "set one of the format's question fields, KEY=VALUE (repeatable)")
	fl.BoolVar(&a.asJSON, "json", false, "print the answer as JSON, in the format's own schema (whosent.ask/v1 for Mandatum)")
	fl.BoolVar(&a.strict, "strict", false, "treat a CONDITIONAL answer as not permitted")
	return c
}

// resourceFlags are the flags that build a Mandatum resource request.
var resourceFlags = []string{"resource-type", "resource-id", "tag", "action", "attr", "request", "attr-from-args"}

// values turns the flags into the format's question. Mandatum's question
// is a resource request, which build assembles from the resource flags.
// Other formats name their own fields; the flags that map onto them are
// used, a flag the format has no field for is refused (rather than quietly
// ignored, which would answer a question nobody asked), and a required
// field left empty is refused too.
func (a *askFlags) values(cmd *cobra.Command, fields []chain.AskField, call *chain.Call, gf *flags) (map[string]string, []string, error) {
	changed := cmd.Flags().Changed
	has := map[string]bool{}
	var keys []string
	for _, fd := range fields {
		has[fd.Key] = true
		keys = append(keys, fd.Key)
	}
	var values map[string]string
	var warnings []string
	switch {
	case has["resource_id"]:
		for _, fl := range []string{"scope", "policy"} {
			if changed(fl) {
				return nil, nil, fmt.Errorf("--%s does not apply to this format's questions", fl)
			}
		}
		var err error
		if values, warnings, err = a.build(cmd, call); err != nil {
			return nil, nil, err
		}
	default:
		values = map[string]string{}
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
		if changed("resource-id") || (changed("action") && !has["command"]) {
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
		for _, fl := range resourceFlags {
			if fl == "resource-id" || fl == "action" {
				continue
			}
			if changed(fl) {
				return nil, nil, refuse(fl)
			}
		}
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
	case "resource_id":
		return "--resource-id"
	case "policy":
		return "--policy"
	case "command":
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

// requestFile is the --request format.
type requestFile struct {
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceTags []string       `json:"resource_tags"`
	Action       string         `json:"action"`
	Attributes   map[string]any `json:"attributes"`
}

// build turns the flags into the question's values, in the field keys the
// formats share: action, resource_type, resource_id, tags, and the
// attributes as one JSON object so typed values survive.
func (a *askFlags) build(cmd *cobra.Command, call *chain.Call) (map[string]string, []string, error) {
	resourceType, action := a.resourceType, a.action
	var resourceID string
	var tags []string
	attrs := map[string]any{}
	var warnings []string
	changed := cmd.Flags().Changed

	if a.request != "" {
		data, err := os.ReadFile(a.request)
		if err != nil {
			return nil, nil, fmt.Errorf("reading request: %w", err)
		}
		var rf requestFile
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rf); err != nil {
			return nil, nil, fmt.Errorf("parsing request %s: %w", a.request, err)
		}
		if rf.ResourceType != "" && !changed("resource-type") {
			resourceType = rf.ResourceType
		}
		if rf.Action != "" && !changed("action") {
			action = rf.Action
		}
		resourceID = rf.ResourceID
		tags = rf.ResourceTags
		for k, v := range rf.Attributes {
			attrs[k] = v
		}
	}

	if a.fromArgs {
		if call == nil || call.Arguments == nil {
			return nil, nil, errors.New("--attr-from-args needs a tools/call request with arguments as the input")
		}
		// The enforcement point does not do this mapping; a deployment
		// decides how arguments become attributes. Say so, every time.
		warnings = append(warnings, "mapping tool arguments to args.* attributes is this tool's assumption, not something an enforcement point does")
		keys := make([]string, 0, len(call.Arguments))
		for k := range call.Arguments {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			attrs["args."+k] = call.Arguments[k]
		}
	}

	if changed("resource-id") {
		resourceID = a.resourceID
	}
	if resourceID == "" && call != nil && call.Name != "" {
		resourceID = call.Name
	}
	tags = append(tags, a.tags...)
	for _, kv := range a.attrs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, nil, fmt.Errorf("--attr %q: want KEY=VALUE", kv)
		}
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			val = v
		}
		attrs[k] = val
	}

	switch {
	case resourceID == "":
		return nil, nil, errors.New("name the resource with --resource-id (or give a tools/call request, which names its tool)")
	case resourceType == "":
		return nil, nil, errors.New("--resource-type is empty")
	case action == "":
		return nil, nil, errors.New("--action is empty")
	}
	for _, t := range tags {
		if strings.Contains(t, ",") {
			return nil, nil, fmt.Errorf("--tag %q: a tag cannot contain a comma", t)
		}
	}
	rawAttrs, err := json.Marshal(attrs)
	if err != nil {
		return nil, nil, fmt.Errorf("attributes: %w", err)
	}
	return map[string]string{
		"action": action, "resource_type": resourceType, "resource_id": resourceID,
		"tags": strings.Join(tags, ","), "attributes_json": string(rawAttrs),
	}, warnings, nil
}
