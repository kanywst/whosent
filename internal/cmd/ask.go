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
  whosent ask call.json --attr-from-args       # a tools/call request names the tool and its arguments`,
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
			values, warnings, err := a.build(cmd, c.Call)
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
	fl.BoolVar(&a.asJSON, "json", false, "print the answer as JSON, in the format's own schema (whosent.ask/v1 for Mandatum)")
	fl.BoolVar(&a.strict, "strict", false, "treat a CONDITIONAL answer as not permitted")
	return c
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
