package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/kanywst/mandatum/pkg/verify"
	"github.com/spf13/cobra"

	"github.com/kanywst/whosent/pkg/diagnose"
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

func newAsk(f *flags, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	a := &askFlags{}
	c := &cobra.Command{
		Use:   "ask [FILE|-]",
		Short: "Would this chain permit an action?",
		Long: `ask checks a request against the chain with mandatum's own matcher, at every
link, so you can see where authority for it ends, or where it appears from
nowhere.

The answer is labelled for how far it can be relied on:
  AUTHORITATIVE  the chain verified with every input supplied
  CONDITIONAL    nothing failed, but some rules were not checked
  HYPOTHETICAL   the chain does not verify, so it permits nothing; this is what the leaf claims

Exit status:
  0   permitted by a VALID chain
  1   not permitted (including any request against an INVALID chain)
  2   permitted, CONDITIONAL on rules that were not checked (1 with --strict)
  3   the command line or an input file is wrong
  70  this tool and mandatum disagree about the chain (a bug in whosent)`,
		Example: `  whosent ask chain.json --resource-id web.fetch --attr args.host=docs.example.org
  whosent ask call.json --attr-from-args       # a tools/call request names the tool and its arguments`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in, opts, err := f.load(cmd, args, stdin)
			if err != nil {
				return err
			}
			req, warnings, err := a.build(cmd, in.Info.ToolCall)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				printer(stderr)("whosent: %s\n", w)
			}
			r, err := diagnoseInput(cmd.Context(), in, opts)
			if err != nil {
				return err
			}
			t := r.Ask(req)
			if a.asJSON {
				if err := writeJSON(stdout, t.JSON(r.Verdict)); err != nil {
					return err
				}
			} else {
				writeTrace(stdout, r, t)
			}
			if !r.Library.Consistent {
				printer(stderr)("whosent: internal inconsistency: %s\n", r.Library.Mismatch)
				return exitError{ExitInconsistent}
			}
			switch {
			case t.Permitted && t.Authority == diagnose.Authoritative:
				return exitError{ExitValid}
			case t.Permitted && !a.strict:
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
	fl.BoolVar(&a.asJSON, "json", false, "print the answer as JSON (schema "+diagnose.TraceSchemaVersion+")")
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

func (a *askFlags) build(cmd *cobra.Command, call *diagnose.ToolCall) (verify.Request, []string, error) {
	req := verify.Request{ResourceType: a.resourceType, Action: a.action, Attributes: map[string]any{}}
	var warnings []string
	changed := cmd.Flags().Changed

	if a.request != "" {
		data, err := os.ReadFile(a.request)
		if err != nil {
			return req, nil, fmt.Errorf("reading request: %w", err)
		}
		var rf requestFile
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rf); err != nil {
			return req, nil, fmt.Errorf("parsing request %s: %w", a.request, err)
		}
		if rf.ResourceType != "" && !changed("resource-type") {
			req.ResourceType = rf.ResourceType
		}
		if rf.Action != "" && !changed("action") {
			req.Action = rf.Action
		}
		req.ResourceID = rf.ResourceID
		req.ResourceTags = rf.ResourceTags
		for k, v := range rf.Attributes {
			req.Attributes[k] = v
		}
	}

	if a.fromArgs {
		if call == nil || call.Arguments == nil {
			return req, nil, errors.New("--attr-from-args needs a tools/call request with arguments as the input")
		}
		// The enforcement point does not do this mapping; a deployment
		// decides how arguments become attributes. Say so, every time.
		warnings = append(warnings, "mapping tool arguments to args.* attributes is this tool's assumption, not something mandatum's enforcement point does")
		keys := make([]string, 0, len(call.Arguments))
		for k := range call.Arguments {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			req.Attributes["args."+k] = call.Arguments[k]
		}
	}

	if changed("resource-id") {
		req.ResourceID = a.resourceID
	}
	if req.ResourceID == "" && call != nil && call.Name != "" {
		req.ResourceID = call.Name
	}
	if len(a.tags) > 0 {
		req.ResourceTags = append(req.ResourceTags, a.tags...)
	}
	for _, kv := range a.attrs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return req, nil, fmt.Errorf("--attr %q: want KEY=VALUE", kv)
		}
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			val = v
		}
		req.Attributes[k] = val
	}

	switch {
	case req.ResourceID == "":
		return req, nil, errors.New("name the resource with --resource-id (or give a tools/call request, which names its tool)")
	case req.ResourceType == "":
		return req, nil, errors.New("--resource-type is empty")
	case req.Action == "":
		return req, nil, errors.New("--action is empty")
	}
	return req, warnings, nil
}

func describeRequest(req verify.Request) string {
	s := fmt.Sprintf("%s %s:%s", req.Action, req.ResourceType, req.ResourceID)
	for _, t := range req.ResourceTags {
		s += " #" + t
	}
	if len(req.Attributes) > 0 {
		keys := make([]string, 0, len(req.Attributes))
		for k := range req.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, req.Attributes[k]))
		}
		s += " {" + strings.Join(parts, ", ") + "}"
	}
	return s
}

func writeTrace(w io.Writer, r *diagnose.Report, t diagnose.Trace) {
	p := printer(w)
	p("=== %s\n    %s\n\n", r.Input.Source, describeRequest(t.Request))
	switch {
	case t.Permitted && t.Authority == diagnose.Authoritative:
		p("✅ PERMITTED (AUTHORITATIVE): the chain verified with every input, and its grant covers this\n")
	case t.Permitted:
		p("⚠️  PERMITTED (CONDITIONAL): covered, but only if the rules that were not checked pass\n")
	case t.Authority == diagnose.Hypothetical && t.Covered:
		p("❌ DENIED: the chain does not verify\n    hypothetically, if it did: the leaf's grant covers this\n")
	case t.Authority == diagnose.Hypothetical:
		p("❌ DENIED: the chain does not verify\n    hypothetically, if it did: still not covered\n")
	case t.Authority == diagnose.NotEvaluable:
		p("❌ DENIED: %s\n", t.Reason)
	default:
		p("❌ DENIED (%s): not covered by the chain's grant\n", t.Authority)
	}
	if t.Reason != "" && t.Authority != diagnose.NotEvaluable {
		p("    %s\n", t.Reason)
	}
	if t.OnlyThroughWidening {
		if t.SponsorGranted {
			p("\n▲ the leaf holds this only because link %d widened authority: the sponsor granted it, link %d dropped it, and re-adding it below does not bring it back\n",
				t.WideningAt, t.FirstRefused)
		} else {
			p("\n▲ the leaf holds this only because link %d widened authority: the sponsor never granted it\n", t.WideningAt)
		}
	}
	p("\n  link by link\n")
	for _, s := range t.Steps {
		name := "(does not parse)"
		if c := r.Links[s.Link].Claims; c != nil {
			name = principal(c.Subject)
		}
		switch {
		case !s.Evaluable:
			p("  %d  %-14s -  cannot tell\n", s.Link, name)
		case s.Permitted:
			p("  %d  %-14s ✓  covered\n", s.Link, name)
		default:
			p("  %d  %-14s ✗  %s\n", s.Link, name, strings.TrimPrefix(s.Reason, "mandatum: "))
		}
	}
}
