package mandatum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// The question form's field keys.
const (
	FieldAction       = "action"
	FieldResourceType = "resource_type"
	FieldResourceID   = "resource_id"
	FieldTags         = "tags"
	FieldAttributes   = "attributes"
	// FieldAttributesJSON carries attributes as one JSON object, so the
	// command line can pass typed values that the comma-separated form
	// field cannot spell.
	FieldAttributesJSON = "attributes_json"
)

var askFields = []chain.AskField{
	{Key: FieldAction, Label: "action", Hint: "what is attempted, such as invoke"},
	{Key: FieldResourceType, Label: "resource type", Hint: "such as mcp_tool"},
	{Key: FieldResourceID, Label: "resource id", Hint: "the literal resource, such as web.fetch", Required: true},
	{Key: FieldTags, Label: "tags", Hint: "comma separated"},
	{Key: FieldAttributes, Label: "attributes", Hint: "key=value, comma separated; values are read as JSON when they parse"},
}

// AskFields are the request's parts.
func (s *Session) AskFields() []chain.AskField { return askFields }

// AskPrefill proposes something worth asking. An MCP tools/call input names
// its own tool; otherwise the selected authority row, as the deepest link
// that holds it holds it, is turned into a concrete request it would cover,
// so pressing enter straight away shows a real answer, and changing one
// field shows what that changes.
func (s *Session) AskPrefill(c *chain.Chain, row int) map[string]string {
	v := map[string]string{FieldAction: "invoke", FieldResourceType: "mcp_tool"}
	r, ok := reportOf(c)
	if !ok {
		return v
	}
	if tc := r.Input.ToolCall; tc != nil && tc.Name != "" {
		v[FieldResourceID] = tc.Name
		return v
	}
	var caps []mda.Capability
	if row >= 0 && row < len(r.Matrix.Rows) {
		mr := r.Matrix.Rows[row]
		for i := len(mr.Cells) - 1; i >= 0 && caps == nil; i-- {
			cell, claims := mr.Cells[i], r.Links[i].Claims
			if claims == nil || len(cell.Caps) == 0 || cell.Kind == diagnose.CellAbsent {
				continue
			}
			if ci := cell.Caps[0]; ci < len(claims.Mandatum.Capabilities) {
				caps = claims.Mandatum.Capabilities[ci : ci+1]
			}
		}
	}
	for i := len(r.Links) - 1; i >= 0 && caps == nil; i-- {
		if cl := r.Links[i].Claims; cl != nil && len(cl.Mandatum.Capabilities) > 0 {
			caps = cl.Mandatum.Capabilities
		}
	}
	if len(caps) == 0 {
		return v
	}
	cp := caps[0]
	v[FieldAction] = cp.Action.Name
	v[FieldResourceType] = cp.Resource.Type
	id := cp.Resource.ID
	if strings.HasSuffix(id, "*") {
		id = strings.TrimSuffix(id, "*") + "example"
	}
	v[FieldResourceID] = id
	v[FieldTags] = strings.Join(cp.Resource.Tags, ", ")
	var attrs []string
	for _, k := range sortedKeys(cp.Conditions) {
		if s, ok := sampleValue(cp.Conditions[k]); ok {
			attrs = append(attrs, k+"="+s)
		}
	}
	v[FieldAttributes] = strings.Join(attrs, ", ")
	return v
}

// sampleValue is a value the condition accepts.
func sampleValue(c mda.Condition) (string, bool) {
	switch {
	case c.Equals != nil:
		return *c.Equals, true
	case len(c.In) > 0:
		return c.In[0], true
	case c.Prefix != nil:
		return *c.Prefix + "example", true
	case c.Min != nil:
		return fmt.Sprint(*c.Min), true
	case c.Max != nil:
		return fmt.Sprint(*c.Max), true
	}
	return "", false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Request reads the form's values as a request, or says which field is
// wrong.
func Request(values map[string]string) (verify.Request, error) {
	req := verify.Request{
		Action:       strings.TrimSpace(values[FieldAction]),
		ResourceType: strings.TrimSpace(values[FieldResourceType]),
		ResourceID:   strings.TrimSpace(values[FieldResourceID]),
		Attributes:   map[string]any{},
	}
	if req.Action == "" || req.ResourceType == "" || req.ResourceID == "" {
		return req, errors.New("action, resource type and resource id are all needed")
	}
	for _, t := range strings.Split(values[FieldTags], ",") {
		if t = strings.TrimSpace(t); t != "" {
			req.ResourceTags = append(req.ResourceTags, t)
		}
	}
	if raw := values[FieldAttributesJSON]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &req.Attributes); err != nil {
			return req, fmt.Errorf("attributes: %w", err)
		}
		if req.Attributes == nil {
			req.Attributes = map[string]any{}
		}
	}
	for _, kv := range strings.Split(values[FieldAttributes], ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return req, fmt.Errorf("attribute %q: want key=value", kv)
		}
		v = strings.TrimSpace(v)
		var parsed any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			req.Attributes[k] = parsed
		} else {
			req.Attributes[k] = v
		}
	}
	return req, nil
}

// Values writes a request back as form values.
func Values(req verify.Request) map[string]string {
	v := map[string]string{
		FieldAction: req.Action, FieldResourceType: req.ResourceType, FieldResourceID: req.ResourceID,
		FieldTags: strings.Join(req.ResourceTags, ", "),
	}
	var attrs []string
	for _, k := range sortedKeys(req.Attributes) {
		b, _ := json.Marshal(req.Attributes[k])
		s := string(b)
		if str, ok := req.Attributes[k].(string); ok && !strings.ContainsAny(str, ", =") {
			s = str
		}
		attrs = append(attrs, k+"="+s)
	}
	v[FieldAttributes] = strings.Join(attrs, ", ")
	return v
}

// Ask checks the request against every link with the reference matcher.
func (s *Session) Ask(_ context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error) {
	r, ok := reportOf(c)
	if !ok {
		return nil, errors.New("this chain was not built by the Mandatum adapter")
	}
	req, err := Request(values)
	if err != nil {
		return nil, err
	}
	return Answer(r, r.Ask(req)), nil
}

// Answer describes a trace in the format-neutral model.
func Answer(r *diagnose.Report, tr diagnose.Trace) *chain.AskResult {
	out := &chain.AskResult{
		Request:    strings.Split(describeRequest(tr.Request, "\n", "  "), "\n"),
		Permitted:  tr.Permitted,
		Authority:  string(tr.Authority),
		StepsTitle: "asked of each link's own grant",
		Values:     Values(tr.Request),
		Native:     tr.JSON(r.Verdict),
	}
	out.Conditional = tr.Permitted && tr.Authority == diagnose.Conditional
	out.Verdict, out.Tone, out.Why = answerVerdict(tr)
	switch {
	case tr.Permitted:
		out.Mark = chain.MarkPass
	case tr.Authority == diagnose.Conditional && tr.Covered:
		out.Mark = chain.MarkUnchecked
	default:
		out.Mark = chain.MarkFail
	}
	if !tr.Covered {
		out.Reason = tr.Reason
	}
	if tr.OnlyThroughWidening {
		// Two different stories, sent to two different people: authority
		// the sponsor never granted, and authority the sponsor granted that
		// a link in between dropped and a later one re-added.
		out.Warning = fmt.Sprintf("the sponsor never granted this: it exists only because link %d widened authority", tr.WideningAt)
		if tr.SponsorGranted {
			out.Warning = fmt.Sprintf("the sponsor granted this, link %d dropped it, and re-adding it at link %d does not bring it back",
				tr.FirstRefused, tr.WideningAt)
		}
	}
	for _, st := range tr.Steps {
		step := chain.AskStep{Link: st.Link, Reason: st.Reason}
		switch {
		case !st.Evaluable:
			step.Outcome = chain.OutcomeUnreadable
		case st.Permitted:
			step.Outcome = chain.OutcomeCovers
		default:
			step.Outcome = chain.OutcomeRefuses
			step.ShowReason = st.Link == tr.FirstRefused
		}
		out.Steps = append(out.Steps, step)
	}
	out.Report = report(r, tr)
	return out
}

// answerVerdict words the answer by how far it can be relied on. A chain
// that does not verify permits nothing, whatever its leaf claims, so that is
// said first and the leaf's claim second.
func answerVerdict(tr diagnose.Trace) (string, chain.Tone, string) {
	switch tr.Authority {
	case diagnose.Authoritative:
		if tr.Permitted {
			return "PERMITTED", chain.ToneGood, "the chain verified with every input, and the leaf's grant covers this request"
		}
		return "DENIED", chain.ToneBad, "the chain verified, but the leaf's grant does not cover this request"
	case diagnose.Conditional:
		if tr.Covered {
			return "PERMITTED IF", chain.ToneWarn, "the leaf's grant covers this request, but only holds if the rules that were not checked pass"
		}
		return "DENIED", chain.ToneBad, "the leaf's grant does not cover this request (some rules were also not checked)"
	case diagnose.Hypothetical:
		if tr.Covered {
			return "DENIED", chain.ToneBad, "the chain does not verify, so it permits nothing. Hypothetically, if it verified, the leaf's grant would cover this request"
		}
		return "DENIED", chain.ToneBad, "the chain does not verify, and even if it did, the leaf's grant would not cover this request"
	}
	return "NOT EVALUABLE", chain.ToneBad, "the leaf does not parse, so it claims nothing that can be read"
}

// describeRequest restates a request: the action and resource, then its
// attributes, separated by sep and joined with join.
func describeRequest(req verify.Request, sep, join string) string {
	s := req.Action + " " + req.ResourceType + ":" + req.ResourceID
	for _, t := range req.ResourceTags {
		s += " #" + t
	}
	var parts []string
	for _, k := range sortedKeys(req.Attributes) {
		parts = append(parts, fmt.Sprintf("%s=%v", k, req.Attributes[k]))
	}
	if len(parts) > 0 {
		s += sep + strings.Join(parts, join)
	}
	return s
}

// report is the command line's human answer.
func report(r *diagnose.Report, t diagnose.Trace) []string {
	var out []string
	p := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	req := describeRequest(t.Request, " {", ", ")
	if len(t.Request.Attributes) > 0 {
		req += "}"
	}
	p("=== %s", r.Input.Source)
	p("    %s", req)
	p("")
	switch {
	case t.Permitted && t.Authority == diagnose.Authoritative:
		p("✅ PERMITTED (AUTHORITATIVE): the chain verified with every input, and its grant covers this")
	case t.Permitted:
		p("⚠️  PERMITTED (CONDITIONAL): covered, but only if the rules that were not checked pass")
	case t.Authority == diagnose.Hypothetical && t.Covered:
		p("❌ DENIED: the chain does not verify")
		p("    hypothetically, if it did: the leaf's grant covers this")
	case t.Authority == diagnose.Hypothetical:
		p("❌ DENIED: the chain does not verify")
		p("    hypothetically, if it did: still not covered")
	case t.Authority == diagnose.NotEvaluable:
		p("❌ DENIED: %s", t.Reason)
	default:
		p("❌ DENIED (%s): not covered by the chain's grant", t.Authority)
	}
	if t.Reason != "" && t.Authority != diagnose.NotEvaluable {
		p("    %s", t.Reason)
	}
	if t.OnlyThroughWidening {
		p("")
		if t.SponsorGranted {
			p("▲ the leaf holds this only because link %d widened authority: the sponsor granted it, link %d dropped it, and re-adding it below does not bring it back",
				t.WideningAt, t.FirstRefused)
		} else {
			p("▲ the leaf holds this only because link %d widened authority: the sponsor never granted it", t.WideningAt)
		}
	}
	p("")
	p("  link by link")
	for _, s := range t.Steps {
		name := "(does not parse)"
		if c := r.Links[s.Link].Claims; c != nil {
			name = principal(c.Subject)
		}
		switch {
		case !s.Evaluable:
			p("  %d  %-14s -  cannot tell", s.Link, name)
		case s.Permitted:
			p("  %d  %-14s ✓  covered", s.Link, name)
		default:
			p("  %d  %-14s ✗  %s", s.Link, name, strings.TrimPrefix(s.Reason, "mandatum: "))
		}
	}
	return out
}

func principal(id string) string {
	if s := diagnose.Short(id); s != id {
		return s
	}
	return id
}
