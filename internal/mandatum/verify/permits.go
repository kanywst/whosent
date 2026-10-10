package verify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// Request is a concrete action an agent is attempting, as opposed to the
// patterns a capability is written in.
type Request struct {
	// ResourceType and ResourceID identify what is being acted on. Both are
	// literal: a request is a thing that happened, not a pattern.
	ResourceType string
	ResourceID   string
	// ResourceTags are the tags the deployment attaches to this resource. A
	// capability requiring a tag matches only a resource carrying it.
	ResourceTags []string
	// Action is what is being attempted.
	Action string
	// Attributes are the values conditions are evaluated against, keyed by
	// the same names the conditions use. For a tool call, a caller
	// populating "args.index" from the tool's arguments is the intended
	// shape; nothing here parses argument paths, because guessing at a
	// caller's naming is how a condition silently matches the wrong value.
	Attributes map[string]any
}

// Permits reports whether the chain's capability set covers req.
//
// This is the check that makes "a Policy Decision Point cannot widen
// authority" true rather than aspirational. Verification establishes what a
// human delegated; a PDP applies policy on top of that. Neither, on its own,
// stops a PDP from permitting something no sponsor granted - only comparing
// the request against the chain does, and only if someone calls it.
//
// A Policy Enforcement Point MUST call this and honour a denial regardless of
// what the PDP said. The ordering that matters is: verify the chain, check it
// permits the request, ask the PDP, and allow only if all three agree. Asking
// the PDP first and skipping this is the shape of the confused deputy the
// project exists to prevent.
//
// A nil error means the chain covers the request. Any error means it does
// not, and names why in terms of the grant rather than the implementation.
func (r *Result) Permits(req Request) error {
	if r == nil {
		return fmt.Errorf("mandatum: no verified chain; a request cannot be permitted by nothing")
	}
	switch {
	case req.ResourceType == "":
		return fmt.Errorf("mandatum: the request names no resource type")
	case req.ResourceID == "":
		return fmt.Errorf("mandatum: the request names no resource")
	case req.Action == "":
		return fmt.Errorf("mandatum: the request names no action")
	}

	// An empty capability set is valid and grants nothing, so this is a
	// denial rather than a vacuous pass.
	if len(r.Capabilities) == 0 {
		return fmt.Errorf(
			"mandatum: %q on %s/%s is outside the chain's grant, which is empty",
			req.Action, req.ResourceType, req.ResourceID)
	}

	why := make([]string, 0, len(r.Capabilities))
	for i, c := range r.Capabilities {
		reason := covers(c, req)
		if reason == "" {
			return nil
		}
		why = append(why, fmt.Sprintf("cap[%d]: %s", i, reason))
	}

	return fmt.Errorf(
		"mandatum: %q on %s/%s is outside the chain's grant (%s)",
		req.Action, req.ResourceType, req.ResourceID, strings.Join(why, "; "))
}

// covers returns "" when the capability admits the request, or a short
// reason why it does not. A reason rather than a bool, because a denial an
// operator cannot explain is a denial they will switch off.
func covers(c mda.Capability, req Request) string {
	if c.Resource.Type != req.ResourceType {
		return fmt.Sprintf("grants %s, not %s", c.Resource.Type, req.ResourceType)
	}
	// The capability's ID may be a prefix pattern; the request's is literal.
	if !idCovers(c.Resource.ID, literal(req.ResourceID)) {
		return fmt.Sprintf("grants %q, not %q", c.Resource.ID, req.ResourceID)
	}
	// Tags on a capability are requirements: the resource must carry them.
	for _, want := range c.Resource.Tags {
		if !slices.Contains(req.ResourceTags, want) {
			return fmt.Sprintf("requires the resource to be tagged %q", want)
		}
	}
	if c.Action.Name != req.Action {
		return fmt.Sprintf("grants %q, not %q", c.Action.Name, req.Action)
	}
	for key, cond := range c.Conditions {
		value, present := req.Attributes[key]
		if !present {
			// The condition restricts something the request did not report.
			// Denying is the only safe reading: treating an absent attribute
			// as satisfying the condition would make every condition
			// optional from the caller's side.
			return fmt.Sprintf("is conditioned on %q, which the request did not supply", key)
		}
		if !satisfies(cond, value) {
			return fmt.Sprintf("condition on %q is not met by %v", key, value)
		}
	}
	return ""
}

// literal escapes a concrete identifier so that idCovers treats it as a
// literal even when it happens to end in the prefix marker. Without this a
// resource genuinely named "foo*" would be read as a pattern.
func literal(id string) string {
	if strings.HasSuffix(id, "*") {
		return id + "\x00"
	}
	return id
}

// satisfies evaluates one condition against one concrete value.
//
// Anything the decidable fragment cannot compare answers false, matching
// entailment: a condition that cannot be evaluated has not been met.
func satisfies(c mda.Condition, value any) bool {
	switch {
	case c.Equals != nil:
		s, ok := value.(string)
		return ok && s == *c.Equals

	case c.In != nil:
		s, ok := value.(string)
		return ok && slices.Contains(c.In, s)

	case c.Prefix != nil:
		s, ok := value.(string)
		return ok && strings.HasPrefix(s, *c.Prefix)

	case c.Min != nil || c.Max != nil:
		n, ok := numeric(value)
		if !ok {
			return false
		}
		if c.Min != nil && n < *c.Min {
			return false
		}
		if c.Max != nil && n > *c.Max {
			return false
		}
		return true

	default:
		return false
	}
}

// numeric accepts the shapes a decoded JSON number arrives in, and the Go
// integer types a caller building attributes by hand is likely to use.
func numeric(value any) (float64, bool) {
	switch n := value.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
