package verify

import (
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

func str2(s string) *string   { return &s }
func num2(f float64) *float64 { return &f }

func granted(caps ...mda.Capability) *Result {
	return &Result{Capabilities: caps}
}

func toolCap(id, action string) mda.Capability {
	return mda.Capability{
		Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id},
		Action:   mda.ActionPattern{Name: action},
	}
}

func call(id, action string) Request {
	return Request{ResourceType: "mcp_tool", ResourceID: id, Action: action}
}

// The property the specification states and nothing used to enforce: a
// decision, from a PDP or anywhere else, cannot reach outside what a human
// delegated. Without this, a compromised or misconfigured PDP permitting
// admin.wipeAll on a chain granting only search.query would be honoured.
func TestARequestOutsideTheGrantIsRefused(t *testing.T) {
	res := granted(toolCap("search.query", "invoke"))

	if err := res.Permits(call("search.query", "invoke")); err != nil {
		t.Fatalf("refused the exact thing that was granted: %v", err)
	}

	err := res.Permits(call("admin.wipeAll", "invoke"))
	if err == nil {
		t.Fatal("permitted a tool the chain does not grant")
	}
	if !strings.Contains(err.Error(), "outside the chain's grant") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

func TestPermits(t *testing.T) {
	tests := []struct {
		name    string
		result  *Result
		req     Request
		wantErr string
	}{
		{"exact match", granted(toolCap("search.query", "invoke")), call("search.query", "invoke"), ""},
		{
			"a prefix grant covers a literal request",
			granted(toolCap("search.*", "invoke")),
			call("search.query", "invoke"),
			"",
		},
		{
			"a prefix grant does not cover an unrelated tool",
			granted(toolCap("search.*", "invoke")),
			call("admin.wipeAll", "invoke"),
			"grants \"search.*\"",
		},
		{
			"a literal grant does not cover a different tool",
			granted(toolCap("search.query", "invoke")),
			call("search.index", "invoke"),
			"not \"search.index\"",
		},
		{
			"the wrong action",
			granted(toolCap("search.query", "invoke")),
			call("search.query", "administer"),
			"grants \"invoke\"",
		},
		{
			"the wrong resource type",
			granted(toolCap("search.query", "invoke")),
			Request{ResourceType: "http", ResourceID: "search.query", Action: "invoke"},
			"grants mcp_tool, not http",
		},
		{
			"an empty grant permits nothing",
			granted(),
			call("search.query", "invoke"),
			"which is empty",
		},
		{
			"any one capability is enough",
			granted(toolCap("admin.read", "invoke"), toolCap("search.query", "invoke")),
			call("search.query", "invoke"),
			"",
		},
		{
			"a resource genuinely named with a trailing star is not a pattern",
			granted(toolCap("search.query", "invoke")),
			call("search.*", "invoke"),
			"outside the chain's grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Permits(tt.req)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("refused a permitted request: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatal("permitted a request outside the grant")
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// Tags on a capability are requirements. A grant scoped to resources tagged
// "public" must not reach one that is not.
func TestTagsAreRequirements(t *testing.T) {
	c := mda.Capability{
		Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*", Tags: []string{"public"}},
		Action:   mda.ActionPattern{Name: "invoke"},
	}
	res := granted(c)

	req := call("search.query", "invoke")
	req.ResourceTags = []string{"public", "cached"}
	if err := res.Permits(req); err != nil {
		t.Fatalf("refused a resource carrying the required tag: %v", err)
	}

	req.ResourceTags = []string{"internal"}
	if err := res.Permits(req); err == nil {
		t.Fatal("permitted a resource missing the required tag")
	}
}

func TestConditionsAreEvaluatedAgainstTheRequest(t *testing.T) {
	conditioned := func(key string, cond mda.Condition) *Result {
		return granted(mda.Capability{
			Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
			Action:     mda.ActionPattern{Name: "invoke"},
			Conditions: map[string]mda.Condition{key: cond},
		})
	}
	with := func(key string, value any) Request {
		r := call("search.query", "invoke")
		r.Attributes = map[string]any{key: value}
		return r
	}

	tests := []struct {
		name    string
		cond    mda.Condition
		value   any
		permits bool
	}{
		{"eq matches", mda.Condition{Equals: str2("public")}, "public", true},
		{"eq does not match", mda.Condition{Equals: str2("public")}, "secret", false},
		{"in contains", mda.Condition{In: []string{"public", "docs"}}, "docs", true},
		{"in does not contain", mda.Condition{In: []string{"public"}}, "secret", false},
		{"empty in matches nothing", mda.Condition{In: []string{}}, "public", false},
		{"prefix matches", mda.Condition{Prefix: str2("pub")}, "public", true},
		{"prefix does not match", mda.Condition{Prefix: str2("pub")}, "secret", false},
		{"range inside", mda.Condition{Min: num2(1), Max: num2(10)}, 5, true},
		{"range below", mda.Condition{Min: num2(1), Max: num2(10)}, 0, false},
		{"range above", mda.Condition{Min: num2(1), Max: num2(10)}, 11, false},
		{"range accepts a decoded JSON number", mda.Condition{Min: num2(1)}, float64(5), true},
		{"a string where a number is required", mda.Condition{Min: num2(1)}, "5", false},
		{"a number where a string is required", mda.Condition{Equals: str2("5")}, 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := conditioned("args.index", tt.cond).Permits(with("args.index", tt.value))
			if tt.permits && err != nil {
				t.Fatalf("refused a request the condition allows: %v", err)
			}
			if !tt.permits && err == nil {
				t.Fatal("permitted a request the condition forbids")
			}
		})
	}
}

// A condition restricting an attribute the caller did not supply must deny.
// Treating an absent attribute as satisfying the condition would make every
// condition optional from the caller's side, which is the whole guarantee.
func TestAnUnsuppliedAttributeDenies(t *testing.T) {
	res := granted(mda.Capability{
		Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
		Action:     mda.ActionPattern{Name: "invoke"},
		Conditions: map[string]mda.Condition{"args.index": {Equals: str2("public")}},
	})

	err := res.Permits(call("search.query", "invoke"))
	if err == nil {
		t.Fatal("permitted a conditioned request that reported no attributes")
	}
	if !strings.Contains(err.Error(), "did not supply") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

func TestPermitsRejectsIncompleteRequests(t *testing.T) {
	res := granted(toolCap("search.query", "invoke"))
	for name, req := range map[string]Request{
		"no resource type": {ResourceID: "x", Action: "invoke"},
		"no resource id":   {ResourceType: "mcp_tool", Action: "invoke"},
		"no action":        {ResourceType: "mcp_tool", ResourceID: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := res.Permits(req); err == nil {
				t.Fatal("permitted an incomplete request")
			}
		})
	}
}

// A caller who ignored Verify's error and passed the nil result must not get
// a permit. This is the shape of the mistake that makes the whole ordering
// pointless.
func TestANilResultPermitsNothing(t *testing.T) {
	var res *Result
	if err := res.Permits(call("search.query", "invoke")); err == nil {
		t.Fatal("a nil result permitted a request")
	}
}
