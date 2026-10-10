package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

func str(s string) *string   { return &s }
func num(f float64) *float64 { return &f }

// condCovers decides whether a child restriction is at least as tight as its
// parent's. It is the finest-grained place where authority can widen, so the
// table below walks the whole decidable fragment in both directions rather
// than sampling it.
//
// The bias throughout is that an undecidable comparison answers false.
// Refusing a delegation the issuer believed valid is recoverable; accepting
// one that widens authority is not.
func TestCondCovers(t *testing.T) {
	tests := []struct {
		name   string
		parent mda.Condition
		child  mda.Condition
		want   bool
	}{
		// eq: nothing is narrower than a fixed value but that same value.
		{"eq/eq same", mda.Condition{Equals: str("a")}, mda.Condition{Equals: str("a")}, true},
		{"eq/eq different", mda.Condition{Equals: str("a")}, mda.Condition{Equals: str("b")}, false},
		{"eq/in", mda.Condition{Equals: str("a")}, mda.Condition{In: []string{"a"}}, false},
		{"eq/prefix", mda.Condition{Equals: str("a")}, mda.Condition{Prefix: str("a")}, false},
		{"eq/range", mda.Condition{Equals: str("a")}, mda.Condition{Min: num(1)}, false},
		{"eq/empty", mda.Condition{Equals: str("a")}, mda.Condition{}, false},

		// in: a subset narrows, a member narrows, anything else does not.
		{"in/in subset", mda.Condition{In: []string{"a", "b", "c"}}, mda.Condition{In: []string{"a", "b"}}, true},
		{"in/in equal", mda.Condition{In: []string{"a", "b"}}, mda.Condition{In: []string{"a", "b"}}, true},
		{"in/in adds a member", mda.Condition{In: []string{"a"}}, mda.Condition{In: []string{"a", "z"}}, false},
		{"in/in disjoint", mda.Condition{In: []string{"a"}}, mda.Condition{In: []string{"z"}}, false},
		// An empty set matches nothing, so it is the narrowest restriction
		// expressible. Such a capability can never apply, which is useless
		// but not unsafe, and rejecting it would mean a parent could not
		// delegate "nothing" explicitly.
		{"in/in empty child", mda.Condition{In: []string{"a"}}, mda.Condition{In: []string{}}, true},
		{"in/eq member", mda.Condition{In: []string{"a", "b"}}, mda.Condition{Equals: str("a")}, true},
		{"in/eq non-member", mda.Condition{In: []string{"a", "b"}}, mda.Condition{Equals: str("z")}, false},
		{"in/prefix", mda.Condition{In: []string{"ab"}}, mda.Condition{Prefix: str("a")}, false},
		{"in/empty", mda.Condition{In: []string{"a"}}, mda.Condition{}, false},

		// prefix: a longer prefix matches a subset of a shorter one.
		{"prefix/prefix longer", mda.Condition{Prefix: str("ab")}, mda.Condition{Prefix: str("abc")}, true},
		{"prefix/prefix equal", mda.Condition{Prefix: str("ab")}, mda.Condition{Prefix: str("ab")}, true},
		{"prefix/prefix shorter", mda.Condition{Prefix: str("ab")}, mda.Condition{Prefix: str("a")}, false},
		{"prefix/prefix empty child", mda.Condition{Prefix: str("ab")}, mda.Condition{Prefix: str("")}, false},
		{"prefix/eq matching", mda.Condition{Prefix: str("ab")}, mda.Condition{Equals: str("abc")}, true},
		{"prefix/eq not matching", mda.Condition{Prefix: str("ab")}, mda.Condition{Equals: str("zz")}, false},
		{"prefix/in all matching", mda.Condition{Prefix: str("a")}, mda.Condition{In: []string{"ab", "ac"}}, true},
		{"prefix/in one escaping", mda.Condition{Prefix: str("a")}, mda.Condition{In: []string{"ab", "zz"}}, false},
		{"prefix/range", mda.Condition{Prefix: str("a")}, mda.Condition{Min: num(1)}, false},

		// range: the child interval must sit inside the parent's, and an
		// unbounded child side is only acceptable where the parent is too.
		{"range/inside", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Min: num(2), Max: num(5)}, true},
		{"range/identical", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Min: num(1), Max: num(10)}, true},
		{"range/min below", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Min: num(0), Max: num(5)}, false},
		{"range/max above", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Min: num(2), Max: num(11)}, false},
		{"range/child unbounded above", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Min: num(2)}, false},
		{"range/child unbounded below", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Max: num(5)}, false},
		{"range/child unbounded both", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{}, false},
		{"range/parent min only, child bounded", mda.Condition{Min: num(1)}, mda.Condition{Min: num(2), Max: num(5)}, true},
		{"range/parent min only, child min only", mda.Condition{Min: num(1)}, mda.Condition{Min: num(2)}, true},
		{"range/parent max only, child max only", mda.Condition{Max: num(10)}, mda.Condition{Max: num(5)}, true},
		{"range/parent max only, child min only", mda.Condition{Max: num(10)}, mda.Condition{Min: num(2)}, false},
		{"range/eq child", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{Equals: str("5")}, false},

		// An empty set matches nothing, so it is the bottom of the lattice:
		// every parent in the fragment entails it, whatever kind it is. The
		// specification says a delegator can always grant nothing on a key,
		// and that has to hold under an eq or range parent too.
		{"eq/in empty", mda.Condition{Equals: str("a")}, mda.Condition{In: []string{}}, true},
		{"prefix/in empty", mda.Condition{Prefix: str("ab")}, mda.Condition{In: []string{}}, true},
		{"range/in empty", mda.Condition{Min: num(1), Max: num(10)}, mda.Condition{In: []string{}}, true},
		{"range min only/in empty", mda.Condition{Min: num(1)}, mda.Condition{In: []string{}}, true},
		// A parent outside the fragment cannot entail anything, including
		// the empty set: there is nothing to reason from.
		{"invalid parent/in empty", mda.Condition{}, mda.Condition{In: []string{}}, false},
		{
			"ambiguous parent/in empty",
			mda.Condition{Equals: str("a"), Prefix: str("a")},
			mda.Condition{In: []string{}},
			false,
		},

		// A parent condition outside the fragment cannot be reasoned about.
		{"empty parent", mda.Condition{}, mda.Condition{Equals: str("a")}, false},
		{"empty both", mda.Condition{}, mda.Condition{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := condCovers(tt.parent, tt.child); got != tt.want {
				t.Errorf("condCovers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEntails(t *testing.T) {
	base := func() mda.Capability {
		return mda.Capability{
			Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
			Action:   mda.ActionPattern{Name: "invoke"},
		}
	}

	tests := []struct {
		name   string
		parent mda.Capability
		child  mda.Capability
		want   bool
	}{
		{"identical", base(), base(), true},
		{
			"resource type differs",
			base(),
			mda.Capability{Resource: mda.ResourcePattern{Type: "http", ID: "search.query"}, Action: mda.ActionPattern{Name: "invoke"}},
			false,
		},
		{
			"action differs",
			base(),
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"}, Action: mda.ActionPattern{Name: "administer"}},
			false,
		},
		{
			"parent prefix covers child literal",
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"}, Action: mda.ActionPattern{Name: "invoke"}},
			base(),
			true,
		},
		{
			"parent prefix does not cover an unrelated literal",
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"}, Action: mda.ActionPattern{Name: "invoke"}},
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "admin.wipe"}, Action: mda.ActionPattern{Name: "invoke"}},
			false,
		},
		{
			"parent prefix covers a longer child prefix",
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "sea*"}, Action: mda.ActionPattern{Name: "invoke"}},
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"}, Action: mda.ActionPattern{Name: "invoke"}},
			true,
		},
		{
			"a literal parent cannot cover a prefix child",
			base(),
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"}, Action: mda.ActionPattern{Name: "invoke"}},
			false,
		},
		{
			"child requiring more tags is narrower",
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "x", Tags: []string{"read"}}, Action: mda.ActionPattern{Name: "invoke"}},
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "x", Tags: []string{"read", "internal"}}, Action: mda.ActionPattern{Name: "invoke"}},
			true,
		},
		{
			"child dropping a required tag is wider",
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "x", Tags: []string{"read", "internal"}}, Action: mda.ActionPattern{Name: "invoke"}},
			mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "x", Tags: []string{"read"}}, Action: mda.ActionPattern{Name: "invoke"}},
			false,
		},
		{
			"child adding a condition on a free key narrows",
			base(),
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {Equals: str("public")}},
			},
			true,
		},
		{
			"child dropping an inherited condition widens",
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {In: []string{"public", "docs"}}},
			},
			base(),
			false,
		},
		{
			"child tightening an inherited condition narrows",
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {In: []string{"public", "docs"}}},
			},
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {Equals: str("public")}},
			},
			true,
		},
		{
			"child loosening an inherited condition widens",
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {Equals: str("public")}},
			},
			mda.Capability{
				Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:     mda.ActionPattern{Name: "invoke"},
				Conditions: map[string]mda.Condition{"args.index": {In: []string{"public", "secret"}}},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entails(tt.parent, tt.child); got != tt.want {
				t.Errorf("entails = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeqNoWider(t *testing.T) {
	constraint := func(id string) mda.Constraint {
		return mda.Constraint{
			ID:     id,
			Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
			After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
		}
	}

	tests := []struct {
		name    string
		parent  *mda.Sequence
		child   *mda.Sequence
		wantErr string
	}{
		{"parent imposes nothing", nil, nil, ""},
		{"parent imposes nothing, child adds a budget", nil, &mda.Sequence{MaxInvocations: 10}, ""},
		{
			"child drops the parent's constraints entirely",
			&mda.Sequence{MaxInvocations: 10}, nil,
			"drops the parent's sequence constraints",
		},
		{"child lowers the budget", &mda.Sequence{MaxInvocations: 100}, &mda.Sequence{MaxInvocations: 50}, ""},
		{"child keeps the budget", &mda.Sequence{MaxInvocations: 100}, &mda.Sequence{MaxInvocations: 100}, ""},
		{
			"child raises the budget",
			&mda.Sequence{MaxInvocations: 100}, &mda.Sequence{MaxInvocations: 200},
			"raises the invocation budget",
		},
		{
			"child removes a budget by setting it unlimited",
			&mda.Sequence{MaxInvocations: 100},
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			"removes the parent's invocation budget",
		},
		{
			"parent unlimited, child bounded",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			&mda.Sequence{MaxInvocations: 5, Constraints: []mda.Constraint{constraint("a")}},
			"",
		},
		{
			"child keeps the inherited constraint",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			"",
		},
		{
			"child keeps it and adds another",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a"), constraint("b")}},
			"",
		},
		{
			"child drops an inherited constraint",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a"), constraint("b")}},
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			`drops inherited sequence constraint "b"`,
		},
		{
			"child keeps the id but redefines the rule",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			&mda.Sequence{Constraints: []mda.Constraint{{
				ID:     "a",
				Forbid: mda.ActionMatcher{ResourceTags: []string{"harmless"}},
				After:  mda.ActionMatcher{ResourceTags: []string{"external-content"}},
			}}},
			`redefines inherited sequence constraint "a"`,
		},
		{
			"child keeps the id but rewrites the trigger",
			&mda.Sequence{Constraints: []mda.Constraint{constraint("a")}},
			&mda.Sequence{Constraints: []mda.Constraint{{
				ID:     "a",
				Forbid: mda.ActionMatcher{ResourceTags: []string{"mutating"}},
				After:  mda.ActionMatcher{ResourceTags: []string{"never-happens"}},
			}}},
			`redefines inherited sequence constraint "a"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := seqNoWider(tt.parent, tt.child)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("rejected a narrowing sequence: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Fatal("accepted a sequence that widens the parent's")
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// The unit tests above exercise the predicates directly. These drive the same
// rules through Verify, so a predicate that is correct but never reached
// still fails the suite.
func TestAttenuationThroughVerify(t *testing.T) {
	withCond := func(iss, sub string, maxDepth int, index []string) mda.Claims {
		c := link(iss, sub, maxDepth, mda.Capability{
			Resource:   mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
			Action:     mda.ActionPattern{Name: "invoke"},
			Conditions: map[string]mda.Condition{"args.index": {In: index}},
		})
		return c
	}
	withSeq := func(iss, sub string, maxDepth, budget int) mda.Claims {
		c := link(iss, sub, maxDepth, capability("mcp_tool", "search.query", "invoke"))
		c.Mandatum.Sequence = &mda.Sequence{MaxInvocations: budget}
		return c
	}

	v := newTestVerifier(t, allowAll{}, noRevocations{})

	t.Run("narrowing a condition is accepted", func(t *testing.T) {
		c := chainOf(
			withCond(sponsorIss, "agent-a", 3, []string{"public", "docs"}),
			withCond("agent-a", "agent-b", 2, []string{"public"}),
		).build()
		if _, err := v.Verify(context.Background(), c); err != nil {
			t.Fatalf("rejected a narrowing condition: %v", err)
		}
	})

	t.Run("widening a condition is rejected", func(t *testing.T) {
		c := chainOf(
			withCond(sponsorIss, "agent-a", 3, []string{"public"}),
			withCond("agent-a", "agent-b", 2, []string{"public", "secret"}),
		).build()
		_, err := v.Verify(context.Background(), c)
		if err == nil {
			t.Fatal("accepted a child that reached an index its parent could not")
		}
		if Rule(err) != "V5" {
			t.Errorf("rejected by %s, want V5 (%v)", Rule(err), err)
		}
	})

	t.Run("lowering a sequence budget is accepted", func(t *testing.T) {
		c := chainOf(withSeq(sponsorIss, "agent-a", 3, 100), withSeq("agent-a", "agent-b", 2, 10)).build()
		if _, err := v.Verify(context.Background(), c); err != nil {
			t.Fatalf("rejected a lowered budget: %v", err)
		}
	})

	t.Run("raising a sequence budget is rejected", func(t *testing.T) {
		c := chainOf(withSeq(sponsorIss, "agent-a", 3, 10), withSeq("agent-a", "agent-b", 2, 1000)).build()
		_, err := v.Verify(context.Background(), c)
		if err == nil {
			t.Fatal("accepted a child that raised its own invocation budget")
		}
		if Rule(err) != "V5" {
			t.Errorf("rejected by %s, want V5 (%v)", Rule(err), err)
		}
	})

	t.Run("dropping inherited sequence constraints is rejected", func(t *testing.T) {
		parent := withSeq(sponsorIss, "agent-a", 3, 10)
		child := link("agent-a", "agent-b", 2, capability("mcp_tool", "search.query", "invoke"))
		c := chainOf(parent, child).build()
		_, err := v.Verify(context.Background(), c)
		if err == nil {
			t.Fatal("a child escaped its parent's sequence limits by omitting the field")
		}
		if !strings.Contains(err.Error(), "drops the parent's sequence constraints") {
			t.Errorf("unexpected reason: %v", err)
		}
	})

	t.Run("the leaf's sequence reaches the caller", func(t *testing.T) {
		c := chainOf(withSeq(sponsorIss, "agent-a", 3, 100), withSeq("agent-a", "agent-b", 2, 10)).build()
		res, err := v.Verify(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if res.Sequence == nil || res.Sequence.MaxInvocations != 10 {
			t.Errorf("result carries %+v, want the leaf's budget of 10", res.Sequence)
		}
	})
}
