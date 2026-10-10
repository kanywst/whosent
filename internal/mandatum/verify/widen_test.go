package verify

import (
	"context"
	"testing"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// A negative invocation budget is an escape, not merely a malformed value.
// Zero means unlimited, and every comparison that treats "unlimited" as zero
// reads a negative the same way - including attenuation, where
// `child > parent` is false for any negative child. A child could set -1
// under a parent's budget of 100 and be unconstrained.
//
// Structural validation refuses it, and V5 refuses it again without relying
// on that, because this is a widening path and one check is not enough.
func TestANegativeBudgetCannotEscapeTheParent(t *testing.T) {
	withBudget := func(iss, sub string, maxDepth, budget int) mda.Claims {
		c := link(iss, sub, maxDepth, capability("mcp_tool", "search.query", "invoke"))
		c.Mandatum.Sequence = &mda.Sequence{MaxInvocations: budget}
		return c
	}

	v := newTestVerifier(t, allowAll{}, noRevocations{})
	chain := chainOf(
		withBudget(sponsorIss, "agent-a", 3, 100),
		withBudget("agent-a", "agent-b", 2, -1),
	).build()

	res, err := v.Verify(context.Background(), chain)
	if err == nil {
		t.Fatalf("accepted a child with budget %d under a parent with 100",
			res.Sequence.MaxInvocations)
	}
}

// The same escape, reaching V5 directly: even if structural validation were
// relaxed, attenuation must still refuse it.
func TestAttenuationRefusesANonPositiveChildBudget(t *testing.T) {
	for _, budget := range []int{0, -1, -1000} {
		parent := mda.Claims{
			ExpiresAt: 100,
			Mandatum: mda.Mandatum{
				MaxDepth: 3,
				Sequence: &mda.Sequence{MaxInvocations: 100},
			},
		}
		child := mda.Claims{
			ExpiresAt: 100,
			Mandatum: mda.Mandatum{
				MaxDepth: 2,
				Sequence: &mda.Sequence{MaxInvocations: budget},
			},
		}
		if err := Attenuates(parent, child); err == nil {
			t.Errorf("a child budget of %d was accepted under a parent budget of 100", budget)
		}
	}
}
