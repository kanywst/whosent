package issue_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/issue"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// A chain is issued for one resource server and is evidence at that one only.
// Without the audience rule, an agent holding a chain for its own server mints
// itself a leaf naming somebody else's and presents it there: it delegates
// only what it holds, to itself, with the same capabilities, so V2 and V5 pass
// - and V9 at the target compares the leaf's audience against the target, so
// that passes too. Every link valid, every rule satisfied, and the sponsor
// never authorized any of it.
func TestASubDelegationCannotRetargetTheChain(t *testing.T) {
	w := newWorld(t)
	root, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
		Subject:      agentA,
		Audience:     audience,
		ID:           "jti-root",
		Lifetime:     time.Hour,
		IssuedAt:     w.now,
		MaxDepth:     issue.Depth(3),
		Capabilities: []mda.Capability{capability("search.query")},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = issue.Delegate(w.a, root, issue.Grant{
		Subject:      agentB,
		Audience:     "https://mcp.victim.example.org",
		ID:           "jti-child",
		Lifetime:     30 * time.Minute,
		IssuedAt:     w.now,
		Capabilities: []mda.Capability{capability("search.query")},
	})
	if err == nil {
		t.Fatal("issued a sub-delegation aimed at a resource server the sponsor never named")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

// The same rule at the verifier, for a chain some other issuer produced. The
// issuer refusing is a convenience; the verifier refusing is the guarantee.
func TestAVerifierRefusesARetargetedChain(t *testing.T) {
	w := newWorld(t)
	chain := w.twoHop()

	// Re-sign the leaf at a different audience, as a hostile issuer would.
	leaf := chain[1].Claims
	leaf.Audience = "https://mcp.victim.example.org"
	chain[1] = w.sign(w.a, leaf)

	v, err := verify.New(w.ring, noRevocations{}, "https://mcp.victim.example.org",
		verify.WithClock(func() time.Time { return w.now.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.Verify(context.Background(), chain); err == nil {
		t.Fatal("a resource server accepted a chain issued for a different one")
	} else if !strings.Contains(err.Error(), "V5") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// Assertion.Claims is a struct field, and anything can be put in it. What an
// issuer signed is Raw. A verifier that evaluated the field would authorize
// claims nobody signed, with a correct signature over the untouched bytes
// making it look checked.
func TestVerificationReadsTheBytesAndNotTheStruct(t *testing.T) {
	w := newWorld(t)
	chain := w.twoHop()

	tampered := chain[1]
	tampered.Claims.Mandatum.Capabilities = []mda.Capability{capability("admin.wipeAll")}
	chain[1] = tampered

	res, err := w.verifier().Verify(context.Background(), chain)
	if err != nil {
		t.Fatalf("a chain with untouched bytes did not verify: %v", err)
	}
	if err := res.Permits(verify.Request{
		ResourceType: "mcp_tool", ResourceID: "admin.wipeAll", Action: "invoke",
	}); err == nil {
		t.Fatal("authorized a capability that exists only in the caller's copy of the claims")
	}
	if err := res.Permits(verify.Request{
		ResourceType: "mcp_tool", ResourceID: "search.query", Action: "invoke",
	}); err != nil {
		t.Fatalf("lost the capability the bytes actually carry: %v", err)
	}
}
