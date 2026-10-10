package issue_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/issue"
	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// deterministicKey returns a fixed keypair so the example's output is stable.
// Real code generates keys with ed25519.GenerateKey.
func deterministicKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// The whole flow: a human sponsors an agent, that agent sub-delegates a
// narrower grant, and a resource server verifies what arrives.
func Example() {
	const (
		idp      = "https://idp.example.org"
		mcp      = "https://mcp.example.org"
		planner  = "spiffe://example.org/ns/agents/planner"
		retrieve = "spiffe://example.org/ns/agents/retriever"
	)
	issuedAt := time.Unix(1789200000, 0)

	idpPub, idpKey := deterministicKey(1)
	plannerPub, plannerKey := deterministicKey(2)

	// The resource server trusts these issuers' keys, and nothing else.
	ring := jose.NewKeyRing()
	_ = ring.Add(idp, "idp-2026", idpPub)
	_ = ring.Add(planner, "planner-1", plannerPub)

	// 1. The identity provider attests that a human delegated to an agent.
	//    max_depth 2 permits two further hops below this grant.
	root, err := issue.Sponsor(
		issue.Signer{ID: idp, KeyID: "idp-2026", Key: idpKey},
		mda.Sponsor{
			Issuer:                idp,
			Subject:               "u-8f31c02e",
			AuthenticationMethods: []string{"pwd", "hwk"},
			AuthenticatedAt:       issuedAt.Add(-10 * time.Minute).Unix(),
		},
		issue.Grant{
			Subject:  planner,
			Audience: mcp,
			ID:       "01JB2X9K7P4Q8R3N6M0V5T2Y7C",
			Lifetime: time.Hour,
			IssuedAt: issuedAt,
			MaxDepth: issue.Depth(2),
			Capabilities: []mda.Capability{{
				Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.*"},
				Action:   mda.ActionPattern{Name: "invoke"},
			}},
		},
	)
	if err != nil {
		panic(err)
	}

	// 2. The planner hands a narrower, shorter-lived grant to a retriever.
	//    It cannot widen either: Delegate refuses before signing.
	child, err := issue.Delegate(
		issue.Signer{ID: planner, KeyID: "planner-1", Key: plannerKey},
		root,
		issue.Grant{
			Subject:  retrieve,
			ID:       "01JB2XA4M0RN5S8Q2K7T3W1Y9D",
			Lifetime: 40 * time.Minute,
			IssuedAt: issuedAt,
			Capabilities: []mda.Capability{{
				Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:   mda.ActionPattern{Name: "invoke"},
			}},
		},
	)
	if err != nil {
		panic(err)
	}

	// 3. The resource server verifies the chain it was handed.
	v, err := verify.New(ring, openRevocations{}, mcp,
		verify.WithClock(func() time.Time { return issuedAt.Add(time.Minute) }))
	if err != nil {
		panic(err)
	}

	res, err := v.Verify(context.Background(), mda.Chain{root, child})
	if err != nil {
		panic(err)
	}

	fmt.Println("sponsor:", res.Sponsor.Subject)
	fmt.Println("agent:  ", res.Agent)
	fmt.Println("hops:   ", res.Depth)
	fmt.Println("revoke: ", res.LeafID)

	// 4. The chain establishes what a human delegated. Before honouring any
	//    decision, check the request is inside it. A PDP that said yes to
	//    something no sponsor granted must not be able to make it happen,
	//    and this call is the only thing that makes that true.
	permitted := res.Permits(verify.Request{
		ResourceType: "mcp_tool", ResourceID: "search.query", Action: "invoke",
	})
	outside := res.Permits(verify.Request{
		ResourceType: "mcp_tool", ResourceID: "admin.wipeAll", Action: "invoke",
	})
	fmt.Println("granted:", permitted == nil)
	fmt.Println("outside:", outside == nil)

	// 5. What the retriever cannot do: widen its own grant. The refusal
	//    happens at issuance, where whoever wrote it can still fix it.
	_, retrieverKey := deterministicKey(3)
	_, err = issue.Delegate(
		issue.Signer{ID: retrieve, KeyID: "retriever-1", Key: retrieverKey},
		child,
		issue.Grant{
			Subject:  "spiffe://example.org/ns/agents/third",
			ID:       "01JB2XB7Q3TS6V9R5N8W4Z2A1F",
			Lifetime: 30 * time.Minute,
			IssuedAt: issuedAt,
			Capabilities: []mda.Capability{{
				Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "admin.wipeAll"},
				Action:   mda.ActionPattern{Name: "invoke"},
			}},
		},
	)
	fmt.Println("escalation:", err != nil)

	// Output:
	// sponsor: u-8f31c02e
	// agent:   spiffe://example.org/ns/agents/retriever
	// hops:    1
	// revoke:  01JB2XA4M0RN5S8Q2K7T3W1Y9D
	// granted: true
	// outside: false
	// escalation: true
}

type openRevocations struct{}

func (openRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }
