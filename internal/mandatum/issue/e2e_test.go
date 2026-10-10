package issue_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/issue"
	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// These tests exercise the whole path with real Ed25519 keys and real
// signatures. The unit tests elsewhere stub signature verification so that a
// failure points at the rule under test; nothing there proves that a chain
// this project issues is one this project accepts. That is what these prove.

const (
	idp      = "https://idp.example.org"
	audience = "https://mcp.example.org"
	agentA   = "spiffe://example.org/ns/agents/planner"
	agentB   = "spiffe://example.org/ns/agents/retriever"
)

type world struct {
	t     *testing.T
	ring  *jose.KeyRing
	idp   issue.Signer
	a     issue.Signer
	b     issue.Signer
	now   time.Time
	spons mda.Sponsor
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		t:    t,
		ring: jose.NewKeyRing(),
		now:  time.Unix(1789200000, 0),
		spons: mda.Sponsor{
			Issuer:                idp,
			Subject:               "u-8f31c02e",
			AuthenticationMethods: []string{"pwd", "hwk"},
			AuthenticatedAt:       1789199400,
		},
	}
	w.idp = w.keypair(idp, "idp-2026")
	w.a = w.keypair(agentA, "a-1")
	w.b = w.keypair(agentB, "b-1")
	return w
}

func (w *world) keypair(id, kid string) issue.Signer {
	w.t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.ring.Add(id, kid, pub); err != nil {
		w.t.Fatal(err)
	}
	return issue.Signer{ID: id, KeyID: kid, Key: priv}
}

func (w *world) verifier() *verify.Verifier {
	w.t.Helper()
	v, err := verify.New(w.ring, noRevocations{}, audience,
		verify.WithClock(func() time.Time { return w.now.Add(time.Minute) }))
	if err != nil {
		w.t.Fatal(err)
	}
	return v
}

type noRevocations struct{}

func (noRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

type revokes struct{ jti string }

func (r revokes) IsRevoked(_ context.Context, jti string) (bool, error) {
	return jti == r.jti, nil
}

func capability(id string) mda.Capability {
	return mda.Capability{
		Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id},
		Action:   mda.ActionPattern{Name: "invoke"},
	}
}

// twoHop issues a real sponsor grant and a real sub-delegation under it.
func (w *world) twoHop() mda.Chain {
	w.t.Helper()

	root, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
		Subject:      agentA,
		Audience:     audience,
		ID:           "jti-root",
		Lifetime:     time.Hour,
		IssuedAt:     w.now,
		MaxDepth:     issue.Depth(3),
		Capabilities: []mda.Capability{capability("search.*")},
	})
	if err != nil {
		w.t.Fatalf("sponsor grant: %v", err)
	}

	child, err := issue.Delegate(w.a, root, issue.Grant{
		Subject:      agentB,
		ID:           "jti-child",
		Lifetime:     40 * time.Minute,
		IssuedAt:     w.now,
		Capabilities: []mda.Capability{capability("search.query")},
	})
	if err != nil {
		w.t.Fatalf("delegate: %v", err)
	}

	return mda.Chain{root, child}
}

// sign serializes claims under a signer's key, as an issuer that is not this
// package would. Tests that need a link saying something issue.Delegate
// refuses have to produce it themselves.
func (w *world) sign(signer issue.Signer, claims mda.Claims) mda.Assertion {
	w.t.Helper()
	raw, err := jose.Sign(claims, signer.Key, signer.KeyID)
	if err != nil {
		w.t.Fatal(err)
	}
	return mda.Assertion{Raw: raw, Claims: claims}
}

func TestRealChainVerifies(t *testing.T) {
	w := newWorld(t)
	chain := w.twoHop()

	res, err := w.verifier().Verify(context.Background(), chain)
	if err != nil {
		t.Fatalf("a chain this project issued was rejected by its own verifier: %v", err)
	}

	if res.Sponsor.Subject != w.spons.Subject {
		t.Errorf("sponsor = %q, want %q", res.Sponsor.Subject, w.spons.Subject)
	}
	if res.Agent != agentB {
		t.Errorf("agent = %q, want %q", res.Agent, agentB)
	}
	if res.Depth != 1 {
		t.Errorf("depth = %d, want 1", res.Depth)
	}
	if res.LeafID != "jti-child" {
		t.Errorf("leaf = %q, want jti-child", res.LeafID)
	}
}

// The wire form is what actually crosses a network. A chain that verifies
// in memory but not after a round trip through its serialization would be
// useless.
func TestChainSurvivesTheWire(t *testing.T) {
	w := newWorld(t)
	original := w.twoHop()

	wire := make([][]byte, len(original))
	for i, a := range original {
		wire[i] = a.Raw
	}

	parsed, err := issue.ParseChain(wire)
	if err != nil {
		t.Fatalf("parsing a chain this project produced: %v", err)
	}

	res, err := w.verifier().Verify(context.Background(), parsed)
	if err != nil {
		t.Fatalf("chain rejected after a round trip through the wire: %v", err)
	}
	if res.Agent != agentB {
		t.Errorf("agent = %q, want %q", res.Agent, agentB)
	}
	if res.ChainDigest != verify.ChainDigest(original) {
		t.Error("the round trip changed the chain digest; audit correlation would break")
	}
}

// The specification says depth 0 has no parent. The field used to serialize
// as the empty string, which is neither absence nor the null the spec named,
// so an implementation checking for null would have rejected every sponsor
// grant this one produces. That is the interop failure §5.1 exists to
// prevent, and nothing was looking at the wire form.
func TestDepthZeroOmitsTheParentOnTheWire(t *testing.T) {
	w := newWorld(t)
	root := w.twoHop()[0]

	parts := strings.Split(string(root.Raw), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		Mandatum map[string]any `json:"mdt"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if v, present := decoded.Mandatum["parent"]; present {
		t.Errorf("depth 0 carries parent=%#v on the wire; it should be absent", v)
	}

	// A child still commits to its parent, or nothing is holding the chain
	// together.
	child := w.twoHop()[1]
	parts = strings.Split(string(child.Raw), ".")
	payload, _ = base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if v, _ := decoded.Mandatum["parent"].(string); v == "" {
		t.Error("a child carries no parent commitment")
	}
}

func TestForgeryIsRejected(t *testing.T) {
	tests := []struct {
		name     string
		tamper   func(*world, mda.Chain) mda.Chain
		wantRule string
	}{
		{
			name: "payload edited after signing",
			tamper: func(_ *world, c mda.Chain) mda.Chain {
				// Widen the leaf's grant, then re-encode without re-signing.
				parts := strings.Split(string(c[1].Raw), ".")
				payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
				edited := strings.Replace(string(payload), "search.query", "admin.wipeAll", 1)
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(edited))
				c[1].Raw = []byte(strings.Join(parts, "."))
				_ = json.Unmarshal([]byte(edited), &c[1].Claims)
				return c
			},
			wantRule: "V3",
		},
		{
			name: "signed by a key the issuer does not hold",
			tamper: func(w *world, c mda.Chain) mda.Chain {
				// An attacker who controls agent-b's process signs a link
				// claiming to come from agent-a.
				impostor := issue.Signer{ID: agentA, KeyID: "a-1", Key: w.b.Key}
				forged, err := issue.Delegate(impostor, c[0], issue.Grant{
					Subject:      agentB,
					ID:           "jti-forged",
					Lifetime:     time.Minute,
					IssuedAt:     w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
				if err != nil {
					w.t.Fatal(err)
				}
				return mda.Chain{c[0], forged}
			},
			wantRule: "V3",
		},
		{
			name: "signature lifted from another assertion",
			tamper: func(_ *world, c mda.Chain) mda.Chain {
				rootSig := strings.Split(string(c[0].Raw), ".")[2]
				parts := strings.Split(string(c[1].Raw), ".")
				parts[2] = rootSig
				c[1].Raw = []byte(strings.Join(parts, "."))
				return c
			},
			wantRule: "V3",
		},
		{
			name: "algorithm downgraded to none",
			tamper: func(_ *world, c mda.Chain) mda.Chain {
				parts := strings.Split(string(c[1].Raw), ".")
				header := `{"alg":"none","typ":"mdt+jwt","kid":"b-1"}`
				parts[0] = base64.RawURLEncoding.EncodeToString([]byte(header))
				parts[2] = ""
				c[1].Raw = []byte(strings.Join(parts, "."))
				return c
			},
			wantRule: "V3",
		},
		{
			name: "media type swapped so the assertion can pose as another token",
			tamper: func(_ *world, c mda.Chain) mda.Chain {
				parts := strings.Split(string(c[1].Raw), ".")
				header := `{"alg":"EdDSA","typ":"JWT","kid":"b-1"}`
				parts[0] = base64.RawURLEncoding.EncodeToString([]byte(header))
				c[1].Raw = []byte(strings.Join(parts, "."))
				return c
			},
			wantRule: "V3",
		},
		{
			name: "link spliced from a different chain",
			tamper: func(w *world, c mda.Chain) mda.Chain {
				// A second, unrelated sponsor grant to the same agent. Its
				// child is validly signed, but was not issued against this
				// root, so the parent commitment will not match.
				other, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
					Subject:      agentA,
					Audience:     audience,
					ID:           "jti-other-root",
					Lifetime:     time.Hour,
					IssuedAt:     w.now,
					MaxDepth:     issue.Depth(3),
					Capabilities: []mda.Capability{capability("search.*")},
				})
				if err != nil {
					w.t.Fatal(err)
				}
				stranger, err := issue.Delegate(w.a, other, issue.Grant{
					Subject:      agentB,
					ID:           "jti-stranger",
					Lifetime:     time.Minute,
					IssuedAt:     w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
				if err != nil {
					w.t.Fatal(err)
				}
				return mda.Chain{c[0], stranger}
			},
			wantRule: "V1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			chain := tt.tamper(w, w.twoHop())

			res, err := w.verifier().Verify(context.Background(), chain)
			if err == nil {
				t.Fatalf("forgery accepted, granting %q authority over %+v", res.Agent, res.Capabilities)
			}
			if got := verify.Rule(err); got != tt.wantRule {
				t.Errorf("rejected by %s, want %s (%v)", got, tt.wantRule, err)
			}
		})
	}
}

// Revoking a parent must stop everything below it. This is the property that
// answers credential piggybacking, so it is checked end to end rather than
// against a stub.
func TestRevokingAParentStopsItsDescendants(t *testing.T) {
	w := newWorld(t)
	chain := w.twoHop()

	v, err := verify.New(w.ring, revokes{jti: "jti-root"}, audience,
		verify.WithClock(func() time.Time { return w.now.Add(time.Minute) }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.Verify(context.Background(), chain); err == nil {
		t.Fatal("revoking the sponsor's grant did not stop the agent below it")
	} else if verify.Rule(err) != "V8" {
		t.Errorf("rejected by %s, want V8 (%v)", verify.Rule(err), err)
	}
}

// The issuer refuses to mint chains the verifier would reject. Each case here
// would otherwise become a failure at a resource server, far from whoever
// could fix it.
func TestIssuerRefusesToWidenAuthority(t *testing.T) {
	tests := []struct {
		name    string
		grant   func(*world, mda.Assertion) (mda.Assertion, error)
		wantErr string
	}{
		{
			name: "a stranger sub-delegating",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.b, root, issue.Grant{
					Subject: agentB, ID: "x", Lifetime: time.Minute, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
			},
			wantErr: "cannot delegate authority granted to",
		},
		{
			name: "child outliving its parent",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "x", Lifetime: 10 * time.Hour, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
			},
			wantErr: "outlives its parent",
		},
		{
			name: "child reusing the parent's depth budget",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "x", Lifetime: time.Minute, IssuedAt: w.now,
					MaxDepth:     issue.Depth(3),
					Capabilities: []mda.Capability{capability("search.query")},
				})
			},
			wantErr: "does not decrease",
		},
		{
			name: "child claiming authority the parent never held",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "x", Lifetime: time.Minute, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("admin.wipeAll")},
				})
			},
			wantErr: "widens the parent's authority",
		},
		{
			name: "child raising its own invocation budget",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				bounded, err := issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "bounded", Lifetime: time.Minute, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
					Sequence:     &mda.Sequence{MaxInvocations: 5},
				})
				if err != nil {
					w.t.Fatal(err)
				}
				return issue.Delegate(w.b, bounded, issue.Grant{
					Subject: "spiffe://example.org/ns/agents/third", ID: "y",
					Lifetime: time.Minute, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
					Sequence:     &mda.Sequence{MaxInvocations: 5000},
				})
			},
			wantErr: "raises the invocation budget",
		},
		{
			name: "capabilities left unset rather than explicitly empty",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "x", Lifetime: time.Minute, IssuedAt: w.now,
				})
			},
			wantErr: "use an empty slice to grant nothing explicitly",
		},
		{
			name: "no revocation handle",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, Lifetime: time.Minute, IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
			},
			wantErr: "unit of revocation",
		},
		{
			name: "no expiry",
			grant: func(w *world, root mda.Assertion) (mda.Assertion, error) {
				return issue.Delegate(w.a, root, issue.Grant{
					Subject: agentB, ID: "x", IssuedAt: w.now,
					Capabilities: []mda.Capability{capability("search.query")},
				})
			},
			wantErr: "assertions do not live forever",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			root := w.twoHop()[0]

			if _, err := tt.grant(w, root); err == nil {
				t.Fatal("the issuer produced a delegation it should have refused")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

// A chain at the sponsor's depth limit must still work, and one hop further
// must not. Off-by-one here would either break legitimate delegation or allow
// unbounded sub-delegation.
func TestDepthBudgetIsExhaustible(t *testing.T) {
	w := newWorld(t)

	root, err := issue.Sponsor(w.idp, w.spons, issue.Grant{
		Subject: agentA, Audience: audience, ID: "r", Lifetime: time.Hour, IssuedAt: w.now,
		MaxDepth:     issue.Depth(1),
		Capabilities: []mda.Capability{capability("search.*")},
	})
	if err != nil {
		t.Fatal(err)
	}

	mid, err := issue.Delegate(w.a, root, issue.Grant{
		Subject: agentB, ID: "m", Lifetime: time.Minute, IssuedAt: w.now,
		Capabilities: []mda.Capability{capability("search.query")},
	})
	if err != nil {
		t.Fatalf("the first sub-delegation should fit within a budget of 1: %v", err)
	}

	if _, err := w.verifier().Verify(context.Background(), mda.Chain{root, mid}); err != nil {
		t.Fatalf("a chain within the sponsor's budget was rejected: %v", err)
	}

	if _, err := issue.Delegate(w.b, mid, issue.Grant{
		Subject: "spiffe://example.org/ns/agents/third", ID: "t",
		Lifetime: time.Minute, IssuedAt: w.now,
		Capabilities: []mda.Capability{capability("search.query")},
	}); err == nil {
		t.Fatal("delegation continued past the sponsor's depth budget")
	} else if !strings.Contains(err.Error(), "depth is exhausted") {
		t.Errorf("unexpected reason: %v", err)
	}
}
