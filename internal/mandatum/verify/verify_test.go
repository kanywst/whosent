package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
)

const (
	sponsorIss = "https://idp.example.org"
	sponsorSub = "u-8f31c02e"
	audience   = "https://mcp.example.org"
)

var testNow = time.Unix(1789200600, 0)

func clock() time.Time { return testNow }

// allowAll accepts every signature. Chain-structure tests use it so that a
// failure points at the rule under test rather than at key handling.
type allowAll struct{}

func (allowAll) VerifySignature(context.Context, string, []byte) error { return nil }

type denyIssuer struct{ issuer string }

func (d denyIssuer) VerifySignature(_ context.Context, iss string, _ []byte) error {
	if iss == d.issuer {
		return errors.New("no key for issuer")
	}
	return nil
}

type noRevocations struct{}

func (noRevocations) IsRevoked(context.Context, string) (bool, error) { return false, nil }

type revokes struct{ jti string }

func (r revokes) IsRevoked(_ context.Context, jti string) (bool, error) {
	return jti == r.jti, nil
}

type brokenRevocation struct{}

func (brokenRevocation) IsRevoked(context.Context, string) (bool, error) {
	return false, errors.New("revocation service unreachable")
}

// builder assembles chains whose parent commitments are correct by
// construction, so that a test which wants to break one has to do it
// explicitly.
type builder struct {
	links []mda.Claims
}

func chainOf(links ...mda.Claims) *builder { return &builder{links: links} }

// build serializes each link and fixes up parent commitments and depths.
//
// The serialization is a real JOSE compact form, because Verify re-derives
// claims from those bytes rather than trusting the Claims field. The key is
// fixed and the signature is never checked here - these tests use a stub
// SignatureVerifier - but the bytes have to parse and have to say what the
// test means them to say.
func (b *builder) build() mda.Chain {
	_, key, err := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		panic(err)
	}

	chain := make(mda.Chain, len(b.links))
	var prevRaw []byte
	for i, c := range b.links {
		c.Mandatum.Depth = i
		if i == 0 {
			c.Mandatum.Parent = ""
		} else {
			c.Mandatum.Parent = mda.Digest(prevRaw)
		}
		raw, err := jose.Sign(c, key, "test")
		if err != nil {
			panic(err)
		}
		chain[i] = mda.Assertion{Raw: raw, Claims: c}
		prevRaw = raw
	}
	return chain
}

// reseal re-serializes link i after a test has edited its claims.
//
// Verify derives claims from the bytes, so editing Claims alone changes
// nothing: a test that wants a link to say something different has to make it
// say so on the wire. Only the last link may be resealed, because every link
// below one commits to its bytes.
func reseal(c mda.Chain, i int) mda.Chain {
	if i != len(c)-1 {
		panic("reseal: resealing a non-leaf link would break the parent commitment below it")
	}
	_, key, err := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		panic(err)
	}
	raw, err := jose.Sign(c[i].Claims, key, "test")
	if err != nil {
		panic(err)
	}
	c[i].Raw = raw
	return c
}

func sponsor() mda.Sponsor {
	return mda.Sponsor{Issuer: sponsorIss, Subject: sponsorSub, AuthenticatedAt: 1789199400}
}

func link(iss, sub string, maxDepth int, caps ...mda.Capability) mda.Claims {
	if caps == nil {
		caps = []mda.Capability{}
	}
	return mda.Claims{
		Issuer:    iss,
		Subject:   sub,
		Audience:  audience,
		IssuedAt:  1789200000,
		ExpiresAt: 1789203600,
		ID:        "jti-" + sub,
		Mandatum: mda.Mandatum{
			Version:      mda.Version,
			Root:         sponsor(),
			MaxDepth:     maxDepth,
			Capabilities: caps,
		},
	}
}

func capability(resType, resID, action string) mda.Capability {
	return mda.Capability{
		Resource: mda.ResourcePattern{Type: resType, ID: resID},
		Action:   mda.ActionPattern{Name: action},
	}
}

// twoHop is the reference chain: sponsor grants to agent A, A sub-delegates a
// narrower grant to agent B.
func twoHop() mda.Chain {
	return chainOf(
		link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.*", "invoke")),
		link("agent-a", "agent-b", 2, capability("mcp_tool", "search.query", "invoke")),
	).build()
}

func newTestVerifier(t *testing.T, sigs SignatureVerifier, rev RevocationChecker) *Verifier {
	t.Helper()
	v, err := New(sigs, rev, audience, WithClock(clock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestVerifyAcceptsAWellFormedChain(t *testing.T) {
	v := newTestVerifier(t, allowAll{}, noRevocations{})

	got, err := v.Verify(context.Background(), twoHop())
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if got.Sponsor.Subject != sponsorSub {
		t.Errorf("sponsor = %q, want %q", got.Sponsor.Subject, sponsorSub)
	}
	if got.Agent != "agent-b" {
		t.Errorf("agent = %q, want agent-b", got.Agent)
	}
	if got.Depth != 1 {
		t.Errorf("depth = %d, want 1", got.Depth)
	}
	if got.LeafID != "jti-agent-b" {
		t.Errorf("leaf id = %q, want jti-agent-b", got.LeafID)
	}
	// Sequence history is kept under RootID. Keyed off the leaf instead,
	// every sub-delegation would get a fresh history and the constraint the
	// sequence package exists to enforce would be escapable by delegating.
	// The two jtis differ in this chain precisely so that a mix-up fails.
	if got.RootID != "jti-agent-a" {
		t.Errorf("root id = %q, want jti-agent-a; sequence history would key off the wrong assertion", got.RootID)
	}
	if len(got.Actors) != 2 || got.Actors[0] != "agent-a" || got.Actors[1] != "agent-b" {
		t.Errorf("actors = %v, want the chain from the sponsor's grantee to the acting agent", got.Actors)
	}
	if got.ChainDigest == "" {
		t.Error("chain digest is empty; audit records could not be correlated")
	}
}

// A single-link chain is the sponsor acting through one agent with no
// sub-delegation. It must work, or the common case is broken.
func TestVerifyAcceptsASingleLink(t *testing.T) {
	v := newTestVerifier(t, allowAll{}, noRevocations{})
	c := chainOf(link(sponsorIss, "agent-a", 1, capability("mcp_tool", "search.query", "invoke"))).build()

	got, err := v.Verify(context.Background(), c)
	if err != nil {
		t.Fatalf("single-link chain rejected: %v", err)
	}
	// With one link the root is the leaf, which is the case a mix-up would
	// pass. The two-hop test is what distinguishes them; this pins that a
	// chain of one still reports both.
	if got.RootID != "jti-agent-a" || got.LeafID != "jti-agent-a" {
		t.Errorf("root %q / leaf %q, want both jti-agent-a", got.RootID, got.LeafID)
	}
}

// Each case below breaks exactly one rule. The rule identifier is asserted,
// not just the presence of an error, so a chain rejected for the wrong reason
// still fails the test - otherwise a bug that rejects everything would look
// like complete coverage.
func TestVerifyRejects(t *testing.T) {
	tests := []struct {
		name     string
		chain    func() mda.Chain
		sigs     SignatureVerifier
		rev      RevocationChecker
		wantRule string
		wantText string
	}{
		{
			name:     "empty chain",
			chain:    func() mda.Chain { return mda.Chain{} },
			wantRule: "V1",
			wantText: "establishes nothing",
		},
		{
			name: "assertion with no serialization",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Raw = nil
				return c
			},
			wantRule: "V1",
			wantText: "no serialization",
		},
		{
			name: "spliced link: parent commitment does not match",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.Mandatum.Parent = mda.Digest([]byte("some other assertion"))
				return reseal(c, 1)
			},
			wantRule: "V1",
			wantText: "was not issued against this chain",
		},
		{
			name: "chain does not start at depth 0",
			chain: func() mda.Chain {
				c := twoHop()
				return c[1:]
			},
			wantRule: "V1",
			wantText: "chain starts at depth 1, not 0",
		},
		{
			name: "depth skips a step",
			chain: func() mda.Chain {
				c := twoHop()
				// max_depth must leave room for the forged depth, or the
				// per-assertion structural check rejects it first and this
				// stops exercising the chain-sequence rule.
				c[1].Claims.Mandatum.Depth = 5
				c[1].Claims.Mandatum.MaxDepth = 9
				return reseal(c, 1)
			},
			wantRule: "V1",
			wantText: "does not follow",
		},
		{
			name: "custody break: issuer is not the parent's delegatee",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.Issuer = "agent-z"
				return reseal(c, 1)
			},
			wantRule: "V2",
			wantText: "the parent delegated to",
		},
		{
			name:     "signature does not verify",
			chain:    twoHop,
			sigs:     denyIssuer{issuer: "agent-a"},
			wantRule: "V3",
			wantText: "did not verify",
		},
		{
			name: "expired link",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.ExpiresAt = testNow.Unix() - 3600
				return reseal(c, 1)
			},
			wantRule: "V4",
			wantText: "expired",
		},
		{
			name: "link issued in the future",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.IssuedAt = testNow.Unix() + 3600
				return reseal(c, 1)
			},
			wantRule: "V4",
			wantText: "in the future",
		},
		{
			name: "child outlives its parent",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.ExpiresAt = c[0].Claims.ExpiresAt + 1
				return reseal(c, 1)
			},
			wantRule: "V5",
			wantText: "outlives its parent",
		},
		{
			name: "child does not decrease max_depth",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.Mandatum.MaxDepth = c[0].Claims.Mandatum.MaxDepth
				return reseal(c, 1)
			},
			wantRule: "V5",
			wantText: "does not decrease",
		},
		{
			name: "child grants a capability the parent lacks",
			chain: func() mda.Chain {
				return chainOf(
					link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.query", "invoke")),
					link("agent-a", "agent-b", 2, capability("mcp_tool", "admin.deleteAll", "invoke")),
				).build()
			},
			wantRule: "V5",
			wantText: "not covered by the parent",
		},
		{
			name: "child widens a prefix into a broader prefix",
			chain: func() mda.Chain {
				return chainOf(
					link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.*", "invoke")),
					link("agent-a", "agent-b", 2, capability("mcp_tool", "*", "invoke")),
				).build()
			},
			wantRule: "V5",
			wantText: "not covered by the parent",
		},
		{
			name: "child changes the action",
			chain: func() mda.Chain {
				return chainOf(
					link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.query", "invoke")),
					link("agent-a", "agent-b", 2, capability("mcp_tool", "search.query", "administer")),
				).build()
			},
			wantRule: "V5",
			wantText: "not covered by the parent",
		},
		{
			name: "attribution stripped: sponsor rewritten mid-chain",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.Mandatum.Root.Subject = "someone-else"
				return reseal(c, 1)
			},
			wantRule: "V6",
			wantText: "the chain is rooted in",
		},
		{
			name: "sponsor authentication time rewritten",
			chain: func() mda.Chain {
				c := twoHop()
				c[1].Claims.Mandatum.Root.AuthenticatedAt = 1
				return reseal(c, 1)
			},
			wantRule: "V6",
			wantText: "authentication time differs",
		},
		{
			name: "child reuses the parent's depth budget",
			chain: func() mda.Chain {
				return chainOf(
					link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.query", "invoke")),
					link("agent-a", "agent-b", 3, capability("mcp_tool", "search.query", "invoke")),
				).build()
			},
			wantRule: "V5",
			wantText: "does not decrease",
		},
		{
			name:     "revoked leaf",
			chain:    twoHop,
			rev:      revokes{jti: "jti-agent-b"},
			wantRule: "V8",
			wantText: "is revoked",
		},
		{
			name:     "revoking a parent kills the descendant",
			chain:    twoHop,
			rev:      revokes{jti: "jti-agent-a"},
			wantRule: "V8",
			wantText: "is revoked",
		},
		{
			name:     "revocation status unknown",
			chain:    twoHop,
			rev:      brokenRevocation{},
			wantRule: "V8",
			wantText: "unanswerable check denies",
		},
		{
			// V5 rule 7 stops a link changing the audience mid-chain, so the
			// case V9 is left holding is a whole chain issued for somebody
			// else and presented here.
			name: "chain addressed to another resource server",
			chain: func() mda.Chain {
				elsewhere := link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.query", "invoke"))
				elsewhere.Audience = "https://other.example.org"
				return chainOf(elsewhere).build()
			},
			wantRule: "V9",
			wantText: "addressed to",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := tt.sigs
			if sigs == nil {
				sigs = allowAll{}
			}
			rev := tt.rev
			if rev == nil {
				rev = noRevocations{}
			}
			v := newTestVerifier(t, sigs, rev)

			res, err := v.Verify(context.Background(), tt.chain())
			if err == nil {
				t.Fatalf("accepted a chain that should be rejected (result: %+v)", res)
			}
			if res != nil {
				t.Error("a rejected chain must not also return a result")
			}
			if got := Rule(err); got != tt.wantRule {
				t.Errorf("rejected by rule %s, want %s (error: %v)", got, tt.wantRule, err)
			}
			if !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("error %q does not mention %q", err, tt.wantText)
			}
		})
	}
}

// Revoking a link must not disturb chains that do not descend from it. If it
// did, selective revocation would be no better than the shared-credential
// situation the project exists to fix.
func TestRevocationIsConfinedToDescendants(t *testing.T) {
	sibling := chainOf(
		link(sponsorIss, "agent-c", 3, capability("mcp_tool", "search.query", "invoke")),
	).build()

	v := newTestVerifier(t, allowAll{}, revokes{jti: "jti-agent-b"})

	if _, err := v.Verify(context.Background(), sibling); err != nil {
		t.Fatalf("revoking agent-b broke an unrelated chain: %v", err)
	}
	if _, err := v.Verify(context.Background(), twoHop()); err == nil {
		t.Fatal("revoking agent-b did not stop agent-b")
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name string
		call func() (*Verifier, error)
		want string
	}{
		{
			"no signature verifier",
			func() (*Verifier, error) { return New(nil, noRevocations{}, audience) },
			"SignatureVerifier is required",
		},
		{
			"no revocation checker",
			func() (*Verifier, error) { return New(allowAll{}, nil, audience) },
			"RevocationChecker is required",
		},
		{
			"no audience",
			func() (*Verifier, error) { return New(allowAll{}, noRevocations{}, "") },
			"audience is required",
		},
		{
			"skew beyond the bound",
			func() (*Verifier, error) {
				return New(allowAll{}, noRevocations{}, audience, WithSkew(time.Hour))
			},
			"outside",
		},
		{
			"negative skew",
			func() (*Verifier, error) {
				return New(allowAll{}, noRevocations{}, audience, WithSkew(-time.Second))
			},
			"outside",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := tt.call()
			if err == nil {
				t.Fatal("accepted an unusable configuration")
			}
			if v != nil {
				t.Error("returned a verifier alongside an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// V7 caps chain length at what the sponsor permitted. It cannot be reached
// through Verify: V5 forces max_depth to fall by one per hop and the
// structural check requires max_depth to exceed depth, so a chain that would
// violate V7 is always rejected earlier. It is kept as defence in depth
// against a future change that relaxes either of those, and tested directly
// so the redundancy is deliberate rather than an untested branch.
func TestDepthCapIsEnforcedIndependently(t *testing.T) {
	// The sponsor permitted no sub-delegation, yet a second link exists.
	overLong := chainOf(
		link(sponsorIss, "agent-a", 0, capability("mcp_tool", "search.query", "invoke")),
		link("agent-a", "agent-b", 0, capability("mcp_tool", "search.query", "invoke")),
	).build()

	err := checkDepth(overLong)
	if err == nil {
		t.Fatal("accepted a chain longer than the sponsor permitted")
	}
	if got := Rule(err); got != "V7" {
		t.Errorf("rejected by rule %s, want V7", got)
	}
	if !strings.Contains(err.Error(), "the sponsor permitted at most") {
		t.Errorf("error %q does not explain the limit", err)
	}

	if err := checkDepth(twoHop()); err != nil {
		t.Errorf("rejected a chain within the sponsor's limit: %v", err)
	}
}

func TestChainDigestDistinguishesChains(t *testing.T) {
	a := ChainDigest(twoHop())

	other := chainOf(
		link(sponsorIss, "agent-a", 3, capability("mcp_tool", "search.*", "invoke")),
		link("agent-a", "agent-d", 2, capability("mcp_tool", "search.query", "invoke")),
	).build()

	if a == ChainDigest(other) {
		t.Error("chains delegating to different agents share a digest")
	}
	if a != ChainDigest(twoHop()) {
		t.Error("chain digest is not deterministic")
	}

	// A prefix of a chain must not collide with the whole chain, or an
	// audit record could not tell a truncated chain from a complete one.
	if a == ChainDigest(twoHop()[:1]) {
		t.Error("a chain and its prefix share a digest")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("agent-a", "agent-b", "search.*", "search.query", int64(1789203600), 3, 2)
	f.Add("", "", "", "", int64(0), 0, 0)
	f.Add("a", "a", "*", "*", int64(-1), -1, 1)

	v, err := New(allowAll{}, noRevocations{}, audience, WithClock(clock))
	if err != nil {
		f.Fatal(err)
	}

	// Verify must terminate and must never panic. It runs on the enforcement
	// path against input an attacker partly controls, so a panic here is a
	// denial of service on every protected tool call.
	f.Fuzz(func(t *testing.T, issA, subB, capA, capB string, exp int64, maxA, maxB int) {
		parent := link(sponsorIss, issA, maxA, capability("mcp_tool", capA, "invoke"))
		child := link(issA, subB, maxB, capability("mcp_tool", capB, "invoke"))
		child.ExpiresAt = exp

		res, err := v.Verify(context.Background(), chainOf(parent, child).build())
		if err != nil {
			return
		}
		// Anything accepted must carry the sponsor through. An accepted
		// chain with no attribution would defeat the point of the format.
		if res.Sponsor.Subject != sponsorSub {
			t.Fatalf("accepted a chain whose sponsor is %q", res.Sponsor.Subject)
		}
		if res.Depth != 1 {
			t.Fatalf("accepted a two-link chain reporting depth %d", res.Depth)
		}
	})
}
