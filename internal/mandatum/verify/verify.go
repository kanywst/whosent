// Package verify implements chain verification for Mandatum Delegation
// Assertions, rules V1 through V9 of docs/spec/delegation-assertion.md.
//
// The package deliberately has no dependencies beyond the standard library,
// pkg/mda, and pkg/jose for the one sentinel that distinguishes a bad JOSE
// header from a malformed serialization. Signature verification and
// revocation lookup are interfaces, so the chain logic - the part where a
// mistake grants authority nobody delegated - can be read, reviewed and
// fuzzed without a JOSE implementation in the way.
//
// Every exported failure names the specification rule it comes from, so a
// denial can be traced to a clause rather than to a stack trace.
package verify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// SignatureVerifier checks that raw was signed by the named issuer.
//
// Implementations must reject unsigned tokens, the "none" algorithm, and any
// algorithm outside their own allowlist. Returning nil is an assertion that
// the issuer signed these exact bytes.
type SignatureVerifier interface {
	VerifySignature(ctx context.Context, issuer string, raw []byte) error
}

// RevocationChecker reports whether an assertion has been revoked.
//
// An implementation that cannot answer must return an error rather than
// false. Verification treats an unanswerable revocation check as a failure,
// because reporting "not revoked" when the answer is unknown would let a
// revoked chain through exactly when the revocation infrastructure is broken.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Verifier verifies chains. The zero value is not usable; use New.
type Verifier struct {
	sigs     SignatureVerifier
	revoked  RevocationChecker
	audience string
	now      func() time.Time
	skew     time.Duration
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock replaces the time source. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) { v.now = now }
}

// WithSkew sets the tolerance applied to time comparisons. It is bounded:
// a large skew silently extends the life of every assertion in the system.
func WithSkew(d time.Duration) Option {
	return func(v *Verifier) { v.skew = d }
}

// MaxSkew is the largest tolerance a Verifier will accept.
const MaxSkew = 5 * time.Minute

// DefaultSkew is applied when WithSkew is not used.
const DefaultSkew = 30 * time.Second

// New returns a Verifier.
//
// audience is the identifier of the resource server doing the verifying; the
// leaf assertion must name it (V9). All three arguments are required: a
// verifier without signature checking or without revocation checking would
// silently be a much weaker thing than its name suggests.
func New(sigs SignatureVerifier, revoked RevocationChecker, audience string, opts ...Option) (*Verifier, error) {
	if sigs == nil {
		return nil, errors.New("verify: a SignatureVerifier is required")
	}
	if revoked == nil {
		return nil, errors.New("verify: a RevocationChecker is required")
	}
	if audience == "" {
		return nil, errors.New("verify: an audience is required for rule V9")
	}
	v := &Verifier{
		sigs:     sigs,
		revoked:  revoked,
		audience: audience,
		now:      time.Now,
		skew:     DefaultSkew,
	}
	for _, o := range opts {
		o(v)
	}
	if v.skew < 0 || v.skew > MaxSkew {
		return nil, fmt.Errorf("verify: skew %s is outside [0, %s]", v.skew, MaxSkew)
	}
	return v, nil
}

// Result describes a chain that passed every rule.
type Result struct {
	// Sponsor is the human the whole chain is attributable to.
	Sponsor mda.Sponsor
	// Agent is the acting principal: the leaf's subject.
	Agent string
	// Actors lists every principal the authority passed through, in order,
	// from the agent the sponsor granted to, down to Agent. It answers "who
	// was upstream". On its own it is a list; paired with ChainDigest, which
	// commits to the exact links, it is a list that cannot have been
	// assembled from pieces of other chains.
	Actors []string
	// Capabilities is the leaf's capability set, already known to be within
	// everything above it. Use Permits rather than reading it directly: a
	// caller comparing these patterns by hand is reimplementing the matcher
	// the issuer used, and the direction that drifts in is permissive.
	Capabilities []mda.Capability
	// Sequence is the leaf's sequence constraints, or nil.
	Sequence *mda.Sequence
	// Depth is the number of delegation hops below the sponsor.
	Depth int
	// ChainDigest identifies this exact chain, for audit correlation.
	ChainDigest string
	// LeafID is the leaf's jti: the handle to revoke this agent alone.
	LeafID string
	// RootID is the sponsor's grant, at depth 0. Sequence state is kept per
	// chain root, so this is the key it is kept under: every chain descending
	// from one grant shares a history, which is what makes a constraint
	// binding across sub-delegation rather than resettable by making another
	// agent.
	RootID string
}

// Verify checks a chain against rules V1 through V9 and returns what the
// chain establishes. A non-nil error means the chain grants nothing; callers
// must not fall back to partial results.
func (v *Verifier) Verify(ctx context.Context, chain mda.Chain) (*Result, error) {
	if len(chain) == 0 {
		return nil, ruleErr("V1", -1, "an empty chain establishes nothing")
	}

	// Claims are re-derived from the bytes rather than taken from the caller.
	// V3 verifies a signature over Raw, so Raw is the only part of an
	// Assertion an issuer vouched for; Assertion.Claims is a field anyone can
	// set. Evaluating what was handed in would mean the whole rule set runs
	// against claims nobody signed, and the correct signature over the
	// untouched bytes would make it look checked.
	parsed := make(mda.Chain, len(chain))
	for i, a := range chain {
		if len(a.Raw) == 0 {
			return nil, ruleErr("V1", i, "assertion has no serialization to commit to")
		}
		claims, err := mda.ParseClaims(a.Raw)
		if err != nil {
			// The algorithm allowlist and the media type are V3's business,
			// even though reading them happens here. Everything else Parse
			// refuses is a malformed serialization, which is V1.
			rule := "V1"
			if errors.Is(err, jose.ErrHeader) {
				rule = "V3"
			}
			return nil, ruleErr(rule, i, err.Error())
		}
		parsed[i] = mda.Assertion{Raw: a.Raw, Claims: claims}
	}
	chain = parsed

	// Structural checks run next. They are cheap, they touch only the
	// assertion's own contents, and rejecting here avoids doing crypto on
	// input that could never be valid.
	for i, a := range chain {
		if err := a.Claims.Validate(); err != nil {
			return nil, ruleErr("V1", i, err.Error())
		}
	}

	if err := v.checkStructure(chain); err != nil { // V1, V2
		return nil, err
	}
	if err := v.checkSignatures(ctx, chain); err != nil { // V3
		return nil, err
	}
	if err := v.checkTime(chain); err != nil { // V4
		return nil, err
	}
	if err := checkAttenuation(chain); err != nil { // V5
		return nil, err
	}
	if err := checkRoot(chain); err != nil { // V6
		return nil, err
	}
	if err := checkDepth(chain); err != nil { // V7
		return nil, err
	}
	if err := v.checkRevocation(ctx, chain); err != nil { // V8
		return nil, err
	}
	if err := v.checkAudience(chain); err != nil { // V9
		return nil, err
	}

	leaf := chain[len(chain)-1]
	actors := make([]string, len(chain))
	for i, a := range chain {
		actors[i] = a.Claims.Subject
	}
	return &Result{
		Sponsor:      leaf.Claims.Mandatum.Root,
		Agent:        leaf.Claims.Subject,
		Actors:       actors,
		Capabilities: leaf.Claims.Mandatum.Capabilities,
		Sequence:     leaf.Claims.Mandatum.Sequence,
		Depth:        leaf.Claims.Mandatum.Depth,
		ChainDigest:  ChainDigest(chain),
		LeafID:       leaf.Claims.ID,
		RootID:       chain[0].Claims.ID,
	}, nil
}

// checkStructure implements V1 (parent commitment) and V2 (custody).
func (v *Verifier) checkStructure(chain mda.Chain) error {
	root := chain[0].Claims.Mandatum
	if root.Depth != 0 {
		return ruleErr("V1", 0, fmt.Sprintf("chain starts at depth %d, not 0", root.Depth))
	}
	if root.Parent != "" {
		return ruleErr("V1", 0, "the first link commits to a parent, so this is not the start of a chain")
	}

	for i := 1; i < len(chain); i++ {
		want := mda.Digest(chain[i-1].Raw)
		if got := chain[i].Claims.Mandatum.Parent; got != want {
			return ruleErr("V1", i, fmt.Sprintf(
				"parent commitment %q does not match the preceding assertion (%q); "+
					"this link was not issued against this chain", got, want))
		}
		if chain[i].Claims.Mandatum.Depth != chain[i-1].Claims.Mandatum.Depth+1 {
			return ruleErr("V1", i, fmt.Sprintf("depth %d does not follow %d",
				chain[i].Claims.Mandatum.Depth, chain[i-1].Claims.Mandatum.Depth))
		}
		// V2: a delegator may only delegate authority it holds, so the
		// issuer of each link must be the subject of the one above it.
		if chain[i].Claims.Issuer != chain[i-1].Claims.Subject {
			return ruleErr("V2", i, fmt.Sprintf(
				"issued by %q, but the parent delegated to %q",
				chain[i].Claims.Issuer, chain[i-1].Claims.Subject))
		}
	}
	return nil
}

// checkSignatures implements V3.
func (v *Verifier) checkSignatures(ctx context.Context, chain mda.Chain) error {
	for i, a := range chain {
		if err := v.sigs.VerifySignature(ctx, a.Claims.Issuer, a.Raw); err != nil {
			return ruleErr("V3", i, fmt.Sprintf("signature by %q did not verify: %v", a.Claims.Issuer, err))
		}
	}
	return nil
}

// checkTime implements V4.
func (v *Verifier) checkTime(chain mda.Chain) error {
	now := v.now()
	for i, a := range chain {
		iat := time.Unix(a.Claims.IssuedAt, 0)
		exp := time.Unix(a.Claims.ExpiresAt, 0)
		if now.Add(v.skew).Before(iat) {
			return ruleErr("V4", i, fmt.Sprintf("issued at %s, which is in the future", iat.UTC()))
		}
		if !now.Add(-v.skew).Before(exp) {
			return ruleErr("V4", i, fmt.Sprintf("expired at %s", exp.UTC()))
		}
	}
	return nil
}

// checkRoot implements V6. The sponsor is duplicated into every link so that
// a partial chain remains attributable; this is where the duplication is
// checked to agree, which is what stops it being used to forge attribution.
func checkRoot(chain mda.Chain) error {
	want := chain[0].Claims.Mandatum.Root
	for i := 1; i < len(chain); i++ {
		got := chain[i].Claims.Mandatum.Root
		if got.Issuer != want.Issuer || got.Subject != want.Subject {
			return ruleErr("V6", i, fmt.Sprintf(
				"names sponsor %s/%s, but the chain is rooted in %s/%s",
				got.Issuer, got.Subject, want.Issuer, want.Subject))
		}
		if got.AuthenticatedAt != want.AuthenticatedAt {
			return ruleErr("V6", i, "sponsor authentication time differs from the root's")
		}
		if !sameStrings(got.AuthenticationMethods, want.AuthenticationMethods) {
			return ruleErr("V6", i, "sponsor authentication methods differ from the root's")
		}
	}
	return nil
}

// checkDepth implements V7.
//
// Given V5, which forces max_depth to fall by at least one per hop, and the
// structural rule that it may not go negative, this is not independently
// reachable: a chain that would violate it fails V5 first. It is kept as
// defence in depth against a later relaxation of V5, and tested directly
// rather than left as an untested branch.
func checkDepth(chain mda.Chain) error {
	hops := len(chain) - 1
	limit := chain[0].Claims.Mandatum.MaxDepth
	if hops > limit {
		return ruleErr("V7", len(chain)-1, fmt.Sprintf(
			"chain has %d delegation hops but the sponsor permitted at most %d", hops, limit))
	}
	return nil
}

// checkRevocation implements V8. Revoking any link kills every chain that
// descends from it, because descendants commit to it by hash.
func (v *Verifier) checkRevocation(ctx context.Context, chain mda.Chain) error {
	for i, a := range chain {
		revoked, err := v.revoked.IsRevoked(ctx, a.Claims.ID)
		if err != nil {
			return ruleErr("V8", i, fmt.Sprintf(
				"revocation status is unknown (%v); an unanswerable check denies", err))
		}
		if revoked {
			return ruleErr("V8", i, fmt.Sprintf("assertion %s is revoked", a.Claims.ID))
		}
	}
	return nil
}

// checkAudience implements V9. Only the leaf is audience-bound: it is the
// assertion actually being presented to this resource server.
func (v *Verifier) checkAudience(chain mda.Chain) error {
	leaf := len(chain) - 1
	if got := chain[leaf].Claims.Audience; got != v.audience {
		return ruleErr("V9", leaf, fmt.Sprintf(
			"addressed to %q, but this is %q", got, v.audience))
	}
	return nil
}

// ChainDigest identifies a chain for audit correlation. It commits to every
// link's serialization in order, so two chains sharing a prefix produce
// different digests.
func ChainDigest(chain mda.Chain) string {
	joined := make([]byte, 0, 64*len(chain))
	for _, a := range chain {
		joined = append(joined, mda.Digest(a.Raw)...)
		joined = append(joined, '\n')
	}
	return mda.Digest(joined)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
