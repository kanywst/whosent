// Package issue builds and signs delegation chains.
//
// Verification is the security-critical half and lives in package verify.
// This half exists so that the two are written against the same
// specification by the same project: a format with only a verifier is one
// nobody can produce chains for, and a format whose issuer takes shortcuts
// the verifier tolerates is one whose rules are theoretical.
//
// Every function here refuses to produce a chain that verification would
// reject on grounds an issuer can determine. Catching an over-broad
// delegation when it is issued gives an error where someone can fix it;
// catching it at enforcement gives an outage.
//
// Two rules are outside that. Expiry depends on when verification happens,
// which an issuer cannot know, so an assertion backdated far enough to be
// born expired is accepted here and refused at V4. And revocation is a
// property of the world after issuance. Everything else that verification
// checks about a single link or a parent-child pair is checked here first.
package issue

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// Signer holds the private key an issuer signs with.
type Signer struct {
	// ID is the issuer's identifier, and becomes `iss`. For a sub-delegating
	// agent it must equal the `sub` of the assertion that granted it
	// authority, or the chain fails custody checking (rule V2).
	ID string
	// KeyID selects among the issuer's keys and becomes the JOSE `kid`.
	// Empty means the issuer's default key.
	KeyID string
	Key   ed25519.PrivateKey
}

// Depth is a convenience for setting Grant.MaxDepth.
//
// The field is a pointer because zero is a meaningful value - authority that
// may be exercised but not sub-delegated - and must be distinguishable from
// "unset, inherit from the parent". A plain int would silently turn the first
// into the second, which widens the grant.
func Depth(n int) *int { return &n }

func (s Signer) check() error {
	if s.ID == "" {
		return errors.New("issue: signer ID is required; it becomes iss")
	}
	if len(s.Key) != ed25519.PrivateKeySize {
		return fmt.Errorf("issue: signer key is %d bytes, want %d", len(s.Key), ed25519.PrivateKeySize)
	}
	return nil
}

// Grant describes the authority to hand over.
type Grant struct {
	// Subject is the agent receiving the authority.
	Subject string
	// Audience is the resource server the assertion may be presented to.
	Audience string
	// ID becomes `jti`, the unit of revocation. Required, and must be unique
	// per assertion: revocation addresses this value, so a reused one would
	// revoke more than intended.
	ID string
	// Lifetime is how long the assertion is valid from IssuedAt.
	Lifetime time.Duration
	// IssuedAt defaults to the current time.
	IssuedAt time.Time
	// MaxDepth is how many further delegations are permitted below the
	// assertion being issued. Use the Depth helper: Depth(0) grants authority
	// that cannot be sub-delegated at all.
	//
	// Required for a sponsor grant. When sub-delegating, nil takes one less
	// than the parent's; an explicit value may only be lower still.
	MaxDepth *int
	// Capabilities is the authority granted. An empty non-nil slice grants
	// nothing, which is valid; a nil slice is an error, because a caller who
	// meant to grant nothing should have to say so.
	Capabilities []mda.Capability
	// Sequence constrains the action series. When sub-delegating it defaults
	// to the parent's and may only be tightened.
	Sequence *mda.Sequence
}

// Sponsor issues the first link of a chain: a human's grant to an agent.
//
// signer is the sponsor's identity provider, not the sponsor. A human does
// not hold a signing key; an authority that authenticated them attests to the
// delegation on their behalf, which is why sponsor carries `amr` and
// `auth_time` for policy to inspect.
func Sponsor(signer Signer, sponsor mda.Sponsor, g Grant) (mda.Assertion, error) {
	if err := signer.check(); err != nil {
		return mda.Assertion{}, err
	}
	if sponsor.Issuer == "" || sponsor.Subject == "" {
		return mda.Assertion{}, errors.New("issue: sponsor must have an issuer and a subject")
	}
	// Without an audience the chain fails V9 at every resource server it is
	// presented to. Delegate defaults to the parent's where a caller gives
	// none, and section 6 rule 7 refuses one that differs, so in a chain this
	// package issues the audience is whatever the sponsor grant named. It is
	// the rule that makes that true, not the defaulting.
	if g.Audience == "" {
		return mda.Assertion{}, errors.New(
			"issue: a sponsor grant must name an audience; a chain without one is refused by every resource server")
	}
	if g.MaxDepth == nil {
		return mda.Assertion{}, errors.New(
			"issue: a sponsor grant must set MaxDepth; use issue.Depth(0) to forbid sub-delegation")
	}
	if *g.MaxDepth < 0 {
		return mda.Assertion{}, fmt.Errorf(
			"issue: max_depth %d is negative; use issue.Depth(0) to forbid sub-delegation", *g.MaxDepth)
	}

	claims, err := g.claims(signer.ID, sponsor, 0, "")
	if err != nil {
		return mda.Assertion{}, err
	}
	return sign(claims, signer)
}

// Delegate issues a child assertion under parent.
//
// The child's parent commitment, depth and sponsor are derived from parent
// rather than taken from the caller, so those cannot be got wrong. Everything
// that can only narrow - expiry, depth budget, capabilities, sequence - is
// checked here against the parent, and an attempt to widen is an error rather
// than a chain that fails later at a resource server.
func Delegate(signer Signer, parent mda.Assertion, g Grant) (mda.Assertion, error) {
	if err := signer.check(); err != nil {
		return mda.Assertion{}, err
	}
	if len(parent.Raw) == 0 {
		return mda.Assertion{}, errors.New("issue: parent has no serialization to commit to")
	}

	p := parent.Claims
	if signer.ID != p.Subject {
		return mda.Assertion{}, fmt.Errorf(
			"issue: signer %q cannot delegate authority granted to %q", signer.ID, p.Subject)
	}

	if p.Mandatum.MaxDepth < 1 {
		return mda.Assertion{}, errors.New(
			"issue: the parent's delegation depth is exhausted; it may act but not sub-delegate")
	}
	if g.MaxDepth == nil {
		g.MaxDepth = Depth(p.Mandatum.MaxDepth - 1)
	}
	if *g.MaxDepth > p.Mandatum.MaxDepth-1 {
		return mda.Assertion{}, fmt.Errorf(
			"issue: max_depth %d does not decrease from the parent's %d",
			*g.MaxDepth, p.Mandatum.MaxDepth)
	}
	if *g.MaxDepth < 0 {
		return mda.Assertion{}, fmt.Errorf("issue: max_depth %d is negative", *g.MaxDepth)
	}
	if g.Sequence == nil {
		g.Sequence = p.Mandatum.Sequence
	}
	if g.Audience == "" {
		g.Audience = p.Audience
	}

	claims, err := g.claims(signer.ID, p.Mandatum.Root, p.Mandatum.Depth+1, mda.Digest(parent.Raw))
	if err != nil {
		return mda.Assertion{}, err
	}
	// The same rules the verifier applies, applied here so an over-broad
	// delegation is an error at the desk of whoever wrote it rather than an
	// outage at a resource server. verify.Attenuates is the single
	// implementation of section 6; duplicating it here would let the issuer
	// drift more permissive than the verifier.
	if err := verify.Attenuates(p, claims); err != nil {
		return mda.Assertion{}, fmt.Errorf("issue: the delegation widens the parent's authority: %w", err)
	}

	return sign(claims, signer)
}

func (g Grant) claims(issuer string, root mda.Sponsor, depth int, parent string) (mda.Claims, error) {
	if g.Subject == "" {
		return mda.Claims{}, errors.New("issue: grant subject is required")
	}
	if g.ID == "" {
		return mda.Claims{}, errors.New("issue: grant ID is required; it is the unit of revocation")
	}
	if g.Capabilities == nil {
		return mda.Claims{}, errors.New(
			"issue: capabilities must be set; use an empty slice to grant nothing explicitly")
	}
	if g.Lifetime <= 0 {
		return mda.Claims{}, errors.New("issue: a positive lifetime is required; assertions do not live forever")
	}

	iat := g.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}

	return mda.Claims{
		Issuer:    issuer,
		Subject:   g.Subject,
		Audience:  g.Audience,
		IssuedAt:  iat.Unix(),
		ExpiresAt: iat.Add(g.Lifetime).Unix(),
		ID:        g.ID,
		Mandatum: mda.Mandatum{
			Version:      mda.Version,
			Root:         root,
			Parent:       parent,
			Depth:        depth,
			MaxDepth:     *g.MaxDepth,
			Capabilities: g.Capabilities,
			Sequence:     g.Sequence,
		},
	}, nil
}

func sign(claims mda.Claims, signer Signer) (mda.Assertion, error) {
	// Structural validation before signing, so that an assertion which could
	// never verify is never produced. An issuer that emits garbage makes the
	// verifier's rejections look like the verifier's fault.
	if err := claims.Validate(); err != nil {
		return mda.Assertion{}, fmt.Errorf("issue: %w", err)
	}
	raw, err := jose.Sign(claims, signer.Key, signer.KeyID)
	if err != nil {
		return mda.Assertion{}, err
	}
	return mda.Assertion{Raw: raw, Claims: claims}, nil
}

// ParseChain decodes a chain from its wire form: the compact serializations
// in order, sponsor first.
//
// The claims it returns are unverified. Pass the result to verify.Verify
// before relying on anything in it; the verifier re-derives claims from the
// bytes rather than trusting what it is handed, so this is a convenience
// rather than a step that establishes anything.
//
// Deprecated: use mda.ParseChain. This forwards to it and will be removed
// before v1.0.
func ParseChain(serializations [][]byte) (mda.Chain, error) {
	return mda.ParseChain(serializations)
}
