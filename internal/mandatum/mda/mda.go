// Package mda defines the Mandatum Delegation Assertion wire format.
//
// An assertion is one signed link in a delegation chain running from an
// authenticated human sponsor to the agent performing an action. The format
// is specified in docs/spec/delegation-assertion.md; this package is the
// normative Go representation of it and nothing more. Verification lives in
// package verify, so that the types can be depended on without pulling in a
// verifier, and so that a bug in verification cannot be masked by a type that
// quietly normalizes its input.
package mda

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Version is the only Delegation Assertion format version this package
// understands. A verifier must reject any other value rather than attempt a
// best-effort interpretation: an assertion whose semantics are unknown cannot
// be safely narrowed.
const Version = 1

// Claims is the JWT claims set carried by a Delegation Assertion.
//
// Registered claims keep their RFC 7519 meaning. Everything specific to
// Mandatum lives under Mandatum, so that the assertion can be carried by
// systems that already process JWTs without colliding with their claims.
type Claims struct {
	// Issuer is the delegator. For depth 0 this is the sponsor's issuing
	// authority; below that it is the parent assertion's Subject.
	Issuer string `json:"iss"`

	// Subject is the delegatee: the agent receiving this authority.
	Subject string `json:"sub"`

	// Audience is the resource server this assertion may be presented to.
	Audience string `json:"aud"`

	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti"`

	Mandatum Mandatum `json:"mdt"`
}

// Mandatum carries the delegation-specific claims.
type Mandatum struct {
	Version int `json:"v"`

	// Root identifies the human sponsor. It is copied byte-for-byte into
	// every link of a chain rather than resolved by walking to depth 0, so
	// that a partial chain can still be attributed. Verification checks the
	// copies agree, so the duplication cannot be used to forge attribution.
	Root Sponsor `json:"root"`

	// Parent is the digest of the parent assertion's compact serialization.
	// It is what makes links non-interchangeable: an assertion cannot be
	// spliced onto a chain it was not issued against.
	//
	// At depth 0 there is no parent and the field is omitted. It carries
	// omitempty for that reason: the field previously serialized as the
	// empty string, which is neither the absence the specification means nor
	// the null it named, and an implementation checking for null would have
	// rejected every sponsor grant this one produces.
	Parent string `json:"parent,omitempty"`

	// Depth is this link's zero-based position in the chain. It orders the
	// chain; it does not bound it.
	Depth int `json:"depth"`

	// MaxDepth is how many further delegations are permitted below this
	// assertion. Zero means this is the end of the line: the holder may act,
	// but may not sub-delegate. It falls by at least one at every hop, so the
	// sponsor's value bounds the whole chain.
	MaxDepth int `json:"max_depth"`

	// Capabilities is the authority granted. An empty slice is meaningful:
	// it grants nothing. It is not the same as an absent field, which is
	// invalid.
	Capabilities []Capability `json:"cap"`

	// Sequence constrains the series of actions taken under this chain.
	// Nil means no sequence constraints apply.
	Sequence *Sequence `json:"seq,omitempty"`
}

// Sponsor is the authenticated human at the root of a chain.
type Sponsor struct {
	Issuer string `json:"iss"`
	// Subject is the sponsor's stable identifier at Issuer. It is the key
	// every audit record is attributable by.
	Subject string `json:"sub"`
	// AuthenticationMethods records how the sponsor authenticated, so that
	// policy can require step-up for high-impact delegation.
	AuthenticationMethods []string `json:"amr,omitempty"`
	AuthenticatedAt       int64    `json:"auth_time,omitempty"`
}

// Capability is one grant: an action on a resource, optionally conditioned.
type Capability struct {
	Resource ResourcePattern `json:"resource"`
	Action   ActionPattern   `json:"action"`
	// Conditions restrict when the capability applies. Only the decidable
	// fragment described in the specification is permitted, so that
	// entailment between a parent and a child capability is always
	// decidable rather than approximated.
	Conditions map[string]Condition `json:"conditions,omitempty"`
}

// ResourcePattern identifies what a capability applies to.
type ResourcePattern struct {
	Type string `json:"type"`
	// ID may be a literal or a prefix pattern ending in "*".
	ID   string   `json:"id"`
	Tags []string `json:"tags,omitempty"`
}

// ActionPattern identifies what may be done.
type ActionPattern struct {
	Name string `json:"name"`
}

// Condition is one restriction from the decidable fragment. Exactly one field
// is set; a condition with zero or more than one set is invalid and must be
// rejected at issuance rather than interpreted at verification time.
type Condition struct {
	Equals *string `json:"eq,omitempty"`

	// In carries no omitempty, deliberately. An empty set is meaningful -
	// it matches nothing, and is how a delegator grants nothing on a key -
	// but encoding/json treats a zero-length slice as empty regardless of
	// nil-ness, so omitempty would drop it. The distinction would then
	// survive in memory and vanish on the wire, which is the worst place
	// for a semantic difference to disappear. Absent encodes as null and
	// decodes back to nil; `[]` decodes to an empty non-nil slice.
	In []string `json:"in"`

	Prefix *string  `json:"prefix,omitempty"`
	Min    *float64 `json:"min,omitempty"`
	Max    *float64 `json:"max,omitempty"`
}

// Sequence constrains a chain's action history rather than a single action.
type Sequence struct {
	// MaxInvocations caps how many actions may be taken under this chain.
	// Zero means unlimited, which is only valid if Constraints is non-empty;
	// an assertion with a Sequence that constrains nothing is invalid.
	MaxInvocations int `json:"max_invocations,omitempty"`

	Constraints []Constraint `json:"constraints,omitempty"`
}

// Constraint forbids an action once a triggering action has occurred in the
// chain's history. This is the shape that catches the pattern per-call
// authorization structurally cannot: read untrusted content, then mutate.
type Constraint struct {
	// ID names the constraint. A denial reports it, so an operator can tell
	// which rule fired without reading the policy.
	ID     string        `json:"id"`
	Forbid ActionMatcher `json:"forbid"`
	After  ActionMatcher `json:"after"`
}

// ActionMatcher selects actions in a history by their tags and type. An
// empty field matches anything, so a matcher with no fields set matches every
// action.
type ActionMatcher struct {
	Action       string   `json:"action,omitempty"`
	ResourceType string   `json:"resource.type,omitempty"`
	ResourceTags []string `json:"resource.tags,omitempty"`
}

// MatchesEverything reports whether this matcher constrains nothing. Valid
// for a constraint's Forbid ("after that, do nothing at all") and a trap for
// its After, which Claims.Validate refuses.
//
// Exported so that evaluation uses this definition rather than its own copy.
// If ActionMatcher gains a field, one place has to learn about it.
func (m ActionMatcher) MatchesEverything() bool {
	return m.Action == "" && m.ResourceType == "" && len(m.ResourceTags) == 0
}

// Assertion is one link as received, together with its parsed claims.
//
// Raw is the compact serialization exactly as it arrived. It is kept because
// the parent commitment is a digest over those bytes; re-serializing the
// claims could produce a different encoding and break the commitment that
// makes splicing detectable.
//
// Claims is a convenience, not an invariant. Nothing stops a caller building
// an Assertion whose Claims say something the signed Raw does not, so
// verification does not trust this field: verify.Verify re-derives claims
// from Raw with ParseClaims and evaluates those. Code outside the verifier
// that reads Claims from an unverified assertion is reading whatever it was
// handed.
type Assertion struct {
	Raw    []byte
	Claims Claims
}

// Chain is an ordered delegation chain, from the sponsor's grant at index 0
// to the acting agent's assertion at the end.
type Chain []Assertion

// Digest returns the parent-commitment value for a compact-serialized
// assertion, as "sha-256:" followed by unpadded base64url, the form the
// Parent field uses. The encoding is specified in §5.1 and is an
// interoperability contract: verifiers compare these as exact strings, so two
// implementations that encode the same hash differently reject every chain
// the other produces.
//
// The digest is taken over the compact serialization exactly as received,
// not over a re-encoding of the parsed claims. Re-encoding would let two
// different wire representations produce the same digest, which would defeat
// the splicing protection the commitment exists to provide.
func Digest(compactSerialization []byte) string {
	sum := sha256.Sum256(compactSerialization)
	return "sha-256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Validate reports whether the claims are structurally well formed. It does
// not check signatures, time, attenuation, revocation, or anything else that
// requires context beyond the assertion itself - those are the verifier's
// rules V2 through V9, and keeping them out of this method prevents a caller
// from mistaking a structural check for a security decision.
func (c Claims) Validate() error {
	if c.Mandatum.Version != Version {
		return fmt.Errorf("mda: unsupported version %d, want %d", c.Mandatum.Version, Version)
	}
	if c.Issuer == "" {
		return fmt.Errorf("mda: iss is required")
	}
	if c.Subject == "" {
		return fmt.Errorf("mda: sub is required")
	}
	if c.ID == "" {
		return fmt.Errorf("mda: jti is required, it is the unit of revocation")
	}
	if c.ExpiresAt == 0 {
		return fmt.Errorf("mda: exp is required, assertions do not live forever")
	}
	if c.Mandatum.Root.Issuer == "" || c.Mandatum.Root.Subject == "" {
		return fmt.Errorf("mda: mdt.root must identify a sponsor")
	}
	if c.Mandatum.Depth < 0 {
		return fmt.Errorf("mda: mdt.depth must not be negative")
	}
	if c.Mandatum.Depth == 0 && c.Mandatum.Parent != "" {
		return fmt.Errorf("mda: depth 0 must not commit to a parent")
	}
	if c.Mandatum.Depth > 0 && c.Mandatum.Parent == "" {
		return fmt.Errorf("mda: depth %d must commit to a parent", c.Mandatum.Depth)
	}
	if c.Mandatum.MaxDepth < 0 {
		return fmt.Errorf("mda: mdt.max_depth %d is negative; use 0 to forbid sub-delegation",
			c.Mandatum.MaxDepth)
	}
	if c.Mandatum.Capabilities == nil {
		return fmt.Errorf("mda: mdt.cap is required; use an empty array to grant nothing")
	}
	if s := c.Mandatum.Sequence; s != nil {
		// A negative budget is not merely malformed, it is an escape. Zero
		// means unlimited, and every comparison that treats "unlimited" as
		// zero reads a negative as unlimited too - including the attenuation
		// check, where `child > parent` is false for any negative child. A
		// child could then set -1 under a parent's budget of 100 and be
		// unconstrained. Refused here so it never reaches that comparison.
		if s.MaxInvocations < 0 {
			return fmt.Errorf("mda: mdt.seq.max_invocations %d is negative; use 0 for unlimited",
				s.MaxInvocations)
		}
		if s.MaxInvocations == 0 && len(s.Constraints) == 0 {
			return fmt.Errorf("mda: mdt.seq is present but constrains nothing")
		}
		seen := make(map[string]struct{}, len(s.Constraints))
		for i, con := range s.Constraints {
			if con.ID == "" {
				return fmt.Errorf("mda: mdt.seq.constraints[%d] has no id; "+
					"a denial must be able to name the rule that fired", i)
			}
			if _, dup := seen[con.ID]; dup {
				// Two rules under one name make the trigger state ambiguous:
				// which of them fired, and which does a denial refer to?
				return fmt.Errorf("mda: mdt.seq.constraints[%d]: id %q appears more than once", i, con.ID)
			}
			seen[con.ID] = struct{}{}

			// An empty trigger is a trap. A constraint says "once X has
			// happened", so an empty X needs some action to have happened
			// first and takes effect from the second action rather than the
			// first, which is not what whoever wrote it meant. Checked here,
			// in the structural validator, so that issuance refuses it too
			// rather than only the evaluator catching it later.
			if con.After.MatchesEverything() {
				return fmt.Errorf("mda: mdt.seq.constraints[%d]: constraint %q has an empty trigger; "+
					"a sequence rule fires after something, so this would take effect from the second "+
					"action, not the first. To forbid an action outright, leave it out of mdt.cap", i, con.ID)
			}
		}
	}
	for i, cap := range c.Mandatum.Capabilities {
		if err := cap.validate(); err != nil {
			return fmt.Errorf("mda: mdt.cap[%d]: %w", i, err)
		}
	}
	return nil
}

func (c Capability) validate() error {
	if c.Resource.Type == "" {
		return fmt.Errorf("resource.type is required")
	}
	if c.Action.Name == "" {
		return fmt.Errorf("action.name is required")
	}
	for key, cond := range c.Conditions {
		if err := cond.validate(); err != nil {
			return fmt.Errorf("condition %q: %w", key, err)
		}
	}
	return nil
}

// Comparisons counts how many of the mutually exclusive alternatives this
// condition sets.
//
// Exported because attenuation checking needs the same count, and two copies
// of the field list would drift. When they drift, the verifier's copy is the
// one that decides whether authority may widen.
func (c Condition) Comparisons() int {
	set := 0
	for _, isSet := range []bool{
		c.Equals != nil,
		c.In != nil,
		c.Prefix != nil,
		c.Min != nil || c.Max != nil,
	} {
		if isSet {
			set++
		}
	}
	return set
}

// InFragment reports whether this condition is one the decidable fragment can
// reason about: exactly one comparison, no more and no fewer.
func (c Condition) InFragment() bool { return c.Comparisons() == 1 }

// validate enforces that exactly one alternative is set. A condition with none
// set would match everything; one with several set would need a combination
// rule that the decidable fragment deliberately does not define.
func (c Condition) validate() error {
	switch n := c.Comparisons(); n {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("no comparison set; a condition that restricts nothing is not a condition")
	default:
		return fmt.Errorf("%d comparisons set; exactly one is permitted", n)
	}
}
