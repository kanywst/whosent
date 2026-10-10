package diagnose

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/revoke"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// DefaultMaxAge is how old a revocation set may be before it is refused,
// matching revoke.NewChecker's own default.
const DefaultMaxAge = 24 * time.Hour

// Options are the inputs to a diagnosis. Everything is optional; whatever is
// absent makes the rules that need it Unchecked rather than passing.
type Options struct {
	// At is the evaluation time. Zero means now, captured once so every
	// rule sees the same instant.
	At time.Time
	// Skew is the tolerance applied to time comparisons. Nil means the
	// library's default. It must be within [0, verify.MaxSkew].
	Skew *time.Duration
	// Audience is the resource server the chain is being presented to. Nil
	// leaves V9 unchecked.
	Audience *string
	// Trust holds the verification keys. Nil leaves every signature
	// unchecked.
	Trust *Trust
	// Revocation is the revocation set. Nil leaves V8 unchecked.
	Revocation *Revocation
	// SimulatedRevocations are jtis to treat as revoked, to show what
	// revoking them would cut off. A report built with any is a
	// hypothetical, and says so.
	SimulatedRevocations []string
}

// Trust is the set of issuers whose keys are known. Which keys belong to
// which issuer is configuration; it is never read from an assertion.
type Trust struct {
	Issuers map[string]*IssuerKeys
}

// IssuerKeys is one issuer's verification keys.
type IssuerKeys struct {
	// Source names where the keys came from, for display.
	Source string
	// Keys maps a kid to its key. The empty kid is the issuer's default
	// key, present when the document holds exactly one usable key, as the
	// library's own resolver does.
	Keys map[string]ed25519.PublicKey
	// Skipped lists keys in the document that cannot be used, with the
	// reason. The library ignores them silently; a person debugging a
	// rotation wants to know.
	Skipped []string
	// Err is set when the key document could not be loaded or used. Every
	// link this issuer signed is then an Error, not Unchecked: the issuer
	// was configured, and an enforcement point would deny.
	Err string
}

// Revocation is a published revocation set and how to read it.
type Revocation struct {
	Set *revoke.Set
	// Source names the set, for display.
	Source string
	// MaxAge bounds how old the set may be at the evaluation time. Nil means
	// DefaultMaxAge; zero disables the bound, as revoke.WithMaxAge(0) does.
	MaxAge *time.Duration
	// Exact resolves a filter hit authoritatively. Without it a hit denies,
	// which is what the specification requires and what a Bloom filter's
	// false-positive rate costs.
	Exact       revoke.Exact
	ExactSource string
}

func (o Options) skew() (time.Duration, error) {
	s := verify.DefaultSkew
	if o.Skew != nil {
		s = *o.Skew
	}
	if s < 0 || s > verify.MaxSkew {
		return 0, fmt.Errorf("skew %s is outside [0, %s]", s, verify.MaxSkew)
	}
	return s, nil
}

func (r *Revocation) maxAge() time.Duration {
	if r.MaxAge == nil {
		return DefaultMaxAge
	}
	return *r.MaxAge
}

// WithAt returns a copy of o evaluated at t. The TUI's time scrub uses it.
func (o Options) WithAt(t time.Time) Options {
	o.At = t
	return o
}

// WithSimulatedRevocations returns a copy of o with jtis treated as revoked.
func (o Options) WithSimulatedRevocations(jtis []string) Options {
	o.SimulatedRevocations = append([]string(nil), jtis...)
	return o
}

// ExactList is an authoritative list of revoked jtis, used to resolve a hit
// in the revocation set's Bloom filter.
type ExactList map[string]bool

// IsRevoked implements revoke.Exact.
func (l ExactList) IsRevoked(_ context.Context, jti string) (bool, error) { return l[jti], nil }
