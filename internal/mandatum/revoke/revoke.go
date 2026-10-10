// Package revoke implements the compact revocation set of specification
// section 7.1, so that a Policy Enforcement Point can evaluate rule V8
// locally instead of asking a service on the path of every authorized call.
//
// The shape is a Bloom filter with a published false-positive rate, plus an
// optional exact lookup consulted only when the filter says "maybe". A Bloom
// filter has no false negatives, so a jti the filter rejects is definitely
// not revoked and needs no lookup at all - which is every call in a healthy
// system. A jti the filter admits is either revoked or one of the small
// fraction of collisions, and something authoritative has to separate them.
//
// Where nothing authoritative is configured, a collision denies. That is the
// specification's rule and it is the safe direction: the cost of a false
// positive is one refused call by an agent that can be reissued, and the cost
// of the opposite is honouring a credential its sponsor revoked.
package revoke

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Version is the wire format version of an encoded set.
const Version = 1

// MaxHashes bounds `hashes` in a published set.
//
// The cost of a lookup is k hash positions, and a lookup happens on the path
// of every authorized action. Without a bound, k is whatever the publisher
// wrote: a set of eighty bytes declaring a k in the billions makes one
// MayContain take seconds and ask for tens of gigabytes, so the document that
// says which agents are revoked doubles as a way to stop the enforcement
// point evaluating anything at all.
//
// Sixty-four is past any operational need rather than a tuned figure. At
// optimal sizing k = -log2(p), so k = 64 is a false-positive rate around
// 10^-19, and a realistic set wanting one in a billion uses k = 30.
const MaxHashes = 64

// wireVersion is what an encoder writes and a decoder requires. A verifier
// that silently accepted a future version would be guessing at semantics it
// does not have.
type wire struct {
	Version     int    `json:"v"`
	Sequence    uint64 `json:"sequence"`
	GeneratedAt int64  `json:"generated_at"`
	Hashes      int    `json:"hashes"`
	Bits        string `json:"bits"`
}

var b64 = base64.RawURLEncoding

// Set is an immutable compact representation of the revoked identifiers at a
// point in time.
//
// It is safe for concurrent use. Publishing a new revocation is publishing a
// new Set, not mutating one: a filter that could have bits added under a
// reader is a filter whose answers depend on when the reader looked.
type Set struct {
	bits        []byte
	hashes      int
	sequence    uint64
	generatedAt time.Time
}

// NewSet builds a set over the given identifiers, sized so that a jti that is
// not revoked is admitted with probability at most falsePositiveRate.
//
// sequence orders one published set against another. A consumer refuses a set
// older than the one it holds, because replacing a newer set with an older
// one reinstates every identifier revoked in between - which is the whole
// attack against a distributed revocation list.
func NewSet(revoked []string, falsePositiveRate float64, sequence uint64, generatedAt time.Time) (*Set, error) {
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		return nil, fmt.Errorf("revoke: false-positive rate must be in (0,1), got %v", falsePositiveRate)
	}
	if generatedAt.IsZero() {
		return nil, errors.New("revoke: a set must record when it was generated")
	}

	// The standard sizing: m = -n·ln(p)/(ln2)², k = (m/n)·ln2. An empty set
	// still gets a byte, so that the arithmetic below has a modulus.
	n := max(len(revoked), 1)
	m := int(math.Ceil(-float64(n) * math.Log(falsePositiveRate) / (math.Ln2 * math.Ln2)))
	m = max(((m+7)/8)*8, 8) // whole bytes, so the wire form has no spare bits
	k := max(int(math.Round(float64(m)/float64(n)*math.Ln2)), 1)
	if k > MaxHashes {
		// Refused rather than clamped. Clamping would build a filter whose
		// false-positive rate is not the one the caller asked for, and say
		// nothing about it; a rate a publisher believes is wrong is worse
		// than a rate they could not have.
		return nil, fmt.Errorf(
			"revoke: a false-positive rate of %v needs %d hash functions, above the %d a set may declare",
			falsePositiveRate, k, MaxHashes)
	}

	s := &Set{
		bits:        make([]byte, m/8),
		hashes:      k,
		sequence:    sequence,
		generatedAt: generatedAt.UTC().Truncate(time.Second),
	}
	for _, jti := range revoked {
		for _, bit := range s.indices(jti) {
			s.bits[bit/8] |= 1 << (bit % 8)
		}
	}
	return s, nil
}

// indices returns the bit positions a jti maps to.
//
// Derivation is fixed by the specification rather than left to the
// implementation: two implementations that index differently produce sets
// neither can read, and the failure mode is that one of them stops honouring
// revocations rather than that it errors.
//
// h = SHA-256(jti); h1 and h2 are its first and second eight bytes read
// big-endian; position i is (h1 + i·h2) mod m.
func (s *Set) indices(jti string) []uint64 {
	sum := sha256.Sum256([]byte(jti))
	h1 := binary.BigEndian.Uint64(sum[0:8])
	h2 := binary.BigEndian.Uint64(sum[8:16])
	m := uint64(len(s.bits)) * 8

	out := make([]uint64, s.hashes)
	for i := range out {
		out[i] = (h1 + uint64(i)*h2) % m
	}
	return out
}

// MayContain reports whether jti might be revoked. False is definitive: a
// Bloom filter has no false negatives, so an identifier the filter rejects
// was not in the set the publisher built. True is not definitive.
func (s *Set) MayContain(jti string) bool {
	if s == nil || len(s.bits) == 0 {
		return false
	}
	for _, bit := range s.indices(jti) {
		if s.bits[bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

// Sequence returns the publisher's ordering number for this set.
func (s *Set) Sequence() uint64 { return s.sequence }

// GeneratedAt returns when the publisher built this set.
func (s *Set) GeneratedAt() time.Time { return s.generatedAt }

// Encode returns the set's wire form, which is what a publisher distributes.
func (s *Set) Encode() ([]byte, error) {
	if s == nil {
		return nil, errors.New("revoke: cannot encode a nil set")
	}
	return json.Marshal(wire{
		Version:     Version,
		Sequence:    s.sequence,
		GeneratedAt: s.generatedAt.Unix(),
		Hashes:      s.hashes,
		Bits:        b64.EncodeToString(s.bits),
	})
}

// ParseSet decodes a published set.
func ParseSet(raw []byte) (*Set, error) {
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("revoke: parsing set: %w", err)
	}
	if w.Version != Version {
		return nil, fmt.Errorf("revoke: set is version %d, this implementation reads %d", w.Version, Version)
	}
	if w.Hashes < 1 || w.Hashes > MaxHashes {
		return nil, fmt.Errorf(
			"revoke: set declares %d hash functions, outside 1..%d; a lookup costs one hash position each and runs before every authorized action",
			w.Hashes, MaxHashes)
	}
	if w.GeneratedAt <= 0 {
		return nil, errors.New("revoke: set does not say when it was generated")
	}
	bits, err := b64.DecodeString(w.Bits)
	if err != nil {
		return nil, fmt.Errorf("revoke: decoding bits: %w", err)
	}
	if len(bits) == 0 {
		return nil, errors.New("revoke: set has no bits")
	}
	return &Set{
		bits:        bits,
		hashes:      w.Hashes,
		sequence:    w.Sequence,
		generatedAt: time.Unix(w.GeneratedAt, 0).UTC(),
	}, nil
}

// Exact is an authoritative answer for one identifier, consulted only when
// the filter says an identifier might be revoked. It is the "exact fallback
// lookup" of section 7.1.
type Exact interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Checker evaluates V8 against a compact set, and implements the
// RevocationChecker interface the chain verifier depends on.
type Checker struct {
	set    *Set
	exact  Exact
	maxAge time.Duration
	now    func() time.Time
}

// Option configures a Checker.
type Option func(*Checker)

// WithExact supplies the authoritative lookup used to resolve a filter hit.
// Without one, a hit denies, which is correct but costs the false-positive
// rate in refused calls.
func WithExact(e Exact) Option {
	return func(c *Checker) { c.exact = e }
}

// WithMaxAge sets how old a set may be before the Checker refuses to answer
// from it. Refusing is a denial: a verifier working from a revocation set of
// unknown age is not enforcing revocation, and should say so rather than
// quietly stop.
func WithMaxAge(d time.Duration) Option {
	return func(c *Checker) { c.maxAge = d }
}

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(c *Checker) {
		if now != nil {
			c.now = now
		}
	}
}

// NewChecker returns a Checker reading from set.
func NewChecker(set *Set, opts ...Option) (*Checker, error) {
	if set == nil {
		return nil, errors.New("revoke: a checker needs a set; use an empty one to revoke nothing")
	}
	c := &Checker{set: set, maxAge: 24 * time.Hour, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// IsRevoked reports whether jti has been revoked.
func (c *Checker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return true, errors.New("revoke: an assertion with no jti cannot be revoked individually")
	}
	if c.maxAge > 0 {
		if age := c.now().Sub(c.set.generatedAt); age > c.maxAge {
			return true, fmt.Errorf("revoke: revocation set is %s old, older than the %s this deployment accepts",
				age.Round(time.Second), c.maxAge)
		}
	}

	if !c.set.MayContain(jti) {
		return false, nil
	}
	if c.exact == nil {
		// Section 7.1: a false positive denies rather than allows.
		return true, nil
	}
	return c.exact.IsRevoked(ctx, jti)
}

// Set returns the set this Checker reads from.
func (c *Checker) Set() *Set { return c.set }

// Replace swaps in a newly published set. It refuses a set that is older than
// the one held, by sequence, because accepting one reinstates everything
// revoked in between.
//
// It is not safe to call concurrently with IsRevoked; build a new Checker if
// a deployment needs that, or guard it.
func (c *Checker) Replace(next *Set) error {
	if next == nil {
		return errors.New("revoke: cannot replace a set with nothing")
	}
	if next.sequence < c.set.sequence {
		return fmt.Errorf("revoke: refusing set with sequence %d, holding %d", next.sequence, c.set.sequence)
	}
	if next.sequence == c.set.sequence && next.generatedAt.Before(c.set.generatedAt) {
		return fmt.Errorf("revoke: refusing an older set at the same sequence %d", next.sequence)
	}
	c.set = next
	return nil
}
