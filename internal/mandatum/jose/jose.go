// Package jose implements the minimum of JWS needed to sign and verify
// Mandatum Delegation Assertions.
//
// This is deliberately not a general JOSE library. It supports exactly one
// algorithm, EdDSA over Ed25519, and rejects everything else before looking
// at a signature. That closes off algorithm confusion by construction rather
// than by configuration: there is no HMAC code path for a token to steer a
// verifier into, and no "none" to accidentally permit.
//
// A general library would be the right choice for a system that must accept
// whatever an arbitrary issuer produces. Mandatum is not that system - the
// assertions it verifies are produced by its own issuers - so the narrower
// surface is worth more here than algorithm breadth. An adapter backed by a
// full JOSE implementation can be added later without changing the verifier,
// which depends only on the SignatureVerifier interface.
package jose

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Algorithm is the only `alg` value this package accepts.
const Algorithm = "EdDSA"

// Type is the `typ` header value for a Delegation Assertion. Tagging the
// media type stops an assertion being replayed as some other kind of JWT that
// happens to be verifiable with the same key.
const Type = "mdt+jwt"

// Header is the JOSE header of a Delegation Assertion.
type Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	// KeyID selects among an issuer's keys, so that an issuer can rotate
	// without a flag day.
	KeyID string `json:"kid,omitempty"`
	// Critical is parsed only so that it can be rejected. A verifier that
	// ignores `crit` is claiming to understand extensions it has never seen.
	Critical []string `json:"crit,omitempty"`
}

var b64 = base64.RawURLEncoding

// Sign returns the compact serialization of claims signed with key.
//
// The returned bytes are what the parent commitment is computed over, so a
// caller must keep them rather than re-serializing the claims later.
func Sign(claims any, key ed25519.PrivateKey, keyID string) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jose: private key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}

	header, err := json.Marshal(Header{Algorithm: Algorithm, Type: Type, KeyID: keyID})
	if err != nil {
		return nil, fmt.Errorf("jose: encoding header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("jose: encoding claims: %w", err)
	}

	signingInput := make([]byte, 0, b64.EncodedLen(len(header))+1+b64.EncodedLen(len(payload)))
	signingInput = b64.AppendEncode(signingInput, header)
	signingInput = append(signingInput, '.')
	signingInput = b64.AppendEncode(signingInput, payload)

	sig := ed25519.Sign(key, signingInput)

	out := append(signingInput, '.')
	return b64.AppendEncode(out, sig), nil
}

// Parse splits a compact serialization and decodes its header and payload
// **without verifying the signature**.
//
// The name says "parse" rather than "decode" or "read" because the result is
// untrusted. Nothing in this package returns verified claims except Verify,
// and callers should treat anything Parse produces as attacker-controlled.
func Parse(compact []byte) (Header, []byte, error) {
	var h Header

	parts := strings.Split(string(compact), ".")
	if len(parts) != 3 {
		return h, nil, fmt.Errorf("jose: compact serialization has %d parts, want 3", len(parts))
	}

	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, nil, fmt.Errorf("jose: decoding header: %w", err)
	}
	// DisallowUnknownFields: an unrecognized header parameter may change how
	// the token should be interpreted, and this package cannot know that it
	// does not. Refusing is the only safe reading.
	dec := json.NewDecoder(strings.NewReader(string(rawHeader)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, fmt.Errorf("jose: parsing header: %w", err)
	}

	if err := h.check(); err != nil {
		return h, nil, err
	}

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, nil, fmt.Errorf("jose: decoding payload: %w", err)
	}
	return h, payload, nil
}

// ErrHeader marks a refusal that is about the JOSE header rather than the
// shape of the serialization: the algorithm, the media type, or a critical
// extension. A caller mapping errors onto the specification's rules needs the
// distinction, because those three are what rule V3 refuses and everything
// else Parse rejects is a structural fault under V1.
var ErrHeader = errors.New("jose: header")

func (h Header) check() error {
	if h.Algorithm != Algorithm {
		// Named explicitly so an operator debugging an integration sees what
		// was offered, and so "none" produces a message rather than silence.
		return fmt.Errorf("%w: alg %q is not supported; only %q is accepted", ErrHeader, h.Algorithm, Algorithm)
	}
	if h.Type != Type {
		return fmt.Errorf("%w: typ %q is not a delegation assertion; want %q", ErrHeader, h.Type, Type)
	}
	if len(h.Critical) > 0 {
		return fmt.Errorf("%w: crit requests extensions this verifier does not implement: %v", ErrHeader, h.Critical)
	}
	return nil
}

// ErrUnknownKey is returned when no key is registered for an issuer and key
// identifier. It is distinguished so a caller can tell a missing key from a
// bad signature: the first is usually a configuration problem, the second is
// not.
var ErrUnknownKey = errors.New("jose: no key for this issuer and kid")

// KeyRing resolves verification keys by issuer and key identifier, and
// implements the SignatureVerifier interface the chain verifier depends on.
//
// The zero value is usable and trusts nothing.
type KeyRing struct {
	keys map[string]ed25519.PublicKey
}

// NewKeyRing returns an empty KeyRing.
func NewKeyRing() *KeyRing { return &KeyRing{keys: map[string]ed25519.PublicKey{}} }

// Add registers a public key for an issuer.
//
// An empty keyID registers the issuer's default key, used when an assertion
// carries no `kid`. Adding the same issuer and keyID twice replaces the key,
// which is how rotation is expressed.
func (r *KeyRing) Add(issuer, keyID string, key ed25519.PublicKey) error {
	if issuer == "" {
		return errors.New("jose: issuer is required")
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("jose: public key for %q is %d bytes, want %d", issuer, len(key), ed25519.PublicKeySize)
	}
	if r.keys == nil {
		r.keys = map[string]ed25519.PublicKey{}
	}
	r.keys[issuer+"\x00"+keyID] = key
	return nil
}

// VerifySignature checks that issuer signed compact.
//
// It resolves the key from the issuer the *chain* asserts, not from anything
// inside the token. A token that could nominate its own verification key
// would verify against a key its holder generated.
func (r *KeyRing) VerifySignature(_ context.Context, issuer string, compact []byte) error {
	h, _, err := Parse(compact)
	if err != nil {
		return err
	}

	key, ok := r.keys[issuer+"\x00"+h.KeyID]
	if !ok {
		return fmt.Errorf("%w: issuer %q, kid %q", ErrUnknownKey, issuer, h.KeyID)
	}

	// Re-derive the signing input from the received bytes rather than from
	// the parsed values, so that a re-encoding cannot change what was signed.
	parts := strings.Split(string(compact), ".")
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("jose: decoding signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	if !ed25519.Verify(key, signingInput, sig) {
		return errors.New("jose: signature does not verify")
	}
	return nil
}
