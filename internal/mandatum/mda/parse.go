package mda

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/kanywst/whosent/internal/mandatum/jose"
)

// ParseClaims decodes the claims of one link from its compact serialization,
// without verifying the signature.
//
// This is the only safe way to obtain the claims a verifier should act on.
// An Assertion carries a Claims field for convenience, and a caller can put
// anything in it; the bytes are what an issuer signed. Verification derives
// claims from Raw for exactly that reason.
func ParseClaims(raw []byte) (Claims, error) {
	_, payload, err := jose.Parse(raw)
	if err != nil {
		return Claims{}, err
	}
	var claims Claims
	if err := unmarshalStrict(payload, &claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// ParseAssertion decodes one link from its compact serialization.
//
// The claims it returns are unverified. Pass the assertion to verify.Verify,
// as part of its chain, before relying on anything in it.
func ParseAssertion(raw []byte) (Assertion, error) {
	claims, err := ParseClaims(raw)
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{Raw: raw, Claims: claims}, nil
}

// ParseChain decodes a chain from its wire form: the compact serializations
// in order, sponsor first.
//
// The claims it returns are unverified. Pass the result to verify.Verify
// before relying on anything in it.
func ParseChain(serializations [][]byte) (Chain, error) {
	chain := make(Chain, 0, len(serializations))
	for i, raw := range serializations {
		a, err := ParseAssertion(raw)
		if err != nil {
			return nil, fmt.Errorf("mda: link %d: %w", i, err)
		}
		chain = append(chain, a)
	}
	return chain, nil
}

// unmarshalStrict decodes JSON and refuses unknown fields and trailing data.
//
// Both refusals matter for an assertion. An unknown claim may be one a newer
// issuer expects to be honoured, and silently dropping it would mean
// enforcing weaker terms than were granted. Trailing data after the JSON
// object is how one payload gets read two ways by two implementations.
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decoding claims: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("decoding claims: trailing data after the claims object")
	}
	return nil
}
