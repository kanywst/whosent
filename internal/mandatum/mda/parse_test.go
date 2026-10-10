package mda_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
)

func key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func claims() mda.Claims {
	return mda.Claims{
		Issuer:    "https://idp.example.org",
		Subject:   "spiffe://example.org/agent",
		Audience:  "https://mcp.example.org",
		IssuedAt:  1789200000,
		ExpiresAt: 1789203600,
		ID:        "01JB2X9K7P4Q8R3N6M0V5T2Y7C",
		Mandatum: mda.Mandatum{
			Version:  mda.Version,
			Root:     mda.Sponsor{Issuer: "https://idp.example.org", Subject: "u-1", AuthenticatedAt: 1789199400},
			MaxDepth: 1,
			Capabilities: []mda.Capability{{
				Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "search.query"},
				Action:   mda.ActionPattern{Name: "invoke"},
			}},
		},
	}
}

// signedWith serializes an arbitrary payload as a delegation assertion, so a
// test can put something on the wire that the Go types would not produce.
func signedWith(t *testing.T, payload any) []byte {
	t.Helper()
	raw, err := jose.Sign(payload, key(t), "k1")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseClaimsReadsWhatWasSigned(t *testing.T) {
	want := claims()
	got, err := mda.ParseClaims(signedWith(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Audience != want.Audience ||
		len(got.Mandatum.Capabilities) != 1 ||
		got.Mandatum.Capabilities[0].Resource.ID != "search.query" {
		t.Errorf("claims did not survive the round trip: %+v", got)
	}
}

// An unknown claim may be one a newer issuer expects to be honoured, so
// dropping it silently would mean enforcing weaker terms than were granted.
func TestParseClaimsRefusesAnUnknownClaim(t *testing.T) {
	var generic map[string]any
	b, err := json.Marshal(claims())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	generic["mdt_extra_terms"] = "honour me"

	_, err = mda.ParseClaims(signedWith(t, generic))
	if err == nil {
		t.Fatal("accepted an assertion carrying a claim this version does not understand")
	}
}

// Trailing data after the claims object is how one payload gets read two ways
// by two implementations.
func TestParseClaimsRefusesTrailingData(t *testing.T) {
	b, err := json.Marshal(claims())
	if err != nil {
		t.Fatal(err)
	}
	doubled := append(append([]byte{}, b...), b...)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"mdt+jwt","kid":"k1"}`))
	raw := []byte(header + "." + base64.RawURLEncoding.EncodeToString(doubled) + ".AAAA")

	if _, err := mda.ParseClaims(raw); err == nil {
		t.Fatal("accepted a payload with a second claims object after the first")
	}
}

func TestParseClaimsRefusesAMalformedSerialization(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":            "",
		"two parts":        "a.b",
		"four parts":       "a.b.c.d",
		"header not b64":   "!!!.e30.AAAA",
		"payload not json": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"mdt+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`not json`)) + ".AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mda.ParseClaims([]byte(raw)); err == nil {
				t.Fatal("accepted a serialization that should have been refused")
			}
		})
	}
}

// The algorithm and media type are refused with a sentinel, because a
// verifier maps those onto rule V3 and everything else onto V1.
func TestAHeaderFaultIsDistinguishable(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"mdt+jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	_, err := mda.ParseClaims([]byte(header + "." + payload + "."))
	if err == nil {
		t.Fatal("accepted alg none")
	}
	if !strings.Contains(err.Error(), "alg") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

func TestParseChainReportsWhichLinkFailed(t *testing.T) {
	good := signedWith(t, claims())
	chain, err := mda.ParseChain([][]byte{good, good})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("parsed %d links, want 2", len(chain))
	}
	if string(chain[0].Raw) != string(good) {
		t.Error("the parsed assertion does not carry the bytes it was parsed from")
	}

	_, err = mda.ParseChain([][]byte{good, []byte("nonsense")})
	if err == nil {
		t.Fatal("accepted a chain with an unparsable link")
	}
	if !strings.Contains(err.Error(), "link 1") {
		t.Errorf("error does not say which link failed: %v", err)
	}
}

func TestParseAssertionCarriesTheBytes(t *testing.T) {
	raw := signedWith(t, claims())
	a, err := mda.ParseAssertion(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Raw) != string(raw) {
		t.Error("ParseAssertion did not keep the serialization it was given")
	}
	if a.Claims.ID != claims().ID {
		t.Error("ParseAssertion did not decode the claims")
	}
	if _, err := mda.ParseAssertion([]byte("nope")); err == nil {
		t.Fatal("accepted a malformed assertion")
	}
}
