package jose

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const issuer = "https://idp.example.org"

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type claims struct {
	Sub string `json:"sub"`
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := keypair(t)
	ring := NewKeyRing()
	if err := ring.Add(issuer, "k1", pub); err != nil {
		t.Fatal(err)
	}

	raw, err := Sign(claims{Sub: "agent"}, priv, "k1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := ring.VerifySignature(context.Background(), issuer, raw); err != nil {
		t.Fatalf("a token this package signed did not verify: %v", err)
	}

	h, payload, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.Algorithm != Algorithm || h.Type != Type || h.KeyID != "k1" {
		t.Errorf("header = %+v", h)
	}
	if !strings.Contains(string(payload), `"sub":"agent"`) {
		t.Errorf("payload = %s", payload)
	}
}

// The point of restricting this package to one algorithm is that the classic
// JWS attacks have no code path to reach. Each case here confirms one of them
// is rejected before a signature is even considered.
func TestHeaderAttacksAreRejected(t *testing.T) {
	pub, priv := keypair(t)
	ring := NewKeyRing()
	if err := ring.Add(issuer, "k1", pub); err != nil {
		t.Fatal(err)
	}
	good, err := Sign(claims{Sub: "agent"}, priv, "k1")
	if err != nil {
		t.Fatal(err)
	}

	reheader := func(header string) []byte {
		parts := strings.Split(string(good), ".")
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(header))
		return []byte(strings.Join(parts, "."))
	}

	tests := []struct {
		name  string
		token []byte
		want  string
	}{
		{"alg none", reheader(`{"alg":"none","typ":"mdt+jwt"}`), `alg "none" is not supported`},
		{"alg HS256, the key-confusion classic", reheader(`{"alg":"HS256","typ":"mdt+jwt"}`), "is not supported"},
		{"alg absent", reheader(`{"typ":"mdt+jwt"}`), `alg "" is not supported`},
		{"typ is a plain JWT", reheader(`{"alg":"EdDSA","typ":"JWT"}`), "is not a delegation assertion"},
		{"typ absent", reheader(`{"alg":"EdDSA"}`), "is not a delegation assertion"},
		{
			"crit demands an extension this verifier does not implement",
			reheader(`{"alg":"EdDSA","typ":"mdt+jwt","crit":["exp"]}`),
			"does not implement",
		},
		{
			"an unknown header parameter",
			reheader(`{"alg":"EdDSA","typ":"mdt+jwt","jwk":{"kty":"OKP"}}`),
			"unknown field",
		},
		{"not three parts", []byte("a.b"), "want 3"},
		{"four parts", []byte("a.b.c.d"), "want 3"},
		{"header is not base64url", []byte("!!!.b.c"), "decoding header"},
		{"header is not JSON", reheader(`not json`), "parsing header"},
		{"empty", []byte(""), "want 3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Parse(tt.token); err == nil {
				t.Fatal("Parse accepted it")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			if err := ring.VerifySignature(context.Background(), issuer, tt.token); err == nil {
				t.Fatal("VerifySignature accepted it")
			}
		})
	}
}

func TestSignatureMustMatch(t *testing.T) {
	pub, priv := keypair(t)
	otherPub, otherPriv := keypair(t)

	ring := NewKeyRing()
	if err := ring.Add(issuer, "k1", pub); err != nil {
		t.Fatal(err)
	}
	if err := ring.Add("https://other.example.org", "k1", otherPub); err != nil {
		t.Fatal(err)
	}

	raw, err := Sign(claims{Sub: "agent"}, priv, "k1")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a payload edited after signing", func(t *testing.T) {
		parts := strings.Split(string(raw), ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
		if err := ring.VerifySignature(context.Background(), issuer, []byte(strings.Join(parts, "."))); err == nil {
			t.Fatal("an edited payload verified")
		}
	})

	t.Run("the wrong issuer's key", func(t *testing.T) {
		err := ring.VerifySignature(context.Background(), "https://other.example.org", raw)
		if err == nil {
			t.Fatal("a token verified against another issuer's key")
		}
	})

	t.Run("a token signed by the wrong key", func(t *testing.T) {
		impostor, err := Sign(claims{Sub: "agent"}, otherPriv, "k1")
		if err != nil {
			t.Fatal(err)
		}
		if err := ring.VerifySignature(context.Background(), issuer, impostor); err == nil {
			t.Fatal("a token signed by a key the issuer does not hold verified")
		}
	})

	t.Run("an unregistered kid", func(t *testing.T) {
		other, err := Sign(claims{Sub: "agent"}, priv, "rotated")
		if err != nil {
			t.Fatal(err)
		}
		err = ring.VerifySignature(context.Background(), issuer, other)
		if !errors.Is(err, ErrUnknownKey) {
			t.Errorf("error = %v, want ErrUnknownKey so callers can tell configuration from forgery", err)
		}
	})

	t.Run("a signature that is not base64url", func(t *testing.T) {
		parts := strings.Split(string(raw), ".")
		parts[2] = "!!!"
		if err := ring.VerifySignature(context.Background(), issuer, []byte(strings.Join(parts, "."))); err == nil {
			t.Fatal("a malformed signature verified")
		}
	})
}

// Key rotation: adding a second key must not invalidate tokens signed with
// the first, and replacing a key under the same kid must take effect.
func TestKeyRotation(t *testing.T) {
	oldPub, oldPriv := keypair(t)
	newPub, newPriv := keypair(t)

	ring := NewKeyRing()
	if err := ring.Add(issuer, "2026-a", oldPub); err != nil {
		t.Fatal(err)
	}
	oldToken, err := Sign(claims{Sub: "agent"}, oldPriv, "2026-a")
	if err != nil {
		t.Fatal(err)
	}

	if err := ring.Add(issuer, "2026-b", newPub); err != nil {
		t.Fatal(err)
	}
	newToken, err := Sign(claims{Sub: "agent"}, newPriv, "2026-b")
	if err != nil {
		t.Fatal(err)
	}

	if err := ring.VerifySignature(context.Background(), issuer, oldToken); err != nil {
		t.Errorf("adding a key invalidated tokens signed with the previous one: %v", err)
	}
	if err := ring.VerifySignature(context.Background(), issuer, newToken); err != nil {
		t.Errorf("the newly added key does not verify its own tokens: %v", err)
	}

	// Retiring the old key must stop tokens signed with it.
	if err := ring.Add(issuer, "2026-a", newPub); err != nil {
		t.Fatal(err)
	}
	if err := ring.VerifySignature(context.Background(), issuer, oldToken); err == nil {
		t.Error("replacing a key under the same kid did not retire the old one")
	}
}

func TestKeyRingRejectsUnusableInput(t *testing.T) {
	pub, _ := keypair(t)
	ring := NewKeyRing()

	if err := ring.Add("", "k", pub); err == nil {
		t.Error("registered a key for an empty issuer")
	}
	if err := ring.Add(issuer, "k", ed25519.PublicKey("too short")); err == nil {
		t.Error("registered a key of the wrong size")
	}
	if _, err := Sign(claims{}, ed25519.PrivateKey("too short"), "k"); err == nil {
		t.Error("signed with a key of the wrong size")
	}
}

// The zero value must trust nothing rather than panic, since a caller that
// forgets NewKeyRing should get denials, not a crash on the enforcement path.
func TestZeroKeyRingTrustsNothing(t *testing.T) {
	_, priv := keypair(t)
	raw, err := Sign(claims{Sub: "agent"}, priv, "k1")
	if err != nil {
		t.Fatal(err)
	}

	var ring KeyRing
	if err := ring.VerifySignature(context.Background(), issuer, raw); err == nil {
		t.Fatal("a zero KeyRing accepted a token")
	}
}

func FuzzParse(f *testing.F) {
	_, priv := keypair(&testing.T{})
	if raw, err := Sign(claims{Sub: "agent"}, priv, "k1"); err == nil {
		f.Add(raw)
	}
	f.Add([]byte("a.b.c"))
	f.Add([]byte(""))
	f.Add([]byte("...."))

	// Parse runs on untrusted bytes at the enforcement point. It must
	// terminate and must never panic, whatever it is handed.
	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := Parse(data)
		if err != nil {
			return
		}
		// Anything Parse accepts must have passed the header checks; a
		// permissive parse would put the algorithm restriction back in doubt.
		if h.Algorithm != Algorithm {
			t.Fatalf("accepted alg %q", h.Algorithm)
		}
		if h.Type != Type {
			t.Fatalf("accepted typ %q", h.Type)
		}
		if len(h.Critical) > 0 {
			t.Fatalf("accepted crit %v", h.Critical)
		}
		_ = payload
	})
}
