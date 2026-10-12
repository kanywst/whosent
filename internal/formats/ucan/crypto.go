package ucan

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	k256ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// errUnsupported marks a signature whosent cannot check, as opposed to one
// that is wrong.
var errUnsupported = errors.New("unsupported")

// verifySig checks sig over payload with the issuer's key, as the varsig
// header says it was made. ECDSA signatures are r||s, 64 bytes.
func verifySig(h Varsig, key DIDKey, payload, sig []byte) error {
	if kt := h.keyType(); kt == KeyUnknown {
		return fmt.Errorf("%w: a varsig header for %s", errUnsupported, h)
	} else if kt != key.Type {
		return fmt.Errorf("the header says %s, the issuer's did:key is %s", kt, key.Type)
	}
	if h.Encoding != encDAGCBOR {
		return fmt.Errorf("%w: a payload signed as %s; only DAG-CBOR is checked here", errUnsupported, h)
	}
	switch key.Type {
	case KeyEd25519:
		if h.Hash != hashSHA2_512 {
			return fmt.Errorf("%w: Ed25519 with %s", errUnsupported, h)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(key.Key, payload, sig) {
			return errors.New("the signature does not verify")
		}
		return nil
	case KeyP256, KeySecp256k1:
		if h.Hash != hashSHA2_256 {
			return fmt.Errorf("%w: %s with %s", errUnsupported, key.Type, h)
		}
		if len(sig) != 64 {
			return fmt.Errorf("an ECDSA signature of %d bytes, want 64 (r||s)", len(sig))
		}
		digest := sha256.Sum256(payload)
		if key.Type == KeyP256 {
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key.Key)
			if x == nil {
				return errors.New("the issuer's P-256 key is not a point on the curve")
			}
			raw := make([]byte, 65)
			raw[0] = 4
			x.FillBytes(raw[1:33])
			y.FillBytes(raw[33:])
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
			if err != nil {
				return errors.New("the issuer's P-256 key is not a point on the curve")
			}
			r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
			if !ecdsa.Verify(pub, digest[:], r, s) {
				return errors.New("the signature does not verify")
			}
			return nil
		}
		pub, err := secp256k1.ParsePubKey(key.Key)
		if err != nil {
			return fmt.Errorf("the issuer's secp256k1 key: %w", err)
		}
		var r, s secp256k1.ModNScalar
		if r.SetByteSlice(sig[:32]) || s.SetByteSlice(sig[32:]) {
			return errors.New("the signature does not verify")
		}
		if !k256ecdsa.NewSignature(&r, &s).Verify(digest[:], pub) {
			return errors.New("the signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("%w: %s keys", errUnsupported, key.Type)
}

// signer mints demo tokens. Keys come from fixed seeds so a demo is the
// same bytes on every run.
type signer struct {
	DID  string
	Name string
	priv ed25519.PrivateKey
}

func newSigner(name string, seed byte) signer {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return signer{DID: didKeyString(KeyEd25519, priv.Public().(ed25519.PublicKey)), Name: name, priv: priv}
}

var edHeader = Varsig{Alg: algEdDSA, Curve: curveEd25519, Hash: hashSHA2_512, Encoding: encDAGCBOR}

func (s signer) sign(payload []byte) []byte { return ed25519.Sign(s.priv, payload) }
