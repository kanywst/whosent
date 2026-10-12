package ucan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	k256ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestEachRequiredAlgorithmVerifies(t *testing.T) {
	payload := []byte("the signed payload")
	digest := sha256.Sum256(payload)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, p256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	p256Sig := make([]byte, 64)
	r.FillBytes(p256Sig[:32])
	s.FillBytes(p256Sig[32:])
	p256Key := DIDKey{Type: KeyP256, Key: elliptic.MarshalCompressed(elliptic.P256(), p256.X, p256.Y)}
	p256Header := Varsig{Alg: algECDSA, Curve: curveP256, Hash: hashSHA2_256, Encoding: encDAGCBOR}

	k256, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := k256ecdsa.Sign(k256, digest[:])
	kr, kss := ks.R(), ks.S()
	k256Sig := make([]byte, 64)
	kr.PutBytesUnchecked(k256Sig[:32])
	kss.PutBytesUnchecked(k256Sig[32:])
	k256Key := DIDKey{Type: KeySecp256k1, Key: k256.PubKey().SerializeCompressed()}
	k256Header := Varsig{Alg: algECDSA, Curve: curveK256, Hash: hashSHA2_256, Encoding: encDAGCBOR}

	ed := newSigner("t", 0x01)
	edKey, _ := parseDIDKey(ed.DID)
	edSig := ed.sign(payload)

	flip := func(b []byte) []byte {
		c := append([]byte(nil), b...)
		c[len(c)-1] ^= 1
		return c
	}
	tests := []struct {
		name        string
		h           Varsig
		key         DIDKey
		sig         []byte
		ok          bool
		unsupported bool
	}{
		{"Ed25519", edHeader, edKey, edSig, true, false},
		{"Ed25519, tampered", edHeader, edKey, flip(edSig), false, false},
		{"P-256", p256Header, p256Key, p256Sig, true, false},
		{"P-256, tampered", p256Header, p256Key, flip(p256Sig), false, false},
		{"secp256k1", k256Header, k256Key, k256Sig, true, false},
		{"secp256k1, tampered", k256Header, k256Key, flip(k256Sig), false, false},
		{"a header that names another key type", p256Header, edKey, edSig, false, false},
		{"an ECDSA signature of the wrong length", p256Header, p256Key, p256Sig[:63], false, false},
		{"a DAG-JSON payload", Varsig{Alg: algEdDSA, Curve: curveEd25519, Hash: hashSHA2_512, Encoding: encDAGJSON}, edKey, edSig, false, true},
		{"an unknown curve", Varsig{Alg: algECDSA, Curve: 0x1201, Hash: hashSHA2_256, Encoding: encDAGCBOR}, p256Key, p256Sig, false, true},
	}
	for _, tt := range tests {
		err := verifySig(tt.h, tt.key, payload, tt.sig)
		if (err == nil) != tt.ok || errors.Is(err, errUnsupported) != tt.unsupported {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

func TestVarsigHeadersRoundTrip(t *testing.T) {
	h, err := parseVarsig([]byte{0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71})
	if err != nil || h != edHeader {
		t.Fatalf("the spec's Ed25519 header decodes as %+v, %v", h, err)
	}
	for _, bad := range [][]byte{{}, {0x35, 0x01}, {0x34, 0x02}, {0x34, 0x01, 0xed, 0x01}, append(edHeader.encode(), 0x00)} {
		if _, err := parseVarsig(bad); err == nil {
			t.Errorf("% x parsed", bad)
		}
	}
}
