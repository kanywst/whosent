package biscuit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
)

// Key is a public key a block is signed or verified with.
type Key struct {
	datalog.PublicKey
	ed ed25519.PublicKey
	ec *ecdsa.PublicKey
	// Uncompressed is set for a P-256 key sent as an uncompressed point:
	// the reference accepts it, though the specification allows only the
	// compressed form.
	Uncompressed bool
}

// keyError is a key the reference cannot parse.
type keyError struct{ msg string }

func (e *keyError) Error() string { return e.msg }

// ParseKey reads a key as the reference does: an Ed25519 key is 32 bytes
// encoding a point on the curve; a P-256 key is a SEC1 point, compressed or
// not.
func ParseKey(pk datalog.PublicKey) (Key, error) {
	k := Key{PublicKey: pk}
	switch pk.Alg {
	case datalog.Ed25519:
		if len(pk.Key) != ed25519.PublicKeySize {
			return k, &keyError{fmt.Sprintf("an Ed25519 key is 32 bytes, this one is %d", len(pk.Key))}
		}
		if _, err := new(edwards25519.Point).SetBytes(pk.Key); err != nil {
			return k, &keyError{"the Ed25519 key is not a point on the curve"}
		}
		k.ed = ed25519.PublicKey(append([]byte(nil), pk.Key...))
		return k, nil
	case datalog.Secp256r1:
		var raw []byte
		switch {
		case len(pk.Key) == 33 && (pk.Key[0] == 2 || pk.Key[0] == 3):
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pk.Key)
			if x == nil {
				return k, &keyError{"the P-256 key is not a point on the curve"}
			}
			raw = make([]byte, 65)
			raw[0] = 4
			x.FillBytes(raw[1:33])
			y.FillBytes(raw[33:])
		case len(pk.Key) == 65 && pk.Key[0] == 4:
			raw = pk.Key
			k.Uncompressed = true
		default:
			return k, &keyError{"the P-256 key is not a SEC1 point"}
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if err != nil {
			return k, &keyError{"the P-256 key is not a point on the curve"}
		}
		k.ec = pub
		return k, nil
	}
	return k, &keyError{"unknown key algorithm"}
}

// sigFormatError is a signature whose bytes cannot be a signature at all,
// which the reference reports apart from one that does not verify.
type sigFormatError struct{ msg string }

func (e *sigFormatError) Error() string { return e.msg }

var errBadSignature = errors.New("the signature does not verify")

// Verify checks a signature over data. Ed25519 is verified strictly, as the
// reference's verify_strict does: a signature or key whose point has small
// order is refused even where plain RFC 8032 verification would accept it.
func (k Key) Verify(data, sig []byte) error {
	switch {
	case k.ed != nil:
		if len(sig) != ed25519.SignatureSize {
			return &sigFormatError{fmt.Sprintf("an Ed25519 signature is 64 bytes, this one is %d", len(sig))}
		}
		if smallOrder(k.ed) || smallOrder(sig[:32]) {
			return errBadSignature
		}
		if !ed25519.Verify(k.ed, data, sig) {
			return errBadSignature
		}
		return nil
	case k.ec != nil:
		if !validDER(sig) {
			return &sigFormatError{"the signature is not an ASN.1 DER ECDSA signature"}
		}
		h := sha256.Sum256(data)
		if !ecdsa.VerifyASN1(k.ec, h[:], sig) {
			return errBadSignature
		}
		return nil
	}
	return errBadSignature
}

// smallOrder reports whether an encoded point has small order, which
// verify_strict refuses. A point that does not decode is not small order;
// verification fails on it anyway.
func smallOrder(b []byte) bool {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return false
	}
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}

// validDER reports whether sig is a DER SEQUENCE of two positive INTEGERs,
// which is what the reference's from_der accepts before verifying.
func validDER(sig []byte) bool {
	if len(sig) < 8 || len(sig) > 72 || sig[0] != 0x30 || int(sig[1]) != len(sig)-2 {
		return false
	}
	rest := sig[2:]
	for i := 0; i < 2; i++ {
		if len(rest) < 2 || rest[0] != 0x02 {
			return false
		}
		n := int(rest[1])
		if n == 0 || n > 33 || len(rest) < 2+n {
			return false
		}
		v := rest[2 : 2+n]
		if v[0]&0x80 != 0 || (n > 1 && v[0] == 0 && v[1]&0x80 == 0) {
			return false
		}
		rest = rest[2+n:]
	}
	return len(rest) == 0
}

// Signer is a private key, for minting demo tokens.
type Signer struct {
	Pub Key
	ed  ed25519.PrivateKey
	ec  *ecdsa.PrivateKey
}

// SignerFromSeed derives an Ed25519 signer from 32 bytes.
func SignerFromSeed(seed []byte) Signer {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	k, _ := ParseKey(datalog.PublicKey{Alg: datalog.Ed25519, Key: pub})
	return Signer{Pub: k, ed: priv}
}

// P256SignerFromSeed derives a P-256 signer from 32 bytes, reduced into
// the curve's scalar range.
func P256SignerFromSeed(seed []byte) (Signer, error) {
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(seed)
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	raw := make([]byte, 32)
	d.FillBytes(raw)
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return Signer{}, err
	}
	unc, err := priv.PublicKey.Bytes()
	if err != nil {
		return Signer{}, err
	}
	comp := make([]byte, 33)
	comp[0] = 2 | (unc[64] & 1)
	copy(comp[1:], unc[1:33])
	k, err := ParseKey(datalog.PublicKey{Alg: datalog.Secp256r1, Key: comp})
	if err != nil {
		return Signer{}, err
	}
	return Signer{Pub: k, ec: priv}, nil
}

// Sign signs data deterministically, so minted demos are the same bytes on
// every run: Ed25519 always is, and P-256 uses RFC 6979.
func (s Signer) Sign(data []byte) ([]byte, error) {
	if s.ed != nil {
		return ed25519.Sign(s.ed, data), nil
	}
	h := sha256.Sum256(data)
	return s.ec.Sign(nil, h[:], crypto.SHA256)
}

// Secret is the private key as a token's proof carries it.
func (s Signer) Secret() ([]byte, error) {
	if s.ed != nil {
		return s.ed.Seed(), nil
	}
	return s.ec.Bytes()
}

// secretMatches reports whether a proof's next secret is the private half
// of key, as the reference checks an open token's last key.
func secretMatches(key Key, secret []byte) (bool, error) {
	switch key.Alg {
	case datalog.Ed25519:
		if len(secret) != ed25519.SeedSize {
			return false, fmt.Errorf("an Ed25519 secret is 32 bytes, this one is %d", len(secret))
		}
		pub := ed25519.NewKeyFromSeed(secret).Public().(ed25519.PublicKey)
		return string(pub) == string(key.Key), nil
	case datalog.Secp256r1:
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), secret)
		if err != nil {
			return false, fmt.Errorf("the P-256 secret is not a valid scalar")
		}
		unc, err := priv.PublicKey.Bytes()
		if err != nil {
			return false, err
		}
		if key.Uncompressed {
			return string(unc) == string(key.Key), nil
		}
		comp := append([]byte{2 | (unc[64] & 1)}, unc[1:33]...)
		return string(comp) == string(key.Key), nil
	}
	return false, errors.New("unknown key algorithm")
}

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func algBytes(a datalog.Algorithm) []byte { return le32(uint32(int32(a))) }

// The signed payloads, exactly as the reference builds them
// (crypto/mod.rs). The algorithm number comes before the key bytes, which
// is the order the reference and every other implementation use; the
// specification's prose lists them the other way round.

func payloadV0(data []byte, next datalog.PublicKey, external []byte) []byte {
	out := append([]byte(nil), data...)
	out = append(out, external...)
	out = append(out, algBytes(next.Alg)...)
	return append(out, next.Key...)
}

func payloadAuthorityV1(data []byte, next datalog.PublicKey, version uint32) []byte {
	out := []byte("\x00BLOCK\x00\x00VERSION\x00")
	out = append(out, le32(version)...)
	out = append(out, "\x00PAYLOAD\x00"...)
	out = append(out, data...)
	out = append(out, "\x00ALGORITHM\x00"...)
	out = append(out, algBytes(next.Alg)...)
	out = append(out, "\x00NEXTKEY\x00"...)
	return append(out, next.Key...)
}

func payloadBlockV1(data []byte, next datalog.PublicKey, external, prevSig []byte, version uint32) []byte {
	out := payloadAuthorityV1(data, next, version)
	out = append(out, "\x00PREVSIG\x00"...)
	out = append(out, prevSig...)
	if external != nil {
		out = append(out, "\x00EXTERNALSIG\x00"...)
		out = append(out, external...)
	}
	return out
}

func payloadExternalV1(data, prevSig []byte, version uint32) []byte {
	out := []byte("\x00EXTERNAL\x00\x00VERSION\x00")
	out = append(out, le32(version)...)
	out = append(out, "\x00PAYLOAD\x00"...)
	out = append(out, data...)
	out = append(out, "\x00PREVSIG\x00"...)
	return append(out, prevSig...)
}

func payloadSeal(data []byte, next datalog.PublicKey, sig []byte) []byte {
	out := append([]byte(nil), data...)
	out = append(out, algBytes(next.Alg)...)
	out = append(out, next.Key...)
	return append(out, sig...)
}
