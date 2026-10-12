package ucan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Content identifiers. A UCAN is named by a CIDv1 of its DAG-CBOR bytes
// with a SHA-256 multihash (ucan-wg/spec "Content Identifiers"); an
// invocation's prf lists its proofs by these.

const (
	cidVersion1  = 0x01
	codecDAGCBOR = 0x71
	hashSHA256   = 0x12
)

// cidOf is the CID a token's bytes are named by.
func cidOf(token []byte) []byte {
	sum := sha256.Sum256(token)
	return append([]byte{cidVersion1, codecDAGCBOR, hashSHA256, 32}, sum[:]...)
}

var base32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// cidText is the CID in base58btc, the multibase the specification
// requires ("zdpu..."). The base32 form other tools print is cidBase32.
func cidText(c []byte) string { return "z" + base58Encode(c) }

// cidBase32 is the "bafy..." form go-ucan and the spec's fixtures print.
func cidBase32(c []byte) string { return "b" + base32Lower.EncodeToString(c) }

// parseCIDText reads a CID written in base58btc ("z...") or base32
// ("b..."), the two forms a revocation list is likely to hold.
func parseCIDText(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "z"):
		return base58Decode(s[1:])
	case strings.HasPrefix(s, "b"):
		return base32Lower.DecodeString(s[1:])
	}
	return nil, errors.New("a CID is base58btc (z...) or base32 (b...)")
}

// shortCID is a CID short enough for a label.
func shortCID(c []byte) string {
	s := cidText(c)
	if len(s) > 14 {
		return s[:8] + "..." + s[len(s)-4:]
	}
	return s
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index = func() [256]int {
	var idx [256]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(base58Alphabet); i++ {
		idx[base58Alphabet[i]] = i
	}
	return idx
}()

func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// maxBase58 bounds what base58Decode accepts. A DID or a CID is well under
// a hundred characters; big.Int arithmetic on a megabyte of digits is
// quadratic.
const maxBase58 = 512

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base58")
	}
	if len(s) > maxBase58 {
		return nil, errors.New("base58 text too long")
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		d := base58Index[s[i]]
		if d < 0 {
			return nil, fmt.Errorf("%q is not a base58 character", s[i])
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	return append(bytes.Repeat([]byte{0}, zeros), n.Bytes()...), nil
}

// KeyType is the algorithm a did:key names.
type KeyType int

// The key types. The specification's cryptosuite requires the first three;
// the others are recognised so that a token signed with one is reported as
// unsupported here rather than malformed.
const (
	KeyUnknown KeyType = iota
	KeyEd25519
	KeyP256
	KeySecp256k1
	KeyP384
	KeyP521
	KeyRSA
)

func (k KeyType) String() string {
	return [...]string{"unknown", "Ed25519", "P-256", "secp256k1", "P-384", "P-521", "RSA"}[k]
}

// Multicodec codes of public keys in a did:key.
var keyCodecs = map[uint64]KeyType{
	0xed:   KeyEd25519,
	0x1200: KeyP256,
	0xe7:   KeySecp256k1,
	0x1201: KeyP384,
	0x1202: KeyP521,
	0x1205: KeyRSA,
}

// DIDKey is a decoded did:key.
type DIDKey struct {
	Type KeyType
	Key  []byte
}

// errNotDIDKey marks a DID of another method. Resolving it would need the
// network, which whosent never uses on a token's say-so.
var errNotDIDKey = errors.New("not a did:key")

// principal is a DID without its fragment: alignment compares principals,
// and a fragment only says which of a DID's keys signed (delegation spec,
// "Principal Alignment").
func principal(did string) string {
	if i := strings.IndexByte(did, '#'); i >= 0 {
		return did[:i]
	}
	return did
}

// parseDIDKey decodes a did:key into its key.
func parseDIDKey(did string) (DIDKey, error) {
	did = principal(did)
	rest, ok := strings.CutPrefix(did, "did:key:")
	if !ok {
		if strings.HasPrefix(did, "did:") {
			return DIDKey{}, errNotDIDKey
		}
		return DIDKey{}, fmt.Errorf("%q is not a DID", did)
	}
	if !strings.HasPrefix(rest, "z") {
		return DIDKey{}, errors.New("a did:key is base58btc (z...)")
	}
	raw, err := base58Decode(rest[1:])
	if err != nil {
		return DIDKey{}, err
	}
	code, n := binary.Uvarint(raw)
	if n <= 0 {
		return DIDKey{}, errors.New("a did:key without a multicodec prefix")
	}
	kt, ok := keyCodecs[code]
	if !ok {
		return DIDKey{}, fmt.Errorf("a did:key with unknown key codec 0x%x", code)
	}
	key := raw[n:]
	switch kt {
	case KeyEd25519:
		if len(key) != 32 {
			return DIDKey{}, fmt.Errorf("an Ed25519 did:key of %d bytes", len(key))
		}
	case KeyP256, KeySecp256k1:
		if len(key) != 33 || (key[0] != 2 && key[0] != 3) {
			return DIDKey{}, fmt.Errorf("a %s did:key that is not a 33-byte compressed point", kt)
		}
	}
	return DIDKey{Type: kt, Key: key}, nil
}

// didKeyString writes a did:key for a public key.
func didKeyString(kt KeyType, key []byte) string {
	var code uint64
	for c, t := range keyCodecs {
		if t == kt {
			code = c
		}
	}
	return "did:key:z" + base58Encode(append(binary.AppendUvarint(nil, code), key...))
}

// shortDID is a DID short enough for the rail: the method, and the first
// and last characters of the key.
func shortDID(did string) string {
	if rest, ok := strings.CutPrefix(did, "did:key:"); ok && len(rest) > 16 {
		return "did:key:" + rest[:8] + "..." + rest[len(rest)-4:]
	}
	if len(did) > 32 {
		return did[:28] + "..."
	}
	return did
}

// Varsig is a decoded varsig v1 header: how a signature was made.
type Varsig struct {
	Alg      uint64 // 0xed EdDSA, 0xec ECDSA
	Curve    uint64
	Hash     uint64
	Encoding uint64 // 0x71 DAG-CBOR, 0x0129 DAG-JSON
}

const (
	varsigPrefix  = 0x34
	varsigVersion = 0x01
	algEdDSA      = 0xed
	algECDSA      = 0xec
	curveEd25519  = 0xed
	curveP256     = 0x1200
	curveK256     = 0xe7
	hashSHA2_256  = 0x12
	hashSHA2_512  = 0x13
	encDAGCBOR    = 0x71
	encDAGJSON    = 0x0129
)

// parseVarsig reads a varsig v1 header.
func parseVarsig(b []byte) (Varsig, error) {
	r := bytes.NewReader(b)
	read := func(what string) (uint64, error) {
		v, err := binary.ReadUvarint(r)
		if err != nil {
			return 0, fmt.Errorf("varsig: no %s", what)
		}
		return v, nil
	}
	p, err := read("prefix")
	if err != nil {
		return Varsig{}, err
	}
	if p != varsigPrefix {
		return Varsig{}, fmt.Errorf("varsig: prefix 0x%x, want 0x34", p)
	}
	v, err := read("version")
	if err != nil {
		return Varsig{}, err
	}
	if v != varsigVersion {
		return Varsig{}, fmt.Errorf("varsig: version %d, want 1", v)
	}
	var h Varsig
	for _, f := range []struct {
		what string
		to   *uint64
	}{{"algorithm", &h.Alg}, {"curve", &h.Curve}, {"hash", &h.Hash}, {"payload encoding", &h.Encoding}} {
		if *f.to, err = read(f.what); err != nil {
			return Varsig{}, err
		}
	}
	if r.Len() != 0 {
		return Varsig{}, fmt.Errorf("varsig: %d bytes after the header", r.Len())
	}
	return h, nil
}

func (h Varsig) encode() []byte {
	b := binary.AppendUvarint(nil, varsigPrefix)
	for _, v := range []uint64{varsigVersion, h.Alg, h.Curve, h.Hash, h.Encoding} {
		b = binary.AppendUvarint(b, v)
	}
	return b
}

// keyType is the key a header's algorithm and curve name, or KeyUnknown.
func (h Varsig) keyType() KeyType {
	switch {
	case h.Alg == algEdDSA && h.Curve == curveEd25519:
		return KeyEd25519
	case h.Alg == algECDSA && h.Curve == curveP256:
		return KeyP256
	case h.Alg == algECDSA && h.Curve == curveK256:
		return KeySecp256k1
	}
	return KeyUnknown
}

// String names a header the way a person reads it.
func (h Varsig) String() string {
	alg := map[uint64]string{algEdDSA: "EdDSA", algECDSA: "ECDSA"}[h.Alg]
	if alg == "" {
		alg = fmt.Sprintf("alg 0x%x", h.Alg)
	}
	curve := map[uint64]string{curveEd25519: "Ed25519", curveP256: "P-256", curveK256: "secp256k1"}[h.Curve]
	if curve == "" {
		curve = fmt.Sprintf("curve 0x%x", h.Curve)
	}
	hash := map[uint64]string{hashSHA2_256: "SHA-256", hashSHA2_512: "SHA-512"}[h.Hash]
	if hash == "" {
		hash = fmt.Sprintf("hash 0x%x", h.Hash)
	}
	enc := map[uint64]string{encDAGCBOR: "DAG-CBOR", encDAGJSON: "DAG-JSON"}[h.Encoding]
	if enc == "" {
		enc = fmt.Sprintf("encoding 0x%x", h.Encoding)
	}
	return alg + " " + curve + ", " + hash + ", " + enc
}
