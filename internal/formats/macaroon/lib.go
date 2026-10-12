package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/nacl/secretbox"
	gomac "gopkg.in/macaroon.v2"
)

// The libmacaroons formats (binary v1 and v2, and their JSON). Decoding is
// go-macaroon's. Verification follows go-macaroon's verify0 step for step,
// but keeps going past a failure so the report can name the caveat or
// discharge that broke; its verdict is compared with go-macaroon's.

const (
	hashLen  = sha256.Size
	nonceLen = 24
)

// keyGen is the HMAC key that turns a root key of any length into the
// 32-byte key a macaroon's chain starts from. libmacaroons and go-macaroon
// share it.
var keyGen = []byte("macaroons-key-generator")

// lmac is one decoded macaroon.
type lmac struct {
	version  int
	location string
	id       []byte
	caveats  []lcav
	sig      [hashLen]byte
}

// lcav is one caveat: a first-party caveat has only an id (its
// predicate); a third-party caveat also has a verification id and the
// location of the service that discharges it.
type lcav struct {
	id  []byte
	vid []byte
	loc string
}

func (c lcav) thirdParty() bool { return len(c.vid) > 0 }

func fromGo(m *gomac.Macaroon) *lmac {
	out := &lmac{version: int(m.Version()), location: m.Location(), id: m.Id()}
	copy(out.sig[:], m.Signature())
	for _, c := range m.Caveats() {
		out.caveats = append(out.caveats, lcav{
			id:  append([]byte(nil), c.Id...),
			vid: append([]byte(nil), c.VerificationId...),
			loc: c.Location,
		})
	}
	return out
}

// toGo rebuilds the macaroon for go-macaroon, the reference the
// verification is compared with.
func (m *lmac) toGo() (*gomac.Macaroon, error) {
	data, err := m.encodeV2()
	if err != nil {
		return nil, err
	}
	var g gomac.Macaroon
	if err := g.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &g, nil
}

func keyedHash(key, text []byte) [hashLen]byte {
	h := hmac.New(sha256.New, key)
	h.Write(text)
	var sum [hashLen]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func keyedHash2(key, d1, d2 []byte) [hashLen]byte {
	a := keyedHash(key, d1)
	b := keyedHash(key, d2)
	return keyedHash(key, append(a[:], b[:]...))
}

// deriveKey turns a root key of any length into a chain's starting key.
func deriveKey(rootKey []byte) [hashLen]byte { return keyedHash(keyGen, rootKey) }

// bindForRequest binds a discharge's signature to the root macaroon it
// travels with, so a discharge cannot be lifted onto another token.
// go-macaroon returns the discharge's signature unchanged when it already
// equals the root's; libmacaroons always hashes. whosent follows
// go-macaroon, its reference; the two differ only for a discharge whose
// signature is the root's own.
func bindForRequest(rootSig, dischargeSig [hashLen]byte) [hashLen]byte {
	if rootSig == dischargeSig {
		return dischargeSig
	}
	var zero [hashLen]byte
	return keyedHash2(zero[:], rootSig[:], dischargeSig[:])
}

func decryptVID(key [hashLen]byte, vid []byte) ([hashLen]byte, error) {
	var out [hashLen]byte
	if len(vid) < nonceLen+secretbox.Overhead {
		return out, errors.New("the verification id is too short to hold a sealed key")
	}
	var nonce [nonceLen]byte
	copy(nonce[:], vid)
	k := key
	text, ok := secretbox.Open(nil, vid[nonceLen:], &nonce, &k)
	if !ok {
		return out, errors.New("the verification id does not open under this chain: a wrong root key, or the caveats before it changed")
	}
	if len(text) != hashLen {
		return out, fmt.Errorf("the sealed key is %d bytes, not %d", len(text), hashLen)
	}
	copy(out[:], text)
	return out, nil
}

func sealVID(key, plain [hashLen]byte, nonce [nonceLen]byte) []byte {
	k := key
	return secretbox.Seal(append([]byte(nil), nonce[:]...), plain[:], &nonce, &k)
}

// macResult is what verifying one macaroon established.
type macResult struct {
	// sigChecked is false when there was no key to check it with.
	sigChecked bool
	sigOK      bool
	sigDetail  string
	caveats    []cavResult
}

type cavResult struct {
	// For a third-party caveat: whether a discharge with its id was
	// presented, which one, and whether the verification id opened.
	discharge     int
	dischargeNote string
	keyChecked    bool
	keyOK         bool
	keyDetail     string
	cavKey        [hashLen]byte
}

// libVerify is the outcome of verifying a root macaroon and its
// discharges.
type libVerify struct {
	root       macResult
	discharges []macResult
	used       []bool
	// order is the discharges in the order the root's third-party
	// caveats reached them; parent[i] is the macaroon whose caveat
	// discharge i satisfies (-1 the root).
	reached []int
	twice   []string
	missing []string
	unused  []int
	ok      bool
}

// verifyLib checks a root macaroon and its discharges the way go-macaroon's
// Verify does, without stopping at the first problem: every macaroon whose
// key can be recovered is checked, so the report can point at the caveat or
// discharge that failed. rootKey nil checks only what needs no key: which
// discharges are present.
func verifyLib(root *lmac, discharges []*lmac, rootKey []byte) libVerify {
	v := libVerify{
		discharges: make([]macResult, len(discharges)),
		used:       make([]bool, len(discharges)),
	}
	var walk func(m *lmac, idx int, key *[hashLen]byte, depth int) macResult
	walk = func(m *lmac, idx int, key *[hashLen]byte, depth int) macResult {
		r := macResult{caveats: make([]cavResult, len(m.caveats))}
		var sig [hashLen]byte
		if key != nil {
			sig = keyedHash(key[:], m.id)
		}
		for i, c := range m.caveats {
			cr := cavResult{discharge: -1}
			if c.thirdParty() {
				if key != nil {
					k, err := decryptVID(sig, c.vid)
					cr.keyChecked = true
					if err != nil {
						cr.keyDetail = err.Error()
					} else {
						cr.keyOK, cr.cavKey = true, k
					}
				}
				// The first discharge with the caveat's id answers it, as in
				// go-macaroon's findDischarge: one already used is an error,
				// not a reason to look further.
				di := -1
				for j, d := range discharges {
					if !bytes.Equal(d.id, c.id) {
						continue
					}
					if v.used[j] {
						cr.dischargeNote = fmt.Sprintf("discharge %d has this caveat's id, but an earlier caveat already used it", j)
						v.twice = append(v.twice, label(c.id))
						break
					}
					di = j
					break
				}
				if di < 0 && cr.dischargeNote == "" {
					v.missing = append(v.missing, label(c.id))
				}
				cr.discharge = di
				if di >= 0 && depth < len(discharges) {
					v.used[di] = true
					v.reached = append(v.reached, di)
					var dk *[hashLen]byte
					if cr.keyOK {
						k := cr.cavKey
						dk = &k
					}
					v.discharges[di] = walk(discharges[di], di+1, dk, depth+1)
				}
				if key != nil {
					sig = keyedHash2(sig[:], c.vid, c.id)
				}
			} else if key != nil {
				sig = keyedHash(sig[:], c.id)
			}
			r.caveats[i] = cr
		}
		if key == nil {
			return r
		}
		if idx > 0 {
			sig = bindForRequest(root.sig, sig)
		}
		r.sigChecked = true
		r.sigOK = hmac.Equal(sig[:], m.sig[:])
		if !r.sigOK {
			if idx > 0 {
				r.sigDetail = "the discharge's signature does not match its caveats, bound to the root macaroon: it was changed, or it was issued for another token"
			} else {
				r.sigDetail = "the signature does not match the identifier and caveats under this root key: a caveat was changed, added or removed, or the key is not the one this macaroon was minted with; an HMAC chain cannot say which"
			}
		}
		return r
	}
	var key *[hashLen]byte
	if rootKey != nil {
		k := deriveKey(rootKey)
		key = &k
	}
	v.root = walk(root, 0, key, 0)
	for i, u := range v.used {
		if !u {
			v.unused = append(v.unused, i)
		}
	}
	v.ok = rootKey != nil && len(v.missing) == 0 && len(v.twice) == 0 && len(v.unused) == 0 && v.root.sigOK
	for _, i := range v.reached {
		if !v.discharges[i].sigOK {
			v.ok = false
		}
	}
	for _, c := range allCaveats(v) {
		if c.keyChecked && !c.keyOK {
			v.ok = false
		}
	}
	return v
}

func allCaveats(v libVerify) []cavResult {
	out := append([]cavResult(nil), v.root.caveats...)
	for _, i := range v.reached {
		out = append(out, v.discharges[i].caveats...)
	}
	return out
}

// referenceVerify is go-macaroon's own verdict on the signatures and
// discharges, the reference whosent's verification must agree with.
func referenceVerify(root *lmac, discharges []*lmac, rootKey []byte) error {
	g, err := root.toGo()
	if err != nil {
		return fmt.Errorf("the reference could not read the root macaroon: %w", err)
	}
	var ds []*gomac.Macaroon
	for i, d := range discharges {
		gd, err := d.toGo()
		if err != nil {
			return fmt.Errorf("the reference could not read discharge %d: %w", i, err)
		}
		ds = append(ds, gd)
	}
	_, err = g.VerifySignature(rootKey, ds)
	return err
}

// label is an identifier or caveat as text when it is text, and as hex
// when it is not.
func label(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return fmt.Sprintf("%x", b)
}

// encodeV2 writes the macaroon in the v2 binary format.
func (m *lmac) encodeV2() ([]byte, error) {
	if len(m.caveats) > maxCaveats {
		return nil, fmt.Errorf("%d caveats; whosent reads at most %d", len(m.caveats), maxCaveats)
	}
	data := []byte{2}
	if m.location != "" {
		data = appendPacket(data, fieldLocation, []byte(m.location))
	}
	data = appendPacket(data, fieldIdentifier, m.id)
	data = append(data, 0)
	for _, c := range m.caveats {
		if c.loc != "" {
			data = appendPacket(data, fieldLocation, []byte(c.loc))
		}
		data = appendPacket(data, fieldIdentifier, c.id)
		if len(c.vid) > 0 {
			data = appendPacket(data, fieldVerificationID, c.vid)
		}
		data = append(data, 0)
	}
	data = append(data, 0)
	return appendPacket(data, fieldSignature, m.sig[:]), nil
}

const (
	fieldLocation       = 1
	fieldIdentifier     = 2
	fieldVerificationID = 4
	fieldSignature      = 6
)

func appendPacket(data []byte, field int, payload []byte) []byte {
	data = binary.AppendUvarint(data, uint64(field))
	data = binary.AppendUvarint(data, uint64(len(payload)))
	return append(data, payload...)
}

// minter builds libmacaroons-format macaroons for the demos, with fixed
// nonces so a demo is the same bytes on every run.
type minter struct {
	m *lmac
}

func mintLib(rootKey []byte, id, location string) *minter {
	k := deriveKey(rootKey)
	m := &lmac{version: 2, location: location, id: []byte(id)}
	m.sig = keyedHash(k[:], m.id)
	return &minter{m: m}
}

// mintDischarge starts a discharge for a third-party caveat whose key the
// third party recovered.
func mintDischarge(cavKey [hashLen]byte, id, location string) *minter {
	m := &lmac{version: 2, location: location, id: []byte(id)}
	m.sig = keyedHash(cavKey[:], m.id)
	return &minter{m: m}
}

func (mt *minter) first(cond string) *minter {
	mt.m.caveats = append(mt.m.caveats, lcav{id: []byte(cond)})
	mt.m.sig = keyedHash(mt.m.sig[:], []byte(cond))
	return mt
}

// third adds a third-party caveat whose discharge root key is cavRootKey,
// and returns the derived key the third party will mint the discharge
// with.
func (mt *minter) third(cavRootKey []byte, id, location string, nonce byte) [hashLen]byte {
	k := deriveKey(cavRootKey)
	var n [nonceLen]byte
	for i := range n {
		n[i] = nonce
	}
	vid := sealVID(mt.m.sig, k, n)
	mt.m.caveats = append(mt.m.caveats, lcav{id: []byte(id), vid: vid, loc: location})
	mt.m.sig = keyedHash2(mt.m.sig[:], vid, []byte(id))
	return k
}

// bind binds a finished discharge to the root it travels with.
func (mt *minter) bind(root *lmac) *minter {
	mt.m.sig = bindForRequest(root.sig, mt.m.sig)
	return mt
}
