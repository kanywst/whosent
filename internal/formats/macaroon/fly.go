package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	fly "github.com/superfly/macaroon"
	// The Fly.io caveat types register themselves when their package is
	// loaded; without it, a flyctl token's caveats decode as unregistered
	// numbers instead of Organization, Apps, Mutations and the rest.
	_ "github.com/superfly/macaroon/flyio"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/chacha20poly1305"
)

// Fly.io tokens (`FlyV1 fm2_...`): comma-joined MessagePack macaroons with
// typed caveats. Decoding and the reference verdict are superfly/macaroon's,
// the code Fly.io verifies with; whosent only reads with it. Verification is
// reproduced step for step so a failure can be located, and compared with
// the library's verdict.

// flyLabels are the token prefixes superfly/macaroon reads.
var flyLabels = []string{"fm2_", "fm1r_", "fm1a_"}

// looksFly reports whether text is a Fly.io token header.
func looksFly(text string) bool {
	t := strings.TrimSpace(text)
	t, _ = fly.StripAuthorizationScheme(t)
	for _, l := range flyLabels {
		if strings.HasPrefix(t, l) {
			return true
		}
	}
	return false
}

// flyToken is one decoded macaroon of a header.
type flyToken struct {
	raw []byte
	m   *fly.Macaroon
}

// flyBundle is a header split into its permission token and discharges.
type flyBundle struct {
	root       *flyToken
	discharges []*flyToken
	// others are further permission tokens: a header may carry one per
	// organization, and any of them can authorize a request.
	others []*flyToken
	// skipped counts tokens the header carried that are not macaroons
	// (fo1_ OAuth tokens), which superfly/macaroon passes over too.
	skipped int
}

func decodeFly(text string) (*flyBundle, error) {
	stripped, _ := fly.StripAuthorizationScheme(strings.TrimSpace(text))
	parts := strings.Split(stripped, ",")
	if len(parts) > maxMacaroons {
		return nil, fmt.Errorf("%d tokens; whosent reads at most %d", len(parts), maxMacaroons)
	}
	raws, err := fly.Parse(stripped)
	if err != nil {
		return nil, err
	}
	b := &flyBundle{skipped: len(parts) - len(raws)}
	var toks []*flyToken
	for i, r := range raws {
		m, err := fly.Decode(r)
		if err != nil {
			return nil, fmt.Errorf("token %d: %w", i, err)
		}
		if len(m.UnsafeCaveats.Caveats) > maxCaveats {
			return nil, fmt.Errorf("token %d has %d caveats; whosent reads at most %d", i, len(m.UnsafeCaveats.Caveats), maxCaveats)
		}
		toks = append(toks, &flyToken{raw: r, m: m})
	}
	// A discharge is minted with the ticket of the caveat it answers as its
	// key id, so a token whose key id is some token's ticket is a
	// discharge. The first token that is not one is the permission token.
	tickets := map[string]bool{}
	for _, t := range toks {
		for _, c := range t.m.UnsafeCaveats.Caveats {
			if c3, ok := c.(*fly.Caveat3P); ok {
				tickets[string(c3.Ticket)] = true
			}
		}
	}
	for _, t := range toks {
		switch {
		case tickets[string(t.m.Nonce.KID)]:
			b.discharges = append(b.discharges, t)
		case b.root == nil:
			b.root = t
		default:
			b.others = append(b.others, t)
		}
	}
	if b.root == nil {
		return nil, errors.New("the header holds only discharges: no permission token")
	}
	return b, nil
}

func flySign(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func flyDigest(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}

func flyUnseal(key, buf []byte) ([]byte, error) {
	const n = chacha20poly1305.NonceSize
	if len(buf) < n+1 {
		return nil, errors.New("too short to hold a sealed key")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, buf[:n], buf[n:], nil)
}

func flySeal(key, plain []byte, nonce byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nn := bytes.Repeat([]byte{nonce}, chacha20poly1305.NonceSize)
	return append(nn, aead.Seal(nil, nn, plain, nil)...)
}

func flyFinalize(tail []byte) []byte {
	return flySign([]byte("proof-signature-finalization"), tail)
}

// flyResult is what verifying one Fly macaroon established.
type flyResult struct {
	sigChecked bool
	sigOK      bool
	sigDetail  string
	caveats    []flyCavResult
	// bindings are the digests a discharge may bind to: one per step of
	// the chain.
	bindings [][]byte
}

type flyCavResult struct {
	discharge  int
	keyChecked bool
	keyOK      bool
	keyDetail  string
	key        []byte
	// bound is set for a BindToParentToken caveat: whether it names a
	// step of the parent's chain.
	boundChecked bool
	bound        bool
	attestation  string
}

type flyVerify struct {
	root       flyResult
	discharges []flyResult
	used       []bool
	missing    []string
	ok         bool
}

// verifyFly reproduces superfly/macaroon's verify without stopping at the
// first problem.
func verifyFly(b *flyBundle, key []byte) flyVerify {
	v := flyVerify{discharges: make([]flyResult, len(b.discharges)), used: make([]bool, len(b.discharges))}
	var walk func(t *flyToken, key []byte, parentBindings [][]byte, isDischarge bool) flyResult
	walk = func(t *flyToken, key []byte, parentBindings [][]byte, isDischarge bool) flyResult {
		m := t.m
		r := flyResult{caveats: make([]flyCavResult, len(m.UnsafeCaveats.Caveats))}
		var cur []byte
		if key != nil {
			cur = flySign(key, m.Nonce.MustEncode())
			r.bindings = append(r.bindings, flyDigest(cur))
		}
		type pending struct {
			cav int
			key []byte
		}
		var toVerify []pending
		for i, c := range m.UnsafeCaveats.Caveats {
			cr := flyCavResult{discharge: -1}
			switch cav := c.(type) {
			case *fly.Caveat3P:
				if !isDischarge {
					for j, d := range b.discharges {
						if bytes.Equal(d.m.Nonce.KID, cav.Ticket) {
							cr.discharge = j
							break
						}
					}
				}
				if cr.discharge < 0 {
					v.missing = append(v.missing, cav.Location)
				}
				if key != nil {
					cr.keyChecked = true
					k, err := flyUnseal(cur, cav.VerifierKey)
					if err != nil {
						cr.keyDetail = "the verifier key does not open under this chain: a wrong signing key, or the caveats before it changed"
					} else {
						cr.keyOK, cr.key = true, k
						if cr.discharge >= 0 {
							toVerify = append(toVerify, pending{i, k})
						}
					}
				}
			case *fly.BindToParentToken:
				if isDischarge && parentBindings != nil {
					cr.boundChecked = true
					for _, bid := range parentBindings {
						if bytes.HasPrefix(bid, *cav) {
							cr.bound = true
							break
						}
					}
				}
			default:
				if fly.IsAttestation(c) && !m.Nonce.Proof {
					cr.attestation = "an attestation in a macaroon that is not a proof"
				}
			}
			if key != nil {
				opc, err := fly.NewCaveatSet(c).MarshalMsgpack()
				if err == nil {
					cur = flySign(cur, opc)
					r.bindings = append(r.bindings, flyDigest(cur))
				}
			}
			r.caveats[i] = cr
		}
		for _, p := range toVerify {
			j := r.caveats[p.cav].discharge
			v.used[j] = true
			v.discharges[j] = walk(b.discharges[j], p.key, r.bindings, true)
		}
		if key == nil {
			return r
		}
		if m.Nonce.Proof {
			cur = flyFinalize(cur)
		}
		r.sigChecked = true
		r.sigOK = hmac.Equal(cur, m.Tail)
		if !r.sigOK {
			r.sigDetail = "the signature does not match the nonce and caveats under this key: a caveat was changed, added or removed, or the key is not the one it was minted with"
		}
		return r
	}
	v.root = walk(b.root, key, nil, false)
	v.ok = key != nil && v.root.sigOK && len(v.missing) == 0
	check := func(r flyResult) {
		for _, c := range r.caveats {
			if (c.keyChecked && !c.keyOK) || (c.boundChecked && !c.bound) || c.attestation != "" {
				v.ok = false
			}
		}
	}
	check(v.root)
	for i, d := range v.discharges {
		if !v.used[i] {
			continue
		}
		if !d.sigOK {
			v.ok = false
		}
		check(d)
	}
	return v
}

// flyReference is superfly/macaroon's own verdict.
func flyReference(b *flyBundle, key []byte) error {
	var ds [][]byte
	for _, d := range b.discharges {
		ds = append(ds, d.raw)
	}
	_, err := b.root.m.Verify(fly.SigningKey(key), ds, nil)
	return err
}

// flyMinter builds Fly-format macaroons for the demos with fixed nonces,
// so a demo is the same bytes on every run. It follows superfly/macaroon's
// New, Add and DischargeTicket; the tests verify what it mints with the
// library.
type flyMinter struct {
	m   *fly.Macaroon
	key []byte
}

func flyNonce(kid, rnd []byte, proof bool) fly.Nonce {
	fields := []any{kid, rnd}
	if proof {
		fields = append(fields, true)
	}
	raw, err := msgpack.Marshal(fields)
	if err != nil {
		panic(err)
	}
	var n fly.Nonce
	if err := msgpack.Unmarshal(raw, &n); err != nil {
		panic(err)
	}
	return n
}

func mintFly(key, kid []byte, location string, rnd byte, proof bool) *flyMinter {
	n := flyNonce(kid, bytes.Repeat([]byte{rnd}, 16), proof)
	m := &fly.Macaroon{Location: location, Nonce: n, UnsafeCaveats: *fly.NewCaveatSet()}
	m.Tail = flySign(key, n.MustEncode())
	return &flyMinter{m: m, key: key}
}

func (f *flyMinter) add(c fly.Caveat) *flyMinter {
	f.m.UnsafeCaveats.Caveats = append(f.m.UnsafeCaveats.Caveats, c)
	opc, err := fly.NewCaveatSet(c).MarshalMsgpack()
	if err != nil {
		panic(err)
	}
	f.m.Tail = flySign(f.m.Tail, opc)
	return f
}

// third adds a third-party caveat for location and returns the ticket and
// the discharge key the third party will recover from it.
func (f *flyMinter) third(thirdKey []byte, location string, nonce byte) (ticket, dischargeKey []byte) {
	dischargeKey = bytes.Repeat([]byte{nonce ^ 0x5a}, 32)
	wire, err := msgpack.Marshal([]any{dischargeKey, fly.NewCaveatSet()})
	if err != nil {
		panic(err)
	}
	ticket = flySeal(thirdKey, wire, nonce)
	c := &fly.Caveat3P{Location: location, Ticket: ticket, VerifierKey: flySeal(f.m.Tail, dischargeKey, nonce+1)}
	f.add(c)
	return ticket, dischargeKey
}

// bind binds a discharge to its permission token, as
// BindToParentMacaroon does.
func (f *flyMinter) bind(parent *fly.Macaroon) *flyMinter {
	b := fly.BindToParentToken(flyDigest(parent.Tail)[:16])
	return f.add(&b)
}

func (f *flyMinter) encode() []byte {
	m := *f.m
	if m.Nonce.Proof {
		m.Tail = flyFinalize(m.Tail)
	}
	raw, err := m.Encode()
	if err != nil {
		panic(err)
	}
	return raw
}

func flyHeader(toks ...[]byte) string {
	var parts []string
	for _, t := range toks {
		parts = append(parts, "fm2_"+base64.StdEncoding.EncodeToString(t))
	}
	return fly.AuthorizationSchemeFlyV1 + " " + strings.Join(parts, ",")
}
