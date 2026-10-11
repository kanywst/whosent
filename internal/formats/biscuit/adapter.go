// Package biscuit reads Biscuit authorization tokens (eclipse-biscuit):
// a root key's grant in an authority block, narrowed by later blocks that
// can only add checks, each block signed by a key the block before it
// handed on.
//
// Everything is checked here, without the reference implementation: the
// protobuf decoding, both signature payload versions, third-party
// signatures, the proof, the symbol tables, and the Datalog itself, which
// package datalog evaluates. The specification's sample tokens, whose
// expected results the reference produced, are the test that keeps the two
// in agreement.
package biscuit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/pkg/chain"
)

// ID is the format's name.
const ID = "biscuit"

// Adapter is the Biscuit format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

var format = chain.Format{
	ID:       ID,
	Name:     "Biscuit",
	RootRole: "root key",
	Rules:    rules,
	Caps:     chain.Capabilities{TimeScrub: true, RevokeSim: true, Ask: true, PerHopSignatures: true},
}

// Format describes Biscuit.
func (Adapter) Format() chain.Format { return format }

// Detect claims text that carries the "biscuit:" prefix, and text or bytes
// that decode as a Biscuit whose authority block holds Datalog. It never
// claims a JWT or JSON: neither is base64url-only text, and neither decodes
// as a Biscuit message.
func (Adapter) Detect(data []byte) chain.Confidence {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, Prefix) {
		return chain.Certain
	}
	if s, ok := looksLikeText(data); ok {
		raw, err := decodeText(s)
		if err == nil && looksLikeBiscuit(raw) {
			return chain.Certain
		}
		return chain.NotMine
	}
	if looksLikeBiscuit(data) {
		return chain.Certain
	}
	return chain.NotMine
}

// Open reads the token and what it is checked against.
func (Adapter) Open(_ context.Context, in chain.Inputs) (chain.Session, error) {
	tok, err := Decode(in.Data)
	if err != nil {
		return nil, err
	}
	opts, err := optionsFrom(in)
	if err != nil {
		return nil, err
	}
	return &Session{tok: tok, opts: opts, at: in.At, source: in.Source}, nil
}

func optionsFrom(in chain.Inputs) (Options, error) {
	o := Options{Limits: datalog.DefaultLimits}
	for _, v := range in.RootKeys {
		k, src, err := readRootKey(v)
		if err != nil {
			return o, err
		}
		o.RootKeys = append(o.RootKeys, k)
		o.RootSources = append(o.RootSources, src)
	}
	if in.RevokedIDs != "" {
		data, err := os.ReadFile(in.RevokedIDs)
		if err != nil {
			return o, fmt.Errorf("reading the revocation list: %w", err)
		}
		o.Revoked = map[string]bool{}
		for n, line := range strings.Split(string(data), "\n") {
			id := strings.ToLower(strings.TrimSpace(line))
			if id == "" || strings.HasPrefix(id, "#") {
				continue
			}
			if _, err := hex.DecodeString(id); err != nil {
				return o, fmt.Errorf("%s line %d: a Biscuit revocation id is hex, the signature of a block", in.RevokedIDs, n+1)
			}
			o.Revoked[id] = true
		}
		o.RevokedSource = filepath.Base(in.RevokedIDs)
	}
	var parts []string
	for _, f := range in.Facts {
		p, err := datalog.ParseProgram(f)
		if err != nil {
			return o, fmt.Errorf("--fact %q: %w", f, err)
		}
		if len(p.Rules)+len(p.Checks)+len(p.Policies) > 0 || len(p.Facts) == 0 {
			return o, fmt.Errorf("--fact %q is not a fact; put rules, checks and policies in an --authorizer file", f)
		}
		o.Program.Append(p)
		o.HasAuthorizer = true
	}
	if len(in.Facts) > 0 {
		parts = append(parts, fmt.Sprintf("%d fact(s) from --fact", len(in.Facts)))
	}
	if in.Authorizer != "" {
		data, err := os.ReadFile(in.Authorizer)
		if err != nil {
			return o, fmt.Errorf("reading the authorizer: %w", err)
		}
		p, err := datalog.ParseProgram(string(data))
		if err != nil {
			return o, fmt.Errorf("%s: %w", in.Authorizer, err)
		}
		o.Program.Append(p)
		o.HasAuthorizer = true
		parts = append(parts, filepath.Base(in.Authorizer))
	}
	o.AuthorizerSource = strings.Join(parts, " and ")
	o.Ignored = chain.IgnoredInputs(in, map[string]string{
		"trust":       "a Biscuit is rooted in a key: give it with --root-key",
		"jwks":        "a Biscuit is rooted in a key: give it with --root-key",
		"revocations": "a Biscuit is revoked by block revocation ids: give them with --revoked-jtis",
		"audience":    "a Biscuit names no audience; give facts with --fact",
	})
	return o, nil
}

// readRootKey reads a root public key given as "ed25519/HEX",
// "secp256r1/HEX", bare hex, or a file holding one of those or the raw 32
// bytes of an Ed25519 key.
func readRootKey(v string) (Key, string, error) {
	if k, err := parseKeyText(v); err == nil {
		return k, "", nil
	}
	data, err := os.ReadFile(v)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Key{}, "", fmt.Errorf("--root-key %q is neither a key (ed25519/HEX, secp256r1/HEX or hex) nor a file", v)
		}
		return Key{}, "", fmt.Errorf("reading --root-key: %w", err)
	}
	if len(data) == 32 {
		k, err := ParseKey(datalog.PublicKey{Alg: datalog.Ed25519, Key: data})
		if err == nil {
			return k, filepath.Base(v), nil
		}
	}
	k, err := parseKeyText(strings.TrimSpace(string(data)))
	if err != nil {
		return Key{}, "", fmt.Errorf("%s: %w", v, err)
	}
	return k, filepath.Base(v), nil
}

func parseKeyText(s string) (Key, error) {
	s = strings.TrimSpace(s)
	alg := datalog.Ed25519
	switch {
	case strings.HasPrefix(s, "ed25519/"):
		s = strings.TrimPrefix(s, "ed25519/")
	case strings.HasPrefix(s, "secp256r1/"):
		s, alg = strings.TrimPrefix(s, "secp256r1/"), datalog.Secp256r1
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, errors.New("not a hex-encoded key")
	}
	if alg == datalog.Ed25519 && len(b) == 33 && (b[0] == 2 || b[0] == 3) {
		alg = datalog.Secp256r1
	}
	return ParseKey(datalog.PublicKey{Alg: alg, Key: b})
}

// Session is one token and what it is checked against.
type Session struct {
	tok    *Token
	opts   Options
	at     time.Time
	source string
}

// Info describes the session.
func (s *Session) Info() chain.Info { return chain.Info{Format: format, At: s.at} }

// Evaluate checks the token at the given time.
func (s *Session) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	at := eo.At
	if at.IsZero() {
		at = s.at
	}
	if at.IsZero() {
		at = time.Now()
	}
	a := analyze(s.tok, s.opts, at.UTC(), eo.SimRevoked)
	return a.chain(s.source), nil
}
