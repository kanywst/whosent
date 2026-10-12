// Package ucan reads UCAN 1.0 delegation chains (ucan-wg/spec): signed
// DAG-CBOR envelopes, each a delegation from its issuer to its audience,
// ending in an invocation whose prf lists them from the subject's own.
//
// Everything is checked here: the envelope, the varsig header and the
// signature against the issuer's did:key, time bounds, principal and
// subject alignment, command attenuation, and the policy language against
// the invocation's arguments. go-ucan v1.2.0 reads the spec's
// release-candidate tags only and departs from its policy semantics, so
// the specification's own 1.0.0 fixtures are the reference here.
package ucan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// ID is the format's name.
const ID = "ucan"

// Adapter is the UCAN format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

var format = chain.Format{
	ID:       ID,
	Name:     "UCAN",
	RootRole: "subject",
	Rules:    rules,
	Caps:     chain.Capabilities{TimeScrub: true, RevokeSim: true, Ask: true, PerHopSignatures: true},
}

// Format describes UCAN.
func (Adapter) Format() chain.Format { return format }

// Detect claims input holding at least one UCAN delegation or invocation
// envelope. Nothing else decodes to one: a JWT, a bundle of JWTs and a
// Biscuit all fail to.
func (Adapter) Detect(data []byte) chain.Confidence {
	in, err := readInput(data)
	if err != nil {
		return chain.NotMine
	}
	for _, t := range in.tokens {
		if t.Err == nil {
			return chain.Certain
		}
	}
	return chain.NotMine
}

// Open reads the chain and what it is checked against.
func (Adapter) Open(_ context.Context, in chain.Inputs) (chain.Session, error) {
	read, err := readInput(in.Data)
	if err != nil {
		return nil, err
	}
	if _, _, _, _, err := assemble(read.tokens); err != nil {
		return nil, err
	}
	opts, err := optionsFrom(in)
	if err != nil {
		return nil, err
	}
	return &Session{tokens: read.tokens, inputFormat: read.format, opts: opts, at: in.At, source: in.Source}, nil
}

func optionsFrom(in chain.Inputs) (Options, error) {
	var o Options
	if in.Skew != nil {
		o.Skew = *in.Skew
	}
	if in.RevokedIDs != "" {
		data, err := os.ReadFile(in.RevokedIDs)
		if err != nil {
			return o, fmt.Errorf("reading the revocation list: %w", err)
		}
		o.Revoked = map[string]bool{}
		for n, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			c, err := parseCIDText(line)
			if err != nil {
				return o, fmt.Errorf("%s line %d: %w", in.RevokedIDs, n+1, err)
			}
			o.Revoked[cidText(c)] = true
		}
		o.RevokedSource = filepath.Base(in.RevokedIDs)
	}
	o.Ignored = chain.IgnoredInputs(in, map[string]string{
		"trust":      "a UCAN issuer's key is its did:key",
		"jwks":       "a UCAN issuer's key is its did:key",
		"root-key":   "a UCAN issuer's key is its did:key",
		"audience":   "the invocation names its executor itself",
		"fact":       "a UCAN policy reads the invocation's arguments",
		"authorizer": "a UCAN policy reads the invocation's arguments",
	})
	return o, nil
}

// Session is one chain and what it is checked against.
type Session struct {
	tokens      []*Token
	inputFormat string
	opts        Options
	at          time.Time
	source      string
}

// Info describes the session.
func (s *Session) Info() chain.Info { return chain.Info{Format: format, At: s.at} }

func (s *Session) when(at time.Time) time.Time {
	switch {
	case !at.IsZero():
		return at.UTC()
	case !s.at.IsZero():
		return s.at.UTC()
	}
	return time.Now().UTC()
}

// Evaluate checks the chain at the given time.
func (s *Session) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	a, err := analyze(s.tokens, s.opts, s.when(eo.At), eo.SimRevoked)
	if err != nil {
		return nil, err
	}
	return a.chain(s.source, s.inputFormat), nil
}
