// Package macaroon is the macaroons format adapter: a macaroon and its
// discharges, in the libmacaroons formats or as a Fly.io token, described
// as a chain of caveats in the format-neutral model.
//
// Anyone can add a caveat, but only the root key's holder can check the
// HMAC chain, so without --root-key every caveat reads and none is vouched
// for. A discharge is drawn under the third-party caveat it answers.
package macaroon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// ID is the format's --format name.
const ID = "macaroon"

// DefaultSkew is the clock tolerance when none is given.
const DefaultSkew = 30 * time.Second

// The rules, in the order the view lists them.
const (
	RuleFormat    = "M1"
	RuleSignature = "M2"
	RuleDischarge = "M3"
	RuleBinding   = "M4"
	RuleTime      = "M5"
	RuleCaveat    = "M6"
)

const (
	specPaper = "Birgisson et al., Macaroons (NDSS 2014)"
	specLib   = "libmacaroons doc/format.txt and README"
	specFly   = "superfly/macaroon"
)

var format = chain.Format{
	ID:       ID,
	Name:     "Macaroon",
	RootRole: "root key",
	Caps:     chain.Capabilities{TimeScrub: true, Ask: true},
	Rules: []chain.RuleInfo{
		{ID: RuleFormat, Title: "format", Spec: specLib + "; " + specFly},
		{ID: RuleSignature, Title: "signature", Spec: specPaper + ", section 3 (HMAC chain); go-macaroon Verify"},
		{ID: RuleDischarge, Title: "discharge", Spec: specPaper + ", section 3 (third-party caveats and discharges)"},
		{ID: RuleBinding, Title: "binding", Spec: specPaper + " (verification ids, binding a discharge to its root); " + specFly + " BindToParentToken"},
		{ID: RuleTime, Title: "time", Spec: "libmacaroons README (time < T); go-macaroon bakery checkers (time-before); " + specFly + " ValidityWindow"},
		{ID: RuleCaveat, Title: "caveat", Spec: "libmacaroons verifier satisfy_exact; the application's own predicates. Fly.io caveats restrict the request instead (flyio Access)"},
	},
}

// Adapter is the macaroons format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

// Format describes macaroons: a root key at the root, caveats narrowing it,
// time scrub for the time conventions; no revocation (macaroons have no
// standard revocation identifier) and no per-hop signatures (one HMAC chain
// covers them all).
func (Adapter) Format() chain.Format { return format }

// Detect claims a Fly.io token by its prefix and a raw v2 binary macaroon
// by its version byte when it parses, and considers base64 or JSON that
// parses as a macaroon plausible.
func (Adapter) Detect(data []byte) chain.Confidence {
	if len(data) > 0 && data[0] == 2 {
		if _, err := sliceBinary(data); err == nil {
			return chain.Certain
		}
		return chain.NotMine
	}
	b, err := decode(data)
	if err != nil {
		return chain.NotMine
	}
	if b.dialect == "fly" {
		return chain.Certain
	}
	return chain.Plausible
}

// Open reads the macaroons and the root key and predicates they are checked
// against.
func (Adapter) Open(_ context.Context, in chain.Inputs) (chain.Session, error) {
	b, err := decode(in.Data)
	if err != nil {
		return nil, err
	}
	if in.Reverse {
		return nil, errors.New("--reverse does not apply to macaroons: the root macaroon is the one whose caveats the others discharge, whatever the order")
	}
	s := &session{b: b, source: in.Source, at: in.At, skew: DefaultSkew}
	if in.Skew != nil {
		s.skew = *in.Skew
	}
	if len(in.RootKeys) > 1 {
		return nil, errors.New("a macaroon has one root key: give --root-key once")
	}
	if len(in.RootKeys) == 1 {
		k, src, err := readRootKey(in.RootKeys[0])
		if err != nil {
			return nil, err
		}
		s.key, s.keySource = k, src
	}
	reasons := map[string]string{
		"trust":        "a macaroon is checked with its root key: give it with --root-key",
		"jwks":         "a macaroon is checked with its root key: give it with --root-key",
		"revocations":  "macaroons have no standard revocation list",
		"revoked-jtis": "macaroons have no standard revocation list",
		"audience":     "a macaroon names no audience; its location is shown instead",
		"authorizer":   "a macaroon's predicates are given one by one with --fact",
	}
	if b.dialect == "fly" {
		reasons["fact"] = "Fly.io caveats are typed, not predicates; --fact applies to libmacaroons-style tokens"
	} else {
		s.facts = map[string]bool{}
		for _, f := range in.Facts {
			s.facts[f] = true
		}
		s.factsGiven = len(in.Facts) > 0
	}
	s.ignored = chain.IgnoredInputs(in, reasons)
	return s, nil
}

// readRootKey reads a root key: hex, `text:SECRET` for a secret written
// as text (libmacaroons' own examples use text keys), or a file holding
// either, or holding the key's raw bytes.
func readRootKey(v string) ([]byte, string, error) {
	if k, ok := parseKeyText(v); ok {
		return k, "", nil
	}
	data, err := os.ReadFile(v)
	if err != nil {
		return nil, "", fmt.Errorf("--root-key %q is neither hex, text:SECRET, nor a readable file", v)
	}
	trimmed := strings.TrimRight(string(data), "\r\n")
	if k, ok := parseKeyText(trimmed); ok {
		return k, v, nil
	}
	if len(trimmed) == 0 {
		return nil, "", fmt.Errorf("%s is empty", v)
	}
	return []byte(trimmed), v, nil
}

func parseKeyText(v string) ([]byte, bool) {
	if s, ok := strings.CutPrefix(v, "text:"); ok && s != "" {
		return []byte(s), true
	}
	if len(v) >= 2 && len(v)%2 == 0 {
		if k, err := hex.DecodeString(v); err == nil {
			return k, true
		}
	}
	return nil, false
}

// Scenarios are the format's demos.
func (Adapter) Scenarios() []chain.Scenario { return scenarios() }

// session is one bundle with the key and predicates it is checked against.
type session struct {
	b          *bundle
	key        []byte
	keySource  string
	facts      map[string]bool
	factsGiven bool
	skew       time.Duration
	at         time.Time
	source     string
	ignored    []string
	// demo is set for a scenario: it names where the inputs came from.
	demo string
	// refuse, set only by tests, replaces the reference implementation's
	// verdict to prove a disagreement is reported.
	refuse func() error
	// askRefuse, set only by tests, replaces the library's answer to a
	// question, to prove a disagreement is reported.
	askRefuse func() error
}

func (s *session) Info() chain.Info { return chain.Info{Format: format, At: s.at} }

func (s *session) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	at := eo.At
	if at.IsZero() {
		at = time.Now()
	}
	return s.evaluate(at), nil
}
