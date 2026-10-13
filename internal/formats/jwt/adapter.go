// Package jwt is the JWT format adapter: it reads the delegation a JWT
// carries in RFC 8693's nested `act` claim (and the profiles built on it:
// ID-JAG, Txn-Tokens, Microsoft Entra's agent claims) and describes it in
// the format-neutral model the view renders.
//
// One token is the issuer's word about who acted for whom. RFC 8693
// section 4.1 makes only the current actor and the token's own claims
// authoritative; prior actors are informational, and nothing verifies them
// hop by hop. whosent shows them as asserted, never as verified.
//
// Several tokens, one per exchange, are a chain that can be checked hop by
// hop: each token is signed on its own, and each exchange can be held to
// extending the actor chain by one, narrowing scope, keeping the subject and
// never outliving the token it replaced. Those hop rules are whosent's
// consistency checks derived from RFC 8693 and the drafts built on it, not a
// verification procedure any specification defines; the report says so.
package jwt

import (
	"context"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// ID is the format's --format name.
const ID = "jwt"

// DefaultSkew is the clock tolerance when none is given, the same default
// every other format uses.
const DefaultSkew = 30 * time.Second

// The rules, in the order the view lists them.
const (
	RuleToken     = "J1"
	RuleSignature = "J2"
	RuleTime      = "J3"
	RuleAudience  = "J4"
	RuleActor     = "J5"
	RuleMayAct    = "J6"
	RuleExtends   = "J7"
	RuleScope     = "J8"
	RuleSubject   = "J9"
	RuleExpiry    = "J10"
	RuleProof     = "J11"
)

// bundleRule marks the rules that compare one token of a bundle with the
// one before it. They are whosent's own consistency checks.
const bundleRule = "whosent bundle rule, derived from RFC 8693; not a procedure any specification defines"

var format = chain.Format{
	ID:       ID,
	Name:     "JWT",
	RootRole: "subject",
	Caps:     chain.Capabilities{TimeScrub: true, Ask: true},
	Rules: []chain.RuleInfo{
		{ID: RuleToken, Title: "token", Spec: "RFC 7515 section 5.2, RFC 7519 section 7.2"},
		{ID: RuleSignature, Title: "signature", Spec: "RFC 7515 section 5.2"},
		{ID: RuleTime, Title: "time", Spec: "RFC 7519 sections 4.1.4 to 4.1.6"},
		{ID: RuleAudience, Title: "audience", Spec: "RFC 7519 section 4.1.3"},
		{ID: RuleActor, Title: "actor", Spec: "RFC 8693 section 4.1; draft-mcguinness-oauth-actor-profile"},
		{ID: RuleMayAct, Title: "may_act", Spec: "RFC 8693 section 4.4"},
		{ID: RuleExtends, Title: "extends", Spec: bundleRule + " (section 4.1, act)"},
		{ID: RuleScope, Title: "scope", Spec: bundleRule + " (section 4.2, scope)"},
		{ID: RuleSubject, Title: "subject", Spec: bundleRule + " (section 4.1, sub)"},
		{ID: RuleExpiry, Title: "expiry", Spec: bundleRule + " (RFC 7519 section 4.1.4, exp)"},
		{ID: RuleProof, Title: "actor proof", Spec: specProofs + " section 7; whosent fails the token on a rejected chain, where the draft only drops the evidence"},
	},
}

// Adapter is the JWT format.
type Adapter struct{}

// New returns the adapter.
func New() Adapter { return Adapter{} }

// Format describes JWT delegation: a subject at the root, time scrub and
// questions, no revocation (JWTs have no standard revocation identifier).
func (Adapter) Format() chain.Format { return format }

// Detect claims a token whose header names a delegation profile, or whose
// claims carry a delegation (act, may_act, Entra's agent facets), and
// considers any other signed JWT plausible.
func (Adapter) Detect(data []byte) chain.Confidence {
	raws, err := splitInput(data)
	if err != nil {
		return chain.NotMine
	}
	h, p, problem := segments(raws[0])
	if problem != "" {
		return chain.NotMine
	}
	head, err := decodeObject(h)
	if err != nil {
		return chain.NotMine
	}
	claims, err := decodeObject(p)
	if err != nil {
		return chain.NotMine
	}
	typ := normType(str(head, "typ"))
	switch typ {
	case typIDJAG, typTxnToken:
		return chain.Certain
	}
	for _, k := range []string{"act", "may_act", "xms_act_fct"} {
		if _, ok := claims[k]; ok {
			return chain.Certain
		}
	}
	return chain.Plausible
}

// Open reads the token or bundle and the keys it is checked against.
func (Adapter) Open(ctx context.Context, in chain.Inputs) (chain.Session, error) {
	raws, err := splitInput(in.Data)
	if err != nil {
		return nil, err
	}
	if in.Reverse {
		for i, j := 0, len(raws)-1; i < j; i, j = i+1, j-1 {
			raws[i], raws[j] = raws[j], raws[i]
		}
	}
	keys, actorKeys, err := loadKeys(ctx, in)
	if err != nil {
		return nil, err
	}
	s := newSession(raws, keys, in.Audience, in.Skew)
	s.actorKeys = actorKeys
	s.source = in.Source
	s.at = in.At
	s.reversed = in.Reverse
	s.ignored = chain.IgnoredInputs(in, map[string]string{
		"root-key":     "a JWT is signed by its issuer: give the issuer's keys with --trust or --jwks",
		"revoked-jtis": "JWTs have no standard revocation list",
		"fact":         "a JWT has no authorizer facts; ask about a scope with whosent ask --scope",
		"authorizer":   "a JWT has no authorizer code; ask about a scope with whosent ask --scope",
	})
	return s, nil
}

// Scenarios are the format's demos.
func (Adapter) Scenarios() []chain.Scenario { return scenarios() }

// session is one token or bundle with the inputs it is checked against.
type session struct {
	tokens []*token
	keys   keyring
	// actorKeys are the keys actors sign actor proofs with.
	actorKeys actorKeyring
	audience  *string
	skew      time.Duration
	at        time.Time
	source    string
	reversed  bool
	// demo is set for a scenario: its summary replaces the input line.
	demo string
	// ignored are the inputs given that a JWT has no use for.
	ignored []string
}

func newSession(raws []string, keys keyring, audience *string, skew *time.Duration) *session {
	s := &session{keys: keys, skew: DefaultSkew}
	if skew != nil {
		s.skew = *skew
	}
	if audience != nil {
		a := *audience
		s.audience = &a
	}
	for _, r := range raws {
		s.tokens = append(s.tokens, parse(r))
	}
	return s
}

func (s *session) Info() chain.Info { return chain.Info{Format: format, At: s.at} }

func (s *session) Evaluate(_ context.Context, eo chain.EvalOptions) (*chain.Chain, error) {
	at := eo.At
	if at.IsZero() {
		at = time.Now()
	}
	return s.evaluate(at), nil
}

// bundle reports whether the session holds several exchanged tokens.
func (s *session) bundle() bool { return len(s.tokens) > 1 }
