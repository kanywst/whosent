package ucan

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// The token kinds this adapter reads, by their envelope tag.
const (
	tagDelegation = "ucan/dlg@1.0.0"
	tagInvocation = "ucan/inv@1.0.0"
)

// maxSafe is the largest integer a UCAN timestamp may be (2^53 - 1).
const maxSafe = 1<<53 - 1

// Token is one UCAN as received.
type Token struct {
	Raw []byte
	CID []byte

	// Err is set when the bytes are not a UCAN envelope at all; nothing
	// else is filled in then.
	Err error

	Sig         []byte
	HeaderBytes []byte
	Header      Varsig
	HeaderErr   error
	// SigPayload is the exact bytes the signature covers: the envelope's
	// second element as it arrived.
	SigPayload []byte
	Tag        string
	Payload    Value

	Iss, Aud string
	HasAud   bool
	// Sub is nil for a powerline delegation (sub: null).
	Sub     *string
	Cmd     string
	Pol     Value
	Policy  Policy
	Args    Value
	Prf     [][]byte
	Nonce   []byte
	Meta    Value
	HasMeta bool
	Nbf     *int64
	Exp     *int64 // nil: never expires (exp: null)
	Iat     *int64

	// Problems are the payload's structural faults, in the order found.
	Problems []string
	// Unknown are payload fields neither spec defines.
	Unknown []string
}

// Delegation reports whether the token is a delegation.
func (t *Token) Delegation() bool { return t.Err == nil && t.Tag == tagDelegation }

// Invocation reports whether the token is an invocation.
func (t *Token) Invocation() bool { return t.Err == nil && t.Tag == tagInvocation }

// decodeToken reads one sealed token: [signature, {h: varsig, tag: payload}].
func decodeToken(raw []byte) *Token {
	t := &Token{Raw: raw, CID: cidOf(raw)}
	if err := t.envelope(); err != nil {
		t.Err = err
		return t
	}
	t.fields()
	return t
}

func (t *Token) envelope() error {
	d := &decoder{b: t.Raw}
	major, n, _, off, err := d.head(0)
	if err != nil {
		return fmt.Errorf("not DAG-CBOR: %w", err)
	}
	if major != 4 || n != 2 {
		return errors.New("not a UCAN envelope: want a two-element array")
	}
	sigStart := off
	sigEnd, err := d.span(sigStart)
	if err != nil {
		return fmt.Errorf("not DAG-CBOR: %w", err)
	}
	payloadEnd, err := d.span(sigEnd)
	if err != nil {
		return fmt.Errorf("not DAG-CBOR: %w", err)
	}
	if payloadEnd != len(t.Raw) {
		return fmt.Errorf("%d bytes after the envelope", len(t.Raw)-payloadEnd)
	}
	sig, err := decodeCBOR(t.Raw[sigStart:sigEnd])
	if err != nil || sig.Kind != KindBytes {
		return errors.New("not a UCAN envelope: the signature is not bytes")
	}
	t.Sig = sig.Bytes
	t.SigPayload = t.Raw[sigEnd:payloadEnd]
	sp, err := decodeCBOR(t.SigPayload)
	if err != nil {
		return fmt.Errorf("not DAG-CBOR: %w", err)
	}
	if sp.Kind != KindMap || len(sp.Map) != 2 {
		return errors.New("not a UCAN envelope: the signed part is not a two-entry map")
	}
	for _, e := range sp.Map {
		switch {
		case e.Key == "h":
			if e.Value.Kind != KindBytes {
				return errors.New("not a UCAN envelope: h is not bytes")
			}
			t.HeaderBytes = e.Value.Bytes
		case strings.HasPrefix(e.Key, "ucan/"):
			t.Tag, t.Payload = e.Key, e.Value
		default:
			return fmt.Errorf("not a UCAN envelope: unexpected key %q", e.Key)
		}
	}
	if t.HeaderBytes == nil || t.Tag == "" {
		return errors.New("not a UCAN envelope: no varsig header or no payload")
	}
	t.Header, t.HeaderErr = parseVarsig(t.HeaderBytes)
	if t.Tag != tagDelegation && t.Tag != tagInvocation {
		return fmt.Errorf("a %s token; whosent reads %s and %s", t.Tag, tagDelegation, tagInvocation)
	}
	if t.Payload.Kind != KindMap {
		return errors.New("the payload is not a map")
	}
	return nil
}

func (t *Token) problem(format string, a ...any) {
	t.Problems = append(t.Problems, fmt.Sprintf(format, a...))
}

// fields reads the payload, recording every structural fault rather than
// stopping at the first.
func (t *Token) fields() {
	inv := t.Tag == tagInvocation
	known := map[string]bool{"iss": true, "aud": true, "sub": true, "cmd": true, "nonce": true, "meta": true, "exp": true}
	if inv {
		for _, k := range []string{"args", "prf", "iat", "cause"} {
			known[k] = true
		}
	} else {
		known["pol"], known["nbf"] = true, true
	}
	for _, e := range t.Payload.Map {
		if !known[e.Key] {
			t.Unknown = append(t.Unknown, e.Key)
		}
	}
	str := func(k string, required bool) (string, bool) {
		v, ok := t.Payload.Get(k)
		if !ok {
			if required {
				t.problem("no %s", k)
			}
			return "", false
		}
		if v.Kind != KindString {
			t.problem("%s is a %s, not a string", k, v.Kind)
			return "", false
		}
		return v.Str, true
	}
	did := func(k string, required bool) (string, bool) {
		s, ok := str(k, required)
		if ok && !strings.HasPrefix(s, "did:") {
			t.problem("%s %q is not a DID", k, s)
		}
		return s, ok
	}
	t.Iss, _ = did("iss", true)
	t.Aud, t.HasAud = did("aud", !inv)
	switch v, ok := t.Payload.Get("sub"); {
	case !ok:
		t.problem("no sub")
	case v.Kind == KindNull:
		if inv {
			t.problem("sub is null; an invocation names its subject")
		}
	case v.Kind == KindString:
		s := v.Str
		t.Sub = &s
		if !strings.HasPrefix(s, "did:") {
			t.problem("sub %q is not a DID", s)
		}
	default:
		t.problem("sub is a %s, not a DID or null", v.Kind)
	}
	if inv && t.HasAud && t.Sub != nil && principal(t.Aud) == principal(*t.Sub) {
		t.problem("aud equals sub; an invocation for its subject leaves aud out")
	}
	if cmd, ok := str("cmd", true); ok {
		t.Cmd = cmd
		if err := checkCommand(cmd); err != nil {
			t.problem("cmd %q: %v", cmd, err)
		}
	}
	switch v, ok := t.Payload.Get("nonce"); {
	case !ok:
		t.problem("no nonce")
	case v.Kind != KindBytes:
		t.problem("nonce is a %s, not bytes", v.Kind)
	default:
		t.Nonce = v.Bytes
	}
	if v, ok := t.Payload.Get("meta"); ok {
		t.Meta, t.HasMeta = v, true
		switch {
		case v.Kind != KindMap:
			t.problem("meta is a %s, not a map", v.Kind)
		case inv && len(v.Map) == 0:
			t.problem("meta is an empty map; an invocation leaves an empty meta out")
		}
	}
	t.Exp = t.time("exp", true, true)
	if inv {
		t.Iat = t.time("iat", false, false)
		switch v, ok := t.Payload.Get("args"); {
		case !ok:
			t.problem("no args")
		case v.Kind != KindMap:
			t.problem("args is a %s, not a map", v.Kind)
		default:
			t.Args = v
		}
		switch v, ok := t.Payload.Get("prf"); {
		case !ok:
			t.problem("no prf")
		case v.Kind != KindList:
			t.problem("prf is a %s, not a list", v.Kind)
		default:
			for i, p := range v.List {
				if p.Kind != KindLink {
					t.problem("prf[%d] is a %s, not a link", i, p.Kind)
					continue
				}
				t.Prf = append(t.Prf, p.Link)
			}
		}
		if v, ok := t.Payload.Get("cause"); ok && v.Kind != KindLink {
			t.problem("cause is a %s, not a link", v.Kind)
		}
		return
	}
	t.Nbf = t.time("nbf", false, false)
	switch v, ok := t.Payload.Get("pol"); {
	case !ok:
		t.problem("no pol")
	default:
		t.Pol = v
		p, err := parsePolicy(v)
		if err != nil {
			t.problem("pol: %v", err)
		}
		t.Policy = p
	}
}

// time reads a timestamp field. A nullable field may be null, which
// returns nil; a required one must be present, null or not.
func (t *Token) time(k string, required, nullable bool) *int64 {
	v, ok := t.Payload.Get(k)
	switch {
	case !ok:
		if required {
			t.problem("no %s; a token that never expires says exp: null", k)
		}
		return nil
	case v.Kind == KindNull && nullable:
		return nil
	case v.Kind != KindInt || v.Big != nil:
		t.problem("%s is a %s, not an integer", k, v.Kind)
		return nil
	case v.Int > maxSafe || v.Int < -maxSafe:
		t.problem("%s %d is outside the range a UCAN timestamp may hold (2^53)", k, v.Int)
		return nil
	}
	n := v.Int
	return &n
}

// checkCommand applies the specification's command syntax: lower case, a
// leading slash, no trailing slash, no empty segment.
func checkCommand(cmd string) error {
	switch {
	case !strings.HasPrefix(cmd, "/"):
		return errors.New("does not start with /")
	case cmd == "/":
		return nil
	case strings.HasSuffix(cmd, "/"):
		return errors.New("ends with /")
	case strings.Contains(cmd, "//"):
		return errors.New("has an empty segment")
	}
	for _, r := range cmd {
		if unicode.IsUpper(r) {
			return errors.New("is not lower case")
		}
	}
	return nil
}

// covers reports whether command a proves command b: "/" proves anything,
// and a command proves itself and the commands nested under it, segment
// by segment ("/crypto" proves "/crypto/sign", not "/cryptocurrency").
func covers(a, b string) bool {
	return a == "/" || a == b || strings.HasPrefix(b, a+"/")
}
