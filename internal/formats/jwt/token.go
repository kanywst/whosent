package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

// MaxTokens bounds how many tokens a bundle may hold, and MaxActors how
// deeply one token may nest `act`. Real exchanges are a handful of hops;
// the bounds keep a hostile input from costing more than a hostile input
// should.
const (
	MaxTokens = 64
	MaxActors = 64
)

// Media types this adapter knows by name. `typ` is compared without the
// "application/" prefix and without case, as RFC 7515 section 4.1.9 says.
const (
	typIDJAG    = "oauth-id-jag+jwt"
	typTxnToken = "txntoken+jwt"
	typAccess   = "at+jwt"
	typWIT      = "wit+jwt"
	typMandatum = "mdt+jwt"
)

// actor is one party named in a token's `act` chain (RFC 8693 section 4.1),
// or one an Entra token names in its own claims.
type actor struct {
	Sub        string
	Iss        string
	SubProfile string
	ClientID   string
	// Role says where the actor came from when it is not an `act` member:
	// "client", "parent application", "requesting workload".
	Role string
	// Object is the actor's claims without the nested `act`, for the raw
	// view.
	Object map[string]any
	// Problem is set when the actor cannot be read as an actor at all.
	Problem string
}

// name is how the actor is shown.
func (a actor) name() string {
	if a.Sub != "" {
		return a.Sub
	}
	if a.ClientID != "" {
		return a.ClientID
	}
	return "(unnamed actor)"
}

// same reports whether two actors are the same party, the way RFC 8693
// identifies one: by subject, and by issuer when both name one.
func (a actor) same(b actor) bool {
	if a.Sub != b.Sub {
		return false
	}
	return a.Iss == "" || b.Iss == "" || a.Iss == b.Iss
}

// entra holds the claims Microsoft Entra uses instead of `act` for agent
// identities (learn.microsoft.com/entra/agent-id/identity-platform/agent-token-claims).
type entra struct {
	Azp       string
	AppID     string
	ParentApp string
	ActFacets []string
	SubFacets []string
	IDType    string
	OID       string
	TenantID  string
}

// token is one JWS as read, before anything about it is decided.
type token struct {
	Raw string
	// Problem is a structural reason the token cannot be checked at all;
	// rule J1 reports it.
	Problem string

	Header     map[string]any
	Claims     map[string]any
	HeaderJSON []byte
	ClaimsJSON []byte

	Alg, Typ, Kid string
	Iss, Sub      string
	SubProfile    string
	ClientID      string
	Aud           []string
	Exp, Nbf, Iat *time.Time
	JTI           string

	// Scopes are the token's scopes in the order it lists them, and
	// ScopeClaim names the claim they came from ("scope" or "scp"), or ""
	// when it has none.
	Scopes     []string
	ScopeClaim string

	// Actors is the `act` chain, oldest first: the deepest nested `act` is
	// the first actor, the outermost one the current actor. ActProblem is
	// set when `act` is present but cannot be read as a chain.
	Actors     []actor
	ActProblem string
	MayAct     *actor

	Entra *entra
	// Kind names the profile the token follows, for the report.
	Kind string
}

// current is the party the token's issuer says is acting now: the outermost
// `act`, or for a token without one, the party that holds it.
func (t *token) current() actor {
	if n := len(t.Actors); n > 0 {
		return t.Actors[n-1]
	}
	return t.holder()
}

// holder is who presents a token that names no actor: the client it was
// issued to, the requesting workload of a Txn-Token, or the subject itself.
func (t *token) holder() actor {
	switch {
	case t.Entra != nil && (t.Entra.Azp != "" || t.Entra.AppID != ""):
		id := t.Entra.Azp
		if id == "" {
			id = t.Entra.AppID
		}
		return actor{Sub: id, Role: "agent application"}
	case t.ClientID != "":
		return actor{Sub: t.ClientID, Role: "client"}
	case str(t.Claims, "azp") != "":
		return actor{Sub: str(t.Claims, "azp"), Role: "client"}
	case str(t.Claims, "req_wl") != "":
		return actor{Sub: str(t.Claims, "req_wl"), Role: "requesting workload"}
	}
	return actor{Sub: t.Sub, Role: "subject"}
}

// hasExplicitActor reports whether the token names an acting party at all,
// rather than leaving the holder to be inferred.
func (t *token) hasExplicitActor() bool {
	return len(t.Actors) > 0
}

// splitInput reads an input as one or more compact serializations: a JSON
// array of strings, or one token per line with blank lines and "#" comments
// skipped. A leading "Bearer " is dropped, so a pasted Authorization header
// works.
func splitInput(data []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\ufeff")))
	if len(trimmed) == 0 {
		return nil, errors.New("no token in the input")
	}
	var out []string
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("reading the bundle: %w", err)
		}
	} else {
		for _, line := range strings.Split(string(trimmed), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
	}
	for i, t := range out {
		t = strings.TrimSpace(t)
		if rest, ok := cutPrefixFold(t, "bearer "); ok {
			t = strings.TrimSpace(rest)
		}
		out[i] = t
	}
	if len(out) == 0 {
		return nil, errors.New("no token in the input")
	}
	if len(out) > MaxTokens {
		return nil, fmt.Errorf("%d tokens; whosent reads at most %d, and a real exchange is a handful", len(out), MaxTokens)
	}
	return out, nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// segments splits a compact serialization and decodes its header and
// payload. It verifies nothing.
func segments(raw string) (header, payload []byte, problem string) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		if len(parts) == 5 {
			return nil, nil, "this is an encrypted JWT (JWE); whosent reads signed tokens only"
		}
		return nil, nil, fmt.Sprintf("a compact JWS has 3 dot-separated parts, this has %d", len(parts))
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "the header is not unpadded base64url"
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "the payload is not unpadded base64url"
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return nil, nil, "the signature is not unpadded base64url"
	}
	return h, p, ""
}

// decodeObject decodes a JSON object, keeping numbers exact, and refuses
// trailing data: a payload two parsers read two ways is a payload one of
// them is wrong about.
func decodeObject(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("not a JSON object")
	}
	if dec.More() {
		return nil, errors.New("trailing data after the object")
	}
	return v, nil
}

// parse reads one token. A token that cannot be read structurally comes
// back with Problem set and whatever could be read.
func parse(raw string) *token {
	t := &token{Raw: raw}
	h, p, problem := segments(raw)
	if problem != "" {
		t.Problem = problem
		return t
	}
	var err error
	if t.Header, err = decodeObject(h); err != nil {
		t.Problem = "the header is not a JSON object: " + err.Error()
		return t
	}
	t.HeaderJSON = h
	if t.Claims, err = decodeObject(p); err != nil {
		t.Problem = "the payload is not a JSON object: " + err.Error()
		return t
	}
	t.ClaimsJSON = p

	t.Alg = str(t.Header, "alg")
	t.Typ = str(t.Header, "typ")
	t.Kid = str(t.Header, "kid")
	t.Iss = str(t.Claims, "iss")
	t.Sub = str(t.Claims, "sub")
	t.SubProfile = str(t.Claims, "sub_profile")
	t.ClientID = str(t.Claims, "client_id")
	t.JTI = str(t.Claims, "jti")
	t.Aud = strs(t.Claims["aud"])
	t.Exp = numericDate(t.Claims["exp"])
	t.Nbf = numericDate(t.Claims["nbf"])
	t.Iat = numericDate(t.Claims["iat"])
	t.readScopes()
	t.readActors()
	if m, ok := t.Claims["may_act"].(map[string]any); ok {
		a := actorFrom(m)
		t.MayAct = &a
	}
	t.readEntra()
	t.Kind = t.kind()

	switch {
	case t.Alg == "":
		t.Problem = "the header has no alg"
	case strings.EqualFold(t.Alg, "none"):
		t.Problem = `alg "none": an unsigned token vouches for nothing, and is refused`
	case strings.HasPrefix(strings.ToUpper(t.Alg), "HS"):
		t.Problem = fmt.Sprintf("alg %q is a shared-secret MAC: anyone who can check it can forge it, so it cannot be checked against published keys", t.Alg)
	case !allowedAlg(t.Alg):
		t.Problem = fmt.Sprintf("alg %q is not one whosent accepts (%s)", t.Alg, strings.Join(algNames(), ", "))
	case t.Header["crit"] != nil:
		// RFC 7515 section 4.1.11: a recipient that does not understand a
		// critical extension must reject the token.
		t.Problem = "the header marks extensions critical (crit), and whosent understands none"
	}
	return t
}

func (t *token) kind() string {
	switch typ := normType(t.Typ); {
	case typ == typIDJAG:
		return "ID-JAG (identity assertion authorization grant)"
	case typ == typTxnToken:
		return "Txn-Token (transaction token)"
	case typ == typWIT:
		return "WIMSE workload identity token"
	case t.Entra != nil:
		return "Microsoft Entra token"
	case typ == typAccess:
		return "access token (RFC 9068)"
	}
	return "JWT"
}

// normType compares media types the way RFC 7515 section 4.1.9 asks.
func normType(typ string) string {
	typ = strings.ToLower(strings.TrimSpace(typ))
	return strings.TrimPrefix(typ, "application/")
}

func (t *token) readScopes() {
	for _, claim := range []string{"scope", "scp"} {
		v, ok := t.Claims[claim]
		if !ok {
			continue
		}
		t.ScopeClaim = claim
		switch x := v.(type) {
		case string:
			t.Scopes = strings.Fields(x)
		case []any:
			for _, e := range x {
				if s, ok := e.(string); ok {
					t.Scopes = append(t.Scopes, strings.Fields(s)...)
				}
			}
		}
		t.Scopes = dedupe(t.Scopes)
		return
	}
}

func (t *token) readActors() {
	v, ok := t.Claims["act"]
	if !ok {
		return
	}
	var chain []actor
	for v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			t.ActProblem = "an act member is not a JSON object"
			break
		}
		if len(chain) == MaxActors {
			t.ActProblem = fmt.Sprintf("act nests more than %d actors", MaxActors)
			break
		}
		chain = append(chain, actorFrom(m))
		v = m["act"]
	}
	// The outermost act is the current actor: reverse into oldest first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	t.Actors = chain
}

func actorFrom(m map[string]any) actor {
	a := actor{
		Sub: str(m, "sub"), Iss: str(m, "iss"), SubProfile: str(m, "sub_profile"),
		ClientID: str(m, "client_id"), Object: map[string]any{},
	}
	for k, v := range m {
		if k != "act" {
			a.Object[k] = v
		}
	}
	if a.Sub == "" {
		a.Problem = "names no sub: RFC 8693 section 4.1 identifies an actor by its subject"
	}
	return a
}

func (t *token) readEntra() {
	_, hasFacet := t.Claims["xms_act_fct"]
	if !hasFacet && !entraIssuer(t.Iss) {
		return
	}
	e := &entra{
		Azp: str(t.Claims, "azp"), AppID: str(t.Claims, "appid"),
		ParentApp: str(t.Claims, "xms_par_app_azp"),
		ActFacets: facets(t.Claims["xms_act_fct"]), SubFacets: facets(t.Claims["xms_sub_fct"]),
		IDType: str(t.Claims, "idtyp"), OID: str(t.Claims, "oid"), TenantID: str(t.Claims, "tid"),
	}
	t.Entra = e
	if len(t.Actors) > 0 || t.ActProblem != "" {
		return
	}
	// Entra names one acting application and, for agent identities, the
	// application it was created from. The parent is the issuer's word
	// about where the agent came from, so it is an asserted actor.
	if e.ParentApp != "" {
		t.Actors = append(t.Actors, actor{Sub: e.ParentApp, Role: "parent application", Object: map[string]any{"xms_par_app_azp": e.ParentApp}})
	}
	id := e.Azp
	if id == "" {
		id = e.AppID
	}
	if id != "" {
		obj := map[string]any{}
		for _, k := range []string{"azp", "appid", "xms_act_fct"} {
			if v, ok := t.Claims[k]; ok {
				obj[k] = v
			}
		}
		t.Actors = append(t.Actors, actor{Sub: id, Role: "agent application", Object: obj})
	}
}

// entraIssuer reports whether iss is one of Microsoft Entra's token issuers.
func entraIssuer(iss string) bool {
	u, err := url.Parse(iss)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "sts.windows.net" || h == "login.microsoftonline.com"
}

// facets reads an Entra facet claim, which appears as a number, a string of
// space-separated numbers, or an array of either.
func facets(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		out = strings.Fields(x)
	case json.Number:
		out = []string{x.String()}
	case []any:
		for _, e := range x {
			out = append(out, facets(e)...)
		}
	}
	return out
}

// facetName labels the facet values Microsoft documents for agent tokens.
func facetName(v string) string {
	switch v {
	case "11":
		return "11 AgentIdentity"
	case "13":
		return "13 AgentIDUser"
	}
	return v
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// numericDate reads an RFC 7519 NumericDate. Anything that is not a finite
// number reads as absent, and the time rule says so.
func numericDate(v any) *time.Time {
	n, ok := v.(json.Number)
	if !ok {
		return nil
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e11 {
		return nil
	}
	sec, frac := math.Modf(f)
	t := time.Unix(int64(sec), int64(frac*1e9)).UTC()
	return &t
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
