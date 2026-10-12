package jwt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kanywst/whosent/internal/safewrite"
	"github.com/kanywst/whosent/pkg/chain"
)

// Demo identities. The keys are derived from fixed seeds, and Ed25519
// signatures are deterministic, so a scenario is the same bytes every time
// it is minted at the same base time.
const (
	demoOkta   = "https://acme.okta.example"
	demoEntra  = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	demoAPI    = "https://api.acme.example"
	demoSaaSAS = "https://auth.saas.example"
	demoUser   = "alice@acme.example"
)

type demoKey struct {
	iss string
	kid string
	key ed25519.PrivateKey
}

func newDemoKey(iss, kid, seed string) demoKey {
	s := sha256.Sum256([]byte("whosent jwt demo " + seed))
	return demoKey{iss: iss, kid: kid, key: ed25519.NewKeyFromSeed(s[:])}
}

var (
	keyOkta     = newDemoKey(demoOkta, "okta-2026", "okta")
	keyEntra    = newDemoKey(demoEntra, "entra-2026", "entra")
	keyAttacker = newDemoKey(demoOkta, "okta-2026", "mallory")
)

// jwks is the published key document for a demo key.
func (k demoKey) jwks() []byte {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: k.key.Public(), KeyID: k.kid, Algorithm: string(jose.EdDSA), Use: "sig",
	}}}
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		panic(err) // a fixed, well-formed key always marshals
	}
	return append(b, '\n')
}

// mint signs claims as a compact JWS with the demo key. Header and claims
// are marshalled from maps, whose keys encoding/json sorts, so the bytes are
// stable.
func mint(k demoKey, typ string, claims map[string]any) string {
	header := map[string]any{"alg": "EdDSA", "kid": k.kid}
	if typ != "" {
		header["typ"] = typ
	}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sig := ed25519.Sign(k.key, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// unsigned is a token with alg "none": the attack RFC 8725 section 3.1
// warns about.
func unsigned(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

func unix(t time.Time) int64 { return t.Unix() }

func act(sub, profile string, inner map[string]any) map[string]any {
	a := map[string]any{"sub": sub, "iss": demoOkta, "sub_profile": profile}
	if inner != nil {
		a["act"] = inner
	}
	return a
}

// demo is a minted scenario: its tokens and every input it is checked
// against.
type demo struct {
	tokens   []string
	keys     []demoKey
	audience string
}

type scenarioDef struct {
	name, title, summary string
	mint                 func(base time.Time) demo
}

func scenarioDefs() []scenarioDef {
	okta := func(base time.Time, exp time.Duration, aud string, keys ...demoKey) demo {
		claims := map[string]any{
			"iss": demoOkta, "sub": demoUser, "sub_profile": "user", "aud": aud,
			"iat": unix(base.Add(-2 * time.Minute)), "exp": unix(base.Add(exp)), "jti": "at-7f3a",
			"client_id": "research-agent", "scope": "files:read calendar:read",
			"act": act("research-agent", "ai_agent", act("planner-agent", "ai_agent", act("chat-ui", "web_app", nil))),
		}
		return demo{tokens: []string{mint(keyOkta, "at+jwt", claims)}, keys: keys, audience: demoAPI}
	}
	bundle := func(base time.Time, change func(i int, c map[string]any)) demo {
		claims := []map[string]any{
			{
				"iss": demoOkta, "sub": demoUser, "sub_profile": "user", "aud": demoOkta,
				"iat": unix(base.Add(-30 * time.Minute)), "exp": unix(base.Add(60 * time.Minute)), "jti": "tok-0",
				"client_id": "chat-ui", "scope": "files:read files:write calendar:read",
				"may_act": map[string]any{"sub": "planner-agent", "iss": demoOkta},
			},
			{
				"iss": demoOkta, "sub": demoUser, "sub_profile": "user", "aud": demoOkta,
				"iat": unix(base.Add(-20 * time.Minute)), "exp": unix(base.Add(40 * time.Minute)), "jti": "tok-1",
				"scope":   "files:read calendar:read",
				"act":     act("planner-agent", "ai_agent", nil),
				"may_act": map[string]any{"sub": "research-agent", "iss": demoOkta},
			},
			{
				"iss": demoOkta, "sub": demoUser, "sub_profile": "user", "aud": demoAPI,
				"iat": unix(base.Add(-10 * time.Minute)), "exp": unix(base.Add(20 * time.Minute)), "jti": "tok-2",
				"scope": "files:read",
				"act":   act("research-agent", "ai_agent", act("planner-agent", "ai_agent", nil)),
			},
		}
		if change != nil {
			for i, c := range claims {
				change(i, c)
			}
		}
		d := demo{keys: []demoKey{keyOkta}, audience: demoAPI}
		for _, c := range claims {
			d.tokens = append(d.tokens, mint(keyOkta, "at+jwt", c))
		}
		return d
	}
	return []scenarioDef{
		{"jwt-okta-style", "One token, three actors",
			"an Okta-style access token: alice, then a chat UI, a planner and a research agent in nested act claims. The token verifies; the prior actors are the issuer's word.",
			func(base time.Time) demo { return okta(base, time.Hour, demoAPI, keyOkta) }},
		{"jwt-bundle-healthy", "Three exchanges, narrowing",
			"three tokens from three exchanges, each signed: every hop adds one actor, keeps the subject, narrows scope and expires sooner.",
			func(base time.Time) demo { return bundle(base, nil) }},
		{"jwt-bundle-widened", "Scope from nowhere",
			"the research agent's token holds files:write, which the planner's token had already dropped.",
			func(base time.Time) demo {
				return bundle(base, func(i int, c map[string]any) {
					if i == 2 {
						c["scope"] = "files:read files:write"
					}
				})
			}},
		{"jwt-bundle-spliced", "A token from another exchange",
			"the last token's actor chain names mallory-agent where the planner should be: it was not exchanged from the token before it.",
			func(base time.Time) demo {
				return bundle(base, func(i int, c map[string]any) {
					if i == 2 {
						c["act"] = act("research-agent", "ai_agent", act("mallory-agent", "ai_agent", nil))
					}
				})
			}},
		{"jwt-expired", "An expired token",
			"the access token expired five minutes ago.",
			func(base time.Time) demo { return okta(base, -5*time.Minute, demoAPI, keyOkta) }},
		{"jwt-wrong-aud", "Addressed to someone else",
			"the token is addressed to a different API than the one it is presented to.",
			func(base time.Time) demo { return okta(base, time.Hour, "https://billing.acme.example", keyOkta) }},
		{"jwt-alg-none", "An unsigned token",
			`a token with alg "none": it vouches for nothing, and is refused before anything else is read.`,
			func(base time.Time) demo {
				return demo{tokens: []string{unsigned(map[string]any{
					"iss": demoOkta, "sub": demoUser, "aud": demoAPI, "exp": unix(base.Add(time.Hour)),
					"scope": "files:read files:write admin", "act": act("research-agent", "ai_agent", nil),
				})}, keys: []demoKey{keyOkta}, audience: demoAPI}
			}},
		{"jwt-forged", "Signed by the wrong key",
			"the token claims the Okta issuer and its kid, but another key signed it.",
			func(base time.Time) demo {
				d := okta(base, time.Hour, demoAPI, keyOkta)
				claims := map[string]any{
					"iss": demoOkta, "sub": demoUser, "aud": demoAPI, "iat": unix(base.Add(-time.Minute)),
					"exp": unix(base.Add(time.Hour)), "scope": "files:read files:write admin",
					"act": act("research-agent", "ai_agent", nil),
				}
				d.tokens = []string{mint(keyAttacker, "at+jwt", claims)}
				return d
			}},
		{"jwt-entra-agent", "An Entra agent identity",
			"a Microsoft Entra token for an agent identity: no act claim, an acting application with agent facets, and the blueprint application it was created from.",
			func(base time.Time) demo {
				claims := map[string]any{
					"iss": demoEntra, "sub": "aB3kdQ9vZ2xYfU8mL1pR4tW7", "upn": demoUser, "oid": "0a8c6f2e-1d3b-4e5f-9a7b-2c4d6e8f0a1b",
					"tid": "9188040d-6c67-4c5b-b112-36a304b66dad", "idtyp": "user", "aud": demoAPI,
					"azp": "agent-c1f5", "xms_act_fct": "11", "xms_sub_fct": "13",
					"xms_par_app_azp": "blueprint-7d2b", "scp": "Files.Read User.Read",
					"iat": unix(base.Add(-5 * time.Minute)), "exp": unix(base.Add(55 * time.Minute)),
				}
				return demo{tokens: []string{mint(keyEntra, "JWT", claims)}, keys: []demoKey{keyEntra}, audience: demoAPI}
			}},
		{"jwt-id-jag", "An identity assertion grant",
			"an ID-JAG (the grant behind MCP's enterprise-managed authorization): Okta asserts that alice's agent may get a token from a SaaS authorization server.",
			func(base time.Time) demo {
				claims := map[string]any{
					"iss": demoOkta, "sub": demoUser, "aud": demoSaaSAS, "client_id": "mcp-agent",
					"resource": "https://mcp.saas.example", "scope": "tickets:read",
					"iat": unix(base.Add(-time.Minute)), "exp": unix(base.Add(4 * time.Minute)), "jti": "jag-41c9",
					"act": act("mcp-agent", "ai_agent", nil),
				}
				return demo{tokens: []string{mint(keyOkta, typIDJAG, claims)}, keys: []demoKey{keyOkta}, audience: demoSaaSAS}
			}},
		{"jwt-unchecked", "Nothing to check against",
			"the Okta-style token with no keys and no audience: nothing fails, and nothing is verified.",
			func(base time.Time) demo {
				d := okta(base, time.Hour, demoAPI)
				d.audience = ""
				return d
			}},
	}
}

func scenarios() []chain.Scenario {
	var out []chain.Scenario
	for _, d := range scenarioDefs() {
		def := d
		out = append(out, chain.Scenario{
			Name: def.name, Title: def.title, Summary: def.summary, Format: ID,
			Open: func(base time.Time) (chain.Session, error) {
				return openDemo(def, base), nil
			},
			Emit: func(dir string, force bool) (string, error) {
				return emitDemo(def, dir, force)
			},
		})
	}
	return out
}

func openDemo(def scenarioDef, base time.Time) *session {
	d := def.mint(base)
	kr := keyring{}
	for _, k := range d.keys {
		var set jose.JSONWebKeySet
		_ = json.Unmarshal(k.jwks(), &set)
		kr[k.iss] = &issuerKeys{Source: hostOf(k.iss) + ".json", Keys: set.Keys}
	}
	var aud *string
	if d.audience != "" {
		a := d.audience
		aud = &a
	}
	s := newSession(d.tokens, kr, aud, nil)
	s.at = base.Add(time.Minute)
	s.source = def.name
	s.demo = def.summary
	return s
}

// FixedBase is the base time emitted fixtures are minted at, so they are
// the same bytes on every run.
var FixedBase = time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)

// emitDemo writes the scenario's token, key documents and trust file, and
// returns the command that checks them.
func emitDemo(def scenarioDef, dir string, force bool) (string, error) {
	d := def.mint(FixedBase)
	if err := safewrite.Dir(dir, force); err != nil {
		return "", err
	}
	jwksDir := filepath.Join(dir, "jwks")
	if fi, err := os.Lstat(jwksDir); err == nil && !fi.IsDir() {
		return "", fmt.Errorf("%s exists and is not a directory; refusing to write through it", jwksDir)
	}
	if err := os.MkdirAll(jwksDir, 0o700); err != nil {
		return "", err
	}
	name := "token.jwt"
	data := []byte(d.tokens[0] + "\n")
	if len(d.tokens) > 1 {
		name = "tokens.json"
		b, err := json.MarshalIndent(d.tokens, "", "  ")
		if err != nil {
			return "", err
		}
		data = append(b, '\n')
	}
	if err := safewrite.File(filepath.Join(dir, name), data); err != nil {
		return "", err
	}
	cmd := []string{"whosent", "check", name, "--format", ID}
	if len(d.keys) > 0 {
		issuers := map[string]map[string]string{}
		seen := map[string]bool{}
		for _, k := range d.keys {
			file := hostOf(k.iss) + ".json"
			if seen[k.iss] {
				continue
			}
			seen[k.iss] = true
			if err := safewrite.File(filepath.Join(jwksDir, file), k.jwks()); err != nil {
				return "", err
			}
			issuers[k.iss] = map[string]string{"jwks_file": filepath.Join("jwks", file)}
		}
		b, err := json.MarshalIndent(map[string]any{"issuers": issuers}, "", "  ")
		if err != nil {
			return "", err
		}
		if err := safewrite.File(filepath.Join(dir, "trust.json"), append(b, '\n')); err != nil {
			return "", err
		}
		cmd = append(cmd, "--trust", "trust.json")
	}
	if d.audience != "" {
		cmd = append(cmd, "--audience", d.audience)
	}
	cmd = append(cmd, "--at", FixedBase.Add(time.Minute).Format(time.RFC3339))
	command := strings.Join(cmd, " ")
	manifest, err := json.MarshalIndent(map[string]string{
		"name": def.name, "title": def.title, "summary": def.summary, "format": ID, "command": command,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := safewrite.File(filepath.Join(dir, "manifest.json"), append(manifest, '\n')); err != nil {
		return "", err
	}
	return command, nil
}

// scenarioNames lists the demos, for tests.
func scenarioNames() []string {
	var out []string
	for _, d := range scenarioDefs() {
		out = append(out, d.name)
	}
	sort.Strings(out)
	return out
}
