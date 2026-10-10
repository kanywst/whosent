package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kanywst/whosent/internal/formats/mandatum"
	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

var base = chaintest.Base

func TestTheAdapterKeepsTheContract(t *testing.T) {
	chaintest.Run(t, New())
}

func evalScenario(t *testing.T, name string) *chain.Chain {
	t.Helper()
	for _, sc := range New().Scenarios() {
		if sc.Name == name {
			s, err := sc.Open(base)
			if err != nil {
				t.Fatal(err)
			}
			c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: s.Info().At})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
	}
	t.Fatalf("no scenario %q", name)
	return nil
}

// Every scenario's verdict, break and failing rules are what its story
// says, so a demo can never quietly start showing something else.
func TestEveryScenarioShowsWhatItSays(t *testing.T) {
	tests := []struct {
		name     string
		verdict  chain.Verdict
		breakAt  int
		failing  []string // rule IDs failing at the break
		asserted int
		links    int
	}{
		{"jwt-okta-style", chain.VerdictValid, -1, nil, 2, 3},
		{"jwt-bundle-healthy", chain.VerdictValid, -1, nil, 0, 3},
		{"jwt-bundle-widened", chain.VerdictInvalid, 2, []string{RuleScope}, 0, 3},
		{"jwt-bundle-spliced", chain.VerdictInvalid, 2, []string{RuleExtends}, 0, 3},
		{"jwt-expired", chain.VerdictInvalid, 2, []string{RuleTime}, 2, 3},
		{"jwt-wrong-aud", chain.VerdictInvalid, 2, []string{RuleAudience}, 2, 3},
		{"jwt-alg-none", chain.VerdictInvalid, 0, []string{RuleToken}, 0, 1},
		{"jwt-forged", chain.VerdictInvalid, 0, []string{RuleSignature}, 0, 1},
		{"jwt-entra-agent", chain.VerdictValid, -1, nil, 1, 2},
		{"jwt-id-jag", chain.VerdictValid, -1, nil, 0, 1},
		{"jwt-unchecked", chain.VerdictIncomplete, -1, nil, 2, 3},
	}
	if got, want := len(tests), len(New().Scenarios()); got != want {
		t.Fatalf("%d scenarios asserted, %d exist: assert every one", got, want)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := evalScenario(t, tt.name)
			if c.Verdict != tt.verdict || c.BreakAt != tt.breakAt {
				t.Fatalf("got %s at %d, want %s at %d: %v", c.Verdict, c.BreakAt, tt.verdict, tt.breakAt, c.Findings())
			}
			if len(c.Links) != tt.links {
				t.Errorf("%d links, want %d", len(c.Links), tt.links)
			}
			asserted := 0
			for _, l := range c.Links {
				if l.Asserted {
					asserted++
				}
			}
			if asserted != tt.asserted {
				t.Errorf("%d asserted links, want %d", asserted, tt.asserted)
			}
			if tt.breakAt >= 0 {
				var failing []string
				for _, ch := range c.Links[tt.breakAt].Checks {
					if ch.Status.Blocking() {
						failing = append(failing, ch.Rule)
					}
				}
				if strings.Join(failing, ",") != strings.Join(tt.failing, ",") {
					t.Errorf("failing at the break: %v, want %v", failing, tt.failing)
				}
			}
		})
	}
}

// A prior actor never looks verified: it is asserted, and the only rule
// that says anything about it is whether it is an actor at all.
func TestPriorActorsAreAssertedNeverVerified(t *testing.T) {
	c := evalScenario(t, "jwt-okta-style")
	for _, l := range c.Links[:2] {
		if !l.Asserted {
			t.Fatalf("link %d (%s) is not asserted", l.Index, l.To)
		}
		for _, ch := range l.Checks {
			if ch.Rule == RuleActor {
				if ch.Status != chain.StatusPass {
					t.Errorf("link %d actor check %s", l.Index, ch.Status)
				}
				continue
			}
			if ch.Status != chain.StatusNotApplicable {
				t.Errorf("link %d %s is %s: nothing could check a prior actor, so it does not apply", l.Index, ch.Rule, ch.Status)
			}
		}
	}
	if got := []string{c.Links[0].To, c.Links[1].To, c.Links[2].To}; strings.Join(got, ">") != "chat-ui>planner-agent>research-agent" {
		t.Errorf("actors oldest first: %v", got)
	}
	if c.Headline == "" || !strings.Contains(c.Headline, "issuer's word") {
		t.Errorf("a VALID single token with prior actors must say they are asserted: %q", c.Headline)
	}
	if c.Matrix == nil || c.Matrix.Rows[0].Cells[0].Kind != chain.CellUnknown {
		t.Error("a prior actor's authority is unknown, not held and not absent")
	}
}

// The nested example of RFC 8693 section 4.1: service16 is the current
// actor, service77 acted before it.
func TestTheRFC8693NestedExample(t *testing.T) {
	payload := `{"aud":"https://service16.example.com","iss":"https://issuer.example.com","exp":1443904100,"nbf":1443904000,"sub":"user@example.com","act":{"sub":"https://service16.example.com","act":{"sub":"https://service77.example.com"}}}`
	raw := compact(`{"alg":"RS256"}`, payload, "c2ln")
	tok := parse(raw)
	if tok.Problem != "" {
		t.Fatal(tok.Problem)
	}
	if len(tok.Actors) != 2 || tok.Actors[0].Sub != "https://service77.example.com" || tok.current().Sub != "https://service16.example.com" {
		t.Fatalf("actors %+v", tok.Actors)
	}
	s := newSession([]string{raw}, nil, nil, nil)
	c, _ := s.Evaluate(context.Background(), chain.EvalOptions{At: time.Unix(1443904050, 0)})
	if !c.Links[0].Asserted || c.Links[1].Asserted {
		t.Errorf("service77 is asserted, service16 is the token's actor: %v %v", c.Links[0].Asserted, c.Links[1].Asserted)
	}
	if c.Verdict != chain.VerdictIncomplete {
		t.Errorf("without keys or an audience the chain is INCOMPLETE, got %s", c.Verdict)
	}
	if c.Links[1].Check(RuleTime).Status != chain.StatusPass {
		t.Errorf("time at the example's own instant: %+v", c.Links[1].Check(RuleTime))
	}
}

func compact(header, payload, sig string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// signWith signs claims with a JOSE key, for tests that need RSA and EC.
func signWith(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(claims)
	obj, err := signer.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwksOf(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignatures(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := map[string]any{"iss": "https://idp", "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}
	keys := func(_ *testing.T, doc []byte) keyring {
		ks, skipped, err := parseJWKS(doc)
		ik := &issuerKeys{Source: "idp.json", Keys: ks, Skipped: skipped}
		if err != nil {
			ik.Err = err.Error()
		}
		return keyring{"https://idp": ik}
	}
	rsaPub := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "r1", Use: "sig"}
	ecPub := jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "e1"}
	tests := []struct {
		name  string
		token string
		keys  keyring
		want  chain.Status
		says  string
	}{
		{"an RS256 token verifies with its issuer's key", signWith(t, jose.RS256, rsaKey, "r1", claims), keys(t, jwksOf(t, rsaPub)), chain.StatusPass, "kid r1"},
		{"an ES256 token verifies with its issuer's key", signWith(t, jose.ES256, ecKey, "e1", claims), keys(t, jwksOf(t, rsaPub, ecPub)), chain.StatusPass, "kid e1"},
		{"a PS256 token verifies", signWith(t, jose.PS256, rsaKey, "r1", claims), keys(t, jwksOf(t, rsaPub)), chain.StatusPass, ""},
		{"another key's signature fails", signWith(t, jose.RS256, otherRSA, "r1", claims), keys(t, jwksOf(t, rsaPub)), chain.StatusFail, "does not verify"},
		{"a kid the issuer does not publish fails", signWith(t, jose.RS256, rsaKey, "nope", claims), keys(t, jwksOf(t, rsaPub)), chain.StatusFail, `kid "nope"`},
		{"no kid with several keys fails", signWith(t, jose.RS256, rsaKey, "", claims), keys(t, jwksOf(t, rsaPub, jose.JSONWebKey{Key: &otherRSA.PublicKey, KeyID: "r2"})), chain.StatusFail, "several keys"},
		{"no kid with one key verifies", signWith(t, jose.RS256, rsaKey, "", claims), keys(t, jwksOf(t, jose.JSONWebKey{Key: &rsaKey.PublicKey})), chain.StatusPass, ""},
		{"an issuer with no keys is unchecked", signWith(t, jose.RS256, rsaKey, "r1", claims), nil, chain.StatusUnchecked, "--jwks"},
		{"an unusable key document is an error", signWith(t, jose.RS256, rsaKey, "r1", claims), keys(t, []byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)), chain.StatusError, "no usable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.keys.verifySig(parse(tt.token))
			if got.Status != tt.want || !strings.Contains(got.Detail, tt.says) {
				t.Errorf("%s %q, want %s mentioning %q", got.Status, got.Detail, tt.want, tt.says)
			}
		})
	}
}

// Algorithms that cannot be checked against published keys are refused
// before anything else: J1 fails and the signature is not attempted.
func TestRefusedAlgorithms(t *testing.T) {
	for _, alg := range []string{"none", "None", "HS256", "HS512", "RS1", ""} {
		h := `{"alg":"` + alg + `"}`
		if alg == "" {
			h = `{}`
		}
		tok := parse(compact(h, `{"sub":"x"}`, "c2ln"))
		if tok.Problem == "" {
			t.Errorf("alg %q was accepted", alg)
		}
		if got := (keyring{}).verifySig(tok); got.Status != chain.StatusSkipped {
			t.Errorf("alg %q: signature %s, want skipped", alg, got.Status)
		}
	}
	if tok := parse(compact(`{"alg":"RS256","crit":["exp"]}`, `{}`, "c2ln")); tok.Problem == "" {
		t.Error("a critical extension whosent does not understand was accepted")
	}
}

func TestKeyDocuments(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name    string
		doc     string
		keys    int
		skipped string
		err     string
	}{
		{"a private key is used only by its public half", string(jwksOf(t, jose.JSONWebKey{Key: priv, KeyID: "p"})), 1, "private key", ""},
		{"an encryption key is skipped", string(jwksOf(t, jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "e", Use: "enc"}, jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "s"})), 1, "use", ""},
		{"a symmetric key is skipped", `{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"h"}]}`, 0, "symmetric", "no usable"},
		{"a duplicate kid is refused", string(jwksOf(t, jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "d"}, jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "d"})), 0, "", "twice"},
		{"not a key set", `[1,2]`, 0, "", "not a JWK Set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, skipped, err := parseJWKS([]byte(tt.doc))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil || len(keys) != tt.keys {
				t.Fatalf("%d keys, %v", len(keys), err)
			}
			if tt.skipped != "" && !strings.Contains(strings.Join(skipped, ";"), tt.skipped) {
				t.Errorf("skipped %v, want one mentioning %q", skipped, tt.skipped)
			}
		})
	}
}

// bundleSession builds an unsigned bundle (keys are not under test here)
// from claims, so each exchange rule can be tested on its own.
func bundleSession(claims ...map[string]any) *session {
	var raws []string
	for _, c := range claims {
		p, _ := json.Marshal(c)
		raws = append(raws, compact(`{"alg":"EdDSA"}`, string(p), "c2ln"))
	}
	aud := "https://api"
	return newSession(raws, nil, &aud, nil)
}

func TestExchangeRules(t *testing.T) {
	now := base
	tok0 := func() map[string]any {
		return map[string]any{"sub": "alice", "aud": "https://api", "scope": "a b c", "iat": now.Add(-30 * time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
			"may_act": map[string]any{"sub": "p"}}
	}
	tok1 := func() map[string]any {
		return map[string]any{"sub": "alice", "aud": "https://api", "scope": "a b", "iat": now.Add(-10 * time.Minute).Unix(), "exp": now.Add(30 * time.Minute).Unix(),
			"act": map[string]any{"sub": "p"}}
	}
	tests := []struct {
		name   string
		edit   func(t0, t1 map[string]any)
		rule   string
		status chain.Status
		says   string
	}{
		{"a clean exchange holds every rule", nil, RuleExtends, chain.StatusPass, "adds p"},
		{"an actor may_act does not name fails", func(_, t1 map[string]any) { t1["act"] = map[string]any{"sub": "q"} }, RuleMayAct, chain.StatusFail, "lets only p"},
		{"an exchange that adds two actors does not extend", func(_, t1 map[string]any) {
			t1["act"] = map[string]any{"sub": "p", "act": map[string]any{"sub": "z"}}
		}, RuleExtends, chain.StatusFail, "adds exactly one"},
		{"a scope the token above lacked widens", func(_, t1 map[string]any) { t1["scope"] = "a d" }, RuleScope, chain.StatusFail, "adds d"},
		{"scope after a token without one cannot be judged", func(t0, _ map[string]any) { delete(t0, "scope") }, RuleScope, chain.StatusUnchecked, "names no scope"},
		{"scp as an array is read", func(_, t1 map[string]any) { delete(t1, "scope"); t1["scp"] = []any{"a"} }, RuleScope, chain.StatusPass, "1 of"},
		{"a changed subject fails", func(_, t1 map[string]any) { t1["sub"] = "mallory" }, RuleSubject, chain.StatusFail, "same subject"},
		{"a later expiry fails", func(_, t1 map[string]any) { t1["exp"] = now.Add(2 * time.Hour).Unix() }, RuleExpiry, chain.StatusFail, "after token 0"},
		{"a dropped expiry fails", func(_, t1 map[string]any) { delete(t1, "exp") }, RuleExpiry, chain.StatusFail, "removed the expiry"},
		{"a token expired before the next was issued fails", func(t0, _ map[string]any) { t0["exp"] = now.Add(-20 * time.Minute).Unix() }, RuleTime, chain.StatusFail, "before token 1"},
		{"no iat on the next token leaves the earlier one's time unknown", func(_, t1 map[string]any) { delete(t1, "iat") }, RuleTime, chain.StatusUnchecked, "no iat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t0, t1 := tok0(), tok1()
			if tt.edit != nil {
				tt.edit(t0, t1)
			}
			c := bundleSession(t0, t1).evaluate(now)
			link := 1
			if tt.rule == RuleTime {
				link = 0
			}
			got := c.Links[link].Check(tt.rule)
			if got.Status != tt.status || !strings.Contains(got.Detail, tt.says) {
				t.Errorf("%s: %s %q, want %s mentioning %q", tt.rule, got.Status, got.Detail, tt.status, tt.says)
			}
			if problems := chaintest.Problems(c); len(problems) > 0 {
				t.Errorf("the chain breaks the contract: %v", problems)
			}
		})
	}
}

func TestTimeAndAudience(t *testing.T) {
	mk := func(claims map[string]any, aud *string) *chain.Chain {
		p, _ := json.Marshal(claims)
		return newSession([]string{compact(`{"alg":"EdDSA"}`, string(p), "c2ln")}, nil, aud, nil).evaluate(base)
	}
	api := "https://api"
	tests := []struct {
		name   string
		claims map[string]any
		aud    *string
		rule   string
		status chain.Status
	}{
		{"expired", map[string]any{"sub": "a", "exp": base.Add(-time.Minute).Unix()}, &api, RuleTime, chain.StatusFail},
		{"within the skew", map[string]any{"sub": "a", "exp": base.Add(10 * time.Second).Unix()}, &api, RuleTime, chain.StatusPass},
		{"not yet valid", map[string]any{"sub": "a", "nbf": base.Add(time.Hour).Unix()}, &api, RuleTime, chain.StatusFail},
		{"issued in the future", map[string]any{"sub": "a", "iat": base.Add(time.Hour).Unix()}, &api, RuleTime, chain.StatusFail},
		{"a non-numeric exp reads as absent", map[string]any{"sub": "a", "exp": "tomorrow"}, &api, RuleTime, chain.StatusPass},
		{"an audience among several", map[string]any{"sub": "a", "aud": []any{"x", "https://api"}}, &api, RuleAudience, chain.StatusPass},
		{"the wrong audience", map[string]any{"sub": "a", "aud": "https://other"}, &api, RuleAudience, chain.StatusFail},
		{"no audience in the token", map[string]any{"sub": "a"}, &api, RuleAudience, chain.StatusFail},
		{"no audience given", map[string]any{"sub": "a", "aud": "x"}, nil, RuleAudience, chain.StatusUnchecked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mk(tt.claims, tt.aud)
			if got := c.Leaf().Check(tt.rule); got.Status != tt.status {
				t.Errorf("%s %q, want %s", got.Status, got.Detail, tt.status)
			}
		})
	}
}

func TestActorShapes(t *testing.T) {
	tests := []struct {
		name   string
		claims string
		status chain.Status
		links  int
	}{
		{"an act that is not an object fails", `{"sub":"a","act":"agent"}`, chain.StatusFail, 1},
		{"a current actor without sub fails", `{"sub":"a","act":{"iss":"x"}}`, chain.StatusFail, 1},
		{"a token without act is held by its client", `{"sub":"a","client_id":"app"}`, chain.StatusPass, 1},
		{"a Txn-Token's requesting workload holds it", `{"sub":"a","req_wl":"spiffe://w"}`, chain.StatusPass, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newSession([]string{compact(`{"alg":"EdDSA"}`, tt.claims, "c2ln")}, nil, nil, nil).evaluate(base)
			if got := c.Leaf().Check(RuleActor); got.Status != tt.status {
				t.Errorf("%s %q, want %s", got.Status, got.Detail, tt.status)
			}
			if len(c.Links) != tt.links {
				t.Errorf("%d links", len(c.Links))
			}
		})
	}
	deep := `{"sub":"a","act":` + strings.Repeat(`{"sub":"x","act":`, MaxActors+5) + `{"sub":"y"}` + strings.Repeat("}", MaxActors+5) + `}`
	tok := parse(compact(`{"alg":"EdDSA"}`, deep, "c2ln"))
	if tok.ActProblem == "" || len(tok.Actors) > MaxActors {
		t.Errorf("a chain nested past %d actors was read: %d actors, %q", MaxActors, len(tok.Actors), tok.ActProblem)
	}
}

func TestEntraNamesItsAgentAndParent(t *testing.T) {
	c := evalScenario(t, "jwt-entra-agent")
	if !c.Links[0].Asserted || c.Links[0].To != "blueprint-7d2b" || c.Links[1].To != "agent-c1f5" {
		t.Fatalf("links %q %q asserted=%v", c.Links[0].To, c.Links[1].To, c.Links[0].Asserted)
	}
	var found bool
	for _, sec := range c.Links[1].Sections {
		for _, l := range sec.Lines {
			if strings.Contains(l.Value, "11 AgentIdentity") {
				found = true
			}
		}
	}
	if !found {
		t.Error("the agent facet is not labelled")
	}
}

func TestDetect(t *testing.T) {
	a := New()
	for _, sc := range a.Scenarios() {
		s, _ := sc.Open(base)
		raws := s.(*session).tokens
		in, _ := json.Marshal([]string{raws[0].Raw})
		if got := a.Detect(in); got == chain.NotMine {
			t.Errorf("%s: its own token is not claimed", sc.Name)
		}
	}
	tests := []struct {
		name string
		in   string
		want chain.Confidence
	}{
		{"act makes a JWT certain", compact(`{"alg":"RS256"}`, `{"sub":"a","act":{"sub":"b"}}`, "c2ln"), chain.Certain},
		{"an ID-JAG media type is certain", compact(`{"alg":"RS256","typ":"oauth-id-jag+jwt"}`, `{"sub":"a"}`, "c2ln"), chain.Certain},
		{"application/ and case do not matter", compact(`{"alg":"RS256","typ":"application/TxnToken+JWT"}`, `{"sub":"a"}`, "c2ln"), chain.Certain},
		{"a plain JWT is plausible", compact(`{"alg":"RS256","typ":"JWT"}`, `{"sub":"a"}`, "c2ln"), chain.Plausible},
		{"a Bearer header is read", "Bearer " + compact(`{"alg":"RS256"}`, `{"sub":"a","act":{"sub":"b"}}`, "c2ln"), chain.Certain},
		{"a Mandatum link is not mine", compact(`{"alg":"EdDSA","typ":"mdt+jwt"}`, `{"sub":"a"}`, "c2ln"), chain.NotMine},
		{"Mandatum claims are not mine", compact(`{"alg":"EdDSA"}`, `{"sub":"a","mdt":{}}`, "c2ln"), chain.NotMine},
		{"garbage", "not a token", chain.NotMine},
		{"empty", "", chain.NotMine},
		{"a JWE", "a.b.c.d.e", chain.NotMine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.Detect([]byte(tt.in)); got != tt.want {
				t.Errorf("%v, want %v", got, tt.want)
			}
		})
	}
	// Mandatum's own demo chain is never claimed Certain by this adapter.
	for _, sc := range mandatum.New().Scenarios() {
		s, err := sc.Open(base)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := s.Evaluate(context.Background(), chain.EvalOptions{At: base})
		_ = c
		dir := t.TempDir()
		if sc.Emit == nil {
			continue
		}
		if _, err := sc.Emit(dir, true); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "chain.json"))
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Detect(data); got != chain.NotMine {
			t.Errorf("Mandatum scenario %s is %v to the JWT adapter", sc.Name, got)
		}
		break
	}
}

func TestOpenReadsFlagsAndRefusesBadOnes(t *testing.T) {
	dir := t.TempDir()
	if _, err := emitDemo(scenarioDefs()[1], dir, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	aud := demoAPI
	s, err := New().Open(context.Background(), chain.Inputs{Data: data, TrustFile: filepath.Join(dir, "trust.json"), Audience: &aud, At: FixedBase.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := s.Evaluate(context.Background(), chain.EvalOptions{At: FixedBase.Add(time.Minute)})
	if c.Verdict != chain.VerdictValid {
		t.Errorf("the emitted healthy bundle is %s: %v", c.Verdict, c.Findings())
	}
	if _, err := New().Open(context.Background(), chain.Inputs{Data: data, JWKS: []string{"x=/nonexistent/keys.json"}}); err == nil {
		t.Error("an unreadable key file was accepted")
	}
	if _, err := New().Open(context.Background(), chain.Inputs{Data: []byte("   ")}); err == nil {
		t.Error("an empty input was accepted")
	}
	many := strings.Repeat(string(data[:0])+"a.b.c\n", MaxTokens+1)
	if _, err := New().Open(context.Background(), chain.Inputs{Data: []byte(many)}); err == nil {
		t.Error("more tokens than the limit were accepted")
	}
	reversed, err := New().Open(context.Background(), chain.Inputs{Data: data, TrustFile: filepath.Join(dir, "trust.json"), Audience: &aud, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := reversed.Evaluate(context.Background(), chain.EvalOptions{At: FixedBase.Add(time.Minute)})
	if rc.Verdict != chain.VerdictInvalid || !rc.Reversed {
		t.Errorf("a bundle read backwards should break: %s", rc.Verdict)
	}
}

// The emitted command checks the emitted files and reaches the same
// verdict as the in-process demo.
func TestEmitWritesWhatTheCommandChecks(t *testing.T) {
	for _, def := range scenarioDefs() {
		dir := t.TempDir()
		cmd, err := emitDemo(def, dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cmd, "--format jwt") || !strings.Contains(cmd, "--at ") {
			t.Errorf("%s: %s", def.name, cmd)
		}
		if _, err := emitDemo(def, dir, false); err == nil {
			t.Errorf("%s: a second emit into a full directory was accepted without force", def.name)
		}
		fi, err := os.Stat(filepath.Join(dir, "jwks"))
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: the key directory is %v", def.name, fi.Mode())
		}
	}
	// A symlink planted at the token's name is replaced, not written
	// through.
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "token.jwt")); err != nil {
		t.Skip("no symlinks here")
	}
	if _, err := emitDemo(scenarioDefs()[0], dir, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Error("emit wrote through a symlink")
	}
}

func TestDemoTokensAreTheSameBytesEveryTime(t *testing.T) {
	for _, def := range scenarioDefs() {
		a, b := def.mint(base), def.mint(base)
		if strings.Join(a.tokens, ",") != strings.Join(b.tokens, ",") {
			t.Errorf("%s: minted twice, different bytes", def.name)
		}
	}
	if len(scenarioNames()) != len(scenarioDefs()) {
		t.Error("scenario names")
	}
}

func TestAsk(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		scenario  string
		scope     string
		aud       string
		verdict   string
		permitted bool
		warning   string
	}{
		{"jwt-bundle-healthy", "files:read", demoAPI, "PERMITTED", true, ""},
		{"jwt-bundle-healthy", "files:write", demoAPI, "DENIED", false, ""},
		{"jwt-bundle-healthy", "files:read", "https://elsewhere", "DENIED", false, ""},
		{"jwt-bundle-widened", "files:write", demoAPI, "DENIED", false, "token 1 dropped it"},
		{"jwt-unchecked", "files:read", demoAPI, "PERMITTED IF", true, "issuer's word"},
		{"jwt-okta-style", "files:read", "", "PERMITTED", true, "issuer's word"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario+" "+tt.scope, func(t *testing.T) {
			c := evalScenario(t, tt.scenario)
			var s *session
			for _, sc := range New().Scenarios() {
				if sc.Name == tt.scenario {
					ss, _ := sc.Open(base)
					s = ss.(*session)
				}
			}
			res, err := s.Ask(ctx, c, map[string]string{askScope: tt.scope, askAudience: tt.aud})
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != tt.verdict || res.Permitted != tt.permitted {
				t.Errorf("%s permitted=%v (%s), want %s %v", res.Verdict, res.Permitted, res.Why, tt.verdict, tt.permitted)
			}
			if tt.warning != "" && !strings.Contains(res.Warning, tt.warning) {
				t.Errorf("warning %q, want one mentioning %q", res.Warning, tt.warning)
			}
		})
	}
	c := evalScenario(t, "jwt-okta-style")
	s, _ := New().Scenarios()[0].Open(base)
	for _, bad := range []string{"", "a b"} {
		if _, err := s.(*session).Ask(ctx, c, map[string]string{askScope: bad}); err == nil {
			t.Errorf("scope %q was accepted", bad)
		}
	}
}

// Strings from a token reach the model as they are: the view and the
// command line clean them. The adapter must still carry them, so the
// cleaning has something to clean, and must not panic on them.
func TestHostileClaimsAreCarriedNotInterpreted(t *testing.T) {
	evil := "x\x1b]52;c;aGk=\x07\u202e\r\nfake"
	claims := map[string]any{"iss": evil, "sub": evil, "aud": evil, "scope": evil + " " + evil, "client_id": evil,
		"act": map[string]any{"sub": evil, "iss": evil, "sub_profile": evil, "act": map[string]any{"sub": evil}}}
	p, _ := json.Marshal(claims)
	c := newSession([]string{compact(`{"alg":"EdDSA","kid":"`+"k\\u001b[2J"+`"}`, string(p), "c2ln")}, nil, &evil, nil).evaluate(base)
	if c.Root.Name != evil || c.Leaf().To != evil {
		t.Errorf("the hostile subject did not reach the model unchanged: %q %q", c.Root.Name, c.Leaf().To)
	}
	if problems := chaintest.Problems(c); len(problems) > 0 {
		t.Error(problems)
	}
}

func FuzzParse(f *testing.F) {
	for _, def := range scenarioDefs() {
		for _, tok := range def.mint(base).tokens {
			f.Add(tok)
		}
	}
	f.Add(compact(`{"alg":"RS256"}`, `{"act":{"act":{"act":null}}}`, "c2ln"))
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, raw string) {
		s := newSession([]string{raw, raw}, nil, nil, nil)
		c := s.evaluate(base)
		if problems := chaintest.Problems(c); len(problems) > 0 {
			t.Errorf("%q: %v", raw, problems)
		}
		_ = (Adapter{}).Detect([]byte(raw))
	})
}
