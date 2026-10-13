package jwt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

// proofCase builds a token carrying actor proofs for planner-agent (older)
// and research-agent (newer), lets the case change any part of it, and
// opens it with the issuer's and both actors' keys.
type proofCase struct {
	older, newer map[string]any
	olderKey     demoKey
	token        map[string]any
	// proofs replaces actor_proofs after both are minted, by index into
	// [newer, older].
	proofs func(newer, older string) []string
}

func proofClaims(k demoKey, aud string) map[string]any {
	return map[string]any{
		"iss": k.sub, "sub": demoUser, "act": map[string]any{"sub": k.sub, "iss": k.iss, "sub_profile": "ai_agent"},
		"target": map[string]any{"aud": []any{aud}},
		"iat":    unix(base.Add(-10 * time.Minute)), "exp": unix(base.Add(time.Hour)), "jti": "proof-" + k.sub,
	}
}

func newProofCase() *proofCase {
	return &proofCase{
		older:    proofClaims(keyPlanner, demoOkta),
		newer:    proofClaims(keyResearch, demoAPI),
		olderKey: keyPlanner,
		token: map[string]any{
			"iss": demoOkta, "sub": demoUser, "aud": demoAPI, "jti": "at-1",
			"iat": unix(base.Add(-2 * time.Minute)), "exp": unix(base.Add(30 * time.Minute)),
			"act":                   act("research-agent", "ai_agent", act("planner-agent", "ai_agent", nil)),
			"actor_proofs_complete": true,
		},
	}
}

func (pc *proofCase) mint() string {
	older := mint(pc.olderKey, typActorProof, pc.older)
	if _, ok := pc.newer["prh"]; !ok {
		alg := "sha-256"
		if a, ok := pc.newer["prh_alg"].(string); ok {
			alg = a
		}
		pc.newer["prh"] = prhOf(alg, older)
	}
	newer := mint(keyResearch, typActorProof, pc.newer)
	if _, ok := pc.token["actor_proofs"]; !ok {
		list := []string{newer, older}
		if pc.proofs != nil {
			list = pc.proofs(newer, older)
		}
		pc.token["actor_proofs"] = list
	}
	return mint(keyOkta, "at+jwt", pc.token)
}

func keysOf(ks ...demoKey) (keyring, actorKeyring) {
	kr, ak := keyring{}, actorKeyring{}
	for _, k := range ks {
		var set jose.JSONWebKeySet
		_ = json.Unmarshal(k.jwks(), &set)
		ik := &issuerKeys{Source: k.kid + ".json", Keys: set.Keys}
		if k.sub != "" {
			ak[actorID{Iss: k.iss, Sub: k.sub}] = ik
		} else {
			kr[k.iss] = ik
		}
	}
	return kr, ak
}

func evalProofs(raws []string, ks ...demoKey) *chain.Chain {
	kr, ak := keysOf(ks...)
	aud := demoAPI
	s := newSession(raws, kr, &aud, nil)
	s.actorKeys = ak
	return s.evaluate(base.Add(time.Minute))
}

var allKeys = []demoKey{keyOkta, keyPlanner, keyResearch}

func TestActorProofs(t *testing.T) {
	tests := []struct {
		name   string
		change func(pc *proofCase)
		keys   []demoKey
		want   chain.Status // J11 on the token's link
		says   string
		// signed is whether the planner's link is the actor's own word.
		signed bool
	}{
		{"every actor signed, hash-linked", nil, allKeys, chain.StatusPass, "2 of 2 actors", true},
		{"without the actors' keys nothing is verified", nil, []demoKey{keyOkta}, chain.StatusUnchecked, "no keys for actor", false},
		{"an older proof for another subject does not stand for its actor", func(pc *proofCase) { pc.older["sub"] = "mallory@victim.example" }, allKeys, chain.StatusPass, "", false},
		{"a chain linked with sha-384 holds", func(pc *proofCase) {
			pc.older["prh_alg"], pc.newer["prh_alg"] = "sha-384", "sha-384"
		}, allKeys, chain.StatusPass, "sha-384", true},
		{"sub_profile compares as a set", func(pc *proofCase) {
			pc.token["act"] = act("research-agent", "AI_Agent ai_agent", act("planner-agent", "ai_agent", nil))
		}, allKeys, chain.StatusPass, "", true},
		{"a forged older proof fails", func(pc *proofCase) { pc.olderKey = keyForger }, allKeys, chain.StatusFail, "does not verify", false},
		{"an altered older proof breaks the hash link", func(pc *proofCase) {
			pc.proofs = func(newer, _ string) []string {
				c := proofClaims(keyPlanner, "https://elsewhere.example")
				return []string{newer, mint(keyPlanner, typActorProof, c)}
			}
		}, allKeys, chain.StatusFail, "prh is not the sha-256", false},
		{"reordered proofs do not align with the act chain", func(pc *proofCase) {
			pc.proofs = func(newer, older string) []string { return []string{older, newer} }
		}, allKeys, chain.StatusFail, "act chain names", false},
		{"more proofs than actors", func(pc *proofCase) {
			pc.proofs = func(newer, older string) []string { return []string{newer, older, older} }
		}, allKeys, chain.StatusFail, "3 proofs for 2 actors", false},
		{"complete with one proof missing", func(pc *proofCase) {
			delete(pc.newer, "prh")
			pc.newer["prh"] = nil
			pc.proofs = func(newer, _ string) []string { return []string{newer} }
		}, allKeys, chain.StatusFail, "actor_proofs_complete is true", false},
		{"the newest proof alone is partial coverage", func(pc *proofCase) {
			pc.token["actor_proofs_complete"] = false
			pc.token["actor_proofs"] = []string{mint(keyResearch, typActorProof, pc.newer)}
		}, allKeys, chain.StatusPass, "1 of 2 actors", false},
		{"the oldest proof carrying prh", func(pc *proofCase) {
			pc.token["actor_proofs_complete"] = false
			pc.newer["prh"] = "AAAA"
			pc.token["actor_proofs"] = []string{mint(keyResearch, typActorProof, pc.newer)}
		}, allKeys, chain.StatusFail, "oldest but carries prh", false},
		{"a newer proof without prh", func(pc *proofCase) {
			pc.proofs = func(_, older string) []string {
				c := proofClaims(keyResearch, demoAPI)
				return []string{mint(keyResearch, typActorProof, c), older}
			}
		}, allKeys, chain.StatusFail, "no prh", false},
		{"mixed prh_alg", func(pc *proofCase) { pc.older["prh_alg"] = "sha-256" }, allKeys, chain.StatusFail, "same prh_alg", false},
		{"a truncated hash", func(pc *proofCase) {
			pc.older["prh_alg"], pc.newer["prh_alg"], pc.newer["prh"] = "sha-256-128", "sha-256-128", "x"
		}, allKeys, chain.StatusFail, "not a hash whosent supports", false},
		{"the token outgrew the actor's consent", func(pc *proofCase) { pc.newer["target"] = map[string]any{"aud": "https://other.example"} }, allKeys, chain.StatusFail, "did not consent", false},
		{"a resource the actor did not consent to", func(pc *proofCase) {
			pc.newer["target"] = map[string]any{"aud": demoAPI, "resource": []any{"https://api.acme.example/files"}}
			pc.token["resource"] = "https://api.acme.example/admin"
		}, allKeys, chain.StatusFail, "resource", false},
		{"a proof bound to another token", func(pc *proofCase) { pc.newer["origin_jti"] = "at-2" }, allKeys, chain.StatusFail, "origin_jti", false},
		{"a proof for another subject", func(pc *proofCase) { pc.newer["sub"] = "bob@acme.example" }, allKeys, chain.StatusFail, "subject", false},
		{"a proof carrying aud", func(pc *proofCase) { pc.newer["aud"] = demoAPI }, allKeys, chain.StatusFail, "carries aud", false},
		{"a proof whose iss is not its actor", func(pc *proofCase) { pc.newer["iss"] = "someone-else" }, allKeys, chain.StatusFail, "signs as itself", false},
		{"a proof whose act nests", func(pc *proofCase) {
			pc.newer["act"] = map[string]any{"sub": "research-agent", "iss": demoOkta, "act": map[string]any{"sub": "x"}}
		}, allKeys, chain.StatusFail, "one hop", false},
		{"a proof without exp", func(pc *proofCase) { delete(pc.older, "exp") }, allKeys, chain.StatusFail, "no exp", false},
		{"an expired older proof", func(pc *proofCase) { pc.older["exp"] = unix(base.Add(-time.Minute)) }, allKeys, chain.StatusFail, "expired", false},
		{"a sub_profile the act chain does not say", func(pc *proofCase) {
			pc.token["act"] = act("research-agent", "service", act("planner-agent", "ai_agent", nil))
		}, allKeys, chain.StatusFail, "sub_profile", false},
		{"actor_proofs_complete that is not a boolean", func(pc *proofCase) { pc.token["actor_proofs_complete"] = "true" }, allKeys, chain.StatusFail, "not a boolean", false},
		{"complete with no proofs at all", func(pc *proofCase) { pc.token["actor_proofs"] = nil; delete(pc.token, "actor_proofs") }, allKeys, chain.StatusPass, "", true},
		{"actor_proofs that is not an array", func(pc *proofCase) { pc.token["actor_proofs"] = "x" }, allKeys, chain.StatusFail, "non-empty array", false},
		{"proofs without an act claim", func(pc *proofCase) {
			pc.token["actor_proofs"] = []string{"a.b.c"}
			delete(pc.token, "act")
		}, allKeys, chain.StatusFail, "no act claim", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := newProofCase()
			if tt.change != nil {
				tt.change(pc)
			}
			c := evalProofs([]string{pc.mint()}, tt.keys...)
			if problems := chaintest.Problems(c); len(problems) > 0 {
				t.Fatal(problems)
			}
			leaf := c.Links[len(c.Links)-1].Check(RuleProof)
			if leaf.Status != tt.want || !strings.Contains(leaf.Detail, tt.says) {
				t.Errorf("J11 %s %q, want %s mentioning %q", leaf.Status, leaf.Detail, tt.want, tt.says)
			}
			if len(c.Links) == 2 {
				if signed := !c.Links[0].Asserted; signed != tt.signed {
					t.Errorf("planner signed=%v, want %v (%v)", signed, tt.signed, c.Links[0].Check(RuleProof))
				}
			}
		})
	}
}

// "complete with no proofs at all" above is a token without the claim. The
// claim saying complete with nothing to be complete is malformed.
func TestCompleteWithoutProofsFails(t *testing.T) {
	pc := newProofCase()
	pc.token["actor_proofs"] = nil
	raw := pc.mint()
	var claims map[string]any
	_ = json.Unmarshal(mustSegment(t, raw), &claims)
	delete(claims, "actor_proofs")
	c := evalProofs([]string{mint(keyOkta, "at+jwt", claims)}, allKeys...)
	if got := c.Leaf().Check(RuleProof); got.Status != chain.StatusFail || !strings.Contains(got.Detail, "carries no actor_proofs") {
		t.Errorf("%s %q", got.Status, got.Detail)
	}
}

func fmtFindings(fs []chain.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Detail)
	}
	return strings.Join(out, "; ")
}

func mustSegment(t *testing.T, raw string) []byte {
	t.Helper()
	_, p, problem := segments(raw)
	if problem != "" {
		t.Fatal(problem)
	}
	return p
}

// A prior actor is promoted only when the token carrying its proof has
// every rule checked and holding: a token that fails its own validation is
// rejected under its own rules (section 7 step 1), and one not checked
// leaves the actor asserted.
func TestSignedActorsWaitOnTheirToken(t *testing.T) {
	raw := newProofCase().mint()
	c := evalProofs([]string{raw}, keyPlanner, keyResearch)
	if l := c.Links[0]; !l.Asserted || !strings.Contains(fmtFindings(l.Findings), "does not verify") {
		t.Errorf("issuer keys missing, planner promoted: %v", l.Findings)
	}
	if c.Verdict != chain.VerdictIncomplete {
		t.Errorf("verdict %s", c.Verdict)
	}

	expired := newProofCase()
	expired.token["exp"] = unix(base.Add(-time.Hour))
	expired.token["iat"] = unix(base.Add(-2 * time.Hour))
	c = evalProofs([]string{expired.mint()}, allKeys...)
	if !c.Links[0].Asserted {
		t.Error("an expired token's proofs promoted a prior actor")
	}

	pc := newProofCase()
	pc.token["actor_proofs"] = nil
	delete(pc.token, "actor_proofs")
	pc.mint()
	forged := mint(keyAttacker, "at+jwt", pc.token)
	c = evalProofs([]string{forged}, allKeys...)
	if !c.Links[0].Asserted {
		t.Error("a forged token's proofs promoted a prior actor")
	}
}

func TestMissingActorKeysAreNamed(t *testing.T) {
	c := evalProofs([]string{newProofCase().mint()}, keyOkta)
	if !strings.Contains(strings.Join(c.Missing, ";"), "actors in the --trust file") || !strings.Contains(c.IncompleteReason, "no actor keys") {
		t.Errorf("missing %v, reason %q", c.Missing, c.IncompleteReason)
	}
	c = evalProofs([]string{newProofCase().mint()}, allKeys...)
	if c.Headline == "" || !strings.Contains(c.Headline, "signed its own hop") {
		t.Errorf("headline %q", c.Headline)
	}
}

// An exchange keeps the proofs it inherits byte for byte (section 6.2): a
// bundle whose second token re-encodes the first's proofs breaks there.
func TestBundleProofsArePreserved(t *testing.T) {
	older := mint(keyPlanner, typActorProof, proofClaims(keyPlanner, demoOkta))
	newerClaims := proofClaims(keyResearch, demoAPI)
	newerClaims["prh"] = prhOf("sha-256", older)
	newer := mint(keyResearch, typActorProof, newerClaims)
	tok := func(i int, actors map[string]any, proofs []string, aud string) string {
		return mint(keyOkta, "at+jwt", map[string]any{
			"iss": demoOkta, "sub": demoUser, "aud": aud, "jti": "t" + string(rune('0'+i)),
			"iat": unix(base.Add(time.Duration(i-3) * time.Minute)), "exp": unix(base.Add(30 * time.Minute)),
			"act": actors, "actor_proofs": proofs,
		})
	}
	t0 := tok(0, act("planner-agent", "ai_agent", nil), []string{older}, demoOkta)
	t1 := tok(1, act("research-agent", "ai_agent", act("planner-agent", "ai_agent", nil)), []string{newer, older}, demoAPI)
	c := evalProofs([]string{t0, t1}, allKeys...)
	if c.Verdict != chain.VerdictValid {
		t.Fatalf("%s: %v", c.Verdict, c.Findings())
	}

	other := mint(keyPlanner, typActorProof, map[string]any{
		"iss": "planner-agent", "sub": demoUser, "act": map[string]any{"sub": "planner-agent", "iss": demoOkta, "sub_profile": "ai_agent"},
		"target": map[string]any{"aud": []any{demoOkta}}, "iat": unix(base.Add(-9 * time.Minute)), "exp": unix(base.Add(time.Hour)), "jti": "proof-planner-2",
	})
	t0 = tok(0, act("planner-agent", "ai_agent", nil), []string{other}, demoOkta)
	c = evalProofs([]string{t0, t1}, allKeys...)
	if got := c.Links[1].Check(RuleProof); got.Status != chain.StatusFail || !strings.Contains(got.Detail, "byte for byte") {
		t.Errorf("%s %q", got.Status, got.Detail)
	}
}

// Strings from a proof reach the model as they are, and a hostile proof
// cannot make the model break its promises.
func TestHostileProofsAreCarried(t *testing.T) {
	evil := "x\x1b]52;c;aGk=\x07\u202e\r\nfake"
	pc := newProofCase()
	pc.token["act"] = map[string]any{"sub": evil, "iss": evil, "act": act("planner-agent", "ai_agent", nil)}
	pc.newer["iss"], pc.newer["act"] = evil, map[string]any{"sub": evil, "iss": evil}
	pc.newer["jti"] = evil
	c := evalProofs([]string{pc.mint()}, allKeys...)
	if problems := chaintest.Problems(c); len(problems) > 0 {
		t.Error(problems)
	}
	if !strings.Contains(c.Leaf().Check(RuleProof).Detail, evil) {
		t.Errorf("the hostile actor did not reach the model unchanged: %q", c.Leaf().Check(RuleProof).Detail)
	}
}

func TestPrhAlgsAreAtLeastSHA256(t *testing.T) {
	for name, h := range prhAlgs {
		if h().Size() < 32 {
			t.Errorf("%s is shorter than SHA-256", name)
		}
	}
}
