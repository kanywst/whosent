package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

var chainKeys = []demoKey{keyChainAS, keyChainPlanner, keyChainResearch}

// evalChain checks the given tokens, presented to demoAPI, with the given
// keys.
func evalChain(raws []string, ks ...demoKey) *chain.Chain {
	kr, ak := keysOf(ks...)
	aud := demoAPI
	s := newSession(raws, kr, &aud, nil)
	s.actorKeys = ak
	return s.evaluate(base.Add(time.Minute))
}

// lastToken mints the healthy workflow with the edits and returns the
// research agent's token.
func lastToken(ed *chainEdits) string {
	toks := mintActorChain(base, chainHops(keyChainPlanner), ed)
	return toks[len(toks)-1]
}

// retoken re-signs the last token after changing its claims.
func retoken(change func(c map[string]any)) string {
	return lastToken(&chainEdits{token: func(i int, c map[string]any) {
		if i == 1 {
			change(c)
		}
	}})
}

func TestActorChain(t *testing.T) {
	tests := []struct {
		name  string
		token string
		keys  []demoKey
		want  chain.Status // J12 on the token's link
		says  string
		// signed is whether the planner's link is the actor's own word.
		signed bool
	}{
		{"path evidence, every step signed and accepted", lastToken(nil), chainKeys, chain.StatusPass, "all 2 actors signed", true},
		{"without the actors' keys nothing is verified", lastToken(nil), []demoKey{keyChainAS}, chain.StatusUnchecked, "no keys for actor", false},
		{"one actor's keys missing leaves its step unchecked", lastToken(nil), []demoKey{keyChainAS, keyChainResearch}, chain.StatusUnchecked, "planner-agent", false},
		{"a forged step proof fails", func() string {
			toks := mintActorChain(base, chainHops(keyChainForger), nil)
			return toks[1]
		}(), chainKeys, chain.StatusFail, "does not verify", false},
		{"an acceptance for another proof", lastToken(&chainEdits{acc: func(i int, c map[string]any) {
			if i == 0 {
				c["step_hash"] = digest("another proof")
			}
		}}), chainKeys, chain.StatusFail, "step_hash", false},
		{"a path spliced at its second step", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 1 {
				c["prev"] = digest("another acceptance")
			}
		}, acc: func(i int, c map[string]any) {
			if i == 1 {
				c["prev"] = digest("another acceptance")
			}
		}}), chainKeys, chain.StatusFail, "prev is not the SHA-256", false},
		{"an opening the actor never committed to", retoken(func(c map[string]any) {
			st := c["acte"].(map[string]any)["steps"].([]any)[0].(map[string]any)
			st["opening"].(map[string]any)["salt"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}), chainKeys, chain.StatusFail, "view_commitment", false},
		{"commitment only shows no actor's signature", retoken(func(c map[string]any) { delete(c, "acte") }), chainKeys, chain.StatusPass, "no actor evidence", false},
		{"current evidence covers only the current actor", retoken(func(c map[string]any) {
			e := c["acte"].(map[string]any)
			st := e["steps"].([]any)[1].(map[string]any)
			delete(st, "opening")
			e["coverage"], e["steps"] = "current", []any{st}
		}), chainKeys, chain.StatusPass, "the current actor signed", false},
		{"disclosed evidence stands on the issuer's attestation", retoken(func(c map[string]any) {
			e := c["acte"].(map[string]any)
			for _, st := range e["steps"].([]any) {
				delete(st.(map[string]any), "opening")
			}
			e["v"], e["coverage"] = 2, "disclosed"
		}), chainKeys, chain.StatusPass, "disclosed actors signed", true},
		{"disclosed coverage under version 1", retoken(func(c map[string]any) {
			e := c["acte"].(map[string]any)
			e["coverage"] = "disclosed"
		}), chainKeys, chain.StatusFail, "not a pairing", false},
		{"introspection delivery is not fetched", retoken(func(c map[string]any) {
			c["acte"] = map[string]any{"v": 1, "coverage": "path", "delivery": "introspection"}
		}), chainKeys, chain.StatusPass, "not fetched", false},
		{"path evidence only under verified-full", lastToken(&chainEdits{
			proof: func(_ int, c map[string]any) { c["actp"] = "verified-subset" },
			acc:   func(_ int, c map[string]any) { c["actp"] = "verified-subset" },
			token: func(_ int, c map[string]any) { c["actp"] = "verified-subset" },
		}), chainKeys, chain.StatusFail, "only for verified-full", false},
		{"a declared profile carries no actc", retoken(func(c map[string]any) { c["actp"] = "declared-full" }), chainKeys, chain.StatusFail, "Declared profile carries no actc", false},
		{"a declared profile is the issuer's word", retoken(func(c map[string]any) {
			c["actp"] = "declared-full"
			delete(c, "actc")
			delete(c, "acte")
		}), chainKeys, chain.StatusPass, "issuer's assertion", false},
		{"an unknown profile fails closed", retoken(func(c map[string]any) { c["actp"] = "verified-everything" }), chainKeys, chain.StatusFail, "not a profile", false},
		{"acti without actp", retoken(func(c map[string]any) { delete(c, "actp") }), chainKeys, chain.StatusFail, "acti without actp", false},
		{"an act member with more than iss and sub", retoken(func(c map[string]any) {
			c["act"].(map[string]any)["sub_profile"] = "ai_agent"
		}), chainKeys, chain.StatusFail, "exactly iss and sub", false},
		{"an extra header member is never ignored", lastToken(&chainEdits{header: func(_ int, h map[string]any) {
			h["jku"] = "https://attacker.example/keys"
		}}), chainKeys, chain.StatusFail, `member "jku"`, false},
		{"the polymorphic EdDSA identifier", lastToken(&chainEdits{header: func(_ int, h map[string]any) {
			h["alg"] = "EdDSA"
		}}), chainKeys, chain.StatusFail, "fully specified", false},
		{"a token wider than the actor asked", retoken(func(c map[string]any) { c["scope"] = "files:read files:write" }), chainKeys, chain.StatusFail, "did not ask for", false},
		{"a scope that is not canonical", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 0 {
				c["target_context"].(map[string]any)["scope"] = "files:write files:read"
			}
		}}), chainKeys, chain.StatusFail, "not canonical", false},
		{"a resource other than the one presented to", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 1 {
				c["target_context"].(map[string]any)["resource"] = "https://billing.acme.example"
			}
		}}), chainKeys, chain.StatusFail, "compares them exactly", false},
		{"a step signed for another subject", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 0 {
				c["sub"] = "mallory@acme.example"
			}
		}}), chainKeys, chain.StatusFail, "subject mapping", false},
		{"accepted before the actor signed", lastToken(&chainEdits{acc: func(i int, c map[string]any) {
			if i == 0 {
				c["accepted_at"] = unix(base.Add(-15 * time.Minute))
			}
		}}), chainKeys, chain.StatusFail, "before the actor signed", false},
		{"accepted past the recommended window is said, not failed", lastToken(&chainEdits{acc: func(i int, c map[string]any) {
			if i == 0 {
				c["accepted_at"] = unix(base.Add(-5 * time.Minute))
			}
		}}), chainKeys, chain.StatusPass, "all 2 actors", true},
		{"an empty request_id", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 0 {
				c["request_id"] = ""
			}
		}}), chainKeys, chain.StatusFail, "request_id", false},
		{"path evidence promised by introspection under a subset profile", lastToken(&chainEdits{
			proof: func(_ int, c map[string]any) { c["actp"] = "verified-subset" },
			acc:   func(_ int, c map[string]any) { c["actp"] = "verified-subset" },
			token: func(_ int, c map[string]any) {
				c["actp"] = "verified-subset"
				c["acte"] = map[string]any{"v": 1, "coverage": "path", "delivery": "introspection"}
			},
		}), chainKeys, chain.StatusFail, "only for verified-full", false},
		{"a NumericDate that is not an integer", lastToken(&chainEdits{proof: func(i int, c map[string]any) {
			if i == 0 {
				c["iat"] = 1786827601.5
			}
		}}), chainKeys, chain.StatusFail, "not an integer", false},
		{"evidence for another head", retoken(func(c map[string]any) {
			e := c["acte"].(map[string]any)
			e["steps"] = e["steps"].([]any)[:1]
			c["act"] = map[string]any{"iss": demoAgents, "sub": "planner-agent"}
		}), chainKeys, chain.StatusFail, "not the token's actc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := evalChain([]string{tt.token}, tt.keys...)
			last := c.Links[len(c.Links)-1]
			got := last.Check(RuleChain)
			if got.Status != tt.want || !strings.Contains(got.Detail, tt.says) {
				t.Fatalf("J12 = %s %q, want %s containing %q", got.Status, got.Detail, tt.want, tt.says)
			}
			planner := c.Links[0]
			if signed := !planner.Asserted && len(c.Links) == 2; signed != tt.signed {
				t.Errorf("planner signed = %v, want %v", signed, tt.signed)
			}
			if len(c.Links) == 2 && !planner.Asserted && planner.Check(RuleChain).Status != chain.StatusPass {
				t.Errorf("a planner drawn as its own word has J12 %s", planner.Check(RuleChain).Status)
			}
		})
	}
}

// Without --audience the current step's resource is not compared, so J12
// does not pass.
func TestActorChainNeedsTheAudience(t *testing.T) {
	kr, ak := keysOf(chainKeys...)
	s := newSession([]string{lastToken(nil)}, kr, nil, nil)
	s.actorKeys = ak
	c := s.evaluate(base.Add(time.Minute))
	if got := c.Leaf().Check(RuleChain); got.Status != chain.StatusUnchecked || !strings.Contains(got.Detail, "--audience") {
		t.Fatalf("J12 = %s %q, want unchecked for want of --audience", got.Status, got.Detail)
	}
	if c.Links[0].Asserted == false {
		t.Error("the planner is drawn as its own word while the chain is unchecked")
	}
}

// Declared tokens of one bundle are one workflow too.
func TestDeclaredBundleKeepsItsWorkflow(t *testing.T) {
	declared := func(acti string) func(int, map[string]any) {
		return func(_ int, c map[string]any) {
			c["actp"], c["acti"] = "declared-full", acti
			delete(c, "actc")
			delete(c, "acte")
		}
	}
	a := mintActorChain(base, chainHops(keyChainPlanner), &chainEdits{token: declared("wf-a")})
	b := mintActorChain(base, chainHops(keyChainPlanner), &chainEdits{token: declared("wf-b")})
	c := evalChain([]string{a[0], b[1]}, chainKeys...)
	if got := c.Links[1].Check(RuleChain); got.Status != chain.StatusFail || !strings.Contains(got.Detail, "acti is stable") {
		t.Fatalf("J12 = %s %q, want a workflow mismatch", got.Status, got.Detail)
	}
}

// A token whose claims repeat a member is read two ways by two parsers;
// the draft rejects it, though encoding/json keeps the last.
func TestActorChainRejectsRepeatedMembers(t *testing.T) {
	tok := lastToken(nil)
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	dup := strings.Replace(string(payload), `"actp":"verified-full"`, `"actp":"declared-full","actp":"verified-full"`, 1)
	if dup == string(payload) {
		t.Fatal("the payload holds no actp to repeat")
	}
	ed := map[string]any{"alg": "EdDSA", "kid": keyChainAS.kid, "typ": "at+jwt"}
	raw := mintPayload(keyChainAS, ed, []byte(dup))
	c := evalChain([]string{raw}, chainKeys...)
	if got := c.Links[len(c.Links)-1].Check(RuleChain); got.Status != chain.StatusFail || !strings.Contains(got.Detail, "repeats member") {
		t.Fatalf("J12 = %s %q, want a repeated member failure", got.Status, got.Detail)
	}
}

// A bundle is held to one workflow: each exchange's acceptance extends the
// one before it.
func TestActorChainBundle(t *testing.T) {
	toks := mintActorChain(base, chainHops(keyChainPlanner), nil)
	c := evalChain(toks, chainKeys...)
	if c.Verdict != chain.VerdictValid {
		t.Fatalf("a healthy bundle is %s: %v", c.Verdict, c.Findings())
	}
	other := mintActorChain(base, chainHops(keyChainPlanner), &chainEdits{
		proof: func(_ int, c map[string]any) { c["acti"] = "wf-other" },
		acc:   func(_ int, c map[string]any) { c["acti"] = "wf-other" },
		token: func(_ int, c map[string]any) { c["acti"] = "wf-other" },
	})
	c = evalChain([]string{toks[0], other[1]}, chainKeys...)
	if got := c.Links[1].Check(RuleChain); got.Status != chain.StatusFail || !strings.Contains(got.Detail, "acti is stable") {
		t.Fatalf("J12 = %s %q, want a workflow mismatch", got.Status, got.Detail)
	}
}

// The view-commitment is over RFC 8785 JSON, which writes <, > and & as
// they are; encoding/json would escape them and never match.
func TestJCSActors(t *testing.T) {
	got := string(jcsActors([]actorID{{Iss: "https://a.example/<x>&", Sub: "q\" \x01"}}))
	want := `[{"iss":"https://a.example/<x>&","sub":"q\"` + " " + `\u0001"}]`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestActorChainScenariosConform(t *testing.T) {
	for _, name := range []string{"jwt-actor-chain", "jwt-actor-chain-forged"} {
		c := evalScenario(t, name)
		if name == "jwt-actor-chain" && c.Headline == "" {
			t.Errorf("%s has no headline", name)
		}
	}
}

// mintPayload signs payload bytes as they are, so a test can sign JSON
// that encoding/json would never produce.
func mintPayload(k demoKey, header map[string]any, payload []byte) string {
	h, _ := json.Marshal(header)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.key, []byte(input)))
}
