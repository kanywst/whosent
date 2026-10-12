package ucan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

func TestTheAdapterKeepsTheContract(t *testing.T) {
	chaintest.Run(t, New())
}

func open(t *testing.T, name string) *Session {
	t.Helper()
	for _, sc := range New().Scenarios() {
		if sc.Name == name {
			s, err := sc.Open(chaintest.Base)
			if err != nil {
				t.Fatal(err)
			}
			return s.(*Session)
		}
	}
	t.Fatalf("no scenario %q", name)
	return nil
}

func evaluate(t *testing.T, name string, at time.Duration, sim ...string) *chain.Chain {
	t.Helper()
	c, err := open(t, name).Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(at), SimRevoked: sim})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func failing(c *chain.Chain) map[string][]int {
	out := map[string][]int{}
	for _, l := range c.Links {
		for _, ch := range l.Checks {
			if ch.Status.Blocking() {
				out[ch.Rule] = append(out[ch.Rule], l.Index)
			}
		}
	}
	return out
}

func TestEachScenarioBreaksWhereItShould(t *testing.T) {
	tests := []struct {
		name    string
		verdict chain.Verdict
		breakAt int
		fails   map[string][]int
	}{
		{"ucan-healthy", chain.VerdictValid, -1, map[string][]int{}},
		{"ucan-widened", chain.VerdictInvalid, 1, map[string][]int{RuleCommand: {1}}},
		{"ucan-misaligned", chain.VerdictInvalid, 1, map[string][]int{RulePrincipals: {1}}},
		{"ucan-expired", chain.VerdictInvalid, 1, map[string][]int{RuleTime: {1}}},
		{"ucan-forged", chain.VerdictInvalid, 1, map[string][]int{RuleSignature: {1}}},
		{"ucan-policy", chain.VerdictInvalid, 2, map[string][]int{RulePolicy: {2}}},
		{"ucan-powerline", chain.VerdictValid, -1, map[string][]int{}},
		{"ucan-revoked", chain.VerdictInvalid, 0, map[string][]int{RuleRevocation: {0}}},
		{"ucan-unchecked", chain.VerdictIncomplete, -1, map[string][]int{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := evaluate(t, tt.name, time.Minute)
			if c.Verdict != tt.verdict || c.BreakAt != tt.breakAt {
				t.Errorf("verdict %s, break %d; want %s, %d\n%v", c.Verdict, c.BreakAt, tt.verdict, tt.breakAt, c.Findings())
			}
			got := failing(c)
			if len(got) != len(tt.fails) {
				t.Errorf("failing rules %v, want %v", got, tt.fails)
			}
			for rule, links := range tt.fails {
				if fmt.Sprint(got[rule]) != fmt.Sprint(links) {
					t.Errorf("%s fails at %v, want %v", rule, got[rule], links)
				}
			}
		})
	}
}

func TestTimeScrubbingExpiresTheChainLinkByLink(t *testing.T) {
	// The invocation lives five minutes, the second delegation forty, the
	// first an hour.
	for _, tt := range []struct {
		at    time.Duration
		valid bool
		where int
	}{
		{time.Minute, true, -1},
		{10 * time.Minute, false, 2},
		{50 * time.Minute, false, 1},
		{2 * time.Hour, false, 0},
	} {
		c := evaluate(t, "ucan-healthy", tt.at)
		if (c.Verdict == chain.VerdictValid) != tt.valid || c.BreakAt != tt.where {
			t.Errorf("at +%s: %s, break %d; want valid %v, break %d", tt.at, c.Verdict, c.BreakAt, tt.valid, tt.where)
		}
	}
}

func TestASimulatedRevocationCutsOffEverythingBelow(t *testing.T) {
	c := evaluate(t, "ucan-healthy", time.Minute)
	id := c.Links[1].RevokeID
	sim := evaluate(t, "ucan-healthy", time.Minute, id)
	if sim.BreakAt != 1 || !sim.Links[1].RevokedSimulated || !sim.Links[2].Unreached || sim.Links[0].Unreached {
		t.Errorf("break %d, link 1 simulated %v, link 2 unreached %v, link 0 unreached %v",
			sim.BreakAt, sim.Links[1].RevokedSimulated, sim.Links[2].Unreached, sim.Links[0].Unreached)
	}
	if c.Links[2].RevokeID != "" {
		t.Error("an invocation is not revoked; it should carry no revocation id")
	}
}

// fixture is one case of the spec's invocation.json.
type fixture struct {
	Name  string `json:"name"`
	Error *struct {
		Name string `json:"name"`
	} `json:"error"`
	Time int64 `json:"time"`
}

// The error each invalid fixture names, and the rule that reports it.
var fixtureRules = map[string]string{
	"InvalidClaim":     "",
	"UnavailableProof": RuleProofs,
	"Expired":          RuleTime,
	"TooEarly":         RuleTime,
	"InvalidAudience":  RulePrincipals,
	"InvalidSubject":   RuleSubject,
	"InvalidSignature": RuleSignature,
	"MatchError":       RulePolicy,
}

// claimRules are where whosent reports the spec's InvalidClaim cases.
var claimRules = map[string]string{
	"no proof":          RuleProofs,
	"invalid powerline": RuleSubject,
}

func TestTheSpecsInvocationFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "spec", "invocation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct{ Valid, Invalid []json.RawMessage }
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Valid) != 7 || len(raw.Invalid) != 13 {
		t.Fatalf("%d valid and %d invalid cases; the copy changed", len(raw.Valid), len(raw.Invalid))
	}
	for _, r := range append(raw.Valid, raw.Invalid...) {
		var f fixture
		if err := json.Unmarshal(r, &f); err != nil {
			t.Fatal(err)
		}
		t.Run(f.Name, func(t *testing.T) {
			if New().Detect(r) != chain.Certain {
				t.Error("the fixture is not detected as UCAN")
			}
			s, err := New().Open(context.Background(), chain.Inputs{Data: r})
			if err != nil {
				t.Fatal(err)
			}
			s.(*Session).opts.Revoked = map[string]bool{}
			c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: time.Unix(f.Time, 0)})
			if err != nil {
				t.Fatal(err)
			}
			fails := failing(c)
			if f.Error == nil {
				if c.Verdict != chain.VerdictValid {
					t.Errorf("a valid fixture is %s: %v", c.Verdict, fails)
				}
				return
			}
			want := fixtureRules[f.Error.Name]
			if f.Error.Name == "InvalidClaim" {
				want = claimRules[f.Name]
			}
			if want == "" {
				t.Fatalf("no rule mapped for %s", f.Error.Name)
			}
			if c.Verdict != chain.VerdictInvalid || len(fails[want]) == 0 {
				t.Errorf("%s should fail %s; got %s with %v", f.Error.Name, want, c.Verdict, fails)
			}
		})
	}
}

func TestTheSpecsDelegationFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "spec", "delegation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Valid []struct {
			Name     string `json:"name"`
			Token    string `json:"token"`
			CID      string `json:"cid"`
			Envelope struct {
				Payload struct {
					Iss, Aud, Sub, Cmd string
					Exp                int64
				} `json:"payload"`
			} `json:"envelope"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Valid {
		raw, err := base64.StdEncoding.DecodeString(v.Token)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(v.Token)
		}
		if err != nil {
			t.Fatal(err)
		}
		tok := decodeToken(raw)
		if tok.Err != nil || len(tok.Problems) > 0 {
			t.Fatalf("%s: %v %v", v.Name, tok.Err, tok.Problems)
		}
		if got := cidBase32(tok.CID); got != v.CID {
			t.Errorf("%s: CID %s, want %s", v.Name, got, v.CID)
		}
		p := v.Envelope.Payload
		if tok.Iss != p.Iss || tok.Aud != p.Aud || tok.Sub == nil || *tok.Sub != p.Sub || tok.Cmd != p.Cmd || tok.Exp == nil || *tok.Exp != p.Exp {
			t.Errorf("%s: decoded %s %s %v %s %v", v.Name, tok.Iss, tok.Aud, tok.Sub, tok.Cmd, tok.Exp)
		}
		key, err := parseDIDKey(tok.Iss)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifySig(tok.Header, key, tok.SigPayload, tok.Sig); err != nil {
			t.Errorf("%s: %v", v.Name, err)
		}
	}
}

func TestTheSpecsPolicyFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "spec", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Valid, Invalid []struct {
			Args     json.RawMessage   `json:"args"`
			Policies []json.RawMessage `json:"policies"`
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	run := func(kind string, want bool, cases []struct {
		Args     json.RawMessage   `json:"args"`
		Policies []json.RawMessage `json:"policies"`
	}) {
		for i, c := range cases {
			args, err := jsonValue(string(c.Args))
			if err != nil {
				t.Fatal(err)
			}
			for j, raw := range c.Policies {
				v, err := jsonValue(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				p, err := parsePolicy(v)
				if err != nil {
					t.Fatalf("%s %d.%d: %v", kind, i, j, err)
				}
				got, _, err := p.match(args, &evaluation{})
				if err != nil || got != want {
					t.Errorf("%s %d.%d: %s against %s gives %v (%v), want %v", kind, i, j, raw, c.Args, got, err, want)
				}
			}
		}
	}
	run("valid", true, f.Valid)
	run("invalid", false, f.Invalid)
}

func TestSelectorsResolveAsTheSpecShows(t *testing.T) {
	args, err := jsonValue(`{"from": "alice@example.com", "to": ["bob@example.com", "carol@not.example.com", "dan@example.com"], "cc": ["fraud@example.com"], "title": "Meeting Confirmation", "m": {"a": 1, "b": 2}}`)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		sel  string
		want string // DAG-JSON, or "fail"
	}{
		{".", ""},
		{".title", `"Meeting Confirmation"`},
		{".cc", `["fraud@example.com"]`},
		{".to[1]", `"carol@not.example.com"`},
		{".to[-1]", `"dan@example.com"`},
		{".to[99]?", "null"},
		{".to[99]", "fail"},
		{".missing", "null"},
		{".missing.deeper", "fail"},
		{".missing.deeper?", "null"},
		{".missing?.deeper", "fail"},
		{".to[1:]", `["carol@not.example.com", "dan@example.com"]`},
		{".to[:-2]", `["bob@example.com"]`},
		{".m[]", `[1, 2]`},
		{`.["title"]`, `"Meeting Confirmation"`},
		{".title[0]", "fail"},
	}
	for _, tt := range tests {
		sel, err := parseSelector(tt.sel)
		if err != nil {
			t.Errorf("%s: %v", tt.sel, err)
			continue
		}
		v, ok := sel.resolve(args)
		switch {
		case tt.want == "fail":
			if ok {
				t.Errorf("%s resolved to %s, want a failure", tt.sel, dagJSON(v, ""))
			}
		case tt.want == "":
			if !ok || !equal(v, args) {
				t.Errorf("%s is not the whole argument", tt.sel)
			}
		case !ok || dagJSON(v, "") != tt.want:
			t.Errorf("%s gave %s (%v), want %s", tt.sel, dagJSON(v, ""), ok, tt.want)
		}
	}
	// Bytes select as a byte array: 0xd6 0xa9 0xc1 0x8c, so .[3] is 140.
	b := vBytes([]byte{0xd6, 0xa9, 0xc1, 0x8c, 0xf8, 0xc4})
	sel, _ := parseSelector(".[3]")
	if v, ok := sel.resolve(b); !ok || v.Kind != KindInt || v.Int != 140 {
		t.Errorf(".[3] on bytes gave %s", dagJSON(v, ""))
	}
	for _, bad := range []string{"", "title", "..", ".a..b", ".[", `.["unterminated]`, ".[1:2:3]", ".a b"} {
		if _, err := parseSelector(bad); err == nil {
			t.Errorf("%q parsed; it should not", bad)
		}
	}
}

func TestGlobMatchingFollowsTheSpecsExamples(t *testing.T) {
	pattern := `Alice\*, Bob*, Carol.`
	for _, s := range []string{"Alice*, Bob, Carol.", "Alice*, Bob, Dan, Erin, Carol.", "Alice*, Bob  , Carol.", "Alice*, Bob*, Carol."} {
		if !globMatch(pattern, s) {
			t.Errorf("%q should match", s)
		}
	}
	for _, s := range []string{"Alice*, Bob, Carol", "Alice*, Bob*, Carol!", "Alice, Bob, Carol.", "Alice Cooper, Bob, Carol.", " Alice*, Bob, Carol. "} {
		if globMatch(pattern, s) {
			t.Errorf("%q should not match", s)
		}
	}
	if !globMatch("*@example.com", "bob@example.com") || globMatch("*@example.com", "bob@example.com.evil") || !globMatch("a*a", "aa") || globMatch("a*a", "a") {
		t.Error("basic wildcard matching is wrong")
	}
}

func TestDetectionClaimsOnlyUCAN(t *testing.T) {
	s := open(t, "ucan-healthy")
	var arr []string
	var ctn []Value
	for _, tok := range s.tokens {
		arr = append(arr, base64.StdEncoding.EncodeToString(tok.Raw))
		ctn = append(ctn, vBytes(tok.Raw))
	}
	js, _ := json.Marshal(arr)
	body := encodeCBOR(vMap(entry("ctn-v1", vList(ctn...))))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(body)
	_ = zw.Close()
	mine := map[string][]byte{
		"json array":           js,
		"lines":                []byte(strings.Join(arr, "\n")),
		"raw":                  s.tokens[0].Raw,
		"container @":          append([]byte("@"), body...),
		"container B":          []byte("B" + base64.StdEncoding.EncodeToString(body)),
		"container C":          []byte("C" + base64.RawURLEncoding.EncodeToString(body)),
		"container M":          append([]byte("M"), gz.Bytes()...),
		"container O":          []byte("O" + base64.StdEncoding.EncodeToString(gz.Bytes())),
		"container P":          []byte("P" + base64.RawURLEncoding.EncodeToString(gz.Bytes())),
		"fixture-style object": []byte(`{"proofs": [{"/": {"bytes": "` + base64.RawStdEncoding.EncodeToString(s.tokens[0].Raw) + `"}}], "invocation": "` + arr[2] + `"}`),
	}
	for name, data := range mine {
		if New().Detect(data) != chain.Certain {
			t.Errorf("%s is not claimed", name)
		}
		in, err := readInput(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if name != "raw" && name != "fixture-style object" && len(in.tokens) != 3 {
			t.Errorf("%s: %d tokens, want 3", name, len(in.tokens))
		}
	}
	notMine := map[string][]byte{
		"jwt":          []byte("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"),
		"jwt bundle":   []byte(`["eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"]`),
		"biscuit text": []byte("CAESfwoVdXNlcjoxMjM0"),
		"garbage":      []byte("hello, world"),
		"empty":        nil,
	}
	for name, data := range notMine {
		if c := New().Detect(data); c != chain.NotMine {
			t.Errorf("%s is claimed (%v)", name, c)
		}
	}
}

func TestStrictDAGCBORIsRequired(t *testing.T) {
	tests := map[string][]byte{
		"a one-byte length under 24":       {0x58, 0x01, 0x00},
		"map keys out of order":            {0xa2, 0x62, 'b', 'b', 0x01, 0x61, 'a', 0x02},
		"a duplicate key":                  {0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
		"indefinite length":                {0x9f, 0x01, 0xff},
		"a 32-bit float":                   {0xfa, 0x3f, 0x80, 0x00, 0x00},
		"NaN":                              {0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0},
		"a tag other than 42":              {0xc1, 0x01},
		"undefined":                        {0xf7},
		"trailing bytes":                   {0x01, 0x02},
		"a length longer than the input":   {0x9a, 0xff, 0xff, 0xff, 0xff},
		"a map key that is not a string":   {0xa1, 0x01, 0x02},
		"a text string that is not UTF-8":  {0x62, 0xff, 0xfe},
		"a link without the identity byte": {0xd8, 0x2a, 0x42, 0x01, 0x71},
	}
	for name, b := range tests {
		if _, err := decodeCBOR(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	// A token whose signed part is not canonical fails the envelope rule,
	// even with a good signature over the bytes as sent.
	raw := open(t, "ucan-healthy").tokens[0].Raw
	tok := decodeToken(append(append([]byte(nil), raw...), 0x00))
	if tok.Err == nil {
		t.Error("trailing bytes after the envelope were accepted")
	}
}

func TestAskAnswersForTheDelegations(t *testing.T) {
	ctx := context.Background()
	s := open(t, "ucan-healthy")
	c, _ := s.Evaluate(ctx, chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
	tests := []struct {
		name, scenario, cmd, args string
		verdict, authority        string
	}{
		{"a covered message is permitted", "ucan-healthy", "/msg/send", `{"from": "alice@example.com", "to": ["bob@example.com"]}`, "PERMITTED", "AUTHORITATIVE"},
		{"a command outside the grant is denied", "ucan-healthy", "/msg/delete", `{}`, "DENIED", "AUTHORITATIVE"},
		{"arguments the policy refuses are denied", "ucan-healthy", "/msg/send", `{"from": "mallory@example.com", "to": ["bob@example.com"]}`, "DENIED", "AUTHORITATIVE"},
		{"without a revocation list the answer is conditional", "ucan-unchecked", "/msg/send", `{"from": "alice@example.com", "to": ["bob@example.com"]}`, "PERMITTED IF", "CONDITIONAL"},
		{"a broken chain permits nothing", "ucan-forged", "/msg/send", `{"from": "alice@example.com", "to": ["bob@example.com"]}`, "DENIED", "HYPOTHETICAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t, tt.scenario)
			c, _ := s.Evaluate(ctx, chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
			r, err := s.Ask(ctx, c, map[string]string{"command": tt.cmd, "args": tt.args})
			if err != nil {
				t.Fatal(err)
			}
			if r.Verdict != tt.verdict || r.Authority != tt.authority {
				t.Errorf("%s (%s): %s; want %s (%s)", r.Verdict, r.Authority, r.Why, tt.verdict, tt.authority)
			}
		})
	}
	for _, bad := range []map[string]string{{"command": ""}, {"command": "msg"}, {"command": "/msg", "args": "[1]"}, {"command": "/msg", "args": "{"}} {
		if _, err := s.Ask(ctx, c, bad); err == nil {
			t.Errorf("%v was answered", bad)
		}
	}
	if p := s.AskPrefill(c, 0); p["command"] != "/msg/send" || !strings.Contains(p["args"], "bob@example.com") {
		t.Errorf("prefill %v does not restate the invocation", p)
	}
}

func TestARevocationListNamesDelegationsByCID(t *testing.T) {
	s := open(t, "ucan-healthy")
	dir := t.TempDir()
	list := filepath.Join(dir, "revoked.txt")
	body := "# revoked\n" + cidBase32(s.tokens[1].CID) + "\n"
	if err := os.WriteFile(list, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var arr []string
	for _, tok := range s.tokens {
		arr = append(arr, base64.StdEncoding.EncodeToString(tok.Raw))
	}
	js, _ := json.Marshal(arr)
	sess, err := New().Open(context.Background(), chain.Inputs{Data: js, RevokedIDs: list, At: chaintest.Base.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := sess.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
	if c.BreakAt != 1 || !c.Links[1].Revoked {
		t.Errorf("a base32 CID on the list did not revoke link 1: break %d", c.BreakAt)
	}
	if err := os.WriteFile(list, []byte("not-a-cid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Open(context.Background(), chain.Inputs{Data: js, RevokedIDs: list}); err == nil {
		t.Error("a list line that is not a CID was accepted")
	}
}

func TestAnInvocationNamingAMissingProofBreaksThere(t *testing.T) {
	s := open(t, "ucan-healthy")
	var arr []string
	for _, tok := range []*Token{s.tokens[0], s.tokens[2]} {
		arr = append(arr, base64.StdEncoding.EncodeToString(tok.Raw))
	}
	js, _ := json.Marshal(arr)
	sess, err := New().Open(context.Background(), chain.Inputs{Data: js})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := sess.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
	if c.BreakAt != 1 || c.Links[1].Readable || len(failing(c)[RuleProofs]) != 1 {
		t.Errorf("break %d, link 1 readable %v, fails %v", c.BreakAt, c.Links[1].Readable, failing(c))
	}
}

func TestTwoInvocationsAreRefused(t *testing.T) {
	s := open(t, "ucan-healthy")
	inv := base64.StdEncoding.EncodeToString(s.tokens[2].Raw)
	js, _ := json.Marshal([]string{inv, inv})
	if _, err := New().Open(context.Background(), chain.Inputs{Data: js}); err == nil {
		t.Error("two invocations were accepted")
	}
}

func TestEmitWritesWhatTheCommandChecks(t *testing.T) {
	for _, sc := range New().Scenarios() {
		dir := filepath.Join(t.TempDir(), sc.Name)
		cmd, err := sc.Emit(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cmd, "--format ucan") {
			t.Errorf("%s: %s", sc.Name, cmd)
		}
		for _, f := range []string{"tokens.json", "manifest.json"} {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				t.Errorf("%s: %v", sc.Name, err)
			}
		}
		if _, err := sc.Emit(dir, false); err == nil {
			t.Errorf("%s: a second emit into a full directory was accepted without force", sc.Name)
		}
	}
}

func TestDIDKeysOfTheThreeRequiredAlgorithmsDecode(t *testing.T) {
	// Vectors from the did:key method spec.
	for did, kt := range map[string]KeyType{
		"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp":  KeyEd25519,
		"did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169": KeyP256,
		"did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme": KeySecp256k1,
	} {
		k, err := parseDIDKey(did)
		if err != nil || k.Type != kt {
			t.Errorf("%s: %v %v", did, k.Type, err)
		}
		if got := didKeyString(k.Type, k.Key); got != did {
			t.Errorf("%s re-encodes as %s", did, got)
		}
	}
	if _, err := parseDIDKey("did:web:example.com"); err != errNotDIDKey {
		t.Errorf("did:web: %v", err)
	}
}

// demoChain evaluates a minted demo a minute after it was minted.
func demoChain(t *testing.T, d demo) *chain.Chain {
	t.Helper()
	var toks []*Token
	for _, raw := range d.tokens {
		toks = append(toks, decodeToken(raw))
	}
	s := &Session{tokens: toks, inputFormat: "demo", opts: d.options(), at: chaintest.Base.Add(time.Minute), source: "test"}
	c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A selector that finds nothing makes its statement false, and not turns
// that true. go-ucan refuses the same policy, so whosent must not call the
// chain VALID on that reading alone.
func TestANegatedMissingSelectorIsNotVouchedFor(t *testing.T) {
	c := demoChain(t, healthy(chaintest.Base, func(ds []dlgSpec, _ *invSpec) {
		ds[1].pol = append(ds[1].pol, stmt(vStr("not"), stmt(vStr("=="), vStr(".to[9]"), vStr("eve@elsewhere.example"))))
	}))
	if c.Verdict == chain.VerdictValid {
		t.Fatalf("VALID on a policy only the spec's reading accepts: %s", c.Headline)
	}
	if st := c.Links[len(c.Links)-1].Check(RulePolicy).Status; st != chain.StatusUnchecked {
		t.Errorf("U7 is %v, want unchecked", st)
	}
}

// Without an invocation no policy is applied, so the headline must not say
// every rule was checked.
func TestDelegationsWithoutAnInvocationSayNoPolicyWasApplied(t *testing.T) {
	d := healthy(chaintest.Base, nil)
	d.tokens = d.tokens[:len(d.tokens)-1]
	c := demoChain(t, d)
	if c.Verdict != chain.VerdictValid {
		t.Fatalf("verdict %v: %s", c.Verdict, c.Headline)
	}
	if strings.Contains(c.Headline, "Every rule was checked") || !strings.Contains(c.Headline, "no policy was applied") {
		t.Errorf("headline: %s", c.Headline)
	}
}
