package macaroon

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	fly "github.com/superfly/macaroon"

	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

func TestTheAdapterKeepsTheContract(t *testing.T) {
	chaintest.Run(t, New())
}

func open(t *testing.T, name string) *session {
	t.Helper()
	for _, sp := range specs {
		if sp.name == name {
			s, err := sp.build(chaintest.Base).session(name, chaintest.Base)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatalf("no scenario %q", name)
	return nil
}

func evaluate(t *testing.T, s *session, at time.Duration) *chain.Chain {
	t.Helper()
	c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(at)})
	if err != nil {
		t.Fatal(err)
	}
	if p := chaintest.Problems(c); len(p) > 0 {
		t.Errorf("the chain breaks the contract: %v", p)
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
		{"macaroon-healthy", chain.VerdictValid, -1, map[string][]int{}},
		{"macaroon-missing-discharge", chain.VerdictInvalid, 4, map[string][]int{RuleDischarge: {4}}},
		{"macaroon-tampered", chain.VerdictInvalid, 0, map[string][]int{RuleSignature: {0, 1, 2, 3, 4}, RuleBinding: {4}}},
		{"macaroon-expired", chain.VerdictInvalid, 3, map[string][]int{RuleTime: {3}}},
		{"macaroon-unchecked", chain.VerdictIncomplete, -1, map[string][]int{}},
		{"macaroon-fly", chain.VerdictIncomplete, -1, map[string][]int{}},
		{"macaroon-fly-request", chain.VerdictValid, -1, map[string][]int{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := evaluate(t, open(t, tt.name), time.Minute)
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
			if c.Inconsistency != nil {
				t.Errorf("the reference disagrees: %s", c.Inconsistency.Detail)
			}
		})
	}
}

// Without a root key nothing about the HMAC chain can be vouched for, so
// no link may look verified, whatever else holds.
func TestWithoutARootKeyNoLinkLooksVerified(t *testing.T) {
	c := evaluate(t, open(t, "macaroon-unchecked"), time.Minute)
	for _, l := range c.Links {
		if l.State == chain.LinkOK {
			t.Errorf("link %d (%s) is OK without a root key", l.Index, l.To)
		}
		if l.Check(RuleSignature).Status != chain.StatusUnchecked {
			t.Errorf("link %d signature is %s, want unchecked", l.Index, l.Check(RuleSignature).Status)
		}
	}
	if c.IncompleteReason != "no root key, no predicates" {
		t.Errorf("the reason does not say what to give: %q", c.IncompleteReason)
	}
}

func TestTimePassingExpiresTheDischargeFirst(t *testing.T) {
	s := open(t, "macaroon-healthy")
	c := evaluate(t, s, 25*time.Minute)
	if c.Verdict != chain.VerdictInvalid || c.BreakAt != 6 {
		t.Errorf("at +25m: %s at %d, want the discharge's twenty minutes to end at link 6", c.Verdict, c.BreakAt)
	}
	c = evaluate(t, s, 2*time.Hour)
	if c.BreakAt != 3 {
		t.Errorf("at +2h: break at %d, want the root's hour at link 3", c.BreakAt)
	}
	c = evaluate(t, s, time.Minute)
	if got := c.Links[6].ExpiresAt; !got.Equal(chaintest.Base.Add(20 * time.Minute)) {
		t.Errorf("the leaf expires at %s, want the discharge's end", got)
	}
}

func TestAPredicateNoFactSatisfiesIsRefused(t *testing.T) {
	s := open(t, "macaroon-healthy")
	s.facts = map[string]bool{"account = 3735928559": true}
	c := evaluate(t, s, time.Minute)
	if c.Verdict != chain.VerdictInvalid || c.BreakAt != 2 || c.Links[2].Check(RuleCaveat).Status != chain.StatusFail {
		t.Errorf("verdict %s at %d; want action = deposit refused at link 2", c.Verdict, c.BreakAt)
	}
}

// whosent's verification is checked against the reference
// implementations' on every scenario, every rule-relevant mutation, and a
// wrong key.
func TestVerificationAgreesWithTheReference(t *testing.T) {
	for _, sp := range specs {
		d := sp.build(chaintest.Base)
		b, err := decode(d.data)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range [][]byte{d.key, []byte("not the key"), nil} {
			if key == nil {
				continue
			}
			var ours, theirs bool
			if b.dialect == "fly" {
				ours = verifyFly(b.fly, key).ok
				theirs = flyReference(b.fly, key) == nil
			} else {
				ours = verifyLib(b.lib[0], b.lib[1:], key).ok
				theirs = referenceVerify(b.lib[0], b.lib[1:], key) == nil
			}
			if ours != theirs {
				t.Errorf("%s with key %q: whosent %v, reference %v", sp.name, key, ours, theirs)
			}
		}
	}
}

// The Fly.io demo is minted by whosent's own code; the library Fly.io
// verifies tokens with must accept it, or the demo shows a token that
// does not exist.
func TestTheFlyDemoVerifiesWithTheLibrary(t *testing.T) {
	b, err := decode([]byte(flyDemo(chaintest.Base)))
	if err != nil {
		t.Fatal(err)
	}
	var ds [][]byte
	for _, d := range b.fly.discharges {
		ds = append(ds, d.raw)
	}
	cavs, err := b.fly.root.m.Verify(fly.SigningKey(flySignKey), ds, nil)
	if err != nil {
		t.Fatalf("superfly/macaroon refuses the demo: %v", err)
	}
	if len(cavs.Caveats) == 0 {
		t.Error("the verified token carries no caveats")
	}
}

func TestADisagreementWithTheReferenceIsReported(t *testing.T) {
	s := open(t, "macaroon-healthy")
	s.refuse = func() error { return errors.New("injected refusal") }
	c := evaluate(t, s, time.Minute)
	if c.Inconsistency == nil || !strings.Contains(c.Inconsistency.Detail, "injected refusal") {
		t.Fatalf("no inconsistency reported: %+v", c.Inconsistency)
	}
	if c.Verdict != chain.VerdictInvalid {
		t.Errorf("verdict %s; the stricter verdict must stand", c.Verdict)
	}
}

// libmacaroons' own verifier tests: the same key, the same exact
// predicates, the same verdict.
func TestLibmacaroonsVerifierTests(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "libmacaroons", "*.vtest"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vtests: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			vt := readVTest(t, f)
			b, err := decode(vt.token)
			if err != nil {
				t.Fatal(err)
			}
			s := &session{b: b, key: vt.key, skew: DefaultSkew, facts: map[string]bool{}}
			for _, p := range vt.exact {
				s.facts[p] = true
			}
			s.factsGiven = true
			c := evaluate(t, s, 0)
			if got := c.Verdict == chain.VerdictValid; got != vt.authorized {
				t.Errorf("verdict %s, libmacaroons authorized=%v\n%v", c.Verdict, vt.authorized, c.Findings())
			}
		})
	}
}

type vtest struct {
	authorized bool
	key        []byte
	exact      []string
	token      []byte
}

func readVTest(t *testing.T, path string) vtest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var vt vtest
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "version "):
		case line == "authorized":
			vt.authorized = true
		case line == "unauthorized":
		case strings.HasPrefix(line, "key "):
			vt.key = []byte(strings.TrimPrefix(line, "key "))
		case strings.HasPrefix(line, "exact "):
			vt.exact = append(vt.exact, strings.TrimPrefix(line, "exact "))
		default:
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(line, "="))
			if err != nil {
				t.Fatalf("token line: %v", err)
			}
			vt.token = raw
		}
	}
	return vt
}

// go-macaroon's interoperability vector: a libmacaroons v1 macaroon with a
// third-party caveat and no discharge.
func TestALibmacaroonsThirdPartyCaveatWithoutItsDischarge(t *testing.T) {
	const v1 = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMmNpZGVudGlmaWVyIHdlIHVzZWQgb3VyIG90aGVyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDMwY2lkIHRoaXMgd2FzIGhvdyB3ZSByZW1pbmQgYXV0aCBvZiBrZXkvcHJlZAowMDUxdmlkIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANNuxQLgWIbR8CefBV-lJVTRbRbBsUB0u7g_8P3XncL-CY8O1KKwkRMOa120aiCoawowMDFiY2wgaHR0cDovL2F1dGgubXliYW5rLwowMDJmc2lnbmF0dXJlINJ9sv0fInYOTD2ugTfi2Pwd9sB0HBiu1LlyVr940fVcCg"
	if New().Detect([]byte(v1)) != chain.Plausible {
		t.Error("a v1 macaroon is not recognised")
	}
	b, err := decode([]byte(v1))
	if err != nil {
		t.Fatal(err)
	}
	s := &session{b: b, key: []byte("this is a different super-secret key; never use the same secret twice"), skew: DefaultSkew}
	c := evaluate(t, s, 0)
	if c.Links[2].To != "via auth.mybank" || c.Links[2].Check(RuleDischarge).Status != chain.StatusFail {
		t.Errorf("link 2 is %q, discharge %s", c.Links[2].To, c.Links[2].Check(RuleDischarge).Status)
	}
}

func TestDetectClaimsMacaroonsAndNothingElse(t *testing.T) {
	healthy := specs[0].build(chaintest.Base).data
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(healthy)))
	if err != nil {
		t.Fatal(err)
	}
	m, _ := mintLib(demoRootKey, "id", "loc").first("a = b").m.toGo()
	js, _ := m.MarshalJSON()
	tests := []struct {
		name string
		in   string
		want chain.Confidence
	}{
		{"a Fly.io header", flyDemo(chaintest.Base), chain.Certain},
		{"a bare fm2 token", strings.TrimPrefix(flyDemo(chaintest.Base), "FlyV1 "), chain.Certain},
		{"raw v2 binary", string(raw), chain.Certain},
		{"base64 v2", string(healthy), chain.Plausible},
		{"wrapped base64", wrap(strings.TrimSpace(string(healthy)), 40), chain.Plausible},
		{"JSON", string(js), chain.Plausible},
		{"a JSON array", "[" + string(js) + "]", chain.Plausible},
		{"a JWT", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln", chain.NotMine},
		{"a JSON array of JWTs", `["a.b.c"]`, chain.NotMine},
		{"another JSON object", `{"chain":["a.b.c"]}`, chain.NotMine},
		{"plain words", "hello world", chain.NotMine},
		{"garbage", "\x00\x01\x02garbage", chain.NotMine},
		{"a broken v2 binary", "\x02\x05", chain.NotMine},
		{"empty", "", chain.NotMine},
	}
	for _, tt := range tests {
		if got := New().Detect([]byte(tt.in)); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s
}

func TestOpenReadsKeysAndRefusesWhatItCannot(t *testing.T) {
	data := specs[0].build(chaintest.Base).data
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "root.key")
	if err := os.WriteFile(keyFile, []byte("whosent demo root key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"text:whosent demo root key", fmt.Sprintf("%x", demoRootKey), keyFile} {
		s, err := New().Open(context.Background(), chain.Inputs{Data: data, RootKeys: []string{k}, Facts: bankFacts})
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		c := evaluate(t, s.(*session), time.Minute)
		if c.Verdict != chain.VerdictValid {
			t.Errorf("--root-key %s: %s", k, c.Verdict)
		}
	}
	bad := []chain.Inputs{
		{Data: []byte("hello")},
		{Data: data, RootKeys: []string{"zz", "yy"}},
		{Data: data, RootKeys: []string{filepath.Join(dir, "missing")}},
		{Data: data, Reverse: true},
		{Data: []byte(strings.Repeat(strings.TrimSpace(string(data))+" ", maxMacaroons+1))},
	}
	for i, in := range bad {
		if _, err := New().Open(context.Background(), in); err == nil {
			t.Errorf("input %d was accepted", i)
		}
	}
}

func TestIgnoredInputsAreReported(t *testing.T) {
	aud := "x"
	s, err := New().Open(context.Background(), chain.Inputs{Data: []byte(flyDemo(chaintest.Base)), Audience: &aud, Facts: []string{"org=4242", "action=r"}})
	if err != nil {
		t.Fatal(err)
	}
	c := evaluate(t, s.(*session), time.Minute)
	got := strings.Join(c.Ignored, " ")
	// --fact is the Fly.io request, so only --audience is ignored.
	if !strings.Contains(got, "--audience") || strings.Contains(got, "--fact") {
		t.Errorf("ignored: %v", c.Ignored)
	}
}

func TestEmitWritesACheckableFixture(t *testing.T) {
	for _, sc := range New().Scenarios() {
		dir := t.TempDir()
		cmd, err := sc.Emit(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(cmd, "--format macaroon") {
			t.Errorf("%s: %s", sc.Name, cmd)
		}
		for _, f := range []string{"token.txt", "manifest.json"} {
			if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
				t.Errorf("%s: %v", sc.Name, err)
			}
		}
		if _, err := sc.Emit(dir, false); err == nil {
			t.Errorf("%s: emitting into a full directory without force was accepted", sc.Name)
		}
	}
}

// Caveats are attacker-written text; they must reach the model unchanged
// (the view and the command line escape them), and nothing about them may
// make the chain look checked.
func TestHostileCaveatsStayData(t *testing.T) {
	hostile := "\x1b]52;c;aGk=\x07\x1b[2J\r\u202eaction = deposit"
	root := mintLib(demoRootKey, "id\x1b[31m", "https://x\x1b[0m").first(hostile)
	d := libDemo([]*lmac{root.m}, demoRootKey, nil)
	b, err := decode(d.data)
	if err != nil {
		t.Fatal(err)
	}
	c := evaluate(t, &session{b: b, key: demoRootKey, skew: DefaultSkew, facts: map[string]bool{}}, 0)
	if c.Links[1].Check(RuleCaveat).Status != chain.StatusUnchecked || c.Verdict == chain.VerdictValid {
		t.Errorf("a hostile predicate was judged: %s, %s", c.Links[1].Check(RuleCaveat).Status, c.Verdict)
	}
}

func TestTimeConventions(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"time < 2020-01-01T00:00", "2020-01-01T00:00:00Z", true},
		{"time < 2026-09-12T09:00:00Z", "2026-09-12T09:00:00Z", true},
		{"time-before 2026-09-12T09:00:00.5+09:00", "2026-09-12T00:00:00Z", true},
		{"time > 2020-01-01T00:00", "", false},
		{"time < soon", "", false},
		{"account = 1", "", false},
	}
	for _, tt := range tests {
		got, ok := timeCaveat(tt.in)
		if ok != tt.ok || (ok && got.UTC().Truncate(time.Second).Format(time.RFC3339) != tt.want) {
			t.Errorf("%q: %v %v, want %s %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, sp := range specs {
		f.Add(sp.build(chaintest.Base).data)
	}
	f.Add([]byte("\x02\x01\x00"))
	f.Add([]byte("fm2_AAAA"))
	f.Add([]byte(`[{"i":"x","s64":"AAAA"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := decode(data)
		if err != nil {
			return
		}
		s := &session{b: b, key: []byte("k"), skew: DefaultSkew, facts: map[string]bool{}}
		c := s.evaluate(chaintest.Base)
		if p := chaintest.Problems(c); len(p) > 0 {
			t.Errorf("the chain breaks the contract: %v", p)
		}
	})
}

// Without a request a Fly.io token is INCOMPLETE; ask supplies one, and
// Fly.io's own access check judges it against the caveats.
func TestAskJudgesAFlyRequestWithFlyiosAccessCheck(t *testing.T) {
	s := open(t, "macaroon-fly")
	c := evaluate(t, s, time.Minute)
	if c.Verdict != chain.VerdictIncomplete {
		t.Fatalf("the Fly.io demo with no request is %s: %v", c.Verdict, c.Findings())
	}
	tests := []struct {
		name    string
		values  map[string]string
		verdict string
	}{
		{"a read on the token's app is allowed", map[string]string{askOrg: "4242", askAction: "r", askApp: "123"}, "PERMITTED"},
		{"a write on the token's app is allowed", map[string]string{askOrg: "4242", askAction: "w", askApp: "123"}, "PERMITTED"},
		{"an org-level request is refused once the token names an app", map[string]string{askOrg: "4242", askAction: "r"}, "DENIED"},
		{"a delete is outside the mask", map[string]string{askOrg: "4242", askAction: "d", askApp: "123"}, "DENIED"},
		{"another org is refused", map[string]string{askOrg: "1", askAction: "r"}, "DENIED"},
		{"another app is refused", map[string]string{askOrg: "4242", askAction: "r", askApp: "999"}, "DENIED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := s.Ask(context.Background(), c, tt.values)
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != tt.verdict || res.Authority != "AUTHORITATIVE" {
				t.Errorf("%s (%s): %s", res.Verdict, res.Authority, res.Reason)
			}
		})
	}
	if _, err := s.Ask(context.Background(), c, map[string]string{askAction: "r"}); err == nil {
		t.Error("a request with no organization is answered")
	}
}

// Without the signing key nothing vouches for the caveats, so the answer is
// conditional at best.
func TestAskWithoutTheKeyIsConditional(t *testing.T) {
	s := open(t, "macaroon-fly")
	s.key = nil
	c := evaluate(t, s, time.Minute)
	res, err := s.Ask(context.Background(), c, map[string]string{askOrg: "4242", askAction: "r", askApp: "123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Authority == "AUTHORITATIVE" {
		t.Errorf("answered %s without the key", res.Authority)
	}
}

// A libmacaroons macaroon is asked about predicates: a verifier holding
// all of them accepts it, one missing a predicate refuses it.
func TestAskJudgesPredicatesAsAVerifierWould(t *testing.T) {
	s := open(t, "macaroon-unchecked")
	s.key = open(t, "macaroon-healthy").key
	c := evaluate(t, s, time.Minute)
	e := &evaluation{s: s, at: c.At}
	e.lib()
	var preds []string
	for _, n := range e.nodes {
		if n.kind == "first" && n.checks[5].Status == chain.StatusUnchecked {
			preds = append(preds, n.cond)
		}
	}
	if len(preds) == 0 {
		t.Skip("the demo has no application predicates")
	}
	all := strings.Join(preds, "; ")
	res, err := s.Ask(context.Background(), c, map[string]string{askPredicates: all})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "PERMITTED" {
		t.Errorf("with every predicate: %s (%s) %s", res.Verdict, res.Authority, res.Reason)
	}
	res, err = s.Ask(context.Background(), c, map[string]string{askPredicates: ""})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "DENIED" {
		t.Errorf("with no predicates: %s", res.Verdict)
	}
}

// A token that does not verify under the given key permits nothing, even a
// request its caveats would allow.
func TestAskWithAWrongKeyIsHypothetical(t *testing.T) {
	s := open(t, "macaroon-fly")
	s.key = []byte("not the signing key")
	c := evaluate(t, s, time.Minute)
	if c.Verdict != chain.VerdictInvalid {
		t.Fatalf("a wrong key gives %s", c.Verdict)
	}
	res, err := s.Ask(context.Background(), c, map[string]string{askOrg: "4242", askAction: "r", askApp: "123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "DENIED" || res.Authority != "HYPOTHETICAL" {
		t.Errorf("%s (%s)", res.Verdict, res.Authority)
	}
}

func TestAgree(t *testing.T) {
	refuse := []chain.AskStep{{Outcome: chain.OutcomeCovers}, {Outcome: chain.OutcomeRefuses}}
	cover := []chain.AskStep{{Outcome: chain.OutcomeCovers}}
	switch {
	case !agree(nil, cover), !agree(errors.New("no"), refuse):
		t.Error("matching answers reported as a disagreement")
	case agree(nil, refuse), agree(errors.New("no"), cover):
		t.Error("a disagreement went unnoticed")
	}
}

// When the library and the caveat-by-caveat reading answer differently,
// the request is refused and the answer carries an inconsistency, which
// makes ask exit 70.
func TestAskReportsADisagreementWithTheLibrary(t *testing.T) {
	s := open(t, "macaroon-fly")
	s.askRefuse = func() error { return errors.New("refused by the stand-in") }
	c := evaluate(t, s, time.Minute)
	res, err := s.Ask(context.Background(), c, map[string]string{askOrg: "4242", askAction: "r", askApp: "123"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inconsistency == nil || res.Permitted {
		t.Errorf("a disagreement went unreported: %s, %+v", res.Verdict, res.Inconsistency)
	}
}

// When superfly/macaroon's Validate and the caveats one by one judge the
// --fact request differently, the disagreement is reported and a refusal
// stands, whichever side refused.
func TestARequestDisagreementIsReported(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		refuse  error
		verdict chain.Verdict
	}{
		{"Validate refuses what every caveat allows", "r", errors.New("injected refusal"), chain.VerdictInvalid},
		{"Validate allows what a caveat refuses", "d", nil, chain.VerdictInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t, "macaroon-fly-request")
			s.flyReq, s.flyReqText, _ = flyRequest([]string{"org=4242", "app=123", "action=" + tt.action})
			s.reqRefuse = func() error { return tt.refuse }
			c := evaluate(t, s, time.Minute)
			if c.Inconsistency == nil || c.Verdict != tt.verdict {
				t.Errorf("inconsistency %v, verdict %s; want a reported disagreement and %s", c.Inconsistency, c.Verdict, tt.verdict)
			}
		})
	}
}

func TestARequestKeyGivenTwiceIsRefused(t *testing.T) {
	if _, _, err := flyRequest([]string{"org=4242", "action=d", "action=r"}); err == nil {
		t.Error("action given twice was accepted")
	}
}
