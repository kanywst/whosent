package biscuit

import (
	"context"
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

func evaluate(t *testing.T, name string, at time.Duration, sim ...string) *chain.Chain {
	t.Helper()
	for _, sc := range New().Scenarios() {
		if sc.Name != name {
			continue
		}
		s, err := sc.Open(chaintest.Base)
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(at), SimRevoked: sim})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatalf("no scenario %q", name)
	return nil
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
		{"biscuit-healthy", chain.VerdictValid, -1, map[string][]int{}},
		{"biscuit-denied", chain.VerdictInvalid, 1, map[string][]int{RuleChecks: {1}}},
		{"biscuit-expired", chain.VerdictInvalid, 2, map[string][]int{RuleChecks: {2}}},
		{"biscuit-forged", chain.VerdictInvalid, 2, map[string][]int{RuleSignature: {2}}},
		{"biscuit-reordered", chain.VerdictInvalid, 1, map[string][]int{RuleSignature: {1, 2}, RuleProof: {2}}},
		{"biscuit-revoked", chain.VerdictInvalid, 1, map[string][]int{RuleRevocation: {1}}},
		{"biscuit-third-party", chain.VerdictValid, -1, map[string][]int{}},
		{"biscuit-sealed", chain.VerdictValid, -1, map[string][]int{}},
		{"biscuit-p256", chain.VerdictValid, -1, map[string][]int{}},
		{"biscuit-unchecked", chain.VerdictIncomplete, -1, map[string][]int{}},
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

func TestTimePassingExpiresTheShortestLivedBlockFirst(t *testing.T) {
	c := evaluate(t, "biscuit-healthy", 25*time.Minute)
	if c.Verdict != chain.VerdictInvalid || c.BreakAt != 2 {
		t.Fatalf("at +25m: %s break %d; the reporting bot's block lives 20 minutes", c.Verdict, c.BreakAt)
	}
	c = evaluate(t, "biscuit-healthy", 45*time.Minute)
	if c.BreakAt != 1 {
		t.Fatalf("at +45m the break is at %d; the payments team's block lives 40 minutes", c.BreakAt)
	}
	if !c.Links[2].Unreached {
		t.Error("the bot's block is below the break but not unreached")
	}
}

func TestExpiryIsReadFromTimeChecks(t *testing.T) {
	c := evaluate(t, "biscuit-healthy", time.Minute)
	want := []time.Duration{time.Hour, 40 * time.Minute, 20 * time.Minute}
	for i, l := range c.Links {
		if got := l.ExpiresAt.Sub(chaintest.Base); got != want[i] {
			t.Errorf("block %d expires at base+%s, want +%s", i, got, want[i])
		}
	}
}

func TestSimulatedRevocationRefusesTheWholeTokenFromThatBlockDown(t *testing.T) {
	c := evaluate(t, "biscuit-healthy", time.Minute)
	sim := evaluate(t, "biscuit-healthy", time.Minute, c.Links[1].RevokeID)
	if sim.Verdict != chain.VerdictInvalid || sim.BreakAt != 1 {
		t.Fatalf("revoking block 1: %s break %d", sim.Verdict, sim.BreakAt)
	}
	if !sim.Links[1].RevokedSimulated || !sim.Links[2].Unreached {
		t.Error("block 1 should be simulated revoked and block 2 unreached")
	}
	if sim.Links[0].State != chain.LinkOK {
		t.Errorf("the authority block is %v; revoking a later block does not touch it", sim.Links[0].State)
	}
	if len(sim.Simulated) != 1 {
		t.Errorf("simulated %v", sim.Simulated)
	}
}

func TestWithoutAnAuthorizerOnlyExpiryIsEvaluated(t *testing.T) {
	c := evaluate(t, "biscuit-unchecked", time.Minute)
	if c.Verdict != chain.VerdictIncomplete {
		t.Fatalf("verdict %s", c.Verdict)
	}
	for _, l := range c.Links {
		if l.Check(RuleChecks).Status != chain.StatusUnchecked {
			t.Errorf("block %d checks %s; the resource checks need the authorizer", l.Index, l.Check(RuleChecks).Status)
		}
	}
	if c.Links[0].Check(RuleSignature).Status != chain.StatusUnchecked {
		t.Error("the authority block's signature was checked without a root key")
	}
	// Block 1 does verify against the key block 0 handed on, but block 0
	// is unauthenticated, so anyone could have minted both: the link is
	// consistent, not verified, and must not look verified.
	if s := c.Links[1].Check(RuleSignature); s.Status != chain.StatusUnchecked || !strings.Contains(s.Detail, "handed on") {
		t.Errorf("block 1's signature is %s (%q); want unchecked, saying it matches the key block 0 handed on", s.Status, s.Detail)
	}
	for _, l := range c.Links {
		if l.State == chain.LinkOK {
			t.Errorf("block %d looks verified in a token rooted in no key", l.Index)
		}
	}
	expired := evaluate(t, "biscuit-unchecked", 25*time.Minute)
	if expired.Verdict != chain.VerdictInvalid || expired.BreakAt != 2 {
		t.Errorf("an expired block fails without any authorizer: got %s break %d", expired.Verdict, expired.BreakAt)
	}
}

func TestAskRunsTheAuthorizerOverTheToken(t *testing.T) {
	sc := New().Scenarios()[0]
	s, err := sc.Open(chaintest.Base)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	asker := s.(chain.Asker)
	tests := []struct {
		facts     string
		permitted bool
		refusedAt int
	}{
		{`resource("orders"); operation("read")`, true, -1},
		{`resource("invoices"); operation("read")`, true, -1},
		{`resource("orders"); operation("write")`, false, 1},
		{`resource("refunds"); operation("read")`, false, 0},
	}
	for _, tt := range tests {
		r, err := asker.Ask(context.Background(), c, map[string]string{askFacts: tt.facts, askPolicy: "allow if true"})
		if err != nil {
			t.Fatalf("%s: %v", tt.facts, err)
		}
		if r.Permitted != tt.permitted || r.Authority != "AUTHORITATIVE" {
			t.Errorf("%s: permitted %v (%s), want %v: %s", tt.facts, r.Permitted, r.Authority, tt.permitted, r.Why)
		}
		first := -1
		for _, st := range r.Steps {
			if st.Outcome == chain.OutcomeRefuses {
				first = st.Link
				break
			}
		}
		if first != tt.refusedAt {
			t.Errorf("%s: first refused at %d, want %d", tt.facts, first, tt.refusedAt)
		}
	}
	if _, err := asker.Ask(context.Background(), c, map[string]string{askFacts: `check if true`}); err == nil {
		t.Error("a check in the facts field was accepted")
	}
}

func TestDetectClaimsBiscuitsAndNothingElse(t *testing.T) {
	sc := New().Scenarios()[0]
	s, _ := sc.Open(chaintest.Base)
	tok := s.(*Session).tok
	text, err := tok.Text()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tok.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile(filepath.Join("testdata", "samples", "test001_basic.bc"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		in   string
		want chain.Confidence
	}{
		{"prefixed text", Prefix + text, chain.Certain},
		{"bare padded text", text, chain.Certain},
		{"bare unpadded text", strings.TrimRight(text, "="), chain.Certain},
		{"raw protobuf", string(raw), chain.Certain},
		{"a sample token", string(sample), chain.Certain},
		{"a JWT", "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln", chain.NotMine},
		{"a JSON array", `["a.b.c"]`, chain.NotMine},
		{"plain words", "hello", chain.NotMine},
		{"garbage", "\x00\x01\x02garbage", chain.NotMine},
		{"empty", "", chain.NotMine},
	}
	for _, tt := range tests {
		if got := New().Detect([]byte(tt.in)); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestMintedTokensRoundTrip(t *testing.T) {
	for _, sc := range New().Scenarios() {
		s, err := sc.Open(chaintest.Base)
		if err != nil {
			t.Fatal(err)
		}
		tok := s.(*Session).tok
		text, err := tok.Text()
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode([]byte(Prefix + text))
		if err != nil {
			t.Fatalf("%s: %v", sc.Name, err)
		}
		again, err := back.Text()
		if err != nil || again != text {
			t.Errorf("%s does not survive encoding", sc.Name)
		}
	}
}

func TestEmitWritesACheckableFixture(t *testing.T) {
	dir := t.TempDir()
	sc := New().Scenarios()[0]
	cmd, err := sc.Emit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"token.b64", "root.pub", "authorizer.datalog", "revoked-ids.txt"} {
		fi, err := os.Lstat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !fi.Mode().IsRegular() {
			t.Errorf("%s is not a regular file", f)
		}
	}
	if !strings.Contains(cmd, "--root-key root.pub") || !strings.Contains(cmd, "--authorizer authorizer.datalog") {
		t.Errorf("command %q", cmd)
	}
	if _, err := sc.Emit(dir, false); err == nil {
		t.Error("emitting into a non-empty directory without force succeeded")
	}
	in := chain.Inputs{Source: "token.b64"}
	in.Data, _ = os.ReadFile(filepath.Join(dir, "token.b64"))
	in.RootKeys = []string{filepath.Join(dir, "root.pub")}
	in.Authorizer = filepath.Join(dir, "authorizer.datalog")
	in.RevokedIDs = filepath.Join(dir, "revoked-ids.txt")
	in.At = emitBase.Add(time.Minute)
	s, err := New().Open(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: in.At})
	if err != nil {
		t.Fatal(err)
	}
	if c.Verdict != chain.VerdictValid {
		t.Errorf("the emitted healthy fixture is %s: %v", c.Verdict, c.Findings())
	}
}

func TestOpenRefusesWhatItCannotRead(t *testing.T) {
	sc := New().Scenarios()[0]
	s, _ := sc.Open(chaintest.Base)
	text, _ := s.(*Session).tok.Text()
	tests := []struct {
		name string
		in   chain.Inputs
	}{
		{"a rule passed as a fact", chain.Inputs{Data: []byte(text), Facts: []string{`a($x) <- b($x)`}}},
		{"an unparsable fact", chain.Inputs{Data: []byte(text), Facts: []string{`resource(`}}},
		{"a root key that is neither", chain.Inputs{Data: []byte(text), RootKeys: []string{"not-a-key-or-file"}}},
		{"not a token", chain.Inputs{Data: []byte("AAAA")}},
	}
	for _, tt := range tests {
		if _, err := New().Open(context.Background(), tt.in); err == nil {
			t.Errorf("%s: opened", tt.name)
		}
	}
}

func problems(c *chain.Chain) []string { return chaintest.Problems(c) }

func TestAskPrefillsARealQuestion(t *testing.T) {
	// The policy field starts as the authorizer's own policies, so asking
	// without editing asks the deployment's question; with no authorizer
	// there is no policy to start from, and none is made up.
	for name, want := range map[string][2]string{
		"biscuit-denied":    {`resource("orders"); operation("write")`, "allow if true;"},
		"biscuit-unchecked": {`resource("orders"); operation("read")`, ""},
	} {
		var s chain.Session
		for _, sc := range New().Scenarios() {
			if sc.Name == name {
				s, _ = sc.Open(chaintest.Base)
			}
		}
		c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: chaintest.Base.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		vals := s.(chain.Asker).AskPrefill(c, 0)
		if vals[askFacts] != want[0] || vals[askPolicy] != want[1] {
			t.Errorf("%s: prefilled %q, want %q", name, vals, want)
		}
	}
}
