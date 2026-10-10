package biscuit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/internal/formats/biscuit/pb"
	"github.com/kanywst/whosent/pkg/chain"
)

// A token under a kilobyte can describe work exponential in its size: a
// join over a few dozen facts, or closures nested a few deep. The engine
// used to check its limits only between fixpoint iterations, and never
// while evaluating a check, so each of these ran for minutes or forever
// and hung check, ask and the view. Each must now stop well inside a
// second, as an error that denies, never as a pass.
func TestHostileTokensStopPromptlyAsAnError(t *testing.T) {
	facts := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "f(%d); ", i)
		}
		return b.String()
	}
	closures := "[1,2,3,4,5,6,7,8,9,10].any($a0 -> "
	for i := 1; i < 9; i++ {
		closures += fmt.Sprintf("[1,2,3,4,5,6,7,8,9,10].any($a%d -> ", i)
	}
	closures += "false" + strings.Repeat(")", 9)
	tests := []struct {
		name string
		src  string
	}{
		{"a six-way join in a check", facts(40) + `check if f($a), f($b), f($c), f($d), f($e), f($g), $a == -1;`},
		{"closures nested nine deep", `check if ` + closures + `;`},
		{"a four-variable rule over sixty facts", facts(60) + `g($a, $b, $c, $d) <- f($a), f($b), f($c), f($d);`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: tt.src})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := m.Token()
			if err != nil {
				t.Fatal(err)
			}
			for _, opts := range []Options{
				readAuthorizer(t, `allow if true;`),
				{RootKeys: []Key{rootSigner.Pub}, Revoked: map[string]bool{}, Limits: datalog.DefaultLimits},
			} {
				start := time.Now()
				c := analyze(tok, opts, testAt, nil).chain("test")
				if d := time.Since(start); d > time.Second {
					t.Errorf("took %s; a hostile token must not hold up the view", d)
				}
				if s := statusOf(c, 0, RuleChecks); s != chain.StatusError {
					t.Errorf("B7 is %s, want an error: a run that hits its limits is refused", s)
				}
				if c.Verdict != chain.VerdictInvalid {
					t.Errorf("verdict %s, want INVALID", c.Verdict)
				}
			}
		})
	}
}

// An authorizer that supplies no time fact gets one from whosent, so the
// clock means something; the reference supplies none, so this is said.
func TestSuppliedTimeIsDisclosed(t *testing.T) {
	tok := mintThree(t, false)
	c := check(t, tok, readAuthorizer(t, `resource("a"); operation("read"); allow if true;`))
	found := false
	for _, f := range c.ChainFindings {
		found = found || f.Code == "b7.time_supplied"
	}
	if !found {
		t.Error("whosent supplied time(...) to an authorizer that had none without saying so")
	}
	c = check(t, tok, readAuthorizer(t, `resource("a"); operation("read"); time(2026-09-12T08:01:00Z); allow if true;`))
	for _, f := range c.ChainFindings {
		if f.Code == "b7.time_supplied" {
			t.Error("an authorizer with its own time fact was told whosent supplied one")
		}
	}
}

// A scope that names a public-key index the table does not define makes
// the reference refuse the token (UnknownExternalKey). whosent used to
// read it as "trusts nothing" and could call the token VALID.
func TestAScopeNamingAnUndefinedKeyIsRefused(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `right("a", "read"); check if true trusting ` + thirdSigner.Pub.String() + `;`})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Token()
	if err != nil {
		t.Fatal(err)
	}
	sb := &tok.Blocks[0]
	var blk pb.Block
	if err := proto.Unmarshal(sb.Data, &blk); err != nil {
		t.Fatal(err)
	}
	if len(blk.PublicKeys) == 0 {
		t.Fatal("the scope's key was not interned; the test would prove nothing")
	}
	blk.PublicKeys = nil
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(&blk)
	if err != nil {
		t.Fatal(err)
	}
	sb.Data = data
	var payload []byte
	if sb.Version == 1 {
		payload = payloadAuthorityV1(data, sb.NextKey, 1)
	} else {
		payload = payloadV0(data, sb.NextKey, nil)
	}
	if sb.Signature, err = rootSigner.Sign(payload); err != nil {
		t.Fatal(err)
	}
	c := check(t, tok, readAuthorizer(t, `allow if true;`))
	if c.Verdict == chain.VerdictValid {
		t.Fatal("a token the reference cannot load is VALID")
	}
	if s := statusOf(c, 0, RuleSymbols); s != chain.StatusFail {
		t.Errorf("B6 is %s, want a failure naming the undefined key", s)
	}
}
