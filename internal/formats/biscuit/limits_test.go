package biscuit

import (
	"context"
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

// The reference signs and verifies P-256 keys in their compressed form,
// whatever form the token carries them in. A token whose next key is sent
// uncompressed and signed over those uncompressed bytes is refused by the
// reference; one signed over the compressed bytes is accepted.
func TestP256KeysAreSignedInTheirCompressedForm(t *testing.T) {
	next := p256Signer(0)
	unc, err := next.ec.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		signOver []byte
		want     chain.Status
	}{
		{"signed over the uncompressed bytes", unc, chain.StatusFail},
		{"signed over the compressed bytes", next.Pub.Key, chain.StatusPass},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Mint(rootSigner, next, BlockSpec{Source: `right("a", "read");`})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := m.Token()
			if err != nil {
				t.Fatal(err)
			}
			sb := &tok.Blocks[0]
			signed := datalog.PublicKey{Alg: datalog.Secp256r1, Key: tt.signOver}
			if sb.Signature, err = rootSigner.Sign(payloadAuthorityV1(sb.Data, signed, 1)); err != nil {
				t.Fatal(err)
			}
			sb.Version, sb.HasVersion = 1, true
			sb.NextKey = datalog.PublicKey{Alg: datalog.Secp256r1, Key: unc}
			raw, err := tok.Encode()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			c := check(t, decoded, readAuthorizer(t, `allow if true;`))
			if s := statusOf(c, 0, RuleSignature); s != tt.want {
				t.Errorf("B3 is %s, want %s", s, tt.want)
			}
		})
	}
}

// Without a root key, a block whose signature does not match the key the
// block above handed on is still a failure: that much is checkable.
func TestATamperedBlockFailsEvenWithoutARootKey(t *testing.T) {
	tok := mintThree(t, false)
	tok.Blocks[1].Signature[5] ^= 1
	c := analyze(tok, Options{Revoked: map[string]bool{}, Limits: datalog.DefaultLimits}, testAt, nil).chain("test")
	if s := statusOf(c, 1, RuleSignature); s != chain.StatusFail {
		t.Errorf("a tampered block 1 is %s without a root key, want a failure", s)
	}
	if c.Verdict != chain.VerdictInvalid {
		t.Errorf("verdict %s", c.Verdict)
	}
}

// The reference prints strings raw, so a string holding a line break and
// a fake check read, in the block's Datalog listing, as a check the block
// does not have. The listing now escapes string terms; the native report
// keeps the reference's bytes.
func TestAStringCannotForgeALineOfDatalog(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `right("x\ncheck if time($t), $t < 2020-01-01T00:00:00Z");`})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Token()
	if err != nil {
		t.Fatal(err)
	}
	c := check(t, tok, readAuthorizer(t, `allow if true;`))
	found := false
	for _, sec := range c.Links[0].Sections {
		if sec.Title != "DATALOG" {
			continue
		}
		for _, l := range sec.Lines {
			found = true
			if strings.HasPrefix(strings.TrimSpace(l.Value), "check if") {
				t.Errorf("a string term forged a line of the listing: %q", l.Value)
			}
			if strings.Contains(l.Value, "\n") {
				t.Errorf("a listing line holds a line break: %q", l.Value)
			}
		}
	}
	if !found {
		t.Fatal("no DATALOG section; the test would prove nothing")
	}
}

// Ask used to drop the session's authorizer and decide with "allow if
// true", answering PERMITTED (AUTHORITATIVE) where the authorizer denies.
// The authorizer's rules, checks and policies now always take part.
func TestAskKeepsTheAuthorizer(t *testing.T) {
	mint := func(src string) *Token {
		m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: src})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := m.Token()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	tests := []struct {
		name       string
		token      string
		authorizer string
		values     map[string]string
		permitted  bool
		authority  string
	}{
		{"a token's reject if still rejects", `right("orders", "read"); reject if operation("delete");`, `operation("delete"); resource("orders"); allow if true;`,
			map[string]string{}, false, "AUTHORITATIVE"},
		{"the authorizer's deny policy still decides", `right("orders", "read");`, `deny if true;`,
			map[string]string{askFacts: `resource("orders"); operation("read")`}, false, "AUTHORITATIVE"},
		{"the authorizer's own check still runs", `right("orders", "read");`, `check if user("admin"); allow if true;`,
			map[string]string{askFacts: `resource("orders"); operation("read")`}, false, "AUTHORITATIVE"},
		{"with no policy anywhere nothing is allowed", `right("orders", "read");`, `resource("orders");`,
			map[string]string{}, false, "AUTHORITATIVE"},
		{"a policy the asker typed is not the deployment's", `right("orders", "read");`, `deny if true;`,
			map[string]string{askFacts: `resource("orders")`, askPolicy: `allow if true`}, true, "CONDITIONAL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := readAuthorizer(t, tt.authorizer)
			s := &Session{tok: mint(tt.token), opts: opts, at: testAt}
			c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: testAt})
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.Ask(context.Background(), c, tt.values)
			if err != nil {
				t.Fatal(err)
			}
			if r.Permitted != tt.permitted || r.Authority != tt.authority {
				t.Errorf("permitted %v (%s), want %v (%s): %s", r.Permitted, r.Authority, tt.permitted, tt.authority, r.Why)
			}
		})
	}
	s := &Session{tok: mint(`right("a", "read");`), opts: Options{RootKeys: []Key{rootSigner.Pub}, Revoked: map[string]bool{}, Limits: datalog.DefaultLimits}, at: testAt}
	if _, err := s.Ask(context.Background(), nil, map[string]string{}); err == nil {
		t.Error("a question with no request and no authorizer was answered")
	}
}
