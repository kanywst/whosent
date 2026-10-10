package biscuit

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/internal/formats/biscuit/pb"
	"github.com/kanywst/whosent/pkg/chain"
)

var testAt = time.Date(2026, 9, 12, 8, 1, 0, 0, time.UTC)

func mintThree(t *testing.T, third bool) *Token {
	t.Helper()
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `right("a", "read"); check if resource($r), operation($o), right($r, $o);`})
	if err != nil {
		t.Fatal(err)
	}
	if third {
		err = m.AppendThirdParty(blockSigner(1), thirdSigner, BlockSpec{Source: `group("x");`})
	} else {
		err = m.Append(blockSigner(1), BlockSpec{Source: `check if operation("read");`})
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Append(blockSigner(2), BlockSpec{Source: `check if resource("a");`}); err != nil {
		t.Fatal(err)
	}
	tok, err := m.Token()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func readAuthorizer(t *testing.T, src string) Options {
	t.Helper()
	p, err := datalog.ParseProgram(src)
	if err != nil {
		t.Fatal(err)
	}
	return Options{RootKeys: []Key{rootSigner.Pub}, Revoked: map[string]bool{}, Program: p, HasAuthorizer: true, Limits: datalog.DefaultLimits}
}

func statusOf(c *chain.Chain, link int, rule string) chain.Status {
	return c.Links[link].Check(rule).Status
}

func check(t *testing.T, tok *Token, opts Options) *chain.Chain {
	t.Helper()
	c := analyze(tok, opts, testAt, nil).chain("test")
	for _, p := range problems(c) {
		t.Error(p)
	}
	return c
}

func TestTamperedTokensBreakWhereTheyWereTampered(t *testing.T) {
	ok := readAuthorizer(t, `resource("a"); operation("read"); allow if true;`)
	tests := []struct {
		name  string
		edit  func(*Token)
		link  int
		rule  string
		third bool
	}{
		{"a signature payload version that does not exist", func(tk *Token) { tk.Blocks[1].Version, tk.Blocks[1].HasVersion = 2, true }, 1, RuleSignature, false},
		{"a next key of the wrong length", func(tk *Token) { tk.Blocks[0].NextKey.Key = tk.Blocks[0].NextKey.Key[:31] }, 0, RuleFormat, false},
		{"a truncated signature", func(tk *Token) { tk.Blocks[2].Signature = tk.Blocks[2].Signature[:10] }, 2, RuleSignature, false},
		{"Datalog that does not decode", func(tk *Token) { tk.Blocks[1].Data = []byte{0xff, 0xff, 0xff} }, 1, RuleFormat, false},
		{"an authority block with a third-party signature", func(tk *Token) {
			tk.Blocks[0].External = &ExternalSig{Signature: make([]byte, 64), Key: thirdSigner.Pub.PublicKey}
		}, 0, RuleThirdParty, false},
		{"a third-party signature that does not verify", func(tk *Token) { tk.Blocks[1].External.Signature[0] ^= 1 }, 1, RuleThirdParty, true},
		{"a third-party block on the legacy payload", func(tk *Token) { tk.Blocks[1].Version, tk.Blocks[1].HasVersion = 0, false }, 1, RuleThirdParty, true},
		{"a proof whose key is not the last block's", func(tk *Token) { tk.NextSecret = seed(0x99) }, 2, RuleProof, false},
		{"a proof that is not a key", func(tk *Token) { tk.NextSecret = []byte{1, 2, 3} }, 2, RuleProof, false},
		{"no proof", func(tk *Token) { tk.NextSecret, tk.HasProof = nil, false }, 2, RuleProof, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := mintThree(t, tt.third)
			tt.edit(tok)
			raw, err := tok.Encode()
			if err != nil {
				t.Fatal(err)
			}
			back, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !tok.HasProof {
				back.HasProof, back.NextSecret = false, nil
			}
			c := check(t, back, ok)
			if c.Verdict != chain.VerdictInvalid {
				t.Fatalf("verdict %s", c.Verdict)
			}
			if s := statusOf(c, tt.link, tt.rule); !s.Blocking() {
				t.Errorf("%s at link %d is %s: %v", tt.rule, tt.link, s, c.Findings())
			}
			for _, l := range c.Links {
				if l.Check(RuleChecks).Status == chain.StatusPass {
					t.Errorf("link %d's checks were evaluated on a token that does not verify", l.Index)
				}
			}
		})
	}
}

func TestASealedTokenWithAForgedSealFails(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `right("a", "read");`})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Sealed()
	if err != nil {
		t.Fatal(err)
	}
	tok.FinalSignature[5] ^= 1
	c := check(t, tok, readAuthorizer(t, `allow if true;`))
	if s := statusOf(c, 0, RuleProof); s != chain.StatusFail {
		t.Errorf("a forged seal is %s", s)
	}
}

func encodeRaw(t *testing.T, b *pb.Block) []byte {
	t.Helper()
	data, err := proto.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBlocksTheReferenceRefusesToRead(t *testing.T) {
	ok := readAuthorizer(t, `allow if true;`)
	tests := []struct {
		name  string
		block *pb.Block
		rule  string
	}{
		{"a datalog version from the future", &pb.Block{Version: proto.Uint32(9)}, RuleVersion},
		{"a check kind in a v3.0 block", &pb.Block{Version: proto.Uint32(3), Checks: []*pb.Check{{Kind: pb.Check_All.Enum()}}}, RuleVersion},
		{"a default symbol redefined", &pb.Block{Version: proto.Uint32(3), Symbols: []string{"read"}}, RuleSymbols},
		{"a symbol an earlier block defined", &pb.Block{Version: proto.Uint32(3), Symbols: []string{"a"}}, RuleSymbols},
		{"a reference to a symbol nobody defined", &pb.Block{Version: proto.Uint32(3), Facts: []*pb.Fact{{Predicate: &pb.Predicate{Name: proto.Uint64(5000)}}}}, RuleSymbols},
		{"a set holding a variable", &pb.Block{Version: proto.Uint32(3), Facts: []*pb.Fact{{Predicate: &pb.Predicate{Name: proto.Uint64(0), Terms: []*pb.Term{{Content: &pb.Term_Set{Set: &pb.TermSet{Set: []*pb.Term{{Content: &pb.Term_Variable{Variable: 0}}}}}}}}}}}, RuleFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `right("a", "read");`})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.appendSigned(blockSigner(1), encodeRaw(t, tt.block), 3, nil); err != nil {
				t.Fatal(err)
			}
			tok, err := m.Token()
			if err != nil {
				t.Fatal(err)
			}
			c := check(t, tok, ok)
			if s := statusOf(c, 1, tt.rule); !s.Blocking() {
				t.Errorf("%s is %s: %v", tt.rule, s, c.Findings())
			}
		})
	}
}

func TestAnExpressionErrorStopsTheAuthorization(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `check if 9223372036854775807 + 1 === 0;`})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := m.Token()
	c := check(t, tok, readAuthorizer(t, `allow if true;`))
	if s := statusOf(c, 0, RuleChecks); s != chain.StatusError {
		t.Errorf("an overflowing check is %s", s)
	}
	unchecked := check(t, tok, Options{RootKeys: []Key{rootSigner.Pub}, Limits: datalog.DefaultLimits})
	if s := statusOf(unchecked, 0, RuleChecks); s != chain.StatusUnchecked {
		t.Errorf("without an authorizer an error decides nothing; got %s", s)
	}
}

func TestExternalFunctionsAreNeverGuessed(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `check if 1.extern::f();`})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := m.Token()
	c := check(t, tok, readAuthorizer(t, `allow if true;`))
	if s := statusOf(c, 0, RuleChecks); s != chain.StatusUnchecked {
		t.Errorf("an extern call is %s", s)
	}
	if c.Verdict != chain.VerdictIncomplete {
		t.Errorf("verdict %s", c.Verdict)
	}
}

func TestPoliciesDecide(t *testing.T) {
	tok := mintThree(t, false)
	cases := []struct {
		src  string
		want chain.Verdict
		code string
	}{
		{`resource("a"); operation("read"); deny if true;`, chain.VerdictInvalid, "b7.deny"},
		{`resource("a"); operation("read"); allow if false;`, chain.VerdictInvalid, "b7.no_policy"},
		{`resource("a"); operation("read"); check if user("x"); allow if true;`, chain.VerdictInvalid, "b7.authorizer_check"},
		// No policy at all: the reference's authorizer has nothing to match
		// and denies (NoMatchingPolicy), so this is not VALID.
		{`resource("a"); operation("read");`, chain.VerdictInvalid, "b7.no_policy"},
		{`resource("a"); operation("read"); allow if true;`, chain.VerdictValid, ""},
	}
	for _, tt := range cases {
		c := check(t, tok, readAuthorizer(t, tt.src))
		if c.Verdict != tt.want {
			t.Errorf("%s: %s", tt.src, c.Verdict)
		}
		if tt.code != "" {
			found := false
			for _, f := range c.ChainFindings {
				found = found || f.Code == tt.code
			}
			if !found {
				t.Errorf("%s: no %s finding in %v", tt.src, tt.code, c.ChainFindings)
			}
		}
	}
}

func TestRootKeysAreReadInEveryForm(t *testing.T) {
	dir := t.TempDir()
	pub := rootSigner.Pub
	hexKey := hex.EncodeToString(pub.Key)
	text := filepath.Join(dir, "root.pub")
	raw := filepath.Join(dir, "root.bin")
	if err := os.WriteFile(text, []byte(pub.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raw, pub.Key, 0o600); err != nil {
		t.Fatal(err)
	}
	p256 := p256Signer(0).Pub
	for _, v := range []string{pub.String(), hexKey, text, raw, p256.String(), hex.EncodeToString(p256.Key)} {
		k, _, err := readRootKey(v)
		if err != nil {
			t.Errorf("%s: %v", v, err)
			continue
		}
		if !k.Equal(pub.PublicKey) && !k.Equal(p256.PublicKey) {
			t.Errorf("%s read as %s", v, k)
		}
	}
	for _, v := range []string{"ed25519/zz", "ed25519/" + hexKey[:10], filepath.Join(dir, "missing")} {
		if _, _, err := readRootKey(v); err == nil {
			t.Errorf("%s was read as a key", v)
		}
	}
}

func TestTheRevocationListIsRead(t *testing.T) {
	tok := mintThree(t, false)
	dir := t.TempDir()
	list := filepath.Join(dir, "revoked.txt")
	id := hexID(tok.Blocks[2].Signature)
	if err := os.WriteFile(list, []byte("# revoked\n\n"+strings.ToUpper(id)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, _ := tok.Text()
	s, err := New().Open(context.Background(), chain.Inputs{Data: []byte(text), RevokedIDs: list, RootKeys: []string{rootSigner.Pub.String()},
		Facts: []string{`resource("a")`, `operation("read")`}, Revocations: "set.json", Audience: new(string), JWKS: []string{"x=y"}, At: testAt})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Evaluate(context.Background(), chain.EvalOptions{At: testAt})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Links[2].Revoked || c.BreakAt != 2 {
		t.Errorf("block 2 is on the list: revoked %v, break %d", c.Links[2].Revoked, c.BreakAt)
	}
	ignored := 0
	for _, kv := range c.CheckedAgainst {
		if kv.Key == "ignored" {
			ignored++
		}
	}
	if ignored != 3 {
		t.Errorf("%d ignored inputs reported, want 3: %v", ignored, c.CheckedAgainst)
	}
	if err := os.WriteFile(list, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New().Open(context.Background(), chain.Inputs{Data: []byte(text), RevokedIDs: list}); err == nil {
		t.Error("a list that is not hex was accepted")
	}
}

func TestP256KeysSentUncompressedAreAcceptedAsTheReferenceDoes(t *testing.T) {
	s := p256Signer(3)
	unc, err := s.ec.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(datalog.PublicKey{Alg: datalog.Secp256r1, Key: unc})
	if err != nil || !k.Uncompressed {
		t.Fatalf("uncompressed key: %v %v", err, k.Uncompressed)
	}
	sig, err := s.Sign([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify([]byte("x"), sig); err != nil {
		t.Errorf("verifying with the uncompressed key: %v", err)
	}
	secret, _ := s.Secret()
	if ok, err := secretMatches(k, secret); err != nil || !ok {
		t.Errorf("the secret does not match its uncompressed key: %v %v", ok, err)
	}
	if _, err := ParseKey(datalog.PublicKey{Alg: datalog.Secp256r1, Key: []byte{5, 1, 2}}); err == nil {
		t.Error("a key that is not a SEC1 point parsed")
	}
	if _, err := ParseKey(datalog.PublicKey{Alg: datalog.Ed25519, Key: make([]byte, 32)}); err != nil {
		t.Logf("the all-zero Ed25519 key: %v", err)
	}
	if !smallOrder(make([]byte, 32)) {
		t.Error("the identity-adjacent encoding should be small order")
	}
}

func TestExpiryReadsLessThanToo(t *testing.T) {
	m, err := Mint(rootSigner, blockSigner(0), BlockSpec{Source: `check if time($t), $t < 2026-09-12T09:00:00Z;`})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := m.Token()
	c := check(t, tok, Options{Limits: datalog.DefaultLimits})
	if got := c.Links[0].ExpiresAt; !got.Equal(time.Date(2026, 9, 12, 8, 59, 59, 0, time.UTC)) {
		t.Errorf("expires %s", got)
	}
}
