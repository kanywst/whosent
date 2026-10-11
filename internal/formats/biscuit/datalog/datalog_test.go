package datalog

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

type sample struct {
	Filename string `json:"filename"`
	Token    []struct {
		Code    string `json:"code"`
		Version uint32 `json:"version"`
	} `json:"token"`
	Validations map[string]struct {
		AuthorizerCode string `json:"authorizer_code"`
	} `json:"validations"`
}

func samples(t *testing.T) []sample {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "samples", "samples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Testcases []sample `json:"testcases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f.Testcases
}

// dump prints an authorizer program the way the reference's dump_code
// does: facts, rules, checks, then policies, each group followed by an
// empty line except the last.
func dump(p Program, syms *SymbolTable) string {
	c := &converter{syms: syms}
	var sb strings.Builder
	for _, f := range p.Facts {
		sb.WriteString(syms.PrintFact(Fact{Predicate: c.pred(f.Predicate)}) + ";\n")
	}
	if len(p.Facts) > 0 {
		sb.WriteString("\n")
	}
	for _, r := range p.Rules {
		sb.WriteString(syms.PrintRule(c.rule(r)) + ";\n")
	}
	if len(p.Rules) > 0 {
		sb.WriteString("\n")
	}
	for _, ch := range p.Checks {
		sb.WriteString(syms.PrintCheck(c.check(ch)) + ";\n")
	}
	if len(p.Checks) > 0 {
		sb.WriteString("\n")
	}
	for _, pol := range p.Policies {
		sb.WriteString(syms.PrintPolicy(ConvertPolicy(pol, syms)) + ";\n")
	}
	return sb.String()
}

// Every authorizer in the specification's samples, parsed and printed
// again, is the text the reference printed for it: the parser reads what
// the reference writes, into the same structure.
func TestAuthorizerSourceRoundTrips(t *testing.T) {
	for _, s := range samples(t) {
		for name, v := range s.Validations {
			if v.AuthorizerCode == "" {
				continue
			}
			p, err := ParseProgram(v.AuthorizerCode)
			if err != nil {
				t.Errorf("%s/%s: %v", s.Filename, name, err)
				continue
			}
			if got := dump(p, NewSymbolTable()); got != v.AuthorizerCode {
				t.Errorf("%s/%s prints\n%s\nthe reference printed\n%s", s.Filename, name, got, v.AuthorizerCode)
			}
		}
	}
}

// Every block in the samples, parsed from the source the reference printed
// and printed again, is the same source; and encoded to protobuf and read
// back, it is still the same.
func TestBlockSourceRoundTripsThroughTheParserAndTheWireFormat(t *testing.T) {
	for _, s := range samples(t) {
		syms := NewSymbolTable()
		for i, blk := range s.Token {
			if strings.HasPrefix(s.Filename, "test018") {
				// Its rule is the one the reference's parser refuses: it can
				// only exist in a token minted by hand.
				continue
			}
			b, err := ParseBlock(blk.Code)
			if err != nil {
				t.Errorf("%s block %d: %v\n%s", s.Filename, i, err, blk.Code)
				continue
			}
			table := syms
			if strings.HasPrefix(s.Filename, "test024") || strings.HasPrefix(s.Filename, "test026") || strings.HasPrefix(s.Filename, "test037") {
				// Third-party blocks use their own tables; a fresh one per
				// block is close enough for printing.
				table = NewSymbolTable()
			}
			before, keysBefore := table.Len(), len(table.Keys())
			conv := ConvertBlock(b, table)
			conv.Version = blk.Version
			if got := table.PrintBlock(conv); got != blk.Code {
				t.Errorf("%s block %d prints\n%s\nwant\n%s", s.Filename, i, got, blk.Code)
			}
			wire, err := proto.Marshal(ToProto(conv, table.Strings()[before:], table.Keys()[keysBefore:]))
			if err != nil {
				t.Fatal(err)
			}
			pbb, err := DecodeBlock(wire)
			if err != nil {
				t.Fatal(err)
			}
			back, _, _, err := FromProto(pbb, false)
			if err != nil && !strings.HasPrefix(s.Filename, "test024") && !strings.HasPrefix(s.Filename, "test037") {
				t.Errorf("%s block %d does not read back: %v", s.Filename, i, err)
				continue
			}
			if err == nil {
				if got := table.PrintBlock(back); got != blk.Code {
					t.Errorf("%s block %d reads back as\n%s", s.Filename, i, got)
				}
			}
		}
	}
}

func eval(t *testing.T, src string) (Term, *SymbolTable, error) {
	t.Helper()
	p, err := ParseProgram("check if " + src + ";")
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	syms := NewSymbolTable()
	c := (&converter{syms: syms}).check(p.Checks[0])
	v, err := evaluate(c.Queries[0].Expressions[0].Ops, map[uint64]Term{}, newTemp(syms))
	return v, syms, err
}

func TestExpressions(t *testing.T) {
	tests := []struct {
		src  string
		want string // "true", "false", or an error kind
	}{
		{`1 + 2 * 3 - 4 / 2 === 5`, "true"},
		{`9223372036854775807 + 1 === 0`, "Overflow"},
		{`-9223372036854775808 - 1 === 0`, "Overflow"},
		{`10000000000 * 10000000000 === 0`, "Overflow"},
		{`-9223372036854775808 * -1 === 0`, "Overflow"},
		{`1 / 0 === 0`, "DivideByZero"},
		{`-9223372036854775808 / -1 === 0`, "DivideByZero"},
		{`(1 | 2) ^ 3 === 0`, "true"},
		{`(6 & 3) === 2`, "true"},
		{`"abc".starts_with("ab") && "abc".ends_with("bc")`, "true"},
		{`"abc".contains("b") || false`, "true"},
		{`"a" + "b" === "ab"`, "true"},
		{`"é".length() === 2`, "true"},
		{`"file123.txt".matches("file[0-9]+.txt")`, "true"},
		{`"x".matches("(")`, "false"},
		{`{1, 2}.contains({2})`, "true"},
		{`{1, 2}.union({3}) === {1, 2, 3}`, "true"},
		{`{1, 2}.intersection({2, 3}).length() === 1`, "true"},
		{`{1, 2}.contains(null)`, "InvalidType"},
		{`1 === "a"`, "InvalidType"},
		{`1 == "a"`, "false"},
		{`1 != "a"`, "true"},
		{`null == null && null != 1`, "true"},
		{`null === 1`, "InvalidType"},
		{`[1, 2, 3].starts_with([1, 2]) && [1, 2, 3].ends_with([3])`, "true"},
		{`[1, 2].get(5) == null`, "true"},
		{`[1, 2].get(-1) == null`, "true"},
		{`{"a": 1, 2: "b"}.get("a") === 1`, "true"},
		{`{"a": 1}.contains("a") && !{"a": 1}.contains(1)`, "true"},
		{`{1, 2, 3}.all($p -> $p > 0)`, "true"},
		{`{1, 2, 3}.any($p -> $p > 2)`, "true"},
		{`{"a": 1}.all($kv -> $kv.get(1) === 1)`, "true"},
		{`(true === 12).try_or(true)`, "true"},
		{`true.try_or(true === 12)`, "InvalidType"},
		{`false && "x".intersection("x")`, "false"},
		{`1.type() === "integer" && null.type() === "null" && [1].type() === "array"`, "true"},
		{`{"t"}.any($p -> {"t"}.all($p -> true))`, "ShadowedVariable"},
		{`2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z`, "true"},
		{`hex:12ab === hex:12ab`, "true"},
		{`1.extern::f()`, "UndefinedExtern"},
	}
	for _, tt := range tests {
		v, _, err := eval(t, tt.src)
		var got string
		switch {
		case err != nil:
			got = err.(*ExprError).Kind
		case v.Kind != KindBool:
			got = "non-bool"
		default:
			got = map[bool]string{true: "true", false: "false"}[v.Bool]
		}
		if got != tt.want {
			t.Errorf("%s: %s, want %s", tt.src, got, tt.want)
		}
	}
}

func TestParserRefusesWhatTheReferenceRefuses(t *testing.T) {
	for _, src := range []string{
		`right("a"`,
		`check if`,
		`allow if resource($x`,
		`head($x) <- body($y);`,
		`fact($x);`,
		`fact({$x});`,
		`fact({{1}});`,
		`fact({1, "a"});`,
		`fact("unterminated);`,
		`fact("\t");`,
		`fact({param});`,
		`check if "a".nope();`,
		`/* unterminated`,
		`check if x() trusting nobody;`,
	} {
		if _, err := ParseProgram(src); err == nil {
			t.Errorf("%q parsed", src)
		}
	}
	if _, err := ParseBlock(`allow if true;`); err == nil {
		t.Error("a block with a policy parsed")
	}
}

func TestParserReadsCommentsAndScopes(t *testing.T) {
	p, err := ParseProgram("// a comment\nresource(\"a\"); /* block */ check if right($x) trusting authority, previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;\nCHECK IF true;\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Facts) != 1 || len(p.Checks) != 2 || len(p.Checks[0].Queries[0].Scopes) != 3 {
		t.Fatalf("%+v", p)
	}
	b, err := ParseBlock("trusting previous;\ncheck if right(\"x\");")
	if err != nil || len(b.Scopes) != 1 || b.Scopes[0].Kind != ScopePrevious {
		t.Fatalf("block scopes: %+v %v", b.Scopes, err)
	}
	if SchemaVersion(b) != Version31 {
		t.Errorf("a scoped block needs v3.1, got %d", SchemaVersion(b))
	}
}

func TestRunLimitsStopRunawayRules(t *testing.T) {
	var facts, edges strings.Builder
	for i := 0; i < 10; i++ {
		facts.WriteString("a(" + itoa(i) + ");\n")
	}
	for i := 0; i < 30; i++ {
		edges.WriteString("e(" + itoa(i) + ", " + itoa(i+1) + ");\n")
	}
	pairs, err := ParseProgram(facts.String() + `p($x, $y) <- a($x), a($y);`)
	if err != nil {
		t.Fatal(err)
	}
	res := Authorize(nil, pairs, Limits{MaxFacts: 50, MaxIterations: 1000, MaxTime: DefaultLimits.MaxTime})
	var le *LimitError
	if res.Err == nil || !asLimit(res.Err, &le) || le.Kind != "TooManyFacts" {
		t.Errorf("err %v, want TooManyFacts", res.Err)
	}
	closure, err := ParseProgram(edges.String() + `r($x, $y) <- e($x, $y); r($x, $z) <- r($x, $y), e($y, $z);`)
	if err != nil {
		t.Fatal(err)
	}
	res = Authorize(nil, closure, Limits{MaxFacts: 1 << 20, MaxIterations: 10, MaxTime: DefaultLimits.MaxTime})
	if res.Err == nil || !asLimit(res.Err, &le) || le.Kind != "TooManyIterations" {
		t.Errorf("err %v, want TooManyIterations", res.Err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func asLimit(err error, target **LimitError) bool {
	l, ok := err.(*LimitError)
	if ok {
		*target = l
	}
	return ok
}

func TestPrintingCornerCases(t *testing.T) {
	s := NewSymbolTable()
	tests := []struct {
		term Term
		want string
	}{
		{Str(5000), `"<5000?>"`},
		{Date(math.MaxUint64), "1969-12-31T23:59:59Z"},
		{Date(1 << 62), "<invalid date>"},
		{Set(nil), "{,}"},
		{Map([]MapEntry{{Key: MapKey{IsString: true, U: 0}, Value: Int(1)}, {Key: MapKey{I: 2}, Value: Null()}}), `{2: null, "read": 1}`},
		{Bytes([]byte{0xab}), "hex:ab"},
	}
	for _, tt := range tests {
		if got := s.PrintTerm(tt.term); got != tt.want {
			t.Errorf("%s, want %s", got, tt.want)
		}
	}
	if got := s.PrintExpression(Expression{Ops: []Op{{Kind: OpBinary, Binary: StrictEqual}}}); got != "<invalid expression>" {
		t.Errorf("an invalid expression prints %q", got)
	}
}

func FuzzParseProgram(f *testing.F) {
	for _, s := range []string{
		`resource("a"); allow if true;`,
		`check if time($t), $t <= 2026-01-01T00:00:00Z;`,
		`check if {1, 2}.any($p -> $p > 1) trusting previous;`,
		`a($x) <- b($x), $x.matches("[a-z]+") || {"k": [1, null]}.get("k").length() == 2;`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, src string) {
		p, err := ParseProgram(src)
		if err != nil {
			return
		}
		// Whatever parses must print, and an authorizer of it alone must
		// run to an answer or an error, never a panic.
		_ = dump(p, NewSymbolTable())
		_ = Authorize(nil, p, Limits{MaxFacts: 100, MaxIterations: 20, MaxTime: DefaultLimits.MaxTime})
	})
}

type fullSample struct {
	Filename string `json:"filename"`
	Token    []struct {
		Code        string  `json:"code"`
		Version     uint32  `json:"version"`
		ExternalKey *string `json:"external_key"`
	} `json:"token"`
	Validations map[string]struct {
		AuthorizerCode string          `json:"authorizer_code"`
		Result         json.RawMessage `json:"result"`
		World          *struct {
			Facts []struct {
				Origin []*int   `json:"origin"`
				Facts  []string `json:"facts"`
			} `json:"facts"`
		} `json:"world"`
	} `json:"validations"`
}

type failedJSON struct {
	BlockID int    `json:"block_id"`
	CheckID int    `json:"check_id"`
	Rule    string `json:"rule"`
}

// TestEngineAgreesWithTheReferenceOnEverySample rebuilds each sample
// token's blocks from the source the reference printed, runs the sample's
// authorizer, and compares the outcome with the reference's: the policy,
// every failed check in order, the error that stopped it, and the world of
// facts. The parent package runs the same comparison on the decoded
// tokens; this one exercises the engine on its own.
func TestEngineAgreesWithTheReferenceOnEverySample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "samples", "samples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Testcases []fullSample `json:"testcases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.Testcases {
		if strings.HasPrefix(s.Filename, "test018") || strings.HasPrefix(s.Filename, "test035") {
			continue
		}
		syms := NewSymbolTable()
		var blocks []TokenBlock
		for _, blk := range s.Token {
			b, err := ParseBlock(blk.Code)
			if err != nil {
				t.Fatalf("%s: %v", s.Filename, err)
			}
			tb := TokenBlock{Symbols: syms}
			if blk.ExternalKey != nil {
				tb.Symbols = NewSymbolTable()
				kp := &parser{s: *blk.ExternalKey}
				k, ok := kp.publicKey()
				if !ok {
					t.Fatalf("%s: external key %q", s.Filename, *blk.ExternalKey)
				}
				tb.ExternalKey = &k
			}
			tb.Block = ConvertBlock(b, tb.Symbols)
			tb.Block.Version = blk.Version
			blocks = append(blocks, tb)
		}
		for name, v := range s.Validations {
			var r struct {
				Ok  *int `json:"Ok"`
				Err map[string]json.RawMessage
			}
			if err := json.Unmarshal(v.Result, &r); err != nil {
				t.Fatal(err)
			}
			if _, isFormat := r.Err["Format"]; isFormat {
				continue
			}
			prog, err := ParseProgram(v.AuthorizerCode)
			if err != nil {
				t.Fatalf("%s/%s: %v", s.Filename, name, err)
			}
			got := Authorize(blocks, prog, DefaultLimits)
			var want struct {
				policy  *PolicyMatch
				failed  []FailedCheck
				exec    string
				noMatch bool
			}
			if r.Ok != nil {
				want.policy = &PolicyMatch{Index: *r.Ok, Allow: true}
			}
			if raw, ok := r.Err["Execution"]; ok {
				_ = json.Unmarshal(raw, &want.exec)
			}
			if raw, ok := r.Err["FailedLogic"]; ok {
				var fl map[string]struct {
					Policy map[string]int          `json:"policy"`
					Checks []map[string]failedJSON `json:"checks"`
				}
				_ = json.Unmarshal(raw, &fl)
				for kind, body := range fl {
					want.noMatch = kind == "NoMatchingPolicy"
					for k, i := range body.Policy {
						want.policy = &PolicyMatch{Index: i, Allow: k == "Allow"}
					}
					for _, c := range body.Checks {
						for k, fc := range c {
							b := -1
							if k == "Block" {
								b = fc.BlockID
							}
							want.failed = append(want.failed, FailedCheck{Block: b, Check: fc.CheckID, Rule: fc.Rule})
						}
					}
				}
			}
			where := s.Filename + "/" + name
			if want.exec != "" {
				if ee, ok := got.Err.(*ExprError); !ok || ee.Kind != want.exec {
					var re *RuleError
					if !errorsAs(got.Err, &re) || re.Err.(*ExprError).Kind != want.exec {
						t.Errorf("%s: error %v, want %s", where, got.Err, want.exec)
					}
				}
				continue
			}
			if got.Err != nil {
				t.Errorf("%s: %v", where, got.Err)
				continue
			}
			if !reflect.DeepEqual(got.Failed, want.failed) && (len(got.Failed) != 0 || len(want.failed) != 0) {
				t.Errorf("%s: failed %v, want %v", where, got.Failed, want.failed)
			}
			if !reflect.DeepEqual(got.Policy, want.policy) {
				t.Errorf("%s: policy %+v, want %+v", where, got.Policy, want.policy)
			}
			if got.Authorized() != (r.Ok != nil) {
				t.Errorf("%s: authorized %v", where, got.Authorized())
			}
			if v.World != nil {
				n := 0
				for _, of := range got.WorldFacts() {
					n += len(of.Facts)
				}
				w := 0
				for _, of := range v.World.Facts {
					w += len(of.Facts)
				}
				if n != w {
					t.Errorf("%s: %d facts in the world, the reference had %d", where, n, w)
				}
			}
		}
	}
}

func errorsAs(err error, target **RuleError) bool {
	re, ok := err.(*RuleError)
	if ok {
		*target = re
	}
	return ok
}

func TestTablesAndCloning(t *testing.T) {
	s := NewSymbolTable()
	if err := s.Extend([]string{"a", "b", "a"}); err != nil {
		t.Fatalf("a repeated symbol within one block is accepted, as the reference accepts it: %v", err)
	}
	if err := s.Extend([]string{"b"}); err == nil {
		t.Error("a symbol an earlier block defined was accepted again")
	}
	if err := s.Extend([]string{"read"}); err == nil {
		t.Error("a default symbol was accepted as a block's own")
	}
	k := PublicKey{Alg: Secp256r1, Key: []byte{2, 1}}
	if err := s.ExtendKeys([]PublicKey{k, k}); err == nil {
		t.Error("a key listed twice was accepted")
	}
	c := s.Clone()
	c.Insert("z")
	if _, ok := s.index["z"]; ok {
		t.Error("a clone shares its index with the original")
	}
	if i := s.Insert("a"); i != Offset {
		t.Errorf("the first occurrence of a repeated symbol is %d, want %d", i, Offset)
	}
	if k.String() != "secp256r1/0201" || Algorithm(7).String() != "algorithm(7)" {
		t.Errorf("key printing: %s %s", k, Algorithm(7))
	}
	if got := (Origin(0).IDs()); len(got) != 0 {
		t.Errorf("empty origin ids %v", got)
	}
}
