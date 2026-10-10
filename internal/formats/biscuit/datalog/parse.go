package datalog

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The parser reads authorizer code: facts, rules, checks and policies, as
// the reference parser (biscuit-parser) reads them. It accepts the same
// language, including that parser's precedence, which differs from the
// specification's prose for the bitwise operators: "^" binds loosest of
// the three and "&" tightest.

// ParseError locates a statement the parser could not read.
type ParseError struct {
	Offset int
	Text   string
	Msg    string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("datalog: %s, at %q", e.Msg, e.Text)
}

type parser struct {
	s   string
	pos int
}

var errNoMatch = errors.New("no match")

func (p *parser) rest() string { return p.s[p.pos:] }

func (p *parser) ws() {
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) lit(t string) bool {
	if strings.HasPrefix(p.rest(), t) {
		p.pos += len(t)
		return true
	}
	return false
}

func (p *parser) litFold(t string) bool {
	if len(p.rest()) >= len(t) && strings.EqualFold(p.rest()[:len(t)], t) {
		p.pos += len(t)
		return true
	}
	return false
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == ':'
}

func (p *parser) name() (string, bool) {
	start := p.pos
	for p.pos < len(p.s) && isNameChar(p.s[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", false
	}
	return p.s[start:p.pos], true
}

// ParseProgram reads authorizer code.
func ParseProgram(src string) (Program, error) {
	var prog Program
	p := &parser{s: src}
	for {
		p.ws()
		if p.pos >= len(p.s) {
			return prog, nil
		}
		if p.lit("//") {
			for p.pos < len(p.s) && p.s[p.pos] != '\n' && p.s[p.pos] != '\r' {
				p.pos++
			}
			continue
		}
		if p.lit("/*") {
			end := strings.Index(p.rest(), "*/")
			if end < 0 {
				return prog, p.fail("an unterminated comment")
			}
			p.pos += end + 2
			continue
		}
		start := p.pos
		if err := p.statement(&prog); err != nil {
			text := src[start:]
			if i := strings.IndexByte(text, ';'); i >= 0 {
				text = text[:i]
			}
			if len(text) > 80 {
				text = text[:80]
			}
			msg := err.Error()
			if errors.Is(err, errNoMatch) {
				msg = "not a fact, rule, check or policy"
			}
			return prog, &ParseError{Offset: start, Text: strings.TrimSpace(text), Msg: msg}
		}
	}
}

func (p *parser) fail(msg string) error { return errors.New(msg) }

// statement tries a rule, a fact, a check, then a policy, as the reference
// does, and requires a ";" or the end of the input after it.
func (p *parser) statement(prog *Program) error {
	start := p.pos
	var firstErr error
	note := func(err error) {
		if !errors.Is(err, errNoMatch) && firstErr == nil {
			firstErr = err
		}
	}
	end := func() error {
		p.ws()
		if p.pos >= len(p.s) || p.lit(";") {
			return nil
		}
		return fmt.Errorf("unexpected %q after the statement", firstRune(p.rest()))
	}

	if r, err := p.rule(); err == nil {
		if err = end(); err == nil {
			prog.Rules = append(prog.Rules, r)
			return nil
		}
		note(err)
	} else {
		note(err)
	}
	p.pos = start
	if f, err := p.fact(); err == nil {
		if err = end(); err == nil {
			prog.Facts = append(prog.Facts, f)
			return nil
		}
		note(err)
	} else {
		note(err)
	}
	p.pos = start
	if c, err := p.check(); err == nil {
		if err = end(); err == nil {
			prog.Checks = append(prog.Checks, c)
			return nil
		}
		note(err)
	} else {
		note(err)
	}
	p.pos = start
	if pol, err := p.policy(); err == nil {
		if err = end(); err == nil {
			prog.Policies = append(prog.Policies, pol)
			return nil
		}
		note(err)
	} else {
		note(err)
	}
	if firstErr != nil {
		return firstErr
	}
	return errNoMatch
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

func (p *parser) fact() (Fact, error) {
	p.ws()
	name, ok := p.name()
	if !ok {
		return Fact{}, errNoMatch
	}
	p.ws()
	if !p.lit("(") {
		return Fact{}, errNoMatch
	}
	var terms []Term
	for {
		t, err := p.termInFact()
		if err != nil {
			return Fact{}, err
		}
		terms = append(terms, t)
		p.ws()
		if p.lit(",") {
			continue
		}
		if p.lit(")") {
			break
		}
		return Fact{}, p.fail("expected \",\" or \")\" in a fact")
	}
	return Fact{Predicate: Predicate{NameS: name, Terms: terms}}, nil
}

func (p *parser) predicate(allowEmpty bool) (Predicate, error) {
	p.ws()
	name, ok := p.name()
	if !ok {
		return Predicate{}, errNoMatch
	}
	p.ws()
	if !p.lit("(") {
		return Predicate{}, errNoMatch
	}
	var terms []Term
	p.ws()
	if allowEmpty && p.lit(")") {
		return Predicate{NameS: name}, nil
	}
	for {
		t, err := p.term()
		if err != nil {
			return Predicate{}, err
		}
		terms = append(terms, t)
		p.ws()
		if p.lit(",") {
			continue
		}
		if p.lit(")") {
			break
		}
		return Predicate{}, p.fail("expected \",\" or \")\" in a predicate")
	}
	return Predicate{NameS: name, Terms: terms}, nil
}

func (p *parser) rule() (Rule, error) {
	head, err := p.predicate(true)
	if err != nil {
		return Rule{}, errNoMatch
	}
	p.ws()
	if !p.lit("<-") {
		return Rule{}, errNoMatch
	}
	r, err := p.ruleBody()
	if err != nil {
		return Rule{}, err
	}
	r.Head = head
	if !namedHeadBound(r) {
		return Rule{}, p.fail("rule head contains variables that are not used in predicates of the rule's body")
	}
	return r, nil
}

func namedHeadBound(r Rule) bool {
	body := map[string]bool{}
	for _, pr := range r.Body {
		for _, t := range pr.Terms {
			if t.Kind == KindVariable {
				body[t.S] = true
			}
		}
	}
	for _, t := range r.Head.Terms {
		if t.Kind == KindVariable && !body[t.S] {
			return false
		}
	}
	return true
}

func (p *parser) ruleBody() (Rule, error) {
	var r Rule
	for {
		p.ws()
		start := p.pos
		pred, err := p.predicate(false)
		if err == nil {
			r.Body = append(r.Body, pred)
		} else {
			p.pos = start
			e, err := p.expr()
			if err != nil {
				if errors.Is(err, errNoMatch) {
					return Rule{}, p.fail("expected a predicate or an expression")
				}
				return Rule{}, err
			}
			r.Expressions = append(r.Expressions, Expression{Ops: e.opcodes()})
		}
		save := p.pos
		p.ws()
		if p.lit(",") {
			continue
		}
		p.pos = save
		break
	}
	scopes, err := p.scopes()
	if err != nil {
		return Rule{}, err
	}
	r.Scopes = scopes
	return r, nil
}

func (p *parser) scopes() ([]Scope, error) {
	save := p.pos
	p.ws()
	if !p.lit("trusting") {
		p.pos = save
		return nil, nil
	}
	var out []Scope
	for {
		p.ws()
		switch {
		case p.lit("authority"):
			out = append(out, Scope{Kind: ScopeAuthority})
		case p.lit("previous"):
			out = append(out, Scope{Kind: ScopePrevious})
		default:
			k, ok := p.publicKey()
			if !ok {
				return nil, p.fail("expected authority, previous, or a public key after trusting")
			}
			out = append(out, Scope{Kind: ScopePublicKey, KeyValue: k, named: true})
		}
		save := p.pos
		p.ws()
		if p.lit(",") {
			continue
		}
		p.pos = save
		return out, nil
	}
}

func (p *parser) publicKey() (PublicKey, bool) {
	var alg Algorithm
	switch {
	case p.lit("ed25519/"):
		alg = Ed25519
	case p.lit("secp256r1/"):
		alg = Secp256r1
	default:
		return PublicKey{}, false
	}
	b, ok := p.hexDigits()
	if !ok {
		return PublicKey{}, false
	}
	return PublicKey{Alg: alg, Key: b}, true
}

func (p *parser) hexDigits() ([]byte, bool) {
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			p.pos++
			continue
		}
		break
	}
	if p.pos == start {
		return nil, false
	}
	b, err := hex.DecodeString(p.s[start:p.pos])
	if err != nil {
		return nil, false
	}
	return b, true
}

func (p *parser) checkBody() ([]Rule, error) {
	var out []Rule
	for {
		r, err := p.ruleBody()
		if err != nil {
			return nil, err
		}
		r.Head = Predicate{NameS: "query"}
		out = append(out, r)
		save := p.pos
		p.ws()
		if p.litFold("or") {
			continue
		}
		p.pos = save
		return out, nil
	}
}

func (p *parser) check() (Check, error) {
	p.ws()
	var kind CheckKind
	switch {
	case p.litFold("check if"):
		kind = CheckOne
	case p.litFold("check all"):
		kind = CheckAll
	case p.litFold("reject if"):
		kind = CheckReject
	default:
		return Check{}, errNoMatch
	}
	qs, err := p.checkBody()
	if err != nil {
		return Check{}, err
	}
	return Check{Queries: qs, Kind: kind}, nil
}

func (p *parser) policy() (Policy, error) {
	p.ws()
	var kind PolicyKind
	switch {
	case p.litFold("allow if"):
		kind = Allow
	case p.litFold("deny if"):
		kind = Deny
	default:
		return Policy{}, errNoMatch
	}
	qs, err := p.checkBody()
	if err != nil {
		return Policy{}, err
	}
	return Policy{Queries: qs, Kind: kind}, nil
}

// terms

func (p *parser) str() (string, bool, error) {
	if !strings.HasPrefix(p.rest(), `"`) {
		return "", false, nil
	}
	p.pos++
	var sb strings.Builder
	for {
		if p.pos >= len(p.s) {
			return "", true, p.fail("an unterminated string")
		}
		c := p.s[p.pos]
		switch c {
		case '"':
			p.pos++
			return sb.String(), true, nil
		case '\\':
			if p.pos+1 >= len(p.s) {
				return "", true, p.fail("an unterminated string")
			}
			switch p.s[p.pos+1] {
			case '\\':
				sb.WriteByte('\\')
			case '"':
				sb.WriteByte('"')
			case 'n':
				sb.WriteByte('\n')
			default:
				return "", true, p.fail(`a string escape other than \\, \" or \n`)
			}
			p.pos += 2
		default:
			sb.WriteByte(c)
			p.pos++
		}
	}
}

func (p *parser) date() (Term, bool) {
	start := p.pos
	end := start
	for end < len(p.s) && !strings.ContainsRune(", )];}", rune(p.s[end])) {
		end++
	}
	if end == start {
		return Term{}, false
	}
	d, err := time.Parse(time.RFC3339Nano, p.s[start:end])
	if err != nil || d.Unix() < 0 {
		return Term{}, false
	}
	p.pos = end
	return Date(uint64(d.Unix())), true
}

func (p *parser) integer() (Term, bool) {
	start := p.pos
	end := start
	if end < len(p.s) && p.s[end] == '-' {
		end++
	}
	digits := end
	for end < len(p.s) && p.s[end] >= '0' && p.s[end] <= '9' {
		end++
	}
	if end == digits {
		return Term{}, false
	}
	i, err := strconv.ParseInt(p.s[start:end], 10, 64)
	if err != nil {
		return Term{}, false
	}
	p.pos = end
	return Int(i), true
}

func (p *parser) variable() (Term, bool) {
	start := p.pos
	if !p.lit("$") {
		return Term{}, false
	}
	n, ok := p.name()
	if !ok {
		p.pos = start
		return Term{}, false
	}
	return Term{Kind: KindVariable, S: n, named: true}, true
}

func (p *parser) scalar(allowVar bool) (Term, bool, error) {
	if strings.HasPrefix(p.rest(), "{") && len(p.rest()) > 1 && isNameChar(p.rest()[1]) && !isDigit(p.rest()[1]) {
		// "{name}" is a parameter, filled in by an application before it
		// hands the code over. Nothing here fills it in.
		if i := strings.IndexByte(p.rest(), '}'); i > 0 && isAllNameChars(p.rest()[1:i]) {
			return Term{}, true, p.fail("parameters such as " + p.rest()[:i+1] + " are not supported: write the value")
		}
	}
	if s, ok, err := p.str(); ok || err != nil {
		if err != nil {
			return Term{}, true, err
		}
		return Term{Kind: KindString, S: s, named: true}, true, nil
	}
	if t, ok := p.date(); ok {
		return t, true, nil
	}
	if allowVar {
		if t, ok := p.variable(); ok {
			return t, true, nil
		}
	}
	if t, ok := p.integer(); ok {
		return t, true, nil
	}
	if p.lit("hex:") {
		b, ok := p.hexDigits()
		if !ok {
			return Term{}, true, p.fail("hex: needs an even number of hex digits")
		}
		return Bytes(b), true, nil
	}
	switch {
	case p.lit("true"):
		return Bool(true), true, nil
	case p.lit("false"):
		return Bool(false), true, nil
	case p.lit("null"):
		return Null(), true, nil
	}
	return Term{}, false, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAllNameChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

// term is a term in a rule: a scalar, a variable, an array, a map or a
// set, tried in the reference's order (a map before a set).
func (p *parser) term() (Term, error) {
	p.ws()
	if t, ok, err := p.scalar(true); ok || err != nil {
		return t, err
	}
	if t, ok, err := p.array(); ok || err != nil {
		return t, err
	}
	start := p.pos
	if t, ok, err := p.mapTerm(); ok {
		return t, err
	}
	p.pos = start
	if t, ok, err := p.set(); ok || err != nil {
		return t, err
	}
	return Term{}, errNoMatch
}

// termInFact is a term without variables, where a set is tried before a
// map.
func (p *parser) termInFact() (Term, error) {
	p.ws()
	if strings.HasPrefix(p.rest(), "$") {
		return Term{}, p.fail("variables are not allowed in facts")
	}
	if t, ok, err := p.scalar(false); ok || err != nil {
		return t, err
	}
	start := p.pos
	if t, ok, err := p.set(); ok || err != nil {
		if err == nil {
			return t, nil
		}
		p.pos = start
	}
	if t, ok, err := p.array(); ok || err != nil {
		return t, err
	}
	p.pos = start
	if t, ok, err := p.mapTerm(); ok {
		return t, err
	}
	return Term{}, p.fail("expected a valid term")
}

func (p *parser) array() (Term, bool, error) {
	p.ws()
	if !p.lit("[") {
		return Term{}, false, nil
	}
	var elems []Term
	p.ws()
	if p.lit("]") {
		return Term{Kind: KindArray}, true, nil
	}
	for {
		t, err := p.termInFact()
		if err != nil {
			return Term{}, true, err
		}
		elems = append(elems, t)
		p.ws()
		if p.lit(",") {
			continue
		}
		if p.lit("]") {
			return Term{Kind: KindArray, Elems: elems}, true, nil
		}
		return Term{}, true, p.fail(`expected "," or "]" in an array`)
	}
}

func (p *parser) mapTerm() (Term, bool, error) {
	p.ws()
	if !p.lit("{") {
		return Term{}, false, nil
	}
	var entries []MapEntry
	p.ws()
	if p.lit("}") {
		return Term{Kind: KindMap}, true, nil
	}
	for {
		p.ws()
		var key MapKey
		if s, ok, err := p.str(); ok || err != nil {
			if err != nil {
				return Term{}, false, err
			}
			key = MapKey{IsString: true, S: s, named: true}
		} else if t, ok := p.integer(); ok {
			key = MapKey{I: t.I}
		} else {
			return Term{}, false, nil
		}
		p.ws()
		if !p.lit(":") {
			return Term{}, false, nil
		}
		v, err := p.termInFact()
		if err != nil {
			return Term{}, true, err
		}
		entries = append(entries, MapEntry{Key: key, Value: v})
		p.ws()
		if p.lit(",") {
			continue
		}
		if p.lit("}") {
			return Term{Kind: KindMap, Map: entries}, true, nil
		}
		return Term{}, true, p.fail(`expected "," or "}" in a map`)
	}
}

func (p *parser) set() (Term, bool, error) {
	if p.lit("{,}") {
		return Term{Kind: KindSet}, true, nil
	}
	p.ws()
	if !p.lit("{") {
		return Term{}, false, nil
	}
	var elems []Term
	kind := -1
	for {
		p.ws()
		if strings.HasPrefix(p.rest(), "$") {
			return Term{}, true, p.fail("variables are not permitted in sets")
		}
		t, ok, err := p.scalar(false)
		if err != nil {
			return Term{}, true, err
		}
		if !ok {
			start := p.pos
			m, mok, merr := p.mapTerm()
			if !mok || merr != nil {
				p.pos = start
				if strings.HasPrefix(p.rest(), "{") {
					return Term{}, true, p.fail("sets cannot contain other sets")
				}
				return Term{}, true, p.fail("expected a valid term in a set")
			}
			t = m
		}
		if kind >= 0 && int(t.Kind) != kind {
			return Term{}, true, p.fail("set elements must have the same type")
		}
		kind = int(t.Kind)
		elems = append(elems, t)
		p.ws()
		if p.lit(",") {
			continue
		}
		if p.lit("}") {
			return Term{Kind: KindSet, Elems: elems}, true, nil
		}
		return Term{}, true, p.fail(`expected "," or "}" in a set`)
	}
}

// expressions

type expr struct {
	op     Op // OpValue, OpUnary or OpBinary
	left   *expr
	right  *expr
	params []string // a closure, when closure is set
	body   *expr
	isClos bool
}

func (e *expr) opcodes() []Op {
	var out []Op
	e.emit(&out)
	return out
}

func (e *expr) emit(out *[]Op) {
	switch {
	case e.isClos:
		*out = append(*out, Op{Kind: OpClosure, ParamsS: e.params, Ops: e.body.opcodes()})
	case e.op.Kind == OpValue:
		*out = append(*out, e.op)
	case e.op.Kind == OpUnary:
		e.left.emit(out)
		*out = append(*out, e.op)
	default:
		e.left.emit(out)
		e.right.emit(out)
		*out = append(*out, e.op)
	}
}

func closure(params []string, body *expr) *expr {
	return &expr{isClos: true, params: params, body: body}
}

func bin(k BinaryKind, l, r *expr) *expr {
	return &expr{op: Op{Kind: OpBinary, Binary: k}, left: l, right: r}
}

func (p *parser) expr() (*expr, error) {
	return p.leftAssoc(p.expr1, []string{"||"}, map[string]BinaryKind{"||": LazyOr})
}

func (p *parser) expr1() (*expr, error) {
	return p.leftAssoc(p.expr2, []string{"&&"}, map[string]BinaryKind{"&&": LazyAnd})
}

func (p *parser) expr2() (*expr, error) {
	l, err := p.expr3()
	if err != nil {
		return nil, err
	}
	save := p.pos
	p.ws()
	ops := []struct {
		t string
		k BinaryKind
	}{
		{"<=", LessOrEqual}, {">=", GreaterOrEqual}, {"<", LessThan}, {">", GreaterThan},
		{"===", StrictEqual}, {"!==", StrictNotEqual}, {"==", HeterogeneousEqual}, {"!=", HeterogeneousNotEqual},
	}
	for _, op := range ops {
		if p.lit(op.t) {
			r, err := p.expr3()
			if err != nil {
				if errors.Is(err, errNoMatch) {
					p.pos = save
					return l, nil
				}
				return nil, err
			}
			return bin(op.k, l, r), nil
		}
	}
	p.pos = save
	return l, nil
}

func (p *parser) expr3() (*expr, error) {
	return p.leftAssoc(p.expr4, []string{"^"}, map[string]BinaryKind{"^": BitwiseXor})
}

func (p *parser) expr4() (*expr, error) {
	return p.leftAssoc(p.expr5, []string{"|"}, map[string]BinaryKind{"|": BitwiseOr})
}

func (p *parser) expr5() (*expr, error) {
	return p.leftAssoc(p.expr6, []string{"&"}, map[string]BinaryKind{"&": BitwiseAnd})
}

func (p *parser) expr6() (*expr, error) {
	return p.leftAssoc(p.expr7, []string{"+", "-"}, map[string]BinaryKind{"+": Add, "-": Sub})
}

func (p *parser) expr7() (*expr, error) {
	return p.leftAssoc(p.expr8, []string{"*", "/"}, map[string]BinaryKind{"*": Mul, "/": Div})
}

// leftAssoc parses operand (op operand)*, backtracking when an operator is
// not followed by an operand: that is how "&" gives way to "&&" and "|" to
// "||", as the reference's many0 does.
func (p *parser) leftAssoc(next func() (*expr, error), toks []string, kinds map[string]BinaryKind) (*expr, error) {
	acc, err := next()
	if err != nil {
		return nil, err
	}
	for {
		save := p.pos
		p.ws()
		matched := ""
		for _, t := range toks {
			if p.lit(t) {
				matched = t
				break
			}
		}
		if matched == "" {
			p.pos = save
			return acc, nil
		}
		r, err := next()
		if err != nil {
			if errors.Is(err, errNoMatch) {
				p.pos = save
				return acc, nil
			}
			return nil, err
		}
		k := kinds[matched]
		if k == LazyAnd || k == LazyOr {
			acc = bin(k, acc, closure(nil, r))
		} else {
			acc = bin(k, acc, r)
		}
	}
}

func (p *parser) expr8() (*expr, error) {
	save := p.pos
	p.ws()
	if p.lit("!") {
		p.ws()
		v, err := p.expr6()
		if err != nil {
			return nil, err
		}
		return &expr{op: Op{Kind: OpUnary, Unary: Negate}, left: v}, nil
	}
	p.pos = save
	return p.expr9()
}

func (p *parser) exprTerm() (*expr, error) {
	save := p.pos
	p.ws()
	if p.lit("(") {
		p.ws()
		v, err := p.expr()
		if err != nil {
			return nil, err
		}
		p.ws()
		if !p.lit(")") {
			return nil, p.fail(`expected ")"`)
		}
		return &expr{op: Op{Kind: OpUnary, Unary: Parens}, left: v}, nil
	}
	p.pos = save
	t, err := p.term()
	if err != nil {
		return nil, err
	}
	return &expr{op: Op{Kind: OpValue, Value: t}}, nil
}

var binaryMethods = []struct {
	name string
	kind BinaryKind
}{
	{"contains", Contains}, {"starts_with", Prefix}, {"ends_with", Suffix}, {"matches", Regex},
	{"intersection", Intersection}, {"union", Union}, {"all", All}, {"any", Any}, {"get", Get},
	{"try_or", TryOr},
}

func (p *parser) expr9() (*expr, error) {
	acc, err := p.exprTerm()
	if err != nil {
		return nil, err
	}
	for strings.HasPrefix(p.rest(), ".") {
		p.pos++
		start := p.pos
		if e, ok, err := p.binaryMethod(acc); ok || err != nil {
			if err != nil {
				return nil, err
			}
			acc = e
			continue
		}
		p.pos = start
		if e, ok, err := p.unaryMethod(acc); ok || err != nil {
			if err != nil {
				return nil, err
			}
			acc = e
			continue
		}
		return nil, p.fail("unknown method ." + firstWord(p.rest()))
	}
	return acc, nil
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return s[:i]
		}
	}
	return s
}

func (p *parser) binaryMethod(recv *expr) (*expr, bool, error) {
	var kind BinaryKind
	ffi := ""
	found := false
	for _, m := range binaryMethods {
		if p.lit(m.name) {
			kind, found = m.kind, true
			break
		}
	}
	if !found {
		if !p.lit("extern::") {
			return nil, false, nil
		}
		n, ok := p.name()
		if !ok {
			return nil, false, nil
		}
		kind, ffi = BinaryFfi, n
	}
	if !p.lit("(") {
		return nil, false, nil
	}
	p.ws()
	if kind == All || kind == Any {
		if !p.lit("$") {
			return nil, false, nil
		}
		param, ok := p.name()
		if !ok {
			return nil, false, nil
		}
		p.ws()
		if !p.lit("->") {
			return nil, false, nil
		}
		p.ws()
		arg, err := p.expr()
		if err != nil {
			return nil, true, err
		}
		p.ws()
		if !p.lit(")") {
			return nil, true, p.fail(`expected ")" after a closure`)
		}
		return bin(kind, recv, closure([]string{param}, arg)), true, nil
	}
	arg, err := p.expr()
	if err != nil {
		if errors.Is(err, errNoMatch) {
			return nil, false, nil
		}
		return nil, true, err
	}
	p.ws()
	if !p.lit(")") {
		return nil, true, p.fail(`expected ")" after a method argument`)
	}
	if kind == TryOr {
		return bin(TryOr, closure(nil, recv), arg), true, nil
	}
	e := bin(kind, recv, arg)
	if ffi != "" {
		e.op.FfiS, e.op.named = ffi, true
	}
	return e, true, nil
}

func (p *parser) unaryMethod(recv *expr) (*expr, bool, error) {
	var kind UnaryKind
	ffi := ""
	switch {
	case p.lit("length"):
		kind = Length
	case p.lit("type"):
		kind = TypeOf
	case p.lit("extern::"):
		n, ok := p.name()
		if !ok {
			return nil, false, nil
		}
		kind, ffi = UnaryFfi, n
	default:
		return nil, false, nil
	}
	if !p.lit("(") {
		return nil, false, nil
	}
	p.ws()
	if !p.lit(")") {
		return nil, false, nil
	}
	e := &expr{op: Op{Kind: OpUnary, Unary: kind}, left: recv}
	if ffi != "" {
		e.op.FfiS, e.op.named = ffi, true
	}
	return e, true, nil
}

// ParseBlock reads a block's source: an optional "trusting ...;" header,
// then facts, rules and checks. Policies belong to authorizers, not blocks.
func ParseBlock(src string) (Block, error) {
	p := &parser{s: src}
	var b Block
	p.ws()
	if strings.HasPrefix(p.rest(), "trusting") {
		scopes, err := p.scopes()
		if err != nil {
			return b, err
		}
		p.ws()
		if !p.lit(";") {
			return b, errors.New(`datalog: expected ";" after the block's trusting annotation`)
		}
		b.Scopes = scopes
	}
	prog, err := ParseProgram(p.rest())
	if err != nil {
		return b, err
	}
	if len(prog.Policies) > 0 {
		return b, errors.New("datalog: a block cannot carry allow or deny policies")
	}
	b.Facts, b.Rules, b.Checks = prog.Facts, prog.Rules, prog.Checks
	return b, nil
}

// SchemaVersion is the lowest datalog version that can carry the block, as
// the reference's builder computes it.
func SchemaVersion(b Block) uint32 {
	switch {
	case checkCompatibility(b, Version31) != nil:
		return Version33
	case checkCompatibility(b, MinVersion) != nil:
		return Version31
	}
	return MinVersion
}
