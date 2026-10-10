package datalog

import (
	"errors"
	"fmt"
	"sort"
)

// TokenBlock is one block as the token carries it: Datalog whose indices
// refer to Symbols, which is the token's table, or for a third-party block
// its own.
type TokenBlock struct {
	Block       Block
	Symbols     *SymbolTable
	ExternalKey *PublicKey
}

// Program is an authorizer's own Datalog, parsed but not yet converted to
// a symbol table: names are strings.
type Program struct {
	Facts    []Fact
	Rules    []Rule
	Checks   []Check
	Policies []Policy
}

// Append adds another program's statements after this one's.
func (p *Program) Append(o Program) {
	p.Facts = append(p.Facts, o.Facts...)
	p.Rules = append(p.Rules, o.Rules...)
	p.Checks = append(p.Checks, o.Checks...)
	p.Policies = append(p.Policies, o.Policies...)
}

// FailedCheck is a check that did not pass. Block is -1 for one of the
// authorizer's own checks.
type FailedCheck struct {
	Block int
	Check int
	Rule  string
}

// PolicyMatch is the policy that decided.
type PolicyMatch struct {
	Index int
	Allow bool
}

// Result is the outcome of an authorization.
type Result struct {
	// Err is set when authorization could not complete: an expression
	// error, a run limit, a rule the reference refuses to load. Nothing
	// else in the result is meaningful then, except ErrOrigin.
	Err error
	// ErrOrigin is the block whose rule or check raised Err, -1 for the
	// authorizer, -2 when unknown.
	ErrOrigin int
	// Failed lists every failed check, in the reference's order: the
	// authorizer's checks, the authority block's, then each later block's.
	Failed []FailedCheck
	// Policy is the first matching policy, or nil when none matched.
	Policy *PolicyMatch
	// World is the facts after the run, for inspection.
	World *World
	// Symbols is the authorizer's symbol table, which World's facts use.
	Symbols *SymbolTable
}

// InvalidBlockRuleError is a token rule whose head uses a variable its body
// never binds. The reference refuses to load such a block, and reports it
// with block 0 whichever block it is in; this keeps the block.
type InvalidBlockRuleError struct {
	Block int
	Rule  string
}

func (e *InvalidBlockRuleError) Error() string {
	return fmt.Sprintf("block %d has a rule whose head uses a variable its body does not bind: %s", e.Block, e.Rule)
}

// Authorized reports whether the token was authorized: no error, no failed
// check, and an allow policy matched.
func (r Result) Authorized() bool {
	return r.Err == nil && len(r.Failed) == 0 && r.Policy != nil && r.Policy.Allow
}

type translator struct {
	from *SymbolTable
	to   *SymbolTable
	err  error
}

func (tr *translator) sym(i uint64) uint64 {
	s, ok := tr.from.Symbol(i)
	if !ok {
		if tr.err == nil {
			tr.err = fmt.Errorf("unknown symbol %d", i)
		}
		return 0
	}
	return tr.to.Insert(s)
}

func (tr *translator) term(t Term) Term {
	switch t.Kind {
	case KindVariable, KindString:
		t.U = tr.sym(t.U)
	case KindSet:
		elems := make([]Term, len(t.Elems))
		for i, e := range t.Elems {
			elems[i] = tr.term(e)
		}
		return Set(elems)
	case KindArray:
		elems := make([]Term, len(t.Elems))
		for i, e := range t.Elems {
			elems[i] = tr.term(e)
		}
		t.Elems = elems
	case KindMap:
		entries := make([]MapEntry, len(t.Map))
		for i, e := range t.Map {
			k := e.Key
			if k.IsString {
				k.U = tr.sym(k.U)
			}
			entries[i] = MapEntry{Key: k, Value: tr.term(e.Value)}
		}
		return Map(entries)
	}
	return t
}

func (tr *translator) pred(p Predicate) Predicate {
	out := Predicate{Name: tr.sym(p.Name), Terms: make([]Term, len(p.Terms))}
	for i, t := range p.Terms {
		out.Terms[i] = tr.term(t)
	}
	return out
}

func (tr *translator) ops(ops []Op) []Op {
	out := make([]Op, len(ops))
	for i, op := range ops {
		switch op.Kind {
		case OpValue:
			op.Value = tr.term(op.Value)
		case OpUnary, OpBinary:
			if (op.Kind == OpUnary && op.Unary == UnaryFfi) || (op.Kind == OpBinary && op.Binary == BinaryFfi) {
				op.Ffi = tr.sym(op.Ffi)
			}
		case OpClosure:
			params := make([]uint64, len(op.Params))
			for j, p := range op.Params {
				params[j] = tr.sym(p)
			}
			op.Params = params
			op.Ops = tr.ops(op.Ops)
		}
		out[i] = op
	}
	return out
}

func (tr *translator) scope(s Scope) Scope {
	if s.Kind == ScopePublicKey {
		k, ok := tr.from.Key(s.Key)
		if !ok {
			// The reference does not check that a scope's key exists in
			// the table either; it simply trusts no block for it.
			return Scope{Kind: ScopePublicKey, Key: ^uint64(0)}
		}
		return Scope{Kind: ScopePublicKey, Key: tr.to.InsertKey(k)}
	}
	return s
}

func (tr *translator) rule(r Rule) Rule {
	out := Rule{Head: tr.pred(r.Head)}
	for _, p := range r.Body {
		out.Body = append(out.Body, tr.pred(p))
	}
	for _, e := range r.Expressions {
		out.Expressions = append(out.Expressions, Expression{Ops: tr.ops(e.Ops)})
	}
	for _, s := range r.Scopes {
		out.Scopes = append(out.Scopes, tr.scope(s))
	}
	return out
}

func (tr *translator) check(c Check) Check {
	out := Check{Kind: c.Kind}
	for _, q := range c.Queries {
		out.Queries = append(out.Queries, tr.rule(q))
	}
	return out
}

// headBound reports whether every head variable appears in a body
// predicate.
func headBound(r Rule) bool {
	body := bodyVariables(r)
	for _, t := range r.Head.Terms {
		if t.Kind == KindVariable && !body[t.U] {
			return false
		}
	}
	return true
}

// Authorize runs an authorizer over a token's blocks, as the reference's
// authorize does: load the blocks and the authorizer's facts and rules,
// run them to a fixpoint, then evaluate every check, then the policies.
func Authorize(blocks []TokenBlock, prog Program, limits Limits) Result {
	res := Result{ErrOrigin: -2}
	if len(blocks) > MaxBlocks {
		res.Err = fmt.Errorf("the token has %d blocks; at most %d can be evaluated", len(blocks), MaxBlocks)
		return res
	}
	syms := NewSymbolTable()
	res.Symbols = syms
	w := NewWorld(syms)
	res.World = w

	keyBlocks := map[uint64][]int{}
	for i, b := range blocks {
		if i > 0 && b.ExternalKey != nil {
			k := syms.InsertKey(*b.ExternalKey)
			keyBlocks[k] = append(keyBlocks[k], i)
		}
	}

	type loaded struct {
		checks []Check
		trust  Origin
	}
	var lb []loaded
	for i, b := range blocks {
		tr := &translator{from: b.Symbols, to: syms}
		var scopes []Scope
		for _, s := range b.Block.Scopes {
			scopes = append(scopes, tr.scope(s))
		}
		blockTrust := trustedOrigins(scopes, defaultTrust, i, keyBlocks)
		for _, f := range b.Block.Facts {
			w.AddFact(originOf(i), Fact{Predicate: tr.pred(f.Predicate)})
		}
		for _, r := range b.Block.Rules {
			if !headBound(r) {
				res.Err = &InvalidBlockRuleError{Block: i, Rule: b.Symbols.PrintRule(r)}
				res.ErrOrigin = i
				return res
			}
			tr2 := tr.rule(r)
			w.AddRule(i, trustedOrigins(tr2.Scopes, blockTrust, i, keyBlocks), tr2)
		}
		var checks []Check
		for _, c := range b.Block.Checks {
			checks = append(checks, tr.check(c))
		}
		if tr.err != nil {
			res.Err = fmt.Errorf("block %d: %w", i, tr.err)
			res.ErrOrigin = i
			return res
		}
		lb = append(lb, loaded{checks: checks, trust: blockTrust})
	}

	conv := &converter{syms: syms}
	for _, f := range prog.Facts {
		w.AddFact(originOf(AuthorizerID), Fact{Predicate: conv.pred(f.Predicate)})
	}
	for _, r := range prog.Rules {
		cr := conv.rule(r)
		w.AddRule(AuthorizerID, trustedOrigins(cr.Scopes, defaultTrust, AuthorizerID, keyBlocks), cr)
	}

	if err := w.Run(limits); err != nil {
		res.Err = err
		var re *RuleError
		if errors.As(err, &re) {
			res.ErrOrigin = re.Origin
			if re.Origin == AuthorizerID {
				res.ErrOrigin = -1
			}
		}
		return res
	}

	authTrust := trustedOrigins(nil, defaultTrust, AuthorizerID, keyBlocks)
	runCheck := func(c Check, origin int, trust Origin) (bool, error) {
		for _, q := range c.Queries {
			qt := trustedOrigins(q.Scopes, trust, origin, keyBlocks)
			var ok bool
			var err error
			switch c.Kind {
			case CheckAll:
				ok, err = w.QueryMatchAll(q, qt)
			case CheckReject:
				ok, err = w.QueryMatch(q, qt)
				ok = !ok
			default:
				ok, err = w.QueryMatch(q, qt)
			}
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}

	for j, c := range prog.Checks {
		cc := conv.check(c)
		ok, err := runCheck(cc, AuthorizerID, authTrust)
		if err != nil {
			res.Err, res.ErrOrigin = err, -1
			return res
		}
		if !ok {
			res.Failed = append(res.Failed, FailedCheck{Block: -1, Check: j, Rule: syms.PrintCheck(cc)})
		}
	}
	if len(lb) > 0 {
		for j, c := range lb[0].checks {
			ok, err := runCheck(c, 0, lb[0].trust)
			if err != nil {
				res.Err, res.ErrOrigin = err, 0
				return res
			}
			if !ok {
				res.Failed = append(res.Failed, FailedCheck{Block: 0, Check: j, Rule: syms.PrintCheck(c)})
			}
		}
	}
policies:
	for i, p := range prog.Policies {
		for _, q := range p.Queries {
			cq := conv.rule(q)
			ok, err := w.QueryMatch(cq, trustedOrigins(cq.Scopes, authTrust, AuthorizerID, keyBlocks))
			if err != nil {
				res.Err, res.ErrOrigin = err, -1
				return res
			}
			if ok {
				res.Policy = &PolicyMatch{Index: i, Allow: p.Kind == Allow}
				break policies
			}
		}
	}
	for i := 1; i < len(lb); i++ {
		for j, c := range lb[i].checks {
			ok, err := runCheck(c, i, lb[i].trust)
			if err != nil {
				res.Err, res.ErrOrigin = err, i
				return res
			}
			if !ok {
				res.Failed = append(res.Failed, FailedCheck{Block: i, Check: j, Rule: syms.PrintCheck(c)})
			}
		}
	}
	return res
}

// WorldFacts groups the world's facts by origin, each group's facts
// printed and sorted, groups in origin order: the shape the specification's
// samples record their expected world in.
func (r Result) WorldFacts() []OriginFacts {
	if r.World == nil {
		return nil
	}
	groups := map[Origin][]string{}
	var order []Origin
	r.World.Facts.Each(func(o Origin, f Fact) {
		if _, ok := groups[o]; !ok {
			order = append(order, o)
		}
		groups[o] = append(groups[o], r.Symbols.PrintFact(f))
	})
	var out []OriginFacts
	for _, o := range order {
		facts := groups[o]
		sort.Strings(facts)
		out = append(out, OriginFacts{Origin: o, Facts: facts})
	}
	return out
}

// OriginFacts is one origin's facts.
type OriginFacts struct {
	Origin Origin
	Facts  []string
}
