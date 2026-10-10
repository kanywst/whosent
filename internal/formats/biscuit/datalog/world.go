package datalog

import (
	"encoding/binary"
	"math/bits"
	"sort"
	"time"
)

// AuthorizerID is the origin the authorizer's own facts and rules carry.
// The reference uses the largest machine integer; this engine numbers
// origins as bits of a word, so the authorizer is the top bit and a token
// may have at most MaxBlocks blocks.
const AuthorizerID = 63

// MaxBlocks is the most blocks a token may have for the engine to evaluate
// it. Real tokens have a handful.
const MaxBlocks = 63

// Origin is a set of block indices (and AuthorizerID), one bit each.
type Origin uint64

func originOf(ids ...int) Origin {
	var o Origin
	for _, id := range ids {
		o |= 1 << uint(id)
	}
	return o
}

// IDs lists the origin's members, in order.
func (o Origin) IDs() []int {
	var out []int
	for o != 0 {
		i := bits.TrailingZeros64(uint64(o))
		out = append(out, i)
		o &^= 1 << uint(i)
	}
	return out
}

// trusted reports whether every member of a fact's origin is trusted.
func trusted(trust, fact Origin) bool { return fact&^trust == 0 }

// Limits bound a run, as the reference's RunLimits do.
type Limits struct {
	MaxFacts      int
	MaxIterations int
	MaxTime       time.Duration
}

// DefaultLimits are the reference's fact and iteration limits. Its default
// time limit is one millisecond, which is a resource guard rather than a
// rule: on a slow or busy machine it would make the same token pass or
// fail by chance, so this engine allows more time and reports reaching it
// as an error, never as a verdict.
var DefaultLimits = Limits{MaxFacts: 1000, MaxIterations: 100, MaxTime: 2 * time.Second}

// LimitError is a run that hit one of its limits.
type LimitError struct{ Kind string }

func (e *LimitError) Error() string { return "run limit reached: " + e.Kind }

type bucket struct {
	facts []Fact
	keys  map[string]struct{}
}

// FactSet holds facts by origin. It iterates in a fixed order (by origin,
// then by insertion), where the reference iterates hash maps in an order
// that varies between runs; the facts it finds are the same either way.
type FactSet struct {
	by      map[Origin]*bucket
	origins []Origin
	n       int
}

func newFactSet() *FactSet { return &FactSet{by: map[Origin]*bucket{}} }

func (fs *FactSet) insert(o Origin, f Fact) bool {
	b, ok := fs.by[o]
	if !ok {
		b = &bucket{keys: map[string]struct{}{}}
		fs.by[o] = b
		fs.origins = append(fs.origins, o)
		sort.Slice(fs.origins, func(i, j int) bool { return fs.origins[i] < fs.origins[j] })
	}
	k := factKey(f)
	if _, dup := b.keys[k]; dup {
		return false
	}
	b.keys[k] = struct{}{}
	b.facts = append(b.facts, f)
	fs.n++
	return true
}

func (fs *FactSet) merge(other *FactSet) {
	for _, o := range other.origins {
		for _, f := range other.by[o].facts {
			fs.insert(o, f)
		}
	}
}

// Len is the number of facts.
func (fs *FactSet) Len() int { return fs.n }

type originFact struct {
	origin Origin
	fact   Fact
}

func (fs *FactSet) visible(trust Origin) []originFact {
	var out []originFact
	for _, o := range fs.origins {
		if !trusted(trust, o) {
			continue
		}
		for _, f := range fs.by[o].facts {
			out = append(out, originFact{o, f})
		}
	}
	return out
}

// Each calls f for every fact and its origin.
func (fs *FactSet) Each(f func(Origin, Fact)) {
	for _, o := range fs.origins {
		for _, fact := range fs.by[o].facts {
			f(o, fact)
		}
	}
}

// factKey encodes a fact so that two facts have the same key exactly when
// they are equal.
func factKey(f Fact) string {
	buf := binary.AppendUvarint(nil, f.Predicate.Name)
	buf = binary.AppendUvarint(buf, uint64(len(f.Predicate.Terms)))
	for _, t := range f.Predicate.Terms {
		buf = appendTerm(buf, t)
	}
	return string(buf)
}

func appendTerm(buf []byte, t Term) []byte {
	buf = append(buf, byte(t.Kind))
	switch t.Kind {
	case KindInteger:
		buf = binary.AppendVarint(buf, t.I)
	case KindVariable, KindString, KindDate:
		buf = binary.AppendUvarint(buf, t.U)
	case KindBytes:
		buf = binary.AppendUvarint(buf, uint64(len(t.B)))
		buf = append(buf, t.B...)
	case KindBool:
		if t.Bool {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	case KindSet, KindArray:
		buf = binary.AppendUvarint(buf, uint64(len(t.Elems)))
		for _, e := range t.Elems {
			buf = appendTerm(buf, e)
		}
	case KindMap:
		buf = binary.AppendUvarint(buf, uint64(len(t.Map)))
		for _, e := range t.Map {
			if e.Key.IsString {
				buf = append(buf, 1)
				buf = binary.AppendUvarint(buf, e.Key.U)
			} else {
				buf = append(buf, 0)
				buf = binary.AppendVarint(buf, e.Key.I)
			}
			buf = appendTerm(buf, e.Value)
		}
	}
	return buf
}

// matchPreds reports whether a fact can match a rule's predicate: same name
// and arity, and equal wherever the rule has a value rather than a
// variable.
func matchPreds(rule, fact Predicate) bool {
	if rule.Name != fact.Name || len(rule.Terms) != len(fact.Terms) {
		return false
	}
	for i, rt := range rule.Terms {
		ft := fact.Terms[i]
		if ft.Kind == KindVariable {
			return false
		}
		if rt.Kind == KindVariable {
			continue
		}
		if !Equal(rt, ft) {
			return false
		}
	}
	return true
}

func bodyVariables(r Rule) map[uint64]bool {
	vs := map[uint64]bool{}
	for _, p := range r.Body {
		for _, t := range p.Terms {
			if t.Kind == KindVariable {
				vs[t.U] = true
			}
		}
	}
	return vs
}

// combine calls yield with every combination of visible facts that matches
// the predicates, and the union of their origins. yield returns false to
// stop. It is the reference's CombineIt: variables are bound left to right,
// and a variable already bound must match again.
func combine(preds []Predicate, facts []originFact, vars map[uint64]Term, varset map[uint64]bool, origin Origin, yield func(Origin, map[uint64]Term) bool) bool {
	if len(preds) == 0 {
		if len(vars) != len(varset) {
			return true
		}
		return yield(origin, vars)
	}
	p := preds[0]
	for _, of := range facts {
		if !matchPreds(p, of.fact.Predicate) {
			continue
		}
		next := make(map[uint64]Term, len(vars)+len(p.Terms))
		for k, v := range vars {
			next[k] = v
		}
		ok := true
		for i, rt := range p.Terms {
			if rt.Kind != KindVariable {
				continue
			}
			if !varset[rt.U] {
				ok = false
				break
			}
			if have, bound := next[rt.U]; bound {
				if !Equal(have, of.fact.Predicate.Terms[i]) {
					ok = false
					break
				}
				continue
			}
			next[rt.U] = of.fact.Predicate.Terms[i]
		}
		if !ok {
			continue
		}
		if !combine(preds[1:], facts, next, varset, origin|of.origin, yield) {
			return false
		}
	}
	return true
}

// exprsHold evaluates a rule's expressions for one combination.
func exprsHold(r Rule, vars map[uint64]Term, syms *SymbolTable) (bool, error) {
	ts := newTemp(syms)
	for _, e := range r.Expressions {
		v, err := evaluate(e.Ops, vars, ts)
		if err != nil {
			return false, err
		}
		if v.Kind != KindBool {
			return false, ErrInvalidType
		}
		if !v.Bool {
			return false, nil
		}
	}
	return true, nil
}

// headFact substitutes the bindings into the head, or reports that a head
// variable is unbound.
func headFact(r Rule, vars map[uint64]Term) (Fact, bool) {
	p := Predicate{Name: r.Head.Name, Terms: make([]Term, len(r.Head.Terms))}
	for i, t := range r.Head.Terms {
		if t.Kind != KindVariable {
			p.Terms[i] = t
			continue
		}
		v, ok := vars[t.U]
		if !ok {
			return Fact{}, false
		}
		p.Terms[i] = v
	}
	return Fact{Predicate: p}, true
}

type scopedRule struct {
	origin int
	trust  Origin
	rule   Rule
}

// World is facts and the rules that extend them.
type World struct {
	Facts      *FactSet
	rules      []scopedRule
	Iterations int
	syms       *SymbolTable
}

// NewWorld returns an empty world over a symbol table.
func NewWorld(syms *SymbolTable) *World {
	return &World{Facts: newFactSet(), syms: syms}
}

// AddFact adds a fact with its origin.
func (w *World) AddFact(o Origin, f Fact) { w.Facts.insert(o, f) }

// AddRule adds a rule defined in block origin, trusting the given origins.
func (w *World) AddRule(origin int, trust Origin, r Rule) {
	w.rules = append(w.rules, scopedRule{origin: origin, trust: trust, rule: r})
}

// RuleError is an expression error raised by a rule, with where the rule
// was defined.
type RuleError struct {
	Origin int
	Err    error
}

func (e *RuleError) Error() string { return e.Err.Error() }
func (e *RuleError) Unwrap() error { return e.Err }

// Run applies the rules until no new fact appears.
func (w *World) Run(limits Limits) error {
	deadline := time.Now().Add(limits.MaxTime)
	index := 0
	for {
		fresh := newFactSet()
		for _, sr := range w.rules {
			visible := w.Facts.visible(sr.trust)
			varset := bodyVariables(sr.rule)
			var err error
			combine(sr.rule.Body, visible, map[uint64]Term{}, varset, 0, func(o Origin, vars map[uint64]Term) bool {
				ok, e := exprsHold(sr.rule, vars, w.syms)
				if e != nil {
					err = e
					return false
				}
				if !ok {
					return true
				}
				f, bound := headFact(sr.rule, vars)
				if !bound {
					return true
				}
				fresh.insert(o|originOf(sr.origin), f)
				return true
			})
			if err != nil {
				return &RuleError{Origin: sr.origin, Err: err}
			}
		}
		before := w.Facts.Len()
		w.Facts.merge(fresh)
		if w.Facts.Len() == before {
			break
		}
		index++
		if index == limits.MaxIterations {
			w.Iterations += index
			return &LimitError{"TooManyIterations"}
		}
		if w.Facts.Len() >= limits.MaxFacts {
			w.Iterations += index
			return &LimitError{"TooManyFacts"}
		}
		if time.Now().After(deadline) {
			w.Iterations += index
			return &LimitError{"Timeout"}
		}
	}
	w.Iterations += index
	return nil
}

// QueryMatch reports whether a query has a match: the first combination
// whose expressions hold. An expression error met before a match is
// returned, as the reference returns it.
func (w *World) QueryMatch(q Rule, trust Origin) (bool, error) {
	visible := w.Facts.visible(trust)
	varset := bodyVariables(q)
	found := false
	var err error
	combine(q.Body, visible, map[uint64]Term{}, varset, 0, func(_ Origin, vars map[uint64]Term) bool {
		ok, e := exprsHold(q, vars, w.syms)
		if e != nil {
			err = e
			return false
		}
		if !ok {
			return true
		}
		if _, bound := headFact(q, vars); !bound {
			return true
		}
		found = true
		return false
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

// QueryMatchAll reports whether a query has at least one combination and
// every combination's expressions hold: "check all".
func (w *World) QueryMatchAll(q Rule, trust Origin) (bool, error) {
	visible := w.Facts.visible(trust)
	varset := bodyVariables(q)
	found, failed := false, false
	var err error
	combine(q.Body, visible, map[uint64]Term{}, varset, 0, func(_ Origin, vars map[uint64]Term) bool {
		found = true
		ok, e := exprsHold(q, vars, w.syms)
		if e != nil {
			err = e
			return false
		}
		if !ok {
			failed = true
			return false
		}
		return true
	})
	if err != nil {
		return false, err
	}
	return found && !failed, nil
}

// trustedOrigins is the reference's TrustedOrigins::from_scopes.
func trustedOrigins(scopes []Scope, defaults Origin, current int, keyBlocks map[uint64][]int) Origin {
	if len(scopes) == 0 {
		return defaults | originOf(current, AuthorizerID)
	}
	o := originOf(AuthorizerID, current)
	for _, s := range scopes {
		switch s.Kind {
		case ScopeAuthority:
			o |= originOf(0)
		case ScopePrevious:
			if current != AuthorizerID {
				for i := 0; i <= current; i++ {
					o |= originOf(i)
				}
			}
		case ScopePublicKey:
			for _, b := range keyBlocks[s.Key] {
				o |= originOf(b)
			}
		}
	}
	return o
}

var defaultTrust = originOf(AuthorizerID, 0)
