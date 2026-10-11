package datalog

// converter turns parsed Datalog, whose strings and variable names are
// held as text, into terms indexed by a symbol table, interning as it goes.
type converter struct {
	syms *SymbolTable
}

func (c *converter) term(t Term) Term {
	switch t.Kind {
	case KindVariable, KindString:
		if t.named {
			return Term{Kind: t.Kind, U: c.syms.Insert(t.S)}
		}
	case KindSet:
		elems := make([]Term, len(t.Elems))
		for i, e := range t.Elems {
			elems[i] = c.term(e)
		}
		return Set(elems)
	case KindArray:
		elems := make([]Term, len(t.Elems))
		for i, e := range t.Elems {
			elems[i] = c.term(e)
		}
		return Array(elems)
	case KindMap:
		entries := make([]MapEntry, len(t.Map))
		for i, e := range t.Map {
			k := e.Key
			if k.IsString && k.named {
				k = MapKey{IsString: true, U: c.syms.Insert(k.S)}
			}
			entries[i] = MapEntry{Key: k, Value: c.term(e.Value)}
		}
		return Map(entries)
	}
	return t
}

func (c *converter) pred(p Predicate) Predicate {
	out := Predicate{Name: p.Name, Terms: make([]Term, len(p.Terms))}
	if p.NameS != "" {
		out.Name = c.syms.Insert(p.NameS)
	}
	for i, t := range p.Terms {
		out.Terms[i] = c.term(t)
	}
	return out
}

func (c *converter) ops(ops []Op) []Op {
	out := make([]Op, len(ops))
	for i, op := range ops {
		switch op.Kind {
		case OpValue:
			op.Value = c.term(op.Value)
		case OpUnary, OpBinary:
			if op.named {
				op.Ffi = c.syms.Insert(op.FfiS)
				op.named = false
			}
		case OpClosure:
			if len(op.ParamsS) > 0 {
				op.Params = make([]uint64, len(op.ParamsS))
				for j, p := range op.ParamsS {
					op.Params[j] = c.syms.Insert(p)
				}
			}
			op.Ops = c.ops(op.Ops)
		}
		out[i] = op
	}
	return out
}

func (c *converter) scope(s Scope) Scope {
	if s.Kind == ScopePublicKey && s.named {
		return Scope{Kind: ScopePublicKey, Key: c.syms.InsertKey(s.KeyValue)}
	}
	return s
}

func (c *converter) rule(r Rule) Rule {
	out := Rule{Head: c.pred(r.Head)}
	for _, p := range r.Body {
		out.Body = append(out.Body, c.pred(p))
	}
	for _, e := range r.Expressions {
		out.Expressions = append(out.Expressions, Expression{Ops: c.ops(e.Ops)})
	}
	for _, s := range r.Scopes {
		out.Scopes = append(out.Scopes, c.scope(s))
	}
	return out
}

func (c *converter) check(ch Check) Check {
	out := Check{Kind: ch.Kind}
	for _, q := range ch.Queries {
		out.Queries = append(out.Queries, c.rule(q))
	}
	return out
}

// ConvertBlock converts a parsed block into terms indexed by syms, for
// minting: the strings and keys it introduces are appended to syms.
func ConvertBlock(b Block, syms *SymbolTable) Block {
	c := &converter{syms: syms}
	out := Block{Version: b.Version, Context: b.Context, HasContext: b.HasContext}
	for _, s := range b.Scopes {
		out.Scopes = append(out.Scopes, c.scope(s))
	}
	for _, f := range b.Facts {
		out.Facts = append(out.Facts, Fact{Predicate: c.pred(f.Predicate)})
	}
	for _, r := range b.Rules {
		out.Rules = append(out.Rules, c.rule(r))
	}
	for _, ch := range b.Checks {
		out.Checks = append(out.Checks, c.check(ch))
	}
	return out
}

// ConvertPolicy converts a parsed policy into terms indexed by syms.
func ConvertPolicy(p Policy, syms *SymbolTable) Policy {
	c := &converter{syms: syms}
	out := Policy{Kind: p.Kind}
	for _, q := range p.Queries {
		out.Queries = append(out.Queries, c.rule(q))
	}
	return out
}
