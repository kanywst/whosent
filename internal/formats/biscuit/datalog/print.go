package datalog

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// The printer reproduces the reference implementation's output byte for
// byte: the specification's samples carry each block's source as the
// reference printed it, and they are this printer's test. In particular a
// string is printed between quotes without escaping, as the reference does;
// whatever reaches a terminal is made safe where it is drawn, not here.

var displayEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)

func (t *SymbolTable) symbolOrPlaceholder(i uint64) string {
	if s, ok := t.Symbol(i); ok {
		return s
	}
	return "<" + strconv.FormatUint(i, 10) + "?>"
}

// PrintTerm prints a term.
func (t *SymbolTable) PrintTerm(term Term) string {
	switch term.Kind {
	case KindVariable:
		return "$" + t.symbolOrPlaceholder(term.U)
	case KindInteger:
		return strconv.FormatInt(term.I, 10)
	case KindString:
		if t.display {
			return `"` + displayEscaper.Replace(t.symbolOrPlaceholder(term.U)) + `"`
		}
		return `"` + t.symbolOrPlaceholder(term.U) + `"`
	case KindDate:
		return PrintDate(term.U)
	case KindBytes:
		return "hex:" + hex.EncodeToString(term.B)
	case KindBool:
		if term.Bool {
			return "true"
		}
		return "false"
	case KindSet:
		if len(term.Elems) == 0 {
			return "{,}"
		}
		parts := make([]string, len(term.Elems))
		for i, e := range term.Elems {
			parts[i] = t.PrintTerm(e)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case KindNull:
		return "null"
	case KindArray:
		parts := make([]string, len(term.Elems))
		for i, e := range term.Elems {
			parts[i] = t.PrintTerm(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case KindMap:
		parts := make([]string, len(term.Map))
		for i, e := range term.Map {
			if e.Key.IsString {
				parts[i] = `"` + t.symbolOrPlaceholder(e.Key.U) + `": ` + t.PrintTerm(e.Value)
			} else {
				parts[i] = strconv.FormatInt(e.Key.I, 10) + ": " + t.PrintTerm(e.Value)
			}
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return "<invalid term>"
}

// PrintDate prints a date as RFC 3339 in UTC, as the reference does. Its
// date library refuses years outside 0 to 9999, and the reference then
// prints a placeholder; so does this.
func PrintDate(secs uint64) string {
	// The reference converts with a wrapping cast, so a date past the
	// signed range prints as one before 1970; this does the same.
	d := time.Unix(int64(secs), 0).UTC()
	if d.Year() < 0 || d.Year() > 9999 {
		return "<invalid date>"
	}
	return d.Format("2006-01-02T15:04:05Z")
}

// PrintPredicate prints a predicate.
func (t *SymbolTable) PrintPredicate(p Predicate) string {
	name, ok := t.Symbol(p.Name)
	if !ok {
		name = "<?>"
	}
	parts := make([]string, len(p.Terms))
	for i, term := range p.Terms {
		parts[i] = t.PrintTerm(term)
	}
	return name + "(" + strings.Join(parts, ", ") + ")"
}

// PrintFact prints a fact.
func (t *SymbolTable) PrintFact(f Fact) string { return t.PrintPredicate(f.Predicate) }

// PrintExpression prints an expression, or a placeholder when its opcodes
// do not form one.
func (t *SymbolTable) PrintExpression(e Expression) string {
	if s, ok := t.printOps(e.Ops); ok {
		return s
	}
	return "<invalid expression>"
}

func (t *SymbolTable) printOps(ops []Op) (string, bool) {
	var stack []string
	pop := func() (string, bool) {
		if len(stack) == 0 {
			return "", false
		}
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return s, true
	}
	for _, op := range ops {
		switch op.Kind {
		case OpValue:
			stack = append(stack, t.PrintTerm(op.Value))
		case OpUnary:
			v, ok := pop()
			if !ok {
				return "", false
			}
			stack = append(stack, t.printUnary(op, v))
		case OpBinary:
			right, ok1 := pop()
			left, ok2 := pop()
			if !ok1 || !ok2 {
				return "", false
			}
			stack = append(stack, t.printBinary(op, left, right))
		case OpClosure:
			body, ok := t.printOps(op.Ops)
			if !ok {
				return "", false
			}
			if len(op.Params) == 0 {
				stack = append(stack, body)
				continue
			}
			params := make([]string, len(op.Params))
			for i, p := range op.Params {
				params[i] = t.PrintTerm(Var(p))
			}
			stack = append(stack, strings.Join(params, ", ")+" -> "+body)
		default:
			return "", false
		}
	}
	if len(stack) != 1 {
		return "", false
	}
	return stack[0], true
}

func (t *SymbolTable) printUnary(op Op, v string) string {
	switch op.Unary {
	case Negate:
		return "!" + v
	case Parens:
		return "(" + v + ")"
	case Length:
		return v + ".length()"
	case TypeOf:
		return v + ".type()"
	case UnaryFfi:
		return v + ".extern::" + t.symbolOrPlaceholder(op.Ffi) + "()"
	}
	return v
}

func (t *SymbolTable) printBinary(op Op, l, r string) string {
	switch op.Binary {
	case LessThan:
		return l + " < " + r
	case GreaterThan:
		return l + " > " + r
	case LessOrEqual:
		return l + " <= " + r
	case GreaterOrEqual:
		return l + " >= " + r
	case StrictEqual:
		return l + " === " + r
	case HeterogeneousEqual:
		return l + " == " + r
	case StrictNotEqual:
		return l + " !== " + r
	case HeterogeneousNotEqual:
		return l + " != " + r
	case Contains:
		return l + ".contains(" + r + ")"
	case Prefix:
		return l + ".starts_with(" + r + ")"
	case Suffix:
		return l + ".ends_with(" + r + ")"
	case Regex:
		return l + ".matches(" + r + ")"
	case Add:
		return l + " + " + r
	case Sub:
		return l + " - " + r
	case Mul:
		return l + " * " + r
	case Div:
		return l + " / " + r
	case And:
		// The eager operators of older blocks print with a "!" the parser
		// does not read back, exactly as the reference prints them.
		return l + " &&! " + r
	case Or:
		return l + " ||! " + r
	case Intersection:
		return l + ".intersection(" + r + ")"
	case Union:
		return l + ".union(" + r + ")"
	case BitwiseAnd:
		return l + " & " + r
	case BitwiseOr:
		return l + " | " + r
	case BitwiseXor:
		return l + " ^ " + r
	case LazyAnd:
		return l + " && " + r
	case LazyOr:
		return l + " || " + r
	case All:
		return l + ".all(" + r + ")"
	case Any:
		return l + ".any(" + r + ")"
	case Get:
		return l + ".get(" + r + ")"
	case BinaryFfi:
		return l + ".extern::" + t.symbolOrPlaceholder(op.Ffi) + "(" + r + ")"
	case TryOr:
		return l + ".try_or(" + r + ")"
	}
	return l + " ? " + r
}

// PrintRuleBody prints a rule's body: predicates, expressions, scopes.
func (t *SymbolTable) PrintRuleBody(r Rule) string {
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = t.PrintPredicate(p)
	}
	exprs := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		exprs[i] = t.PrintExpression(e)
	}
	var e string
	switch {
	case len(exprs) == 0:
	case len(preds) == 0:
		e = strings.Join(exprs, ", ")
	default:
		e = ", " + strings.Join(exprs, ", ")
	}
	scopes := ""
	if len(r.Scopes) > 0 {
		parts := make([]string, len(r.Scopes))
		for i, s := range r.Scopes {
			parts[i] = t.PrintScope(s)
		}
		scopes = " trusting " + strings.Join(parts, ", ")
	}
	return strings.Join(preds, ", ") + e + scopes
}

// PrintScope prints one scope annotation.
func (t *SymbolTable) PrintScope(s Scope) string {
	switch s.Kind {
	case ScopeAuthority:
		return "authority"
	case ScopePrevious:
		return "previous"
	}
	if k, ok := t.Key(s.Key); ok {
		return k.String()
	}
	return "<unknown public key id>"
}

// PrintRule prints a rule.
func (t *SymbolTable) PrintRule(r Rule) string {
	return t.PrintPredicate(r.Head) + " <- " + t.PrintRuleBody(r)
}

// PrintCheck prints a check.
func (t *SymbolTable) PrintCheck(c Check) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = t.PrintRuleBody(q)
	}
	kind := "check if"
	switch c.Kind {
	case CheckAll:
		kind = "check all"
	case CheckReject:
		kind = "reject if"
	}
	return kind + " " + strings.Join(queries, " or ")
}

// PrintPolicy prints a policy.
func (t *SymbolTable) PrintPolicy(p Policy) string {
	queries := make([]string, len(p.Queries))
	for i, q := range p.Queries {
		queries[i] = t.PrintRuleBody(q)
	}
	kind := "allow if"
	if p.Kind == Deny {
		kind = "deny if"
	}
	return kind + " " + strings.Join(queries, " or ")
}

// PrintBlock prints a block's source as the reference does: facts, rules,
// then checks, each followed by ";\n".
func (t *SymbolTable) PrintBlock(b Block) string {
	var sb strings.Builder
	for _, f := range b.Facts {
		sb.WriteString(t.PrintFact(f))
		sb.WriteString(";\n")
	}
	for _, r := range b.Rules {
		sb.WriteString(t.PrintRule(r))
		sb.WriteString(";\n")
	}
	for _, c := range b.Checks {
		sb.WriteString(t.PrintCheck(c))
		sb.WriteString(";\n")
	}
	return sb.String()
}
