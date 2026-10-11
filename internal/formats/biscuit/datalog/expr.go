package datalog

import (
	"errors"
	"math"
	"strings"
)

// ExprError is an expression that could not be evaluated. The reference
// implementation stops the whole authorization on one, so the engine does
// too. Its names are the reference's error names.
type ExprError struct{ Kind string }

func (e *ExprError) Error() string { return "expression error: " + e.Kind }

// The expression errors.
var (
	ErrInvalidType      = &ExprError{"InvalidType"}
	ErrOverflow         = &ExprError{"Overflow"}
	ErrDivideByZero     = &ExprError{"DivideByZero"}
	ErrUnknownSymbol    = &ExprError{"UnknownSymbol"}
	ErrUnknownVariable  = &ExprError{"UnknownVariable"}
	ErrInvalidStack     = &ExprError{"InvalidStack"}
	ErrShadowedVariable = &ExprError{"ShadowedVariable"}
	ErrUndefinedExtern  = &ExprError{"UndefinedExtern"}
)

// IsExprError reports whether err is an expression error.
func IsExprError(err error) bool {
	var e *ExprError
	return errors.As(err, &e)
}

type stackElem struct {
	closure bool
	params  []uint64
	ops     []Op
	term    Term
}

// evaluate runs an expression's opcodes against the variable bindings.
func evaluate(ops []Op, values map[uint64]Term, syms *temp) (Term, error) {
	var stack []stackElem
	pop := func() (stackElem, bool) {
		if len(stack) == 0 {
			return stackElem{}, false
		}
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return e, true
	}
	for _, op := range ops {
		if !syms.b.tick() {
			return Term{}, syms.b.err
		}
		switch op.Kind {
		case OpValue:
			if op.Value.Kind == KindVariable {
				v, ok := values[op.Value.U]
				if !ok {
					return Term{}, ErrUnknownVariable
				}
				stack = append(stack, stackElem{term: v})
				continue
			}
			stack = append(stack, stackElem{term: op.Value})
		case OpUnary:
			e, ok := pop()
			if !ok || e.closure {
				return Term{}, ErrInvalidStack
			}
			r, err := unary(op, e.term, syms)
			if err != nil {
				return Term{}, err
			}
			stack = append(stack, stackElem{term: r})
		case OpBinary:
			right, ok1 := pop()
			left, ok2 := pop()
			if !ok1 || !ok2 {
				return Term{}, ErrInvalidStack
			}
			var r Term
			var err error
			switch {
			case !right.closure && !left.closure:
				r, err = applyBinary(op, left.term, right.term, syms)
			case right.closure && !left.closure:
				r, err = withClosure(op, left.term, right.params, right.ops, values, syms)
			case !right.closure && left.closure:
				r, err = withClosure(op, right.term, left.params, left.ops, values, syms)
			default:
				return Term{}, ErrInvalidStack
			}
			if err != nil {
				return Term{}, err
			}
			stack = append(stack, stackElem{term: r})
		case OpClosure:
			stack = append(stack, stackElem{closure: true, params: op.Params, ops: op.Ops})
		default:
			return Term{}, ErrInvalidStack
		}
	}
	if len(stack) != 1 || stack[0].closure {
		return Term{}, ErrInvalidStack
	}
	return stack[0].term, nil
}

func withClosure(op Op, left Term, params []uint64, body []Op, values map[uint64]Term, syms *temp) (Term, error) {
	for _, p := range params {
		if _, ok := values[p]; ok {
			return Term{}, ErrShadowedVariable
		}
	}
	vals := make(map[uint64]Term, len(values)+len(params))
	for k, v := range values {
		vals[k] = v
	}
	if op.Kind != OpBinary {
		return Term{}, ErrInvalidType
	}
	switch {
	case op.Binary == TryOr && len(params) == 0:
		v, err := evaluate(body, vals, syms)
		if err != nil {
			// try_or turns an expression error into its default, but a
			// run that has hit its limits is over: swallowing that here
			// would let the rest of the run go on past the deadline.
			if IsLimitError(err) {
				return Term{}, err
			}
			return left, nil
		}
		return v, nil
	case op.Binary == LazyOr && len(params) == 0 && left.Kind == KindBool:
		if left.Bool {
			return Bool(true), nil
		}
		return evaluate(body, vals, syms)
	case op.Binary == LazyAnd && len(params) == 0 && left.Kind == KindBool:
		if !left.Bool {
			return Bool(false), nil
		}
		return evaluate(body, vals, syms)
	case (op.Binary == All || op.Binary == Any) && len(params) == 1:
		var items []Term
		switch left.Kind {
		case KindSet, KindArray:
			items = left.Elems
		case KindMap:
			for _, e := range left.Map {
				items = append(items, Array([]Term{keyTerm(e.Key), e.Value}))
			}
		default:
			return Term{}, ErrInvalidType
		}
		all := op.Binary == All
		for _, item := range items {
			vals[params[0]] = item
			r, err := evaluate(body, vals, syms)
			delete(vals, params[0])
			if err != nil {
				return Term{}, err
			}
			if r.Kind != KindBool {
				return Term{}, ErrInvalidType
			}
			if all && !r.Bool {
				return Bool(false), nil
			}
			if !all && r.Bool {
				return Bool(true), nil
			}
		}
		return Bool(all), nil
	}
	return Term{}, ErrInvalidType
}

func keyTerm(k MapKey) Term {
	if k.IsString {
		return Str(k.U)
	}
	return Int(k.I)
}

func unary(op Op, v Term, syms *temp) (Term, error) {
	switch op.Unary {
	case Negate:
		if v.Kind == KindBool {
			return Bool(!v.Bool), nil
		}
	case Parens:
		return v, nil
	case Length:
		switch v.Kind {
		case KindString:
			s, ok := syms.symbol(v.U)
			if !ok {
				return Term{}, ErrUnknownSymbol
			}
			return Int(int64(len(s))), nil
		case KindBytes:
			return Int(int64(len(v.B))), nil
		case KindSet, KindArray:
			return Int(int64(len(v.Elems))), nil
		case KindMap:
			return Int(int64(len(v.Map))), nil
		}
	case TypeOf:
		name := ""
		switch v.Kind {
		case KindVariable:
			return Term{}, ErrInvalidType
		case KindInteger:
			name = "integer"
		case KindString:
			name = "string"
		case KindDate:
			name = "date"
		case KindBytes:
			name = "bytes"
		case KindBool:
			name = "bool"
		case KindSet:
			name = "set"
		case KindNull:
			name = "null"
		case KindArray:
			name = "array"
		case KindMap:
			name = "map"
		}
		return Str(syms.insert(name)), nil
	case UnaryFfi:
		// External functions are the authorizer's own code. With none
		// registered, the reference reports this, and so does this engine.
		return Term{}, ErrUndefinedExtern
	}
	return Term{}, ErrInvalidType
}

func boolOf(b bool) (Term, error) { return Bool(b), nil }

// binary applies a two-operand operation. The cases follow the order of the
// reference implementation's match, because where two of its arms could
// apply, the first one decides.
func applyBinary(op Op, l, r Term, syms *temp) (Term, error) {
	k := op.Binary
	eq := k == StrictEqual || k == HeterogeneousEqual
	ne := k == StrictNotEqual || k == HeterogeneousNotEqual
	switch {
	// integer
	case l.Kind == KindInteger && r.Kind == KindInteger:
		switch {
		case k == LessThan:
			return boolOf(l.I < r.I)
		case k == GreaterThan:
			return boolOf(l.I > r.I)
		case k == LessOrEqual:
			return boolOf(l.I <= r.I)
		case k == GreaterOrEqual:
			return boolOf(l.I >= r.I)
		case eq:
			return boolOf(l.I == r.I)
		case ne:
			return boolOf(l.I != r.I)
		case k == Add:
			s := l.I + r.I
			if (r.I > 0 && s < l.I) || (r.I < 0 && s > l.I) {
				return Term{}, ErrOverflow
			}
			return Int(s), nil
		case k == Sub:
			s := l.I - r.I
			if (r.I > 0 && s > l.I) || (r.I < 0 && s < l.I) {
				return Term{}, ErrOverflow
			}
			return Int(s), nil
		case k == Mul:
			if l.I == 0 || r.I == 0 {
				return Int(0), nil
			}
			p := l.I * r.I
			if p/r.I != l.I || (l.I == -1 && r.I == math.MinInt64) || (r.I == -1 && l.I == math.MinInt64) {
				return Term{}, ErrOverflow
			}
			return Int(p), nil
		case k == Div:
			// The reference's checked division fails on a zero divisor and
			// on the one overflowing quotient, and reports both the same.
			if r.I == 0 || (l.I == math.MinInt64 && r.I == -1) {
				return Term{}, ErrDivideByZero
			}
			return Int(l.I / r.I), nil
		case k == BitwiseAnd:
			return Int(l.I & r.I), nil
		case k == BitwiseOr:
			return Int(l.I | r.I), nil
		case k == BitwiseXor:
			return Int(l.I ^ r.I), nil
		}
	// string
	case l.Kind == KindString && r.Kind == KindString:
		switch k {
		case Prefix, Suffix, Regex, Contains, Add:
			a, okA := syms.symbol(l.U)
			b, okB := syms.symbol(r.U)
			if !okA || !okB {
				return Term{}, ErrUnknownSymbol
			}
			switch k {
			case Prefix:
				return boolOf(strings.HasPrefix(a, b))
			case Suffix:
				return boolOf(strings.HasSuffix(a, b))
			case Regex:
				re, err := syms.b.compile(b)
				if err != nil {
					// The reference treats a pattern it cannot compile as
					// one that matches nothing.
					return boolOf(false)
				}
				return boolOf(re.MatchString(a))
			case Contains:
				return boolOf(strings.Contains(a, b))
			case Add:
				return Str(syms.insert(a + b)), nil
			}
		}
		switch {
		case eq:
			return boolOf(l.U == r.U)
		case ne:
			return boolOf(l.U != r.U)
		}
	// date
	case l.Kind == KindDate && r.Kind == KindDate:
		switch {
		case k == LessThan:
			return boolOf(l.U < r.U)
		case k == GreaterThan:
			return boolOf(l.U > r.U)
		case k == LessOrEqual:
			return boolOf(l.U <= r.U)
		case k == GreaterOrEqual:
			return boolOf(l.U >= r.U)
		case eq:
			return boolOf(l.U == r.U)
		case ne:
			return boolOf(l.U != r.U)
		}
	// bytes
	case l.Kind == KindBytes && r.Kind == KindBytes:
		switch {
		case eq:
			return boolOf(string(l.B) == string(r.B))
		case ne:
			return boolOf(string(l.B) != string(r.B))
		}
	}

	// set
	if l.Kind == KindSet {
		if r.Kind == KindSet {
			switch {
			case eq:
				return boolOf(Equal(l, r))
			case ne:
				return boolOf(!Equal(l, r))
			case k == Intersection:
				var out []Term
				for _, e := range l.Elems {
					if contains(r.Elems, e) {
						out = append(out, e)
					}
				}
				return Set(out), nil
			case k == Union:
				return Set(append(append([]Term(nil), l.Elems...), r.Elems...)), nil
			case k == Contains:
				for _, e := range r.Elems {
					if !contains(l.Elems, e) {
						return boolOf(false)
					}
				}
				return boolOf(true)
			}
		}
		if k == Contains {
			switch r.Kind {
			case KindInteger, KindDate, KindBool, KindString, KindBytes:
				return boolOf(contains(l.Elems, r))
			}
		}
	}

	// boolean
	if l.Kind == KindBool && r.Kind == KindBool {
		switch {
		case k == And:
			return boolOf(l.Bool && r.Bool)
		case k == Or:
			return boolOf(l.Bool || r.Bool)
		case eq:
			return boolOf(l.Bool == r.Bool)
		case ne:
			return boolOf(l.Bool != r.Bool)
		}
	}

	// null
	switch {
	case eq && l.Kind == KindNull && r.Kind == KindNull:
		return boolOf(true)
	case k == HeterogeneousEqual && (l.Kind == KindNull || r.Kind == KindNull):
		return boolOf(false)
	case ne && l.Kind == KindNull && r.Kind == KindNull:
		return boolOf(false)
	case k == HeterogeneousNotEqual && (l.Kind == KindNull || r.Kind == KindNull):
		return boolOf(true)
	}

	// array
	if l.Kind == KindArray {
		switch {
		case eq && r.Kind == KindArray:
			return boolOf(Equal(l, r))
		case ne && r.Kind == KindArray:
			return boolOf(!Equal(l, r))
		case k == Contains:
			return boolOf(contains(l.Elems, r))
		case k == Prefix && r.Kind == KindArray:
			if len(r.Elems) > len(l.Elems) {
				return boolOf(false)
			}
			for i, e := range r.Elems {
				if !Equal(l.Elems[i], e) {
					return boolOf(false)
				}
			}
			return boolOf(true)
		case k == Suffix && r.Kind == KindArray:
			if len(r.Elems) > len(l.Elems) {
				return boolOf(false)
			}
			off := len(l.Elems) - len(r.Elems)
			for i, e := range r.Elems {
				if !Equal(l.Elems[off+i], e) {
					return boolOf(false)
				}
			}
			return boolOf(true)
		case k == Get && r.Kind == KindInteger:
			if r.I < 0 || r.I >= int64(len(l.Elems)) {
				return Null(), nil
			}
			return l.Elems[r.I], nil
		}
	}

	// map
	if l.Kind == KindMap {
		switch {
		case eq && r.Kind == KindMap:
			return boolOf(Equal(l, r))
		case ne && r.Kind == KindMap:
			return boolOf(!Equal(l, r))
		case k == Contains:
			for _, e := range l.Map {
				if (!e.Key.IsString && r.Kind == KindInteger && e.Key.I == r.I) ||
					(e.Key.IsString && r.Kind == KindString && e.Key.U == r.U) {
					return boolOf(true)
				}
			}
			return boolOf(false)
		case k == Get && (r.Kind == KindInteger || r.Kind == KindString):
			for _, e := range l.Map {
				if (!e.Key.IsString && r.Kind == KindInteger && e.Key.I == r.I) ||
					(e.Key.IsString && r.Kind == KindString && e.Key.U == r.U) {
					return e.Value, nil
				}
			}
			return Null(), nil
		}
	}

	switch k {
	case HeterogeneousEqual:
		return boolOf(false)
	case HeterogeneousNotEqual:
		return boolOf(true)
	case BinaryFfi:
		return Term{}, ErrUndefinedExtern
	}
	return Term{}, ErrInvalidType
}
