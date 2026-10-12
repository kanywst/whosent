package ucan

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// The UCAN policy language (delegation spec, "Policy"). Evaluation follows
// the specification's text and its policy fixtures, which go-ucan v1.2.0
// does not: it compares 1 and 1.0 as different and will not quantify over
// a map.

// Policy is a delegation's pol: statements that must all hold.
type Policy []Statement

// Statement is one predicate.
type Statement struct {
	Op string
	// Sel is the selector of a comparison, like or quantifier.
	Sel     Selector
	SelText string
	// Value is what == != < <= > >= compare against; Pattern is a like's
	// glob.
	Value   Value
	Pattern string
	// Sub is the statement under not, all and any; Subs those under and
	// and or.
	Sub  *Statement
	Subs []Statement
	// Src is the statement as written, for display.
	Src Value
}

// parsePolicy reads a pol value.
func parsePolicy(v Value) (Policy, error) {
	if v.Kind != KindList {
		return nil, fmt.Errorf("a %s, not a list of statements", v.Kind)
	}
	var p Policy
	for i, e := range v.List {
		s, err := parseStatement(e)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		p = append(p, s)
	}
	return p, nil
}

func parseStatement(v Value) (Statement, error) {
	if v.Kind != KindList || len(v.List) < 2 || len(v.List) > 3 {
		return Statement{}, errors.New("not a 2- or 3-element list")
	}
	if v.List[0].Kind != KindString {
		return Statement{}, errors.New("the operator is not a string")
	}
	s := Statement{Op: v.List[0].Str, Src: v}
	sel := func() error {
		if v.List[1].Kind != KindString {
			return errors.New("the selector is not a string")
		}
		var err error
		s.SelText = v.List[1].Str
		s.Sel, err = parseSelector(s.SelText)
		return err
	}
	switch s.Op {
	case "not":
		if len(v.List) != 2 {
			return s, errors.New("not takes one statement")
		}
		sub, err := parseStatement(v.List[1])
		if err != nil {
			return s, err
		}
		s.Sub = &sub
	case "and", "or":
		if len(v.List) != 2 || v.List[1].Kind != KindList {
			return s, fmt.Errorf("%s takes a list of statements", s.Op)
		}
		for _, e := range v.List[1].List {
			sub, err := parseStatement(e)
			if err != nil {
				return s, err
			}
			s.Subs = append(s.Subs, sub)
		}
	case "==", "!=":
		if len(v.List) != 3 {
			return s, fmt.Errorf("%s takes a selector and a value", s.Op)
		}
		if err := sel(); err != nil {
			return s, err
		}
		s.Value = v.List[2]
	case "<", "<=", ">", ">=":
		if len(v.List) != 3 {
			return s, fmt.Errorf("%s takes a selector and a number", s.Op)
		}
		if err := sel(); err != nil {
			return s, err
		}
		if k := v.List[2].Kind; k != KindInt && k != KindFloat {
			return s, fmt.Errorf("%s compares against a number, not a %s", s.Op, k)
		}
		s.Value = v.List[2]
	case "like":
		if len(v.List) != 3 || v.List[2].Kind != KindString {
			return s, errors.New("like takes a selector and a pattern string")
		}
		if err := sel(); err != nil {
			return s, err
		}
		if strings.HasSuffix(strings.ReplaceAll(v.List[2].Str, `\\`, ""), `\`) {
			return s, errors.New("the pattern ends in a lone backslash")
		}
		s.Pattern = v.List[2].Str
	case "all", "any":
		if len(v.List) != 3 {
			return s, fmt.Errorf("%s takes a selector and a statement", s.Op)
		}
		if err := sel(); err != nil {
			return s, err
		}
		sub, err := parseStatement(v.List[2])
		if err != nil {
			return s, err
		}
		s.Sub = &sub
	default:
		return s, fmt.Errorf("unknown operator %q", s.Op)
	}
	return s, nil
}

// Selector is a parsed jq-like selector.
type Selector []segment

type segKind int

const (
	segIdentity segKind = iota
	segField
	segIndex
	segSlice
	segIterate
)

type segment struct {
	kind         segKind
	field        string
	index        int64
	lo, hi       int64
	hasLo, hasHi bool
	optional     bool
}

var fieldName = regexp.MustCompile(`^[a-zA-Z_\p{L}][a-zA-Z0-9$_\p{L}\-]*`)

// parseSelector reads a selector: a leading dot, then fields (.foo,
// ["key"]), indexes ([0], [-1]), slices ([1:3]) and iterators ([]), each
// optionally followed by ?.
func parseSelector(s string) (Selector, error) {
	if !strings.HasPrefix(s, ".") {
		return nil, fmt.Errorf("selector %q does not start with a dot", s)
	}
	if strings.Contains(s, "..") {
		return nil, fmt.Errorf("selector %q has two dots in a row", s)
	}
	sel := Selector{{kind: segIdentity}}
	rest := s[1:]
	afterDot := true
	for rest != "" {
		var seg segment
		switch {
		case rest[0] == '?':
			sel[len(sel)-1].optional = true
			rest = rest[1:]
			continue
		case rest[0] == '[':
			end, err := closingBracket(rest)
			if err != nil {
				return nil, fmt.Errorf("selector %q: %w", s, err)
			}
			seg, err = bracket(rest[1:end])
			if err != nil {
				return nil, fmt.Errorf("selector %q: %w", s, err)
			}
			rest = rest[end+1:]
		case rest[0] == '.':
			// ".foo." and ".foo.[0]": the dot only separates.
			rest, afterDot = rest[1:], true
			continue
		case afterDot:
			m := fieldName.FindString(rest)
			if m == "" {
				return nil, fmt.Errorf("selector %q: unexpected %q", s, rest)
			}
			seg = segment{kind: segField, field: m}
			rest = rest[len(m):]
		default:
			return nil, fmt.Errorf("selector %q: unexpected %q", s, rest)
		}
		afterDot = false
		sel = append(sel, seg)
	}
	return sel, nil
}

// closingBracket finds the ] that closes s[0], skipping quoted strings.
func closingBracket(s string) (int, error) {
	inQuote := false
	for i := 1; i < len(s); i++ {
		switch {
		case inQuote && s[i] == '\\':
			i++
		case s[i] == '"':
			inQuote = !inQuote
		case !inQuote && s[i] == ']':
			return i, nil
		}
	}
	return 0, errors.New("unclosed [")
}

var (
	indexText = regexp.MustCompile(`^-?\d+$`)
	sliceText = regexp.MustCompile(`^(-?\d*):(-?\d*)$`)
)

func bracket(in string) (segment, error) {
	switch {
	case in == "":
		return segment{kind: segIterate}, nil
	case strings.HasPrefix(in, `"`):
		key, err := strconv.Unquote(in)
		if err != nil {
			return segment{}, fmt.Errorf("field %s: %w", in, err)
		}
		return segment{kind: segField, field: key}, nil
	case indexText.MatchString(in):
		n, err := strconv.ParseInt(in, 10, 64)
		if err != nil || n > maxSafe || n < -maxSafe {
			return segment{}, fmt.Errorf("index %s is out of range", in)
		}
		return segment{kind: segIndex, index: n}, nil
	}
	m := sliceText.FindStringSubmatch(in)
	if m == nil || (m[1] == "" && m[2] == "") {
		return segment{}, fmt.Errorf("[%s] is not an index, a slice or a field", in)
	}
	seg := segment{kind: segSlice}
	for i, part := range m[1:] {
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n > maxSafe || n < -maxSafe {
			return segment{}, fmt.Errorf("slice bound %s is out of range", part)
		}
		if i == 0 {
			seg.lo, seg.hasLo = n, true
		} else {
			seg.hi, seg.hasHi = n, true
		}
	}
	return seg, nil
}

// resolve applies the selector. ok is false when a segment cannot be
// resolved; an optional segment that cannot be resolved yields null
// instead, and resolution stops there. A missing map key is null, not a
// failure (delegation spec, "Validation").
func (sel Selector) resolve(v Value) (Value, bool) {
	cur := v
	for _, seg := range sel {
		next, ok := seg.apply(cur)
		if !ok {
			if seg.optional {
				return Value{Kind: KindNull}, true
			}
			return Value{}, false
		}
		cur = next
	}
	return cur, true
}

func (seg segment) apply(cur Value) (Value, bool) {
	switch seg.kind {
	case segIdentity:
		return cur, true
	case segField:
		if cur.Kind != KindMap {
			return Value{}, false
		}
		if v, ok := cur.Get(seg.field); ok {
			return v, true
		}
		return Value{Kind: KindNull}, true
	case segIndex:
		switch cur.Kind {
		case KindList:
			i, ok := absIndex(seg.index, len(cur.List))
			if !ok {
				return Value{}, false
			}
			return cur.List[i], true
		case KindBytes:
			i, ok := absIndex(seg.index, len(cur.Bytes))
			if !ok {
				return Value{}, false
			}
			return vInt(int64(cur.Bytes[i])), true
		}
		return Value{}, false
	case segSlice:
		switch cur.Kind {
		case KindList:
			lo, hi := seg.bounds(len(cur.List))
			return vList(cur.List[lo:hi]...), true
		case KindBytes:
			lo, hi := seg.bounds(len(cur.Bytes))
			return vBytes(append([]byte(nil), cur.Bytes[lo:hi]...)), true
		case KindString:
			r := []rune(cur.Str)
			lo, hi := seg.bounds(len(r))
			return vStr(string(r[lo:hi])), true
		}
		return Value{}, false
	case segIterate:
		switch cur.Kind {
		case KindList:
			return cur, true
		case KindMap:
			vals := make([]Value, len(cur.Map))
			for i, e := range cur.Map {
				vals[i] = e.Value
			}
			return vList(vals...), true
		}
		return Value{}, false
	}
	return Value{}, false
}

func absIndex(i int64, n int) (int, bool) {
	if i < 0 {
		i += int64(n)
	}
	if i < 0 || i >= int64(n) {
		return 0, false
	}
	return int(i), true
}

// bounds clamps a slice to the collection, as jq does; a backward slice is
// empty.
func (seg segment) bounds(n int) (int, int) {
	lo, hi := int64(0), int64(n)
	if seg.hasLo {
		lo = seg.lo
		if lo < 0 {
			lo += int64(n)
		}
	}
	if seg.hasHi {
		hi = seg.hi
		if hi < 0 {
			hi += int64(n)
		}
	}
	lo = min(max(lo, 0), int64(n))
	hi = min(max(hi, 0), int64(n))
	if lo >= hi {
		return 0, 0
	}
	return int(lo), int(hi)
}

// evaluation carries what one policy check noticed besides its answer.
type evaluation struct {
	steps int
	// unresolved is set when a selector could not be resolved: the
	// statement is false, which a not then turns true.
	unresolved bool
	// negated is set when a not turned such a false into true: the spec
	// allows it, go-ucan refuses it, so the answer cannot be vouched for.
	negated bool
	// emptyAny is set when any was asked of an empty collection.
	emptyAny bool
}

// maxSteps bounds one evaluation. A real policy over real arguments takes
// a few dozen.
const maxSteps = 1 << 20

var errTooLarge = errors.New("the policy and its arguments are too large to evaluate")

// match evaluates the policy against args. failed is the first top-level
// statement that does not hold.
func (p Policy) match(args Value, ev *evaluation) (ok bool, failed int, err error) {
	for i, s := range p {
		holds, err := s.eval(args, ev)
		if err != nil {
			return false, i, err
		}
		if !holds {
			return false, i, nil
		}
	}
	return true, -1, nil
}

func (s Statement) eval(v Value, ev *evaluation) (bool, error) {
	ev.steps++
	if ev.steps > maxSteps {
		return false, errTooLarge
	}
	switch s.Op {
	case "not":
		before := ev.unresolved
		ev.unresolved = false
		r, err := s.Sub.eval(v, ev)
		if ev.unresolved && !r {
			ev.negated = true
		}
		ev.unresolved = ev.unresolved || before
		return !r, err
	case "and":
		for _, sub := range s.Subs {
			if r, err := sub.eval(v, ev); err != nil || !r {
				return false, err
			}
		}
		return true, nil
	case "or":
		if len(s.Subs) == 0 {
			return true, nil
		}
		for _, sub := range s.Subs {
			r, err := sub.eval(v, ev)
			if err != nil || r {
				return r, err
			}
		}
		return false, nil
	}
	got, ok := s.Sel.resolve(v)
	if !ok {
		ev.unresolved = true
		return false, nil
	}
	switch s.Op {
	case "==":
		return equal(got, s.Value), nil
	case "!=":
		return !equal(got, s.Value), nil
	case "<", "<=", ">", ">=":
		c, ok := numCompare(got, s.Value)
		if !ok {
			return false, nil
		}
		switch s.Op {
		case "<":
			return c < 0, nil
		case "<=":
			return c <= 0, nil
		case ">":
			return c > 0, nil
		}
		return c >= 0, nil
	case "like":
		if got.Kind != KindString {
			return false, nil
		}
		return globMatch(s.Pattern, got.Str), nil
	case "all", "any":
		var items []Value
		switch got.Kind {
		case KindList:
			items = got.List
		case KindMap:
			for _, e := range got.Map {
				items = append(items, e.Value)
			}
		default:
			return false, nil
		}
		if s.Op == "any" && len(items) == 0 {
			ev.emptyAny = true
		}
		for _, it := range items {
			r, err := s.Sub.eval(it, ev)
			if err != nil {
				return false, err
			}
			if s.Op == "all" && !r {
				return false, nil
			}
			if s.Op == "any" && r {
				return true, nil
			}
		}
		return s.Op == "all", nil
	}
	return false, fmt.Errorf("unknown operator %q", s.Op)
}

func toBig(v Value) (*big.Float, bool) {
	f := new(big.Float).SetPrec(256)
	switch {
	case v.Kind == KindInt && v.Big != nil:
		return f.SetInt(v.Big), true
	case v.Kind == KindInt:
		return f.SetInt64(v.Int), true
	case v.Kind == KindFloat:
		return f.SetFloat64(v.Float), true
	}
	return nil, false
}

// numCompare compares two numbers whatever their kind: the specification
// makes 1, 1.0 and 1.00 equal.
func numCompare(a, b Value) (int, bool) {
	x, ok1 := toBig(a)
	y, ok2 := toBig(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return x.Cmp(y), true
}

// equal is the deep equality == uses, agnostic to numeric kind at every
// level.
func equal(a, b Value) bool {
	if c, ok := numCompare(a, b); ok {
		return c == 0
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindNull:
		return true
	case KindBool:
		return a.Bool == b.Bool
	case KindString:
		return a.Str == b.Str
	case KindBytes:
		return bytes.Equal(a.Bytes, b.Bytes)
	case KindLink:
		return bytes.Equal(a.Link, b.Link)
	case KindList:
		if len(a.List) != len(b.List) {
			return false
		}
		for i := range a.List {
			if !equal(a.List[i], b.List[i]) {
				return false
			}
		}
		return true
	case KindMap:
		if len(a.Map) != len(b.Map) {
			return false
		}
		for _, e := range a.Map {
			o, ok := b.Get(e.Key)
			if !ok || !equal(e.Value, o) {
				return false
			}
		}
		return true
	}
	return false
}

// globMatch matches s against a pattern whose only special character is
// *, any number of characters; \* is a literal star, and a backslash
// escapes whatever follows it.
func globMatch(pattern, s string) bool {
	parts := []string{""}
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '\\' && i+1 < len(pattern):
			i++
			parts[len(parts)-1] += string(pattern[i])
		case c == '*':
			parts = append(parts, "")
		default:
			parts[len(parts)-1] += string(c)
		}
	}
	if len(parts) == 1 {
		return s == parts[0]
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return len(s) >= len(last) && strings.HasSuffix(s, last)
}
