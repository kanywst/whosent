package datalog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/kanywst/whosent/internal/formats/biscuit/pb"
)

// The supported block versions: v3.0 to v3.3.
const (
	MinVersion = 3
	Version31  = 4
	Version32  = 5
	Version33  = 6
	MaxVersion = 6
)

// FormatError is a block the reference implementation refuses to read.
// Version is set when the refusal is about the block's datalog version.
type FormatError struct {
	Msg     string
	Version bool
}

func (e *FormatError) Error() string { return e.Msg }

func formatErr(format string, a ...any) error {
	return &FormatError{Msg: fmt.Sprintf(format, a...)}
}

func versionErr(format string, a ...any) error {
	return &FormatError{Msg: fmt.Sprintf(format, a...), Version: true}
}

// IsVersionError reports whether err refuses a block for its version.
func IsVersionError(err error) bool {
	var fe *FormatError
	return errors.As(err, &fe) && fe.Version
}

// unknownField reports whether a message carries field num among the
// fields it did not recognise. Go's protobuf keeps an out-of-range value of
// a closed enum there, where the reference's decoder keeps the raw number
// and refuses it later; looking here is how this tells the two cases apart.
func unknownField(m proto.Message, num protowire.Number) bool {
	b := m.ProtoReflect().GetUnknown()
	for len(b) > 0 {
		n, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			return false
		}
		if n == num {
			return true
		}
		b = b[l:]
		m := protowire.ConsumeFieldValue(n, typ, b)
		if m < 0 {
			return false
		}
		b = b[m:]
	}
	return false
}

// DecodeBlock reads a serialized block. It decodes as the reference's
// decoder does: a missing required field takes its default value, and an
// unknown field is ignored.
func DecodeBlock(data []byte) (*pb.Block, error) {
	var b pb.Block
	if err := (proto.UnmarshalOptions{AllowPartial: true, DiscardUnknown: false}).Unmarshal(data, &b); err != nil {
		return nil, formatErr("error deserializing block: %v", err)
	}
	return &b, nil
}

// FromProto converts a decoded block, applying the reference's checks in
// its order (proto_block_to_token_block): version range, facts, rules, the
// check kinds the version allows, third-party version, checks, scopes,
// public keys, symbols, and the features the version allows.
func FromProto(in *pb.Block, external bool) (Block, []string, []PublicKey, error) {
	var out Block
	version := in.GetVersion()
	if version < MinVersion || version > MaxVersion {
		return out, nil, nil, versionErr("datalog version %d is outside the supported range %d to %d (v3.0 to v3.3)", version, MinVersion, MaxVersion)
	}
	out.Version = version
	if in.Context != nil {
		out.Context, out.HasContext = in.GetContext(), true
	}
	for _, f := range in.GetFacts() {
		p, err := predFromProto(f.GetPredicate())
		if err != nil {
			return out, nil, nil, err
		}
		out.Facts = append(out.Facts, Fact{Predicate: p})
	}
	for _, r := range in.GetRules() {
		rule, err := ruleFromProto(r, version)
		if err != nil {
			return out, nil, nil, err
		}
		out.Rules = append(out.Rules, rule)
	}
	if version < MaxVersion {
		for _, c := range in.GetChecks() {
			present := c.Kind != nil || unknownField(c, 2)
			if version < Version31 && present {
				return out, nil, nil, versionErr("check kinds are only supported on datalog v3.1+ blocks")
			}
			if version < Version33 && c.Kind != nil && c.GetKind() == pb.Check_Reject {
				return out, nil, nil, versionErr("reject if is only supported in datalog v3.3+")
			}
		}
	}
	if version < Version32 && external {
		return out, nil, nil, versionErr("third-party blocks are only supported in datalog v3.2+")
	}
	for _, c := range in.GetChecks() {
		var kind CheckKind
		switch {
		case unknownField(c, 2):
			return out, nil, nil, formatErr("invalid check kind")
		case c.Kind == nil:
			kind = CheckOne
		default:
			kind = CheckKind(c.GetKind())
		}
		check := Check{Kind: kind}
		for _, q := range c.GetQueries() {
			rule, err := ruleFromProto(q, version)
			if err != nil {
				return out, nil, nil, err
			}
			check.Queries = append(check.Queries, rule)
		}
		out.Checks = append(out.Checks, check)
	}
	for _, s := range in.GetScope() {
		sc, err := scopeFromProto(s)
		if err != nil {
			return out, nil, nil, err
		}
		out.Scopes = append(out.Scopes, sc)
	}
	var keys []PublicKey
	for _, k := range in.GetPublicKeys() {
		pk := KeyFromProto(k)
		for _, have := range keys {
			if have.Equal(pk) {
				return out, nil, nil, formatErr("public key %s appears twice in the block's key table", pk)
			}
		}
		keys = append(keys, pk)
	}
	for _, s := range in.GetSymbols() {
		if _, ok := defaultIndex(s); ok {
			return out, nil, nil, fmt.Errorf("%w: %q is a default symbol", ErrSymbolOverlap, s)
		}
	}
	if err := checkCompatibility(out, version); err != nil {
		return out, nil, nil, err
	}
	return out, in.GetSymbols(), keys, nil
}

// KeyFromProto reads a public key as the reference's PublicKeyData does: an
// algorithm number it does not know reads as Ed25519, the default.
//
// A P-256 key sent as an uncompressed point is turned into the compressed
// form here. The reference parses keys and from then on uses to_bytes(),
// which is always compressed: in every signature payload, in the seal, and
// when it interns a third-party key for scopes. Using the bytes as sent
// would verify signatures the reference rejects and trust blocks it does
// not. A key that is not a valid point is kept as sent, for the key
// parser to refuse.
func KeyFromProto(k *pb.PublicKey) PublicKey {
	alg := Ed25519
	if k.GetAlgorithm() == pb.PublicKey_SECP256R1 {
		alg = Secp256r1
	}
	return Canonical(PublicKey{Alg: alg, Key: k.GetKey()})
}

// Canonical returns the encoding the reference signs and compares keys
// by: compressed SEC1 for P-256, the bytes as they are for Ed25519.
func Canonical(pk PublicKey) PublicKey {
	if pk.Alg != Secp256r1 || len(pk.Key) != 65 || pk.Key[0] != 4 {
		return pk
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pk.Key); err != nil {
		return pk
	}
	x := new(big.Int).SetBytes(pk.Key[1:33])
	y := new(big.Int).SetBytes(pk.Key[33:])
	return PublicKey{Alg: pk.Alg, Key: elliptic.MarshalCompressed(elliptic.P256(), x, y)}
}

func scopeFromProto(s *pb.Scope) (Scope, error) {
	switch c := s.GetContent().(type) {
	case *pb.Scope_ScopeType_:
		switch c.ScopeType {
		case pb.Scope_Authority:
			return Scope{Kind: ScopeAuthority}, nil
		case pb.Scope_Previous:
			return Scope{Kind: ScopePrevious}, nil
		}
		return Scope{}, formatErr("unexpected value %d for scope type", int32(c.ScopeType))
	case *pb.Scope_PublicKey:
		return Scope{Kind: ScopePublicKey, Key: uint64(c.PublicKey)}, nil
	}
	return Scope{}, formatErr("expected content field in Scope")
}

func ruleFromProto(r *pb.Rule, version uint32) (Rule, error) {
	var out Rule
	for _, p := range r.GetBody() {
		pr, err := predFromProto(p)
		if err != nil {
			return out, err
		}
		out.Body = append(out.Body, pr)
	}
	for _, e := range r.GetExpressions() {
		ops, err := opsFromProto(e.GetOps())
		if err != nil {
			return out, err
		}
		out.Expressions = append(out.Expressions, Expression{Ops: ops})
	}
	if version < Version31 && len(r.GetScope()) > 0 {
		return out, versionErr("scopes are only supported in datalog v3.1+")
	}
	for _, s := range r.GetScope() {
		sc, err := scopeFromProto(s)
		if err != nil {
			return out, err
		}
		out.Scopes = append(out.Scopes, sc)
	}
	head, err := predFromProto(r.GetHead())
	if err != nil {
		return out, err
	}
	out.Head = head
	return out, nil
}

func predFromProto(p *pb.Predicate) (Predicate, error) {
	out := Predicate{Name: p.GetName()}
	for _, t := range p.GetTerms() {
		term, err := termFromProto(t)
		if err != nil {
			return out, err
		}
		out.Terms = append(out.Terms, term)
	}
	return out, nil
}

func termFromProto(t *pb.Term) (Term, error) {
	switch c := t.GetContent().(type) {
	case *pb.Term_Variable:
		return Var(uint64(c.Variable)), nil
	case *pb.Term_Integer:
		return Int(c.Integer), nil
	case *pb.Term_String_:
		return Str(c.String_), nil
	case *pb.Term_Date:
		return Date(c.Date), nil
	case *pb.Term_Bytes:
		return Bytes(c.Bytes), nil
	case *pb.Term_Bool:
		return Bool(c.Bool), nil
	case *pb.Term_Set:
		var elems []Term
		kind := -1
		for _, e := range c.Set.GetSet() {
			var k int
			switch e.GetContent().(type) {
			case *pb.Term_Variable:
				return Term{}, formatErr("sets cannot contain variables")
			case *pb.Term_Set:
				return Term{}, formatErr("sets cannot contain other sets")
			case nil:
				return Term{}, formatErr("ID content enum is empty")
			case *pb.Term_Integer:
				k = 2
			case *pb.Term_String_:
				k = 3
			case *pb.Term_Date:
				k = 4
			case *pb.Term_Bytes:
				k = 5
			case *pb.Term_Bool:
				k = 6
			case *pb.Term_Null:
				k = 8
			case *pb.Term_Array:
				k = 9
			case *pb.Term_Map:
				k = 10
			}
			if kind >= 0 && kind != k {
				return Term{}, formatErr("sets elements must have the same type")
			}
			kind = k
			v, err := termFromProto(e)
			if err != nil {
				return Term{}, err
			}
			elems = append(elems, v)
		}
		return Set(elems), nil
	case *pb.Term_Null:
		return Null(), nil
	case *pb.Term_Array:
		var elems []Term
		for _, e := range c.Array.GetArray() {
			v, err := termFromProto(e)
			if err != nil {
				return Term{}, err
			}
			elems = append(elems, v)
		}
		return Array(elems), nil
	case *pb.Term_Map:
		var entries []MapEntry
		for _, e := range c.Map.GetEntries() {
			var key MapKey
			switch k := e.GetKey().GetContent().(type) {
			case *pb.MapKey_Integer:
				key = MapKey{I: k.Integer}
			case *pb.MapKey_String_:
				key = MapKey{IsString: true, U: k.String_}
			default:
				return Term{}, formatErr("ID content enum is empty")
			}
			v, err := termFromProto(e.GetValue())
			if err != nil {
				return Term{}, err
			}
			entries = append(entries, MapEntry{Key: key, Value: v})
		}
		return Map(entries), nil
	}
	return Term{}, formatErr("ID content enum is empty")
}

func opsFromProto(ops []*pb.Op) ([]Op, error) {
	var out []Op
	for _, op := range ops {
		switch c := op.GetContent().(type) {
		case *pb.Op_Value:
			v, err := termFromProto(c.Value)
			if err != nil {
				return nil, err
			}
			out = append(out, Op{Kind: OpValue, Value: v})
		case *pb.Op_Unary:
			if c.Unary.Kind == nil || unknownField(c.Unary, 1) {
				return nil, formatErr("unary operation is empty")
			}
			k := UnaryKind(c.Unary.GetKind())
			hasName := c.Unary.FfiName != nil
			switch {
			case k == UnaryFfi && !hasName:
				return nil, formatErr("missing ffi name")
			case k != UnaryFfi && hasName:
				return nil, formatErr("ffi name set on a regular unary operation")
			}
			out = append(out, Op{Kind: OpUnary, Unary: k, Ffi: c.Unary.GetFfiName()})
		case *pb.Op_Binary:
			if c.Binary.Kind == nil || unknownField(c.Binary, 1) {
				return nil, formatErr("binary operation is empty")
			}
			k := BinaryKind(c.Binary.GetKind())
			hasName := c.Binary.FfiName != nil
			switch {
			case k == BinaryFfi && !hasName:
				return nil, formatErr("missing ffi name")
			case k != BinaryFfi && hasName:
				return nil, formatErr("ffi name set on a regular binary operation")
			}
			out = append(out, Op{Kind: OpBinary, Binary: k, Ffi: c.Binary.GetFfiName()})
		case *pb.Op_Closure:
			body, err := opsFromProto(c.Closure.GetOps())
			if err != nil {
				return nil, err
			}
			params := make([]uint64, len(c.Closure.GetParams()))
			for i, p := range c.Closure.GetParams() {
				params[i] = uint64(p)
			}
			out = append(out, Op{Kind: OpClosure, Params: params, Ops: body})
		default:
			return nil, formatErr("operation is empty")
		}
	}
	return out, nil
}

// checkCompatibility refuses a block that uses a feature newer than its
// version, as the reference's SchemaVersion::check_compatibility does.
func checkCompatibility(b Block, version uint32) error {
	scopes := len(b.Scopes) > 0
	for _, r := range b.Rules {
		scopes = scopes || len(r.Scopes) > 0
	}
	checkAll, v33 := false, false
	for _, c := range b.Checks {
		for _, q := range c.Queries {
			scopes = scopes || len(q.Scopes) > 0
		}
		switch c.Kind {
		case CheckAll:
			checkAll = true
		case CheckReject:
			v33 = true
		}
	}
	v31 := false
	for _, r := range b.Rules {
		v31 = v31 || hasV31Op(r.Expressions)
	}
	for _, c := range b.Checks {
		for _, q := range c.Queries {
			v31 = v31 || hasV31Op(q.Expressions)
		}
	}
	if !v33 {
		for _, r := range b.Rules {
			if predV33(r.Head) || hasV33Op(r.Expressions) {
				v33 = true
			}
			for _, p := range r.Body {
				v33 = v33 || predV33(p)
			}
		}
		for _, c := range b.Checks {
			for _, q := range c.Queries {
				for _, p := range q.Body {
					v33 = v33 || predV33(p)
				}
				v33 = v33 || hasV33Op(q.Expressions)
			}
		}
	}
	if !v33 {
		for _, f := range b.Facts {
			v33 = v33 || predV33(f.Predicate)
		}
	}
	if version < Version31 {
		switch {
		case scopes:
			return versionErr("scopes are only supported in datalog v3.1+")
		case v31:
			return versionErr("bitwise operators and != are only supported in datalog v3.1+")
		case checkAll:
			return versionErr("check all is only supported in datalog v3.1+")
		}
		return nil
	}
	if version < Version33 && v33 {
		return versionErr("maps, arrays, null, closures are only supported in datalog v3.3+")
	}
	return nil
}

func hasV31Op(es []Expression) bool {
	for _, e := range es {
		for _, op := range e.Ops {
			if op.Kind == OpBinary {
				switch op.Binary {
				case BitwiseAnd, BitwiseOr, BitwiseXor, StrictNotEqual:
					return true
				}
			}
		}
	}
	return false
}

// hasV33Op looks only at the top level of each expression, not inside
// closures, as the reference does.
func hasV33Op(es []Expression) bool {
	for _, e := range es {
		for _, op := range e.Ops {
			switch op.Kind {
			case OpValue:
				if termV33(op.Value) {
					return true
				}
			case OpClosure:
				return true
			case OpUnary:
				if op.Unary == TypeOf || op.Unary == UnaryFfi {
					return true
				}
			case OpBinary:
				switch op.Binary {
				case HeterogeneousEqual, HeterogeneousNotEqual, LazyAnd, LazyOr, All, Any, BinaryFfi:
					return true
				}
			}
		}
	}
	return false
}

func predV33(p Predicate) bool {
	for _, t := range p.Terms {
		if termV33(t) {
			return true
		}
	}
	return false
}

// termV33 is the reference's contains_v3_3_term: null, or a set holding
// null. Arrays and maps are not looked for, exactly as there.
func termV33(t Term) bool {
	switch t.Kind {
	case KindNull:
		return true
	case KindSet:
		for _, e := range t.Elems {
			if e.Kind == KindNull {
				return true
			}
		}
	}
	return false
}

// ToProto encodes a block, for minting.
func ToProto(b Block, symbols []string, keys []PublicKey) *pb.Block {
	out := &pb.Block{Symbols: symbols, Version: proto.Uint32(b.Version)}
	if b.HasContext {
		out.Context = proto.String(b.Context)
	}
	for _, f := range b.Facts {
		out.Facts = append(out.Facts, &pb.Fact{Predicate: predToProto(f.Predicate)})
	}
	for _, r := range b.Rules {
		out.Rules = append(out.Rules, ruleToProto(r))
	}
	for _, c := range b.Checks {
		pc := &pb.Check{}
		if c.Kind != CheckOne {
			pc.Kind = pb.Check_Kind(c.Kind).Enum()
		}
		for _, q := range c.Queries {
			pc.Queries = append(pc.Queries, ruleToProto(q))
		}
		out.Checks = append(out.Checks, pc)
	}
	for _, s := range b.Scopes {
		out.Scope = append(out.Scope, scopeToProto(s))
	}
	for _, k := range keys {
		out.PublicKeys = append(out.PublicKeys, KeyToProto(k))
	}
	return out
}

// KeyToProto encodes a public key.
func KeyToProto(k PublicKey) *pb.PublicKey {
	return &pb.PublicKey{Algorithm: pb.PublicKey_Algorithm(k.Alg).Enum(), Key: k.Key}
}

func scopeToProto(s Scope) *pb.Scope {
	switch s.Kind {
	case ScopeAuthority:
		return &pb.Scope{Content: &pb.Scope_ScopeType_{ScopeType: pb.Scope_Authority}}
	case ScopePrevious:
		return &pb.Scope{Content: &pb.Scope_ScopeType_{ScopeType: pb.Scope_Previous}}
	}
	return &pb.Scope{Content: &pb.Scope_PublicKey{PublicKey: int64(s.Key)}}
}

func ruleToProto(r Rule) *pb.Rule {
	out := &pb.Rule{Head: predToProto(r.Head)}
	for _, p := range r.Body {
		out.Body = append(out.Body, predToProto(p))
	}
	for _, e := range r.Expressions {
		out.Expressions = append(out.Expressions, &pb.Expression{Ops: opsToProto(e.Ops)})
	}
	for _, s := range r.Scopes {
		out.Scope = append(out.Scope, scopeToProto(s))
	}
	return out
}

func predToProto(p Predicate) *pb.Predicate {
	out := &pb.Predicate{Name: proto.Uint64(p.Name)}
	for _, t := range p.Terms {
		out.Terms = append(out.Terms, termToProto(t))
	}
	return out
}

func termToProto(t Term) *pb.Term {
	switch t.Kind {
	case KindVariable:
		return &pb.Term{Content: &pb.Term_Variable{Variable: uint32(t.U)}}
	case KindInteger:
		return &pb.Term{Content: &pb.Term_Integer{Integer: t.I}}
	case KindString:
		return &pb.Term{Content: &pb.Term_String_{String_: t.U}}
	case KindDate:
		return &pb.Term{Content: &pb.Term_Date{Date: t.U}}
	case KindBytes:
		return &pb.Term{Content: &pb.Term_Bytes{Bytes: t.B}}
	case KindBool:
		return &pb.Term{Content: &pb.Term_Bool{Bool: t.Bool}}
	case KindSet:
		set := &pb.TermSet{}
		for _, e := range t.Elems {
			set.Set = append(set.Set, termToProto(e))
		}
		return &pb.Term{Content: &pb.Term_Set{Set: set}}
	case KindNull:
		return &pb.Term{Content: &pb.Term_Null{Null: &pb.Empty{}}}
	case KindArray:
		arr := &pb.Array{}
		for _, e := range t.Elems {
			arr.Array = append(arr.Array, termToProto(e))
		}
		return &pb.Term{Content: &pb.Term_Array{Array: arr}}
	}
	m := &pb.Map{}
	for _, e := range t.Map {
		key := &pb.MapKey{Content: &pb.MapKey_Integer{Integer: e.Key.I}}
		if e.Key.IsString {
			key = &pb.MapKey{Content: &pb.MapKey_String_{String_: e.Key.U}}
		}
		m.Entries = append(m.Entries, &pb.MapEntry{Key: key, Value: termToProto(e.Value)})
	}
	return &pb.Term{Content: &pb.Term_Map{Map: m}}
}

func opsToProto(ops []Op) []*pb.Op {
	var out []*pb.Op
	for _, op := range ops {
		switch op.Kind {
		case OpValue:
			out = append(out, &pb.Op{Content: &pb.Op_Value{Value: termToProto(op.Value)}})
		case OpUnary:
			u := &pb.OpUnary{Kind: pb.OpUnary_Kind(op.Unary).Enum()}
			if op.Unary == UnaryFfi {
				u.FfiName = proto.Uint64(op.Ffi)
			}
			out = append(out, &pb.Op{Content: &pb.Op_Unary{Unary: u}})
		case OpBinary:
			b := &pb.OpBinary{Kind: pb.OpBinary_Kind(op.Binary).Enum()}
			if op.Binary == BinaryFfi {
				b.FfiName = proto.Uint64(op.Ffi)
			}
			out = append(out, &pb.Op{Content: &pb.Op_Binary{Binary: b}})
		case OpClosure:
			params := make([]uint32, len(op.Params))
			for i, p := range op.Params {
				params[i] = uint32(p)
			}
			out = append(out, &pb.Op{Content: &pb.Op_Closure{Closure: &pb.OpClosure{Params: params, Ops: opsToProto(op.Ops)}}})
		}
	}
	return out
}
