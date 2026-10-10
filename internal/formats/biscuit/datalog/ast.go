package datalog

// Predicate is a name and its terms.
type Predicate struct {
	Name uint64
	// NameS is the name before conversion to a symbol table.
	NameS string
	Terms []Term
}

// Fact is a predicate without variables.
type Fact struct {
	Predicate Predicate
}

// ScopeKind is what a scope annotation trusts.
type ScopeKind int

// The scope kinds.
const (
	ScopeAuthority ScopeKind = iota
	ScopePrevious
	ScopePublicKey
)

// Scope is one origin a rule or block trusts.
type Scope struct {
	Kind ScopeKind
	// Key indexes the public key table, for ScopePublicKey.
	Key uint64
	// KeyValue is the key itself, before conversion.
	KeyValue PublicKey
	named    bool
}

// Rule derives its head from its body. A check's queries are rules whose
// head is never used.
type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	Scopes      []Scope
}

// CheckKind is how a check reads its queries.
type CheckKind int

// The check kinds, numbered as in the protobuf schema.
const (
	CheckOne CheckKind = iota
	CheckAll
	CheckReject
)

// Check is a list of queries, any one of which satisfies it ("reject if":
// any one of which fails it).
type Check struct {
	Queries []Rule
	Kind    CheckKind
}

// PolicyKind is what a matching policy decides.
type PolicyKind int

// The policy kinds.
const (
	Allow PolicyKind = iota
	Deny
)

// Policy is an authorizer's allow or deny rule.
type Policy struct {
	Queries []Rule
	Kind    PolicyKind
}

// UnaryKind is a one-operand operation, numbered as in the schema.
type UnaryKind int

// The unary operations.
const (
	Negate UnaryKind = iota
	Parens
	Length
	TypeOf
	UnaryFfi
)

// BinaryKind is a two-operand operation, numbered as in the schema.
type BinaryKind int

// The binary operations.
const (
	LessThan BinaryKind = iota
	GreaterThan
	LessOrEqual
	GreaterOrEqual
	StrictEqual
	Contains
	Prefix
	Suffix
	Regex
	Add
	Sub
	Mul
	Div
	And
	Or
	Intersection
	Union
	BitwiseAnd
	BitwiseOr
	BitwiseXor
	StrictNotEqual
	HeterogeneousEqual
	HeterogeneousNotEqual
	LazyAnd
	LazyOr
	All
	Any
	Get
	BinaryFfi
	TryOr
)

// OpKind is what an opcode does.
type OpKind int

// The opcode kinds.
const (
	OpValue OpKind = iota
	OpUnary
	OpBinary
	OpClosure
)

// Op is one opcode of the expression machine.
type Op struct {
	Kind   OpKind
	Value  Term
	Unary  UnaryKind
	Binary BinaryKind
	// Ffi names the external function, for UnaryFfi and BinaryFfi.
	Ffi   uint64
	FfiS  string
	named bool
	// Params and Ops are a closure's parameters and body.
	Params  []uint64
	ParamsS []string
	Ops     []Op
}

// Expression is a list of opcodes.
type Expression struct {
	Ops []Op
}

// Block is one block's Datalog.
type Block struct {
	Facts   []Fact
	Rules   []Rule
	Checks  []Check
	Scopes  []Scope
	Version uint32
	Context string
	// HasContext tells an empty context apart from none.
	HasContext bool
}

// UsesFfi reports whether any expression calls an external function, which
// only the authorizer that defines it can evaluate.
func (b Block) UsesFfi() bool {
	for _, r := range b.Rules {
		if ruleUsesFfi(r) {
			return true
		}
	}
	for _, c := range b.Checks {
		for _, q := range c.Queries {
			if ruleUsesFfi(q) {
				return true
			}
		}
	}
	return false
}

func ruleUsesFfi(r Rule) bool {
	for _, e := range r.Expressions {
		if opsUseFfi(e.Ops) {
			return true
		}
	}
	return false
}

func opsUseFfi(ops []Op) bool {
	for _, op := range ops {
		switch {
		case op.Kind == OpUnary && op.Unary == UnaryFfi,
			op.Kind == OpBinary && op.Binary == BinaryFfi:
			return true
		case op.Kind == OpClosure && opsUseFfi(op.Ops):
			return true
		}
	}
	return false
}
