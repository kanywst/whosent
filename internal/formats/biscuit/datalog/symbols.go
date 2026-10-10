package datalog

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// DefaultSymbols are the strings every symbol table starts with, at indices
// 0 to 27. Indices up to 1023 are reserved for them; a token's own strings
// start at 1024.
var DefaultSymbols = [...]string{
	"read", "write", "resource", "operation", "right", "time", "role", "owner",
	"tenant", "namespace", "user", "team", "service", "admin", "email", "group",
	"member", "ip_address", "client", "client_ip", "domain", "path", "version",
	"cluster", "node", "hostname", "nonce", "query",
}

// Offset is the index of the first symbol a token defines.
const Offset = 1024

// Algorithm is a public key's signature algorithm, numbered as in the
// protobuf schema.
type Algorithm int32

// The algorithms.
const (
	Ed25519   Algorithm = 0
	Secp256r1 Algorithm = 1
)

func (a Algorithm) String() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case Secp256r1:
		return "secp256r1"
	}
	return fmt.Sprintf("algorithm(%d)", int32(a))
}

// PublicKey is a key as Datalog names it in a scope annotation.
type PublicKey struct {
	Alg Algorithm
	Key []byte
}

// String is the key as Datalog prints it: "ed25519/" and lower-case hex.
func (k PublicKey) String() string { return k.Alg.String() + "/" + hex.EncodeToString(k.Key) }

// Equal reports whether two keys are the same key.
func (k PublicKey) Equal(o PublicKey) bool {
	return k.Alg == o.Alg && string(k.Key) == string(o.Key)
}

// ErrSymbolOverlap is returned when a block defines a symbol that is
// already in the table it extends. The reference implementation refuses
// such a token, because two indices for one string would make two equal
// strings compare unequal.
var ErrSymbolOverlap = errors.New("a block defines a symbol the token already has")

// SymbolTable maps indices to strings and to public keys.
type SymbolTable struct {
	symbols []string
	index   map[string]uint64
	keys    []PublicKey
}

// NewSymbolTable returns a table holding only the default symbols.
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{index: map[string]uint64{}}
}

// Clone returns an independent copy.
func (t *SymbolTable) Clone() *SymbolTable {
	c := &SymbolTable{
		symbols: append([]string(nil), t.symbols...),
		index:   make(map[string]uint64, len(t.index)),
		keys:    append([]PublicKey(nil), t.keys...),
	}
	for k, v := range t.index {
		c.index[k] = v
	}
	return c
}

func defaultIndex(s string) (uint64, bool) {
	for i, d := range DefaultSymbols {
		if d == s {
			return uint64(i), true
		}
	}
	return 0, false
}

// Extend appends a block's symbols, refusing any the table already has or
// that is a default symbol.
func (t *SymbolTable) Extend(symbols []string) error {
	for _, s := range symbols {
		if _, ok := defaultIndex(s); ok {
			return fmt.Errorf("%w: %q is a default symbol", ErrSymbolOverlap, s)
		}
		if _, ok := t.index[s]; ok {
			return fmt.Errorf("%w: %q", ErrSymbolOverlap, s)
		}
	}
	// A string listed twice within one block is not refused: the reference
	// implementation compares a block's symbols only against the table it
	// extends. The first occurrence is the one lookups find, as there.
	for _, s := range symbols {
		if _, ok := t.index[s]; !ok {
			t.index[s] = uint64(Offset + len(t.symbols))
		}
		t.symbols = append(t.symbols, s)
	}
	return nil
}

// ExtendKeys appends a block's public keys, refusing a duplicate.
func (t *SymbolTable) ExtendKeys(keys []PublicKey) error {
	for _, k := range keys {
		for _, have := range t.keys {
			if have.Equal(k) {
				return fmt.Errorf("public key %s appears twice in the key table", k)
			}
		}
		t.keys = append(t.keys, k)
	}
	return nil
}

// Insert returns the index of s, adding it when it is new.
func (t *SymbolTable) Insert(s string) uint64 {
	if i, ok := defaultIndex(s); ok {
		return i
	}
	if i, ok := t.index[s]; ok {
		return i
	}
	i := uint64(Offset + len(t.symbols))
	t.symbols = append(t.symbols, s)
	t.index[s] = i
	return i
}

// InsertKey returns the index of k in the key table, adding it when new.
func (t *SymbolTable) InsertKey(k PublicKey) uint64 {
	for i, have := range t.keys {
		if have.Equal(k) {
			return uint64(i)
		}
	}
	t.keys = append(t.keys, k)
	return uint64(len(t.keys) - 1)
}

// Symbol returns the string at index i.
func (t *SymbolTable) Symbol(i uint64) (string, bool) {
	if i < Offset {
		if i < uint64(len(DefaultSymbols)) {
			return DefaultSymbols[i], true
		}
		return "", false
	}
	j := i - Offset
	if j < uint64(len(t.symbols)) {
		return t.symbols[j], true
	}
	return "", false
}

// Key returns the public key at index i.
func (t *SymbolTable) Key(i uint64) (PublicKey, bool) {
	if i < uint64(len(t.keys)) {
		return t.keys[i], true
	}
	return PublicKey{}, false
}

// Len is the number of symbols the table defines beyond the defaults.
func (t *SymbolTable) Len() int { return len(t.symbols) }

// Strings are the symbols the table defines beyond the defaults.
func (t *SymbolTable) Strings() []string { return append([]string(nil), t.symbols...) }

// Keys is the public key table.
func (t *SymbolTable) Keys() []PublicKey { return append([]PublicKey(nil), t.keys...) }

// temp is a symbol table an expression may add strings to while it runs,
// such as the result of concatenating two strings, without changing the
// table it reads from. It mirrors the reference implementation's
// TemporarySymbolTable: a string the base already has keeps its index.
type temp struct {
	base   *SymbolTable
	offset uint64
	extra  []string
}

func newTemp(base *SymbolTable) *temp {
	return &temp{base: base, offset: uint64(Offset + base.Len())}
}

func (t *temp) symbol(i uint64) (string, bool) {
	if i >= t.offset {
		j := i - t.offset
		if j < uint64(len(t.extra)) {
			return t.extra[j], true
		}
		return "", false
	}
	return t.base.Symbol(i)
}

func (t *temp) insert(s string) uint64 {
	if i, ok := defaultIndex(s); ok {
		return i
	}
	if i, ok := t.base.index[s]; ok {
		return i
	}
	for j, e := range t.extra {
		if e == s {
			return t.offset + uint64(j)
		}
	}
	t.extra = append(t.extra, s)
	return t.offset + uint64(len(t.extra)-1)
}
