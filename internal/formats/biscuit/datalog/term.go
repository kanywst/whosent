// Package datalog is Biscuit's logic language: its terms, its printer, its
// expression machine, its fact engine and its parser.
//
// It follows the reference implementation, eclipse-biscuit/biscuit-rust,
// rather than the specification's prose wherever the two differ, because a
// token is only ever accepted or refused by an implementation. Each place
// where that choice was made says so. The engine is checked against the
// specification's sample tokens, whose expected results the reference
// implementation produced.
package datalog

import (
	"bytes"
	"slices"
)

// Kind is a term's type. The order is the reference implementation's enum
// order, which is what its derived ordering of terms compares first; sets
// and maps are ordered by it, and printing follows that order.
type Kind uint8

// The kinds, in the reference order.
const (
	KindVariable Kind = iota
	KindInteger
	KindString
	KindDate
	KindBytes
	KindBool
	KindSet
	KindNull
	KindArray
	KindMap
)

// Term is one value. Which fields mean something depends on Kind:
//
//   - Variable: U is the variable name's symbol index (S its name before
//     conversion).
//   - Integer: I.
//   - String: U is the symbol index (S the string before conversion).
//   - Date: U is seconds since the Unix epoch.
//   - Bytes: B.
//   - Bool: Bool.
//   - Set: Elems, sorted and without duplicates.
//   - Array: Elems, in order.
//   - Map: Map, sorted by key.
//
// Strings are symbol indices, as in the reference implementation, because
// the order of a set of strings is the order of their indices, not of the
// strings: printing a set any other way would print a different token.
type Term struct {
	Kind  Kind
	I     int64
	U     uint64
	B     []byte
	Bool  bool
	Elems []Term
	Map   []MapEntry
	// S is a string or a variable name in a term that has not been
	// converted to a symbol table yet, such as one just parsed.
	S string
	// named marks a term built from source text, whose S holds the string
	// or variable name.
	named bool
}

// MapKey is a map key: an integer or a string.
type MapKey struct {
	IsString bool
	I        int64
	U        uint64
	S        string
	named    bool
}

// MapEntry is one key and its value.
type MapEntry struct {
	Key   MapKey
	Value Term
}

// Int is an integer term.
func Int(i int64) Term { return Term{Kind: KindInteger, I: i} }

// Str is a string term from a symbol index.
func Str(sym uint64) Term { return Term{Kind: KindString, U: sym} }

// Date is a date term.
func Date(secs uint64) Term { return Term{Kind: KindDate, U: secs} }

// Bytes is a byte array term.
func Bytes(b []byte) Term { return Term{Kind: KindBytes, B: b} }

// Bool is a boolean term.
func Bool(b bool) Term { return Term{Kind: KindBool, Bool: b} }

// Null is the null term.
func Null() Term { return Term{Kind: KindNull} }

// Var is a variable term from the symbol index of its name.
func Var(sym uint64) Term { return Term{Kind: KindVariable, U: sym} }

// Set builds a set: sorted, duplicates removed.
func Set(elems []Term) Term {
	return Term{Kind: KindSet, Elems: canonical(elems)}
}

// Array builds an array.
func Array(elems []Term) Term { return Term{Kind: KindArray, Elems: elems} }

// Map builds a map: sorted by key, a later duplicate key replacing an
// earlier one, as inserting into the reference implementation's ordered
// map does.
func Map(entries []MapEntry) Term {
	sorted := append([]MapEntry(nil), entries...)
	sortEntries(sorted)
	out := sorted[:0]
	for _, e := range sorted {
		if n := len(out); n > 0 && compareKeys(out[n-1].Key, e.Key) == 0 {
			// The sort is stable, so the later of two equal keys comes
			// second and wins, as a later insert does.
			out[n-1] = e
			continue
		}
		out = append(out, e)
	}
	return Term{Kind: KindMap, Map: out}
}

func canonical(elems []Term) []Term {
	out := append([]Term(nil), elems...)
	sortTerms(out)
	uniq := out[:0]
	for i, t := range out {
		if i == 0 || Compare(t, uniq[len(uniq)-1]) != 0 {
			uniq = append(uniq, t)
		}
	}
	return uniq
}

// Compare orders terms as the reference implementation's derived ordering
// does: by kind first, then by value. Two terms are equal exactly when it
// returns 0.
func Compare(a, b Term) int {
	if a.Kind != b.Kind {
		if a.Kind < b.Kind {
			return -1
		}
		return 1
	}
	switch a.Kind {
	case KindInteger:
		return cmpInt(a.I, b.I)
	case KindVariable, KindString, KindDate:
		return cmpUint(a.U, b.U)
	case KindBytes:
		return bytes.Compare(a.B, b.B)
	case KindBool:
		switch {
		case a.Bool == b.Bool:
			return 0
		case !a.Bool:
			return -1
		}
		return 1
	case KindNull:
		return 0
	case KindSet, KindArray:
		for i := 0; i < len(a.Elems) && i < len(b.Elems); i++ {
			if c := Compare(a.Elems[i], b.Elems[i]); c != 0 {
				return c
			}
		}
		return cmpInt(int64(len(a.Elems)), int64(len(b.Elems)))
	case KindMap:
		for i := 0; i < len(a.Map) && i < len(b.Map); i++ {
			if c := compareKeys(a.Map[i].Key, b.Map[i].Key); c != 0 {
				return c
			}
			if c := Compare(a.Map[i].Value, b.Map[i].Value); c != 0 {
				return c
			}
		}
		return cmpInt(int64(len(a.Map)), int64(len(b.Map)))
	}
	return 0
}

// Equal reports whether two terms are the same value.
func Equal(a, b Term) bool { return Compare(a, b) == 0 }

func compareKeys(a, b MapKey) int {
	if a.IsString != b.IsString {
		// Integer keys come first: the reference enum lists them first.
		if !a.IsString {
			return -1
		}
		return 1
	}
	if a.IsString {
		return cmpUint(a.U, b.U)
	}
	return cmpInt(a.I, b.I)
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func sortTerms(ts []Term) { slices.SortStableFunc(ts, Compare) }

func sortEntries(es []MapEntry) {
	slices.SortStableFunc(es, func(a, b MapEntry) int { return compareKeys(a.Key, b.Key) })
}

// contains reports whether a sorted set holds t.
func contains(set []Term, t Term) bool {
	for _, e := range set {
		if Equal(e, t) {
			return true
		}
	}
	return false
}
