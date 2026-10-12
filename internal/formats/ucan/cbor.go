package ucan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"unicode/utf8"
)

// Kind is the IPLD data model kind of a Value.
type Kind int

// The kinds DAG-CBOR can carry.
const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindFloat
	KindString
	KindBytes
	KindList
	KindMap
	KindLink
)

func (k Kind) String() string {
	return [...]string{"null", "bool", "integer", "float", "string", "bytes", "list", "map", "link"}[k]
}

// Value is one decoded DAG-CBOR item.
//
// An integer that fits an int64 is held in Int. DAG-CBOR allows the whole
// 64-bit range of both signs, so a larger magnitude is held in Big instead:
// policies compare such values exactly rather than through a float.
type Value struct {
	Kind  Kind
	Bool  bool
	Int   int64
	Big   *big.Int
	Float float64
	Str   string
	Bytes []byte
	List  []Value
	Map   []Entry
	// Link is a CID, without the multibase identity prefix DAG-CBOR wraps
	// it in.
	Link []byte
}

// Entry is one map entry. Maps keep the order they were encoded in, which
// canonical DAG-CBOR fixes, so two equal maps list their entries alike.
type Entry struct {
	Key   string
	Value Value
}

// Get returns a map's value for key.
func (v Value) Get(key string) (Value, bool) {
	for _, e := range v.Map {
		if e.Key == key {
			return e.Value, true
		}
	}
	return Value{}, false
}

// Limits on what a decode may build, so a few hostile bytes cannot ask for
// gigabytes or recurse without end. Real tokens are a few hundred bytes and
// a handful of levels deep.
const (
	maxDepth = 64
	maxItems = 1 << 16
)

// errNotCanonical marks input that is valid CBOR but not canonical
// DAG-CBOR. A UCAN is signed over its canonical encoding, so bytes that are
// not canonical are not the bytes that were signed.
var errNotCanonical = errors.New("not canonical DAG-CBOR")

type decoder struct {
	b     []byte
	items int
}

// decodeCBOR decodes exactly one canonical DAG-CBOR item that fills b.
func decodeCBOR(b []byte) (Value, error) {
	d := &decoder{b: b}
	v, end, err := d.item(0, 0)
	if err != nil {
		return Value{}, err
	}
	if end != len(b) {
		return Value{}, fmt.Errorf("%d bytes after the item", len(b)-end)
	}
	return v, nil
}

// head reads an item's initial byte and argument, refusing an argument
// that is not in its shortest form.
func (d *decoder) head(off int) (major byte, arg uint64, info byte, next int, err error) {
	if off >= len(d.b) {
		return 0, 0, 0, 0, errors.New("unexpected end of input")
	}
	ib := d.b[off]
	major, info = ib>>5, ib&0x1f
	off++
	switch {
	case info < 24:
		return major, uint64(info), info, off, nil
	case info == 24:
		if off+1 > len(d.b) {
			return 0, 0, 0, 0, errors.New("unexpected end of input")
		}
		arg = uint64(d.b[off])
		if arg < 24 && major != 7 {
			return 0, 0, 0, 0, fmt.Errorf("%w: a one-byte argument under 24", errNotCanonical)
		}
		return major, arg, info, off + 1, nil
	case info == 25:
		if off+2 > len(d.b) {
			return 0, 0, 0, 0, errors.New("unexpected end of input")
		}
		arg = uint64(binary.BigEndian.Uint16(d.b[off:]))
		if arg <= math.MaxUint8 && major != 7 {
			return 0, 0, 0, 0, fmt.Errorf("%w: a two-byte argument that fits one", errNotCanonical)
		}
		return major, arg, info, off + 2, nil
	case info == 26:
		if off+4 > len(d.b) {
			return 0, 0, 0, 0, errors.New("unexpected end of input")
		}
		arg = uint64(binary.BigEndian.Uint32(d.b[off:]))
		if arg <= math.MaxUint16 && major != 7 {
			return 0, 0, 0, 0, fmt.Errorf("%w: a four-byte argument that fits two", errNotCanonical)
		}
		return major, arg, info, off + 4, nil
	case info == 27:
		if off+8 > len(d.b) {
			return 0, 0, 0, 0, errors.New("unexpected end of input")
		}
		arg = binary.BigEndian.Uint64(d.b[off:])
		if arg <= math.MaxUint32 && major != 7 {
			return 0, 0, 0, 0, fmt.Errorf("%w: an eight-byte argument that fits four", errNotCanonical)
		}
		return major, arg, info, off + 8, nil
	case info == 31:
		return 0, 0, 0, 0, fmt.Errorf("%w: indefinite length", errNotCanonical)
	}
	return 0, 0, 0, 0, fmt.Errorf("reserved additional information %d", info)
}

func (d *decoder) count(n uint64, off int) error {
	// Every item takes at least one byte, so a count beyond what is left
	// cannot be honest; checking it first keeps allocation bounded by the
	// input.
	if n > uint64(len(d.b)-off) {
		return fmt.Errorf("a length of %d with %d bytes left", n, len(d.b)-off)
	}
	d.items += int(n)
	if d.items > maxItems {
		return errors.New("too many items")
	}
	return nil
}

func (d *decoder) item(off, depth int) (Value, int, error) {
	if depth > maxDepth {
		return Value{}, 0, errors.New("nested too deeply")
	}
	major, arg, info, off, err := d.head(off)
	if err != nil {
		return Value{}, 0, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return Value{Kind: KindInt, Big: new(big.Int).SetUint64(arg)}, off, nil
		}
		return Value{Kind: KindInt, Int: int64(arg)}, off, nil
	case 1:
		// The value is -1 - arg.
		if arg > math.MaxInt64 {
			b := new(big.Int).SetUint64(arg)
			return Value{Kind: KindInt, Big: b.Neg(b).Sub(b, big.NewInt(1))}, off, nil
		}
		return Value{Kind: KindInt, Int: -1 - int64(arg)}, off, nil
	case 2, 3:
		if arg > uint64(len(d.b)-off) {
			return Value{}, 0, errors.New("a string longer than the input")
		}
		end := off + int(arg)
		if major == 2 {
			return Value{Kind: KindBytes, Bytes: append([]byte(nil), d.b[off:end]...)}, end, nil
		}
		s := d.b[off:end]
		if !utf8.Valid(s) {
			return Value{}, 0, errors.New("a text string that is not UTF-8")
		}
		return Value{Kind: KindString, Str: string(s)}, end, nil
	case 4:
		if err := d.count(arg, off); err != nil {
			return Value{}, 0, err
		}
		list := make([]Value, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			var v Value
			v, off, err = d.item(off, depth+1)
			if err != nil {
				return Value{}, 0, err
			}
			list = append(list, v)
		}
		return Value{Kind: KindList, List: list}, off, nil
	case 5:
		if err := d.count(arg*2, off); err != nil {
			return Value{}, 0, err
		}
		m := make([]Entry, 0, int(arg))
		var prev []byte
		for i := uint64(0); i < arg; i++ {
			kstart := off
			var k Value
			k, off, err = d.item(off, depth+1)
			if err != nil {
				return Value{}, 0, err
			}
			if k.Kind != KindString {
				return Value{}, 0, errors.New("a map key that is not a string")
			}
			key := d.b[kstart:off]
			if prev != nil {
				// DAG-CBOR orders keys by the length of their encoding,
				// then bytewise; equal keys are duplicates.
				if c := keyOrder(prev, key); c == 0 {
					return Value{}, 0, fmt.Errorf("duplicate map key %q", k.Str)
				} else if c > 0 {
					return Value{}, 0, fmt.Errorf("%w: map keys out of order at %q", errNotCanonical, k.Str)
				}
			}
			prev = key
			var v Value
			v, off, err = d.item(off, depth+1)
			if err != nil {
				return Value{}, 0, err
			}
			m = append(m, Entry{Key: k.Str, Value: v})
		}
		return Value{Kind: KindMap, Map: m}, off, nil
	case 6:
		if arg != 42 {
			return Value{}, 0, fmt.Errorf("tag %d; DAG-CBOR allows only tag 42", arg)
		}
		var v Value
		v, off, err = d.item(off, depth+1)
		if err != nil {
			return Value{}, 0, err
		}
		if v.Kind != KindBytes || len(v.Bytes) < 2 || v.Bytes[0] != 0 {
			return Value{}, 0, errors.New("a CID link that is not identity-prefixed bytes")
		}
		return Value{Kind: KindLink, Link: v.Bytes[1:]}, off, nil
	case 7:
		switch info {
		case 20:
			return Value{Kind: KindBool, Bool: false}, off, nil
		case 21:
			return Value{Kind: KindBool, Bool: true}, off, nil
		case 22:
			return Value{Kind: KindNull}, off, nil
		case 27:
			f := math.Float64frombits(arg)
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return Value{}, 0, errors.New("a float that is NaN or infinite")
			}
			return Value{Kind: KindFloat, Float: f}, off, nil
		case 25, 26:
			return Value{}, 0, fmt.Errorf("%w: a float narrower than 64 bits", errNotCanonical)
		}
		return Value{}, 0, fmt.Errorf("simple value %d", arg)
	}
	return Value{}, 0, fmt.Errorf("major type %d", major)
}

// keyOrder compares two encoded keys the way DAG-CBOR sorts them.
func keyOrder(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}

// span returns where the item starting at off ends, without building it.
// The envelope uses it to find the exact bytes that were signed.
func (d *decoder) span(off int) (int, error) {
	_, end, err := d.item(off, 0)
	return end, err
}

// encodeCBOR writes v as canonical DAG-CBOR. Demos mint with it; reading
// never re-encodes, because the bytes that were signed are the ones that
// arrived.
func encodeCBOR(v Value) []byte {
	var buf bytes.Buffer
	encodeItem(&buf, v)
	return buf.Bytes()
}

func writeHead(buf *bytes.Buffer, major byte, arg uint64) {
	switch {
	case arg < 24:
		buf.WriteByte(major<<5 | byte(arg))
	case arg <= math.MaxUint8:
		buf.WriteByte(major<<5 | 24)
		buf.WriteByte(byte(arg))
	case arg <= math.MaxUint16:
		buf.WriteByte(major<<5 | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(arg))
	case arg <= math.MaxUint32:
		buf.WriteByte(major<<5 | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(arg))
	default:
		buf.WriteByte(major<<5 | 27)
		_ = binary.Write(buf, binary.BigEndian, arg)
	}
}

func encodeItem(buf *bytes.Buffer, v Value) {
	switch v.Kind {
	case KindNull:
		buf.WriteByte(0xf6)
	case KindBool:
		if v.Bool {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case KindInt:
		if v.Big != nil {
			if v.Big.Sign() >= 0 {
				writeHead(buf, 0, v.Big.Uint64())
			} else {
				n := new(big.Int).Neg(v.Big)
				writeHead(buf, 1, n.Sub(n, big.NewInt(1)).Uint64())
			}
			return
		}
		if v.Int >= 0 {
			writeHead(buf, 0, uint64(v.Int))
		} else {
			writeHead(buf, 1, uint64(-1-v.Int))
		}
	case KindFloat:
		buf.WriteByte(0xfb)
		_ = binary.Write(buf, binary.BigEndian, math.Float64bits(v.Float))
	case KindString:
		writeHead(buf, 3, uint64(len(v.Str)))
		buf.WriteString(v.Str)
	case KindBytes:
		writeHead(buf, 2, uint64(len(v.Bytes)))
		buf.Write(v.Bytes)
	case KindList:
		writeHead(buf, 4, uint64(len(v.List)))
		for _, e := range v.List {
			encodeItem(buf, e)
		}
	case KindMap:
		entries := append([]Entry(nil), v.Map...)
		sort.Slice(entries, func(i, j int) bool {
			a, b := entries[i].Key, entries[j].Key
			if len(a) != len(b) {
				return len(a) < len(b)
			}
			return a < b
		})
		writeHead(buf, 5, uint64(len(entries)))
		for _, e := range entries {
			writeHead(buf, 3, uint64(len(e.Key)))
			buf.WriteString(e.Key)
			encodeItem(buf, e.Value)
		}
	case KindLink:
		buf.Write([]byte{0xd8, 42})
		writeHead(buf, 2, uint64(len(v.Link)+1))
		buf.WriteByte(0)
		buf.Write(v.Link)
	}
}

// Constructors the demos and tests build payloads with.

func vStr(s string) Value           { return Value{Kind: KindString, Str: s} }
func vInt(i int64) Value            { return Value{Kind: KindInt, Int: i} }
func vBytes(b []byte) Value         { return Value{Kind: KindBytes, Bytes: b} }
func vList(vs ...Value) Value       { return Value{Kind: KindList, List: append([]Value{}, vs...)} }
func vLink(c []byte) Value          { return Value{Kind: KindLink, Link: c} }
func vNull() Value                  { return Value{Kind: KindNull} }
func vMap(es ...Entry) Value        { return Value{Kind: KindMap, Map: append([]Entry{}, es...)} }
func entry(k string, v Value) Entry { return Entry{Key: k, Value: v} }
