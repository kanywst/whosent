package ucan

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// dagJSON writes a value as DAG-JSON: bytes as {"/":{"bytes":...}} and
// links as {"/":"bafy..."}. indent is "" for one line.
func dagJSON(v Value, indent string) string {
	var b strings.Builder
	writeJSON(&b, v, indent, "")
	return b.String()
}

func quote(s string) string {
	q, _ := json.Marshal(s)
	return string(q)
}

func writeJSON(b *strings.Builder, v Value, indent, prefix string) {
	nl := func(p string) {
		if indent != "" {
			b.WriteString("\n" + p)
		}
	}
	sep := ","
	if indent == "" {
		sep = ", "
	}
	switch v.Kind {
	case KindNull:
		b.WriteString("null")
	case KindBool:
		b.WriteString(strconv.FormatBool(v.Bool))
	case KindInt:
		if v.Big != nil {
			b.WriteString(v.Big.String())
		} else {
			b.WriteString(strconv.FormatInt(v.Int, 10))
		}
	case KindFloat:
		s := strconv.FormatFloat(v.Float, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		b.WriteString(s)
	case KindString:
		b.WriteString(quote(v.Str))
	case KindBytes:
		b.WriteString(`{"/": {"bytes": "` + base64.RawStdEncoding.EncodeToString(v.Bytes) + `"}}`)
	case KindLink:
		b.WriteString(`{"/": "` + cidBase32(v.Link) + `"}`)
	case KindList:
		if len(v.List) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[")
		for i, e := range v.List {
			if i > 0 {
				b.WriteString(sep)
			}
			nl(prefix + indent)
			writeJSON(b, e, indent, prefix+indent)
		}
		nl(prefix)
		b.WriteString("]")
	case KindMap:
		if len(v.Map) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{")
		for i, e := range v.Map {
			if i > 0 {
				b.WriteString(sep)
			}
			nl(prefix + indent)
			b.WriteString(quote(e.Key) + ": ")
			writeJSON(b, e.Value, indent, prefix+indent)
		}
		nl(prefix)
		b.WriteString("}")
	}
}

// String writes the statement as it appears in a pol.
func (s Statement) String() string { return dagJSON(s.Src, "") }
