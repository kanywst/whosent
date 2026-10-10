package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kanywst/whosent/internal/termsafe"
)

// printer returns the one way human output reaches a terminal: the format
// string is this program's own, and every argument is passed through
// termsafe before it is formatted.
//
// Sanitizing here rather than at each call site is the point. Nearly every
// string in a report is the chain's own (subjects, jtis, resource ids, and
// library error text quoting them), and a call site that forgot would hand
// the terminal to whoever wrote the chain. With one choke point there is
// nothing to forget.
func printer(w io.Writer) func(format string, a ...any) {
	return func(format string, a ...any) {
		_, _ = fmt.Fprintf(w, format, safeArgs(a)...)
	}
}

func safeArgs(a []any) []any {
	out := make([]any, len(a))
	for i, v := range a {
		out[i] = safe(v)
	}
	return out
}

// safe neutralizes one argument. Numbers and booleans cannot carry a control
// character and pass through, so their verbs (%d, %5.1f) keep working.
func safe(v any) any {
	switch x := v.(type) {
	case string:
		return termsafe.Text(x)
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = termsafe.Text(s)
		}
		return out
	case error:
		return termsafe.Text(x.Error())
	case fmt.Stringer:
		return termsafe.Text(x.String())
	case []byte:
		return termsafe.Text(string(x))
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	}
	// Anything else would be formatted by reflection, which prints string
	// fields raw. Format it first and sanitize the result.
	return termsafe.Text(fmt.Sprint(v))
}

// writeJSON is the one way machine output is written. encoding/json escapes
// the C0 controls but leaves bidi and C1 characters raw, and --json output
// is read on terminals too; termsafe.JSON escapes those as well, without
// changing what the document means.
func writeJSON(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(termsafe.JSON(buf.Bytes()))
	return err
}
