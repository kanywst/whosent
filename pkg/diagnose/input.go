package diagnose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// ChainMetaKey is the `_meta` key a tools/call request carries its chain
// under (specification section 8.1). It is copied rather than imported from
// mandatum's pkg/mcp, which would pull a CEL evaluator into a tool that never
// evaluates CEL; a test asserts the two stay equal.
const ChainMetaKey = "io.github.kanywst.mandatum/chain"

// MaxLinks is the longest chain whosent reads.
//
// The specification sets no length, but a valid chain cannot be longer than
// its sponsor's max_depth plus one, and that budget falls by at least one at
// every hop. Real delegation runs to a handful of hops; sixty-four is past
// any operational need rather than a tuned figure. The bound is there for
// the input that is not a real chain: diagnosis compares every hop's
// capabilities pairwise, and a file of thousands of links each adding a
// capability turns that into minutes of CPU for whoever runs whosent on it,
// in CI or anywhere else an untrusted chain is checked.
const MaxLinks = 64

// MaxCapabilities is the most capabilities one link may grant, and
// MaxSetValues the most values its set conditions may list in total, for
// whosent to read it.
//
// Both bound the same thing MaxLinks does: diagnosis compares capabilities
// pairwise at every hop, several times over (the hop diff, the matrix, the
// lineage notes), and a set condition is compared value against value. A
// chain at these limits diagnoses in well under a second; a megabyte of
// capabilities or of set values, which fits in a request mandatum's
// enforcement point will read, costs tens of seconds. Real grants name a
// handful of tools and a handful of values, so the limits are far past any
// operational need rather than tuned.
const (
	MaxCapabilities = 64
	MaxSetValues    = 1024
)

// checkSize refuses a chain past the limits above. A link that does not
// parse is let through: it costs nothing to diagnose, and it is a finding.
func checkSize(links [][]byte) error {
	if len(links) > MaxLinks {
		return fmt.Errorf("the chain has %d links; whosent reads at most %d, and a real chain is a handful", len(links), MaxLinks)
	}
	for i, raw := range links {
		c, err := mda.ParseClaims(raw)
		if err != nil {
			continue
		}
		caps := c.Mandatum.Capabilities
		if len(caps) > MaxCapabilities {
			return fmt.Errorf("link %d grants %d capabilities; whosent reads at most %d per link", i, len(caps), MaxCapabilities)
		}
		values := 0
		for _, cp := range caps {
			for _, cond := range cp.Conditions {
				values += len(cond.In)
			}
		}
		if values > MaxSetValues {
			return fmt.Errorf("link %d lists %d values in its set conditions; whosent reads at most %d per link", i, values, MaxSetValues)
		}
	}
	return nil
}

// Input is a chain read from a file or stdin, before diagnosis.
type Input struct {
	Links [][]byte
	Info  InputInfo
}

// ReadInput reads a chain in any of the forms it is found in, detected from
// the first non-blank byte:
//
//   - a JSON array of compact serializations, sponsor first: the wire form;
//   - a JSON object: a whole JSON-RPC tools/call request, its params, a bare
//     `_meta`, or {"chain": [...]};
//   - one compact serialization per line, with blank lines and lines
//     starting with # ignored.
//
// Bytes inside a serialization are never changed, because the parent
// commitment is a digest over exactly those bytes. JSON array entries are
// taken verbatim, as an enforcement point decodes them; only the line form
// trims whitespace around each line, and says so.
func ReadInput(data []byte, source string) (Input, error) {
	in, err := readInput(data, source)
	if err == nil && len(in.Links) > MaxLinks {
		err = fmt.Errorf("%s holds %d links; whosent reads at most %d, and a real chain is a handful", source, len(in.Links), MaxLinks)
	}
	return in, err
}

func readInput(data []byte, source string) (Input, error) {
	in := Input{Info: InputInfo{Source: source}}
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\ufeff")), " \t\r\n")
	switch {
	case len(trimmed) == 0:
		in.Info.Format = "lines"
		return in, nil
	case trimmed[0] == '[':
		links, err := decodeLinks(trimmed)
		if err != nil {
			return in, fmt.Errorf("reading %s as a JSON array of compact serializations: %w", source, err)
		}
		in.Links, in.Info.Format = links, "json-array"
		return in, nil
	case trimmed[0] == '{':
		return readObject(trimmed, in)
	}
	return readLines(bytes.TrimPrefix(data, []byte("\ufeff")), in)
}

func decodeLinks(raw json.RawMessage) ([][]byte, error) {
	var links []string
	if err := json.Unmarshal(raw, &links); err != nil {
		return nil, err
	}
	out := make([][]byte, len(links))
	for i, l := range links {
		out[i] = []byte(l)
	}
	return out, nil
}

// toolCallMethod is the JSON-RPC method an enforcement point checks a chain
// on. Every other method is forwarded without looking at one.
const toolCallMethod = "tools/call"

// readObject reads a chain out of a JSON object.
//
// A JSON-RPC request is read exactly the way mandatum's enforcement point
// reads one (pkg/mcp/http.go): the envelope is decoded into a struct, so
// "params" matches case-insensitively and a later duplicate wins, and once
// there are params, the chain is looked for there and nowhere else. Reading
// it any other way would let one request mean two things: a decoy chain in
// "params" for this tool and the real one in "Params" for the enforcement
// point, or a chain this tool finds in a top-level "_meta" on a request the
// enforcement point refuses for carrying none.
//
// Objects without params are this tool's conveniences, tried in order: a
// bare params object (which can also name the tool), a bare _meta, and
// {"chain": [...]}.
func readObject(data []byte, in Input) (Input, error) {
	var envelope struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return in, fmt.Errorf("reading %s as a JSON object: %w", in.Info.Source, err)
	}
	if len(envelope.Params) > 0 {
		if envelope.Method != toolCallMethod {
			return in, fmt.Errorf("%s has params but its method is %q, not %q; an enforcement point checks a chain "+
				"only on %s and forwards anything else without reading one", in.Info.Source, envelope.Method, toolCallMethod, toolCallMethod)
		}
		call, links, err := parseToolCall(envelope.Params)
		if err != nil {
			return in, fmt.Errorf("%s: %w", in.Info.Source, err)
		}
		in.Links, in.Info.Format, in.Info.ToolCall = links, "jsonrpc", call
		return in, nil
	}

	if call, links, err := parseToolCall(data); err == nil {
		in.Links, in.Info.Format, in.Info.ToolCall = links, "json-object", call
		return in, nil
	} else if !errors.Is(err, errNoChain) {
		return in, fmt.Errorf("%s: %w", in.Info.Source, err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return in, fmt.Errorf("reading %s as a JSON object: %w", in.Info.Source, err)
	}
	for _, key := range []string{ChainMetaKey, "chain"} {
		if raw, ok := top[key]; ok {
			links, err := decodeLinks(raw)
			if err != nil {
				return in, fmt.Errorf("%q is not an array of compact serializations: %w", key, err)
			}
			in.Links, in.Info.Format = links, "json-object"
			return in, nil
		}
	}
	return in, fmt.Errorf("%s is a JSON object with no chain in it; expected a tools/call request, "+
		"its params, a _meta object carrying %q, or {\"chain\": [...]}", in.Info.Source, ChainMetaKey)
}

// errNoChain is parseToolCall's refusal for params that carry no chain at
// all, as opposed to one that is malformed.
var errNoChain = fmt.Errorf("the call carries no delegation chain at _meta[%q]", ChainMetaKey)

// parseToolCall mirrors mandatum's pkg/mcp parseToolCall: the same struct,
// the same lookup, the same refusals, in the same order. It stops short of
// parsing the links, which the enforcement point also does at this step:
// here a link that does not parse is a finding to show, not a reason to
// refuse the file.
func parseToolCall(params json.RawMessage) (*ToolCall, [][]byte, error) {
	if len(params) == 0 {
		return nil, nil, errors.New("a tools/call request with no params names no tool")
	}
	var p struct {
		Name      string                     `json:"name"`
		Arguments map[string]any             `json:"arguments"`
		Meta      map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, nil, err
	}
	raw, ok := p.Meta[ChainMetaKey]
	if !ok {
		return nil, nil, errNoChain
	}
	links, err := decodeLinks(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("_meta[%q] is not an array of compact serializations: %w", ChainMetaKey, err)
	}
	if len(links) == 0 {
		return nil, nil, errors.New("the delegation chain is empty, and an empty chain establishes nothing")
	}
	var call *ToolCall
	if p.Name != "" || p.Arguments != nil {
		call = &ToolCall{Name: p.Name, Arguments: p.Arguments}
	}
	return call, links, nil
}

func readLines(data []byte, in Input) (Input, error) {
	in.Info.Format = "lines"
	trimmedAny := false
	for n, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t != strings.TrimSuffix(line, "\r") && t != "" {
			trimmedAny = true
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !looksCompact(t) {
			return in, fmt.Errorf("line %d of %s is not a compact serialization "+
				"(want three base64url segments separated by dots); the file can also be a JSON array or a tools/call request",
				n+1, in.Info.Source)
		}
		in.Links = append(in.Links, []byte(t))
	}
	if trimmedAny {
		in.Info.Normalizations = append(in.Info.Normalizations, "trimmed whitespace around lines")
	}
	return in, nil
}

// looksCompact accepts three dot-separated segments of base64url characters.
// It is a gate against handing over the wrong file, not a parser: a
// serialization that passes it can still fail to parse, and that failure is
// a finding.
func looksCompact(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for i, p := range parts {
		if p == "" && i != 2 {
			return false
		}
		for _, r := range p {
			if !isBase64URL(r) {
				return false
			}
		}
	}
	return true
}

// Reverse returns the links in the opposite order.
func Reverse(links [][]byte) [][]byte {
	out := make([][]byte, len(links))
	for i, l := range links {
		out[len(links)-1-i] = l
	}
	return out
}

func isBase64URL(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	}
	return r == '-' || r == '_'
}
