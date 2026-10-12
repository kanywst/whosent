package ucan

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxTokens bounds how many tokens one input may hold. A real chain is a
// handful of delegations and an invocation.
const maxTokens = 64

// maxInflated bounds a gzipped container once inflated.
const maxInflated = 1 << 20

// input is what was read.
type input struct {
	tokens []*Token
	format string
}

// readInput reads tokens in any of the shapes UCANs travel in: a container
// (ucan-wg/container v0.1.0), a JSON array of base64 tokens or DAG-JSON
// bytes, the spec fixtures' {"invocation", "proofs"} object, base64 tokens
// one per line, or one raw token.
func readInput(data []byte) (input, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return input{}, errors.New("no input")
	}
	// Binary forms keep their trailing bytes: in raw CBOR a final 0x20 is
	// data, not whitespace.
	unpadded := bytes.TrimLeft(data, " \t\r\n")
	from := trimmed
	if unpadded[0] == '@' || unpadded[0] == 'M' {
		from = unpadded
	}
	if raws, ok, err := readContainer(from); ok {
		if err != nil {
			return input{}, err
		}
		return tokensOf(raws, "container")
	}
	switch trimmed[0] {
	case '[', '{':
		raws, err := readJSON(trimmed)
		if err != nil {
			return input{}, err
		}
		return tokensOf(raws, "json")
	case 0x82:
		return tokensOf([][]byte{unpadded}, "dag-cbor")
	}
	var raws [][]byte
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := decodeBase64(line)
		if err != nil {
			return input{}, fmt.Errorf("a line that is not base64: %w", err)
		}
		raws = append(raws, b)
	}
	return tokensOf(raws, "base64")
}

func tokensOf(raws [][]byte, format string) (input, error) {
	if len(raws) == 0 {
		return input{}, errors.New("no tokens")
	}
	if len(raws) > maxTokens {
		return input{}, fmt.Errorf("%d tokens; whosent reads at most %d", len(raws), maxTokens)
	}
	in := input{format: format}
	for _, r := range raws {
		in.tokens = append(in.tokens, decodeToken(r))
	}
	return in, nil
}

// readContainer reads a container. ok is false when data does not start
// with a container header.
func readContainer(data []byte) (raws [][]byte, ok bool, err error) {
	var body []byte
	switch data[0] {
	case '@', 'M':
		body = data[1:]
	case 'B':
		body, err = base64.StdEncoding.DecodeString(string(data[1:]))
	case 'C':
		body, err = base64.RawURLEncoding.DecodeString(string(data[1:]))
	case 'O':
		body, err = base64.StdEncoding.DecodeString(string(data[1:]))
	case 'P':
		body, err = base64.RawURLEncoding.DecodeString(string(data[1:]))
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, false, nil
	}
	if data[0] == 'M' || data[0] == 'O' || data[0] == 'P' {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false, nil
		}
		body, err = io.ReadAll(io.LimitReader(zr, maxInflated+1))
		if err != nil {
			return nil, false, nil
		}
		if len(body) > maxInflated {
			return nil, true, errors.New("the container inflates past a megabyte")
		}
	}
	v, err := decodeCBOR(body)
	if err != nil || v.Kind != KindMap {
		return nil, false, nil
	}
	ctn, found := v.Get("ctn-v1")
	if !found {
		return nil, false, nil
	}
	if len(v.Map) != 1 || ctn.Kind != KindList {
		return nil, true, errors.New("a container holds only ctn-v1, a list of token bytes")
	}
	for i, e := range ctn.List {
		if e.Kind != KindBytes {
			return nil, true, fmt.Errorf("container entry %d is a %s, not token bytes", i, e.Kind)
		}
		raws = append(raws, e.Bytes)
	}
	return raws, true, nil
}

// readJSON reads a JSON array of tokens, or the fixtures' object.
func readJSON(data []byte) ([][]byte, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		return jsonTokens(arr)
	}
	var obj struct {
		Invocation json.RawMessage   `json:"invocation"`
		Proofs     []json.RawMessage `json:"proofs"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if obj.Invocation == nil && obj.Proofs == nil {
		if b, err := jsonToken(data); err == nil {
			return [][]byte{b}, nil
		}
		return nil, errors.New(`a JSON object of UCANs has "invocation" and "proofs"`)
	}
	out, err := jsonTokens(obj.Proofs)
	if err != nil {
		return nil, err
	}
	if obj.Invocation != nil {
		b, err := jsonToken(obj.Invocation)
		if err != nil {
			return nil, fmt.Errorf("invocation: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}

func jsonTokens(arr []json.RawMessage) ([][]byte, error) {
	var out [][]byte
	for i, e := range arr {
		b, err := jsonToken(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}

// jsonToken reads a base64 string or DAG-JSON bytes, {"/": {"bytes": ...}}.
func jsonToken(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return decodeBase64(s)
	}
	var link struct {
		Slash struct {
			Bytes string `json:"bytes"`
		} `json:"/"`
	}
	if err := json.Unmarshal(raw, &link); err != nil || link.Slash.Bytes == "" {
		return nil, errors.New(`want a base64 string or {"/": {"bytes": ...}}`)
	}
	return decodeBase64(link.Slash.Bytes)
}

// decodeBase64 accepts the standard and URL alphabets, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}
