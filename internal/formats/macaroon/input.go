package macaroon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	gomac "gopkg.in/macaroon.v2"
)

// Limits on what whosent reads. Real tokens carry a root macaroon, a few
// discharges and a handful of caveats; the limits keep a hostile input
// from making the view or the verification slow.
const (
	maxMacaroons = 16
	maxCaveats   = 128
)

// bundle is a decoded input: a root macaroon and its discharges, in one of
// the two dialects.
type bundle struct {
	dialect  string // "libmacaroons" or "fly"
	encoding string
	norms    []string
	lib      []*lmac // root first, then discharges
	fly      *flyBundle
}

// decode reads any of the inputs the format accepts:
//
//   - a Fly.io header or token (`FlyV1 fm2_...`, `fm2_...`, comma-joined);
//   - libmacaroons binary, v1 or v2, one macaroon or a root and its
//     discharges written back to back (raw, or base64 in any alphabet,
//     padded or not, wrapped across lines or not);
//   - several base64 macaroons separated by whitespace or commas;
//   - JSON: one macaroon object (v1 or v2 field names), or an array of
//     objects or of base64 strings.
func decode(data []byte) (*bundle, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}
	if data[0] == 2 {
		ms, err := sliceBinary(data)
		if err != nil {
			return nil, fmt.Errorf("v2 binary: %w", err)
		}
		return libBundle(ms, "v2 binary", nil)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("neither text nor a v2 binary macaroon")
	}
	text := strings.TrimSpace(string(data))
	if looksFly(text) {
		fb, err := decodeFly(text)
		if err != nil {
			return nil, err
		}
		return &bundle{dialect: "fly", encoding: "Fly.io token header", fly: fb}, nil
	}
	switch {
	case strings.HasPrefix(text, "{"):
		m, err := jsonMacaroon([]byte(text))
		if err != nil {
			return nil, err
		}
		return libBundle([]*gomac.Macaroon{m}, "JSON", nil)
	case strings.HasPrefix(text, "["):
		return jsonArray([]byte(text))
	}
	// One base64 run, possibly wrapped across lines: libmacaroons'
	// serializer and pymacaroons both wrap.
	joined := strings.Join(strings.Fields(text), "")
	if ms, err := base64Slice(joined); err == nil {
		var norms []string
		if joined != text {
			norms = append(norms, "joined base64 that was wrapped across lines")
		}
		return libBundle(ms, encodingOf(ms), norms)
	}
	var ms []*gomac.Macaroon
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		part, err := base64Slice(tok)
		if err != nil {
			return nil, fmt.Errorf("not a macaroon: %w", err)
		}
		ms = append(ms, part...)
		if len(ms) > maxMacaroons {
			return nil, fmt.Errorf("more than %d macaroons", maxMacaroons)
		}
	}
	return libBundle(ms, encodingOf(ms), []string{"read whitespace- or comma-separated macaroons"})
}

func base64Slice(s string) ([]*gomac.Macaroon, error) {
	raw, err := gomac.Base64Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	return sliceBinary(raw)
}

// sliceBinary reads macaroons written back to back, as go-macaroon's Slice
// does, but stops at the limit instead of reading on.
func sliceBinary(raw []byte) ([]*gomac.Macaroon, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty macaroon")
	}
	if raw[0] != 2 && !isHex(raw[0]) {
		return nil, errors.New("not a v1 or v2 binary macaroon")
	}
	var s gomac.Slice
	if err := s.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	if len(s) > maxMacaroons {
		return nil, fmt.Errorf("%d macaroons; whosent reads at most %d", len(s), maxMacaroons)
	}
	return s, nil
}

func isHex(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}

func jsonMacaroon(data []byte) (*gomac.Macaroon, error) {
	var m gomac.Macaroon
	if err := m.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("JSON macaroon: %w", err)
	}
	return &m, nil
}

func jsonArray(data []byte) (*bundle, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("JSON array: %w", err)
	}
	if len(items) == 0 {
		return nil, errors.New("an empty JSON array")
	}
	if len(items) > maxMacaroons {
		return nil, fmt.Errorf("%d macaroons; whosent reads at most %d", len(items), maxMacaroons)
	}
	var ms []*gomac.Macaroon
	for i, it := range items {
		it = bytes.TrimSpace(it)
		if len(it) > 0 && it[0] == '"' {
			var s string
			if err := json.Unmarshal(it, &s); err != nil {
				return nil, err
			}
			part, err := base64Slice(s)
			if err != nil {
				return nil, fmt.Errorf("item %d: %w", i, err)
			}
			ms = append(ms, part...)
			continue
		}
		m, err := jsonMacaroon(it)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		ms = append(ms, m)
	}
	return libBundle(ms, "JSON array", nil)
}

func encodingOf(ms []*gomac.Macaroon) string {
	if len(ms) > 0 && ms[0].Version() == gomac.V1 {
		return "v1 binary, base64"
	}
	return "v2 binary, base64"
}

func libBundle(ms []*gomac.Macaroon, encoding string, norms []string) (*bundle, error) {
	if len(ms) == 0 {
		return nil, errors.New("no macaroon")
	}
	if len(ms) > maxMacaroons {
		return nil, fmt.Errorf("%d macaroons; whosent reads at most %d", len(ms), maxMacaroons)
	}
	b := &bundle{dialect: "libmacaroons", encoding: encoding, norms: norms}
	for i, m := range ms {
		if len(m.Caveats()) > maxCaveats {
			return nil, fmt.Errorf("macaroon %d has %d caveats; whosent reads at most %d", i, len(m.Caveats()), maxCaveats)
		}
		b.lib = append(b.lib, fromGo(m))
	}
	return b, nil
}
