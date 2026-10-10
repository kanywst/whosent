package diagnose_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kanywst/whosent/pkg/diagnose"
)

func TestReadInputDetectsEveryForm(t *testing.T) {
	s := scenario(t, "healthy")
	links := make([]string, len(s.Links))
	for i, l := range s.Links {
		links[i] = string(l)
	}
	arr, _ := json.Marshal(links)
	key := diagnose.ChainMetaKey
	rpc, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "web.fetch", "arguments": map[string]any{"host": "docs.example.org"}, "_meta": map[string]any{key: links}},
	})
	params, _ := json.Marshal(map[string]any{"name": "web.fetch", "_meta": map[string]any{key: links}})
	meta, _ := json.Marshal(map[string]any{key: links})
	conv, _ := json.Marshal(map[string]any{"chain": links})
	lines := "# a comment\n\n" + strings.Join(links, "\r\n") + "\n"

	tests := []struct {
		name   string
		data   string
		format string
		tool   string
	}{
		{"a JSON array is the wire form", string(arr), "json-array", ""},
		{"leading whitespace and a BOM do not hide the array", "\ufeff \n" + string(arr), "json-array", ""},
		{"a whole tools/call request carries the tool and its arguments", string(rpc), "jsonrpc", "web.fetch"},
		{"the params of a request are enough", string(params), "json-object", "web.fetch"},
		{"a bare _meta works", string(meta), "json-object", ""},
		{"a chain key works", string(conv), "json-object", ""},
		{"one serialization per line, with comments and CRLF", lines, "lines", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := diagnose.ReadInput([]byte(tt.data), "test")
			if err != nil {
				t.Fatal(err)
			}
			if in.Info.Format != tt.format {
				t.Errorf("format %q, want %q", in.Info.Format, tt.format)
			}
			if len(in.Links) != len(links) {
				t.Fatalf("%d links, want %d", len(in.Links), len(links))
			}
			for i := range links {
				if string(in.Links[i]) != links[i] {
					t.Errorf("link %d changed in reading; the parent commitment is over these exact bytes", i)
				}
			}
			switch {
			case tt.tool == "" && in.Info.ToolCall != nil && in.Info.ToolCall.Name != "":
				t.Errorf("unexpected tool call %+v", in.Info.ToolCall)
			case tt.tool != "" && (in.Info.ToolCall == nil || in.Info.ToolCall.Name != tt.tool):
				t.Errorf("tool call %+v, want %s", in.Info.ToolCall, tt.tool)
			}
		})
	}
}

// A JSON entry is used exactly as an enforcement point would decode it,
// whitespace and all. Trimming it would diagnose a chain the enforcement
// point never sees.
func TestJSONEntriesAreNeverTrimmed(t *testing.T) {
	in, err := diagnose.ReadInput([]byte(`[" a.b.c "]`), "test")
	if err != nil {
		t.Fatal(err)
	}
	if string(in.Links[0]) != " a.b.c " {
		t.Errorf("entry became %q", in.Links[0])
	}
}

func TestReadInputRefusesWhatIsNotAChain(t *testing.T) {
	tests := []struct {
		name, data, mention string
	}{
		{"a PEM file is not a chain", "-----BEGIN CERTIFICATE-----\nMIIB\n", "line 1"},
		{"a JSON object without a chain says where it looked", `{"foo": 1}`, "no chain in it"},
		{"an array of numbers is not serializations", `[1, 2]`, "JSON array"},
		{"a meta key holding a string is refused", `{"chain": "a.b.c"}`, "not an array"},
		{"a broken JSON array is refused", `["a.b.c"`, "JSON array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := diagnose.ReadInput([]byte(tt.data), "test")
			if err == nil || !strings.Contains(err.Error(), tt.mention) {
				t.Errorf("error %v, want one mentioning %q", err, tt.mention)
			}
		})
	}
	t.Run("empty input is an empty chain, which diagnosis reports", func(t *testing.T) {
		in, err := diagnose.ReadInput([]byte("  \n"), "test")
		if err != nil || len(in.Links) != 0 {
			t.Errorf("links %d err %v", len(in.Links), err)
		}
	})
}

func TestReadInputRefusesMoreLinksThanItReads(t *testing.T) {
	links := make([]string, diagnose.MaxLinks+1)
	for i := range links {
		links[i] = "a.b.c"
	}
	arr, _ := json.Marshal(links)
	for name, data := range map[string]string{"array": string(arr), "lines": strings.Join(links, "\n")} {
		if _, err := diagnose.ReadInput([]byte(data), "test"); err == nil || !strings.Contains(err.Error(), "at most") {
			t.Errorf("%s: %d links read without complaint: %v", name, len(links), err)
		}
	}
}
