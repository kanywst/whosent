package diagnose_test

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// This file is the request-reading half of mandatum's MCP enforcement
// point, copied from kanywst/mandatum v0.2.0 (commit ebb3fb8),
// pkg/mcp/http.go: Middleware up to the call to Authorize, and
// parseToolCall. mandatum is archived, so that code no longer moves; this
// copy is the oracle the parity test reads requests against.
//
// It is a test file on purpose. The rest of pkg/mcp brings CEL and an
// AuthZEN client with it, none of which the binary needs, and none of which
// decides which chain a request carries. Only the parts that do are here,
// with their logic unchanged: the envelope is decoded into a struct (so
// keys match case-insensitively and the last duplicate wins), anything but
// tools/call is forwarded unchecked, and params are read exactly as
// parseToolCall reads them.

// mcpChainMetaKey is pkg/mcp's ChainMetaKey. TestChainMetaKeyMatchesMandatum
// checks it against diagnose.ChainMetaKey.
const mcpChainMetaKey = "io.github.kanywst.mandatum/chain"

// mcpMaxBodyBytes is pkg/mcp's DefaultMaxBodyBytes.
const mcpMaxBodyBytes int64 = 1 << 20

// mcpOutcome is what the enforcement point does with a request body:
// forwarded (it checks nothing), unreadable (it refuses before verifying
// anything), or the parsed chain it goes on to verify.
type mcpOutcome struct {
	Forwarded bool
	Err       error
	Chain     mda.Chain
}

// mcpRead mirrors Middleware's handling of a body up to Authorize.
func mcpRead(body []byte) mcpOutcome {
	// http.MaxBytesReader refuses a body longer than the limit, which the
	// middleware reports as a body that could not be read.
	if int64(len(body)) > mcpMaxBodyBytes {
		return mcpOutcome{Err: errors.New("the request body could not be read")}
	}

	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return mcpOutcome{Err: fmt.Errorf("the request is not a JSON-RPC message: %w", err)}
	}

	if envelope.Method != "tools/call" {
		return mcpOutcome{Forwarded: true}
	}

	chain, err := mcpParseToolCall(envelope.Params)
	if err != nil {
		return mcpOutcome{Err: fmt.Errorf("the tool call could not be read: %w", err)}
	}
	return mcpOutcome{Chain: chain}
}

// mcpParseToolCall is parseToolCall, returning only the chain.
func mcpParseToolCall(params json.RawMessage) (mda.Chain, error) {
	if len(params) == 0 {
		return nil, errors.New("a tools/call request with no params names no tool")
	}

	var p struct {
		Name      string                     `json:"name"`
		Arguments map[string]any             `json:"arguments"`
		Meta      map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	raw, ok := p.Meta[mcpChainMetaKey]
	if !ok {
		return nil, fmt.Errorf("the call carries no delegation chain at _meta[%q]", mcpChainMetaKey)
	}
	var links []string
	if err := json.Unmarshal(raw, &links); err != nil {
		return nil, fmt.Errorf("_meta[%q] is not an array of compact serializations: %w", mcpChainMetaKey, err)
	}
	if len(links) == 0 {
		return nil, errors.New("the delegation chain is empty, and an empty chain establishes nothing")
	}

	serializations := make([][]byte, 0, len(links))
	for _, link := range links {
		serializations = append(serializations, []byte(link))
	}
	return mda.ParseChain(serializations)
}
