package diagnose_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/mandatum/pkg/authzen"
	"github.com/kanywst/mandatum/pkg/jose"
	"github.com/kanywst/mandatum/pkg/mcp"
	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/sequence"
	"github.com/kanywst/mandatum/pkg/verify"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// This test imports mandatum's pkg/mcp, and with it CEL, so that the oracle
// is the enforcement point itself rather than a reading of its source. Test
// imports do not reach the binary; TestBinaryDoesNotImportCEL guards that.

type denyAll struct{}

func (denyAll) Evaluate(context.Context, authzen.Request) (authzen.Decision, error) {
	return authzen.Decision{}, nil
}

type notRevoked struct{}

func (notRevoked) IsRevoked(context.Context, string) (bool, error) { return false, nil }

// oneLink signs a single parseable link whose issuer names the chain, so the
// enforcement point's denial, which quotes the issuer whose signature it
// could not check, says which chain it read.
func oneLink(t *testing.T, issuer string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := jose.Sign(mda.Claims{
		Issuer: issuer, Subject: "agent", Audience: "aud", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ID: issuer + "-jti",
		Mandatum: mda.Mandatum{Version: mda.Version, Root: mda.Sponsor{Issuer: "idp", Subject: "alice"}, Capabilities: []mda.Capability{}},
	}, priv, "k")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// enforcementPoint reports what mandatum's MCP middleware made of a request
// body: "forwarded" (it checked nothing), "unreadable" (it refused the
// request before verifying anything), or the issuer of the chain it went on
// to verify.
func enforcementPoint(t *testing.T, body string, issuers ...string) string {
	t.Helper()
	v, err := verify.New(jose.NewKeyRing(), notRevoked{}, "aud")
	if err != nil {
		t.Fatal(err)
	}
	seq, err := sequence.NewEvaluator(sequence.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	e, err := mcp.New(v, mcp.CatalogFunc(func(string, map[string]any) (mcp.Facts, error) { return mcp.Facts{}, nil }),
		denyAll{}, seq, mcp.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	if err != nil {
		t.Fatal(err)
	}
	h := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	switch {
	case rec.Code == http.StatusOK:
		return "forwarded"
	case strings.Contains(rec.Body.String(), "could not be read"), strings.Contains(rec.Body.String(), "not a JSON-RPC message"):
		return "unreadable"
	}
	for _, iss := range issuers {
		if strings.Contains(logs.String(), iss) {
			return iss
		}
	}
	t.Fatalf("cannot tell what the enforcement point did: %d %s\n%s", rec.Code, rec.Body, logs.String())
	return ""
}

// whosentReads reports what this tool makes of the same body: "unreadable"
// when it refuses, or the issuer of the chain it diagnoses.
func whosentReads(t *testing.T, body string) string {
	t.Helper()
	in, err := diagnose.ReadInput([]byte(body), "test")
	if err != nil {
		return "unreadable"
	}
	if len(in.Links) == 0 {
		return "empty"
	}
	a, err := mda.ParseAssertion(in.Links[0])
	if err != nil {
		t.Fatalf("read a link that does not parse: %v", err)
	}
	return a.Claims.Issuer
}

// A tools/call request must mean one thing. If this tool read a different
// chain from the one the enforcement point verifies, it would diagnose a
// decoy, and an attacker could put a clean chain where whosent looks and the
// real one where mandatum does. Every case runs the same bytes through
// mandatum's own middleware and through ReadInput, and both must land on the
// same chain, or both refuse.
func TestToolCallsAreReadExactlyAsTheEnforcementPointReadsThem(t *testing.T) {
	realLink, decoy := oneLink(t, "real-issuer"), oneLink(t, "decoy-issuer")
	k := diagnose.ChainMetaKey
	meta := func(links ...string) map[string]any { return map[string]any{k: links} }
	params := func(links ...string) map[string]any {
		return map[string]any{"name": "web.fetch", "_meta": meta(links...)}
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	body := func(method string, p any) string {
		return enc(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": p})
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"an ordinary request", body("tools/call", params(realLink)), "real-issuer"},
		{"params spelled with a capital is still params",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","Params":` + enc(params(realLink)) + `}`, "real-issuer"},
		{"with params and Params both present, the later one wins",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + enc(params(decoy)) + `,"Params":` + enc(params(realLink)) + `}`, "real-issuer"},
		{"a duplicated params key: the later one wins",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + enc(params(decoy)) + `,"params":` + enc(params(realLink)) + `}`, "real-issuer"},
		{"_meta spelled with capitals is still _meta",
			body("tools/call", map[string]any{"name": "x", "_META": meta(realLink)}), "real-issuer"},
		{"the chain key itself is matched exactly",
			body("tools/call", map[string]any{"name": "x", "_meta": map[string]any{strings.ToUpper(k): []string{realLink}}}), "unreadable"},
		{"params with no chain are refused, even with a chain elsewhere in the request",
			enc(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "x"}, "_meta": meta(realLink), "chain": []string{realLink}}), "unreadable"},
		{"an empty chain is refused", body("tools/call", params()), "unreadable"},
		{"null params are refused", body("tools/call", nil), "unreadable"},
		{"a chain that is not an array is refused", body("tools/call", map[string]any{"name": "x", "_meta": map[string]any{k: realLink}}), "unreadable"},
		{"a request that is not JSON is refused", `{"method":"tools/call","params":`, "unreadable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := enforcementPoint(t, tt.body, "real-issuer", "decoy-issuer")
			if ep != tt.want {
				t.Fatalf("the enforcement point did %q, the test expected %q; the oracle has moved", ep, tt.want)
			}
			if got := whosentReads(t, tt.body); got != ep {
				t.Errorf("whosent read %q, the enforcement point %q", got, ep)
			}
		})
	}

	// A request the enforcement point forwards unchecked has no chain to
	// diagnose: whosent says so rather than checking one nobody checks.
	for _, tt := range []struct{ name, body string }{
		{"a method other than tools/call is forwarded unchecked", body("tools/list", params(realLink))},
		{"a request with no method is forwarded unchecked", enc(map[string]any{"jsonrpc": "2.0", "id": 1, "params": params(realLink)})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if ep := enforcementPoint(t, tt.body, "real-issuer"); ep != "forwarded" {
				t.Fatalf("the enforcement point did %q; the oracle has moved", ep)
			}
			if got := whosentReads(t, tt.body); got != "unreadable" {
				t.Errorf("whosent diagnosed %q, a chain the enforcement point never checks", got)
			}
		})
	}
}
