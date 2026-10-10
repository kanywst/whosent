package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/whosent/internal/mandatum/jose"

	"github.com/kanywst/whosent/pkg/diagnose"
)

func key(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func x(k ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func doc(keys ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

func okp(k ed25519.PrivateKey, kid string, extra map[string]any) map[string]any {
	m := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x(k)}
	if kid != "" {
		m["kid"] = kid
	}
	for a, b := range extra {
		m[a] = b
	}
	return m
}

// documents covers every rule the library applies to a key document.
func documents() map[string][]byte {
	k1, k2 := key(1), key(2)
	return map[string][]byte{
		"one key with a kid":                 doc(okp(k1, "a", nil)),
		"one key without a kid":              doc(okp(k1, "", nil)),
		"two keys with kids":                 doc(okp(k1, "a", nil), okp(k2, "b", nil)),
		"two keys, one without a kid":        doc(okp(k1, "a", nil), okp(k2, "", nil)),
		"the same key twice under one kid":   doc(okp(k1, "a", nil), okp(k1, "a", nil)),
		"two keys under one kid":             doc(okp(k1, "a", nil), okp(k2, "a", nil)),
		"an encryption key is skipped":       doc(okp(k1, "a", map[string]any{"use": "enc"}), okp(k2, "b", nil)),
		"a key for another alg is skipped":   doc(okp(k1, "a", map[string]any{"alg": "ES256"}), okp(k2, "b", nil)),
		"key_ops without verify is skipped":  doc(okp(k1, "a", map[string]any{"key_ops": []string{"sign"}}), okp(k2, "b", nil)),
		"key_ops with verify is used":        doc(okp(k1, "a", map[string]any{"key_ops": []string{"sign", "verify"}})),
		"an RSA key is skipped":              doc(map[string]any{"kty": "RSA", "n": "x", "e": "AQAB", "kid": "r"}, okp(k2, "b", nil)),
		"a short x is skipped":               doc(map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "s"}, okp(k2, "b", nil)),
		"nothing usable":                     doc(okp(k1, "a", map[string]any{"use": "enc"})),
		"no keys at all":                     []byte(`{"keys":[]}`),
		"not JSON":                           []byte(`nope`),
		"a SPIFFE bundle with extra members": []byte(`{"spiffe_sequence":3,"spiffe_refresh_hint":60,"keys":[` + string(mustJSON(okp(k1, "a", map[string]any{"use": "sig"}))) + `]}`),
		"a negative spiffe_sequence":         []byte(`{"spiffe_sequence":-1,"keys":[` + string(mustJSON(okp(k1, "a", nil))) + `]}`),
		"a string spiffe_sequence":           []byte(`{"spiffe_sequence":"3","keys":[` + string(mustJSON(okp(k1, "a", nil))) + `]}`),
		"a fractional spiffe_sequence":       []byte(`{"spiffe_sequence":1.5,"keys":[` + string(mustJSON(okp(k1, "a", nil))) + `]}`),
		"an overflowing spiffe_sequence":     []byte(`{"spiffe_sequence":18446744073709551616,"keys":[` + string(mustJSON(okp(k1, "a", nil))) + `]}`),
		"a key_ops string, not a list":       doc(okp(k1, "a", map[string]any{"key_ops": "verify"})),
		"an x5c key alongside":               doc(map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "use": "x509-svid"}, okp(k2, "b", nil)),
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// sign makes an assertion-shaped token signed by k with kid, which is all a
// signature check reads.
func sign(t *testing.T, k ed25519.PrivateKey, kid string) []byte {
	t.Helper()
	raw, err := jose.Sign(map[string]any{"iss": "iss"}, k, kid)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The loader must accept exactly the documents the library's resolver
// accepts, and resolve the same key for every kid. Each document is served
// over TLS to jose.NewJWKS and loaded by ParseDocument, and a token for every
// (key, kid) combination is checked against both.
func TestParseDocumentAgreesWithTheLibrary(t *testing.T) {
	signers := []ed25519.PrivateKey{key(1), key(2), key(3)}
	kids := []string{"", "a", "b", "r", "s", "zzz"}
	for name, body := range documents() {
		t.Run(name, func(t *testing.T) {
			compareWithLibrary(t, body, signers, kids)
		})
	}
}

func compareWithLibrary(t *testing.T, body []byte, signers []ed25519.PrivateKey, kids []string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	keys, _, perr := ParseDocument(body)
	ring := jose.NewKeyRing()
	for kid, k := range keys {
		if err := ring.Add("iss", kid, k); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range signers {
		for _, kid := range kids {
			lib := jose.NewJWKS(jose.WithHTTPClient(srv.Client()))
			if err := lib.AddSource("iss", srv.URL); err != nil {
				t.Fatal(err)
			}
			raw := sign(t, k, kid)
			libErr := lib.VerifySignature(context.Background(), "iss", raw)
			var ourErr error
			if perr != nil {
				ourErr = perr
			} else {
				ourErr = ring.VerifySignature(context.Background(), "iss", raw)
			}
			if (libErr == nil) != (ourErr == nil) {
				t.Errorf("kid %q signer %x: library says %v, loader says %v", kid, k.Public().(ed25519.PublicKey)[:4], libErr, ourErr)
			}
			if libErr != nil && ourErr != nil && perr == nil &&
				errors.Is(libErr, jose.ErrUnknownKey) != errors.Is(ourErr, jose.ErrUnknownKey) {
				t.Errorf("kid %q: unknown-key classification differs: library %v, loader %v", kid, libErr, ourErr)
			}
		}
	}
}

func FuzzParseDocumentAgreesWithTheLibrary(f *testing.F) {
	for _, d := range documents() {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<16 {
			return
		}
		compareWithLibrary(t, body, []ed25519.PrivateKey{key(1), key(2)}, []string{"", "a", "b"})
	})
}

func TestParseDocumentSaysWhatItSkipped(t *testing.T) {
	_, skipped, err := ParseDocument(documents()["an encryption key is skipped"])
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], `use "enc"`) {
		t.Errorf("skipped %v", skipped)
	}
}

func TestReadFileResolvesPathsAgainstTheTrustFile(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "trust.json")
	// The absolute path is built from a real directory rather than written as
	// "/abs/c.json", which is not absolute on Windows and would be joined.
	abs := filepath.Join(t.TempDir(), "c.json")
	absJSON, _ := json.Marshal(abs)
	write(t, tf, `{"issuers":{"a":{"jwks_file":"jwks/a.json"},"b":{"jwks_url":"https://keys.example.org/b"},"c":{"jwks_file":`+string(absJSON)+`}}}`)
	got, err := ReadFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{
		{"a", filepath.Join(dir, "jwks", "a.json")},
		{"b", "https://keys.example.org/b"},
		{"c", abs},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReadFileRefusesAmbiguity(t *testing.T) {
	tests := map[string]string{
		"both a file and a URL": `{"issuers":{"a":{"jwks_file":"x","jwks_url":"https://y"}}}`,
		"neither":               `{"issuers":{"a":{}}}`,
		"an unknown member":     `{"issuers":{"a":{"jwks":"x"}}}`,
		"not JSON":              `nope`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "trust.json")
			write(t, p, body)
			if _, err := ReadFile(p); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	write(t, good, string(doc(okp(key(1), "a", nil))))
	bad := filepath.Join(dir, "bad.json")
	write(t, bad, `{"keys":[]}`)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write(doc(okp(key(2), "b", nil)))
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxBytes+1))
		default:
			http.Error(w, "no", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	l := Loader{Client: srv.Client()}

	tr, err := l.Load(context.Background(), []Source{
		{"good", good}, {"bad", bad}, {"url", srv.URL + "/ok"}, {"down", srv.URL + "/down"}, {"big", srv.URL + "/big"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for iss, wantErr := range map[string]bool{"good": false, "bad": true, "url": false, "down": true, "big": true} {
		ik := tr.Issuers[iss]
		if (ik.Err != "") != wantErr {
			t.Errorf("%s: err %q, want error=%v", iss, ik.Err, wantErr)
		}
	}
	if tr.Issuers["good"].Source != "good.json" {
		t.Errorf("a file source is shown by its name, got %q", tr.Issuers["good"].Source)
	}

	t.Run("a missing file is a usage error, not a key that failed to load", func(t *testing.T) {
		if _, err := l.Load(context.Background(), []Source{{"x", filepath.Join(dir, "typo.json")}}); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("a plaintext URL is refused as configuration", func(t *testing.T) {
		if _, err := l.Load(context.Background(), []Source{{"x", "http://keys.example.org"}}); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("an issuer configured twice is refused", func(t *testing.T) {
		if _, err := l.Load(context.Background(), []Source{{"x", good}, {"x", good}}); err == nil {
			t.Error("accepted")
		}
	})
}

func TestParseFlag(t *testing.T) {
	s, err := ParseFlag("https://idp.example.org=jwks/idp.json")
	if err != nil || s.Issuer != "https://idp.example.org" || s.Location != "jwks/idp.json" || s.IsURL() {
		t.Errorf("got %+v %v", s, err)
	}
	s, err = ParseFlag("spiffe://example.org/a=jwks/a.json")
	if err != nil || s.Issuer != "spiffe://example.org/a" || s.Location != "jwks/a.json" {
		t.Errorf("got %+v %v", s, err)
	}
	s, err = ParseFlag("iss=https://k.example.org/j?v=2")
	if err != nil || s.Location != "https://k.example.org/j?v=2" || !s.IsURL() {
		t.Errorf("got %+v %v", s, err)
	}
	for _, bad := range []string{"noequals", "=x", "x="} {
		if _, err := ParseFlag(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// "Key sources must be https" has to hold at every hop. An https endpoint
// that redirects to plaintext would otherwise hand over a key document an
// on-path attacker can rewrite.
func TestFetchRefusesARedirectToPlaintext(t *testing.T) {
	body := doc(okp(key(1), "a", nil))
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer plain.Close()
	hits := 0
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-plain":
			http.Redirect(w, r, plain.URL+"/keys", http.StatusFound)
		case "/to-tls":
			http.Redirect(w, r, "/keys", http.StatusFound)
		case "/loop":
			hits++
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = w.Write(body)
		}
	}))
	defer tlsSrv.Close()

	load := func(path string) *diagnose.IssuerKeys {
		t.Helper()
		got, err := Loader{Client: tlsSrv.Client()}.Load(context.Background(), []Source{{Issuer: "iss", Location: tlsSrv.URL + path}})
		if err != nil {
			t.Fatal(err)
		}
		return got.Issuers["iss"]
	}
	if ik := load("/to-plain"); ik.Err == "" || !strings.Contains(ik.Err, "not https") {
		t.Errorf("a redirect to plaintext was followed: keys %d, err %q", len(ik.Keys), ik.Err)
	}
	if ik := load("/to-tls"); ik.Err != "" || len(ik.Keys) == 0 {
		t.Errorf("an https to https redirect should be followed: err %q", ik.Err)
	}
	if ik := load("/loop"); ik.Err == "" || hits > maxRedirects+1 {
		t.Errorf("a redirect loop was followed %d times: err %q", hits, ik.Err)
	}
}
