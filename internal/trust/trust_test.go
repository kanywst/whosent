package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const body = `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"a"}]}`

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
		{Issuer: "a", Location: filepath.Join(dir, "jwks", "a.json")},
		{Issuer: "b", Location: "https://keys.example.org/b"},
		{Issuer: "c", Location: abs},
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

func TestLoadDocuments(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	write(t, good, body)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(body))
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxBytes+1))
		default:
			http.Error(w, "no", http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	l := Loader{Client: srv.Client()}

	docs, err := l.LoadDocuments(context.Background(), []Source{
		{Issuer: "good", Location: good}, {Issuer: "url", Location: srv.URL + "/ok"}, {Issuer: "down", Location: srv.URL + "/down"}, {Issuer: "big", Location: srv.URL + "/big"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Document{}
	for _, d := range docs {
		got[d.Issuer] = d
	}
	for iss, wantErr := range map[string]bool{"good": false, "url": false, "down": true, "big": true} {
		if (got[iss].Err != "") != wantErr {
			t.Errorf("%s: err %q, want error=%v", iss, got[iss].Err, wantErr)
		}
	}
	if got["good"].Source != "good.json" || string(got["good"].Data) != body {
		t.Errorf("a file source is shown by its name and read whole, got %q", got["good"].Source)
	}

	t.Run("a missing file is a usage error, not a key that failed to load", func(t *testing.T) {
		if _, err := l.LoadDocuments(context.Background(), []Source{{Issuer: "x", Location: filepath.Join(dir, "typo.json")}}); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("a plaintext URL is refused as configuration", func(t *testing.T) {
		if _, err := l.LoadDocuments(context.Background(), []Source{{Issuer: "x", Location: "http://keys.example.org"}}); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("an issuer configured twice is refused", func(t *testing.T) {
		if _, err := l.LoadDocuments(context.Background(), []Source{{Issuer: "x", Location: good}, {Issuer: "x", Location: good}}); err == nil {
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
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
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
			_, _ = w.Write([]byte(body))
		}
	}))
	defer tlsSrv.Close()

	load := func(path string) Document {
		t.Helper()
		got, err := Loader{Client: tlsSrv.Client()}.LoadDocuments(context.Background(), []Source{{Issuer: "iss", Location: tlsSrv.URL + path}})
		if err != nil {
			t.Fatal(err)
		}
		return got[0]
	}
	if d := load("/to-plain"); d.Err == "" || !strings.Contains(d.Err, "not https") {
		t.Errorf("a redirect to plaintext was followed: %d bytes, err %q", len(d.Data), d.Err)
	}
	if d := load("/to-tls"); d.Err != "" || len(d.Data) == 0 {
		t.Errorf("an https to https redirect should be followed: err %q", d.Err)
	}
	if d := load("/loop"); d.Err == "" || hits > maxRedirects+1 {
		t.Errorf("a redirect loop was followed %d times: err %q", hits, d.Err)
	}
}

// An actor's keys are named by (act.iss, act.sub): the same sub under two
// issuers is two actors, and one under one issuer configured twice is a
// mistake.
func TestReadFileReadsActors(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "trust.json")
	write(t, tf, `{"issuers":{"a":{"jwks_file":"a.json"}},"actors":[`+
		`{"iss":"a","sub":"planner","jwks_file":"jwks/p.json"},`+
		`{"iss":"b","sub":"planner","jwks_url":"https://keys.example.org/p"}]}`)
	got, err := ReadFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	want := []Source{
		{Issuer: "a", Location: filepath.Join(dir, "a.json")},
		{Issuer: "a", Location: filepath.Join(dir, "jwks", "p.json"), Actor: "planner"},
		{Issuer: "b", Location: "https://keys.example.org/p", Actor: "planner"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for name, body := range map[string]string{
		"an actor without iss":    `{"actors":[{"sub":"p","jwks_file":"x"}]}`,
		"an actor without sub":    `{"actors":[{"iss":"a","jwks_file":"x"}]}`,
		"an actor without keys":   `{"actors":[{"iss":"a","sub":"p"}]}`,
		"an actor with both":      `{"actors":[{"iss":"a","sub":"p","jwks_file":"x","jwks_url":"https://y"}]}`,
		"an unknown actor member": `{"actors":[{"iss":"a","sub":"p","jwks_file":"x","kid":"k"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "trust.json")
			write(t, p, body)
			if _, err := ReadFile(p); err == nil {
				t.Error("accepted")
			}
		})
	}

	good := filepath.Join(dir, "good.json")
	write(t, good, body)
	if _, err := (Loader{}).LoadDocuments(context.Background(), []Source{
		{Issuer: "a", Location: good, Actor: "p"}, {Issuer: "a", Location: good, Actor: "p"},
	}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("an actor configured twice: %v", err)
	}
	docs, err := (Loader{}).LoadDocuments(context.Background(), []Source{
		{Issuer: "a", Location: good}, {Issuer: "a", Location: good, Actor: "p"},
	})
	if err != nil || len(docs) != 2 || docs[1].Actor != "p" || docs[0].Actor != "" {
		t.Errorf("an issuer and an actor under it: %+v %v", docs, err)
	}
}
