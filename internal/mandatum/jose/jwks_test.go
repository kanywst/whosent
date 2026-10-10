package jose_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwksFor renders a document publishing the given Ed25519 keys.
func jwksFor(keys map[string]ed25519.PublicKey) string {
	var entries []string
	for kid, k := range keys {
		entries = append(entries, fmt.Sprintf(
			`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q,"use":"sig","alg":"EdDSA"}`, b64url(k), kid))
	}
	return `{"keys":[` + strings.Join(entries, ",") + `]}`
}

// keyServer serves a document over TLS and counts how often it was asked for.
type keyServer struct {
	*httptest.Server
	body  atomic.Value // string
	hits  atomic.Int64
	code  atomic.Int64
	delay time.Duration
}

func newKeyServer(t *testing.T, body string) *keyServer {
	t.Helper()
	ks := &keyServer{}
	ks.body.Store(body)
	ks.code.Store(http.StatusOK)
	ks.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks.hits.Add(1)
		time.Sleep(ks.delay)
		code := int(ks.code.Load())
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(ks.body.Load().(string)))
		}
	}))
	t.Cleanup(ks.Close)
	return ks
}

func resolverFor(t *testing.T, ks *keyServer, issuer string, opts ...jose.JWKSOption) *jose.JWKS {
	t.Helper()
	opts = append([]jose.JWKSOption{jose.WithHTTPClient(ks.Client())}, opts...)
	j := jose.NewJWKS(opts...)
	// httptest gives an https URL, which AddSource requires.
	if err := j.AddSource(issuer, ks.URL); err != nil {
		t.Fatal(err)
	}
	return j
}

func signed(t *testing.T, key ed25519.PrivateKey, kid string) []byte {
	t.Helper()
	compact, err := jose.Sign(map[string]any{"sub": "agent"}, key, kid)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestJWKSResolvesAKeyItFetched(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	j := resolverFor(t, ks, "https://idp.example.org")

	if err := j.VerifySignature(context.Background(), "https://idp.example.org", signed(t, priv, "k1")); err != nil {
		t.Fatalf("a key the issuer publishes did not verify: %v", err)
	}
	if got := ks.hits.Load(); got != 1 {
		t.Errorf("fetched the document %d times, want 1", got)
	}
}

// The whole point of resolving a key for the issuer the chain names is that a
// key belonging to somebody else does not verify.
func TestJWKSRefusesAnotherIssuersKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	j := resolverFor(t, ks, "https://idp.example.org")

	err := j.VerifySignature(context.Background(), "https://idp.example.org", signed(t, otherPriv, "k1"))
	if err == nil {
		t.Fatal("a signature from a key the issuer does not publish verified")
	}
}

func TestJWKSRefusesAnIssuerWithNoSource(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	j := resolverFor(t, ks, "https://idp.example.org")

	err := j.VerifySignature(context.Background(), "https://evil.example.org", signed(t, priv, "k1"))
	if !errors.Is(err, jose.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey for an unregistered issuer, got %v", err)
	}
	if ks.hits.Load() != 0 {
		t.Error("fetched a document for an issuer with no registered source")
	}
}

func TestAddSourceRefusesPlaintextAndNonsense(t *testing.T) {
	j := jose.NewJWKS()
	for name, u := range map[string]string{
		"http":        "http://idp.example.org/jwks.json",
		"no scheme":   "idp.example.org/jwks.json",
		"no host":     "https:///jwks.json",
		"not a url":   "https://exa mple.org/\x7f",
		"file scheme": "file:///etc/keys.json",
	} {
		t.Run(name, func(t *testing.T) {
			if err := j.AddSource("https://idp.example.org", u); err == nil {
				t.Fatalf("accepted %q as a key source", u)
			}
		})
	}
	if err := j.AddSource("", "https://idp.example.org/jwks.json"); err == nil {
		t.Error("accepted a source with no issuer")
	}
}

// A fetched document is used until its TTL expires, and not refetched per
// verification: an authorization check that makes a network call every time
// is a denial of service against the resource it protects.
func TestJWKSCachesUntilTheTTLExpires(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))

	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "https://idp.example.org",
		jose.WithCacheTTL(time.Minute),
		jose.WithClock(func() time.Time { return now }))

	assertion := signed(t, priv, "k1")
	for range 5 {
		if err := j.VerifySignature(context.Background(), "https://idp.example.org", assertion); err != nil {
			t.Fatal(err)
		}
	}
	if got := ks.hits.Load(); got != 1 {
		t.Fatalf("fetched %d times inside the TTL, want 1", got)
	}

	now = now.Add(61 * time.Second)
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", assertion); err != nil {
		t.Fatal(err)
	}
	if got := ks.hits.Load(); got != 2 {
		t.Fatalf("fetched %d times after the TTL expired, want 2", got)
	}
}

// An issuer that rotates publishes a new kid. A verifier that waited for the
// TTL would reject every assertion signed with the new key until it expired.
func TestAnUnknownKidRefetchesOnce(t *testing.T) {
	oldPub, _, _ := ed25519.GenerateKey(nil)
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": oldPub}))

	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "https://idp.example.org",
		jose.WithCacheTTL(time.Hour),
		jose.WithClock(func() time.Time { return now }))

	rotated := signed(t, newPriv, "k2")
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", rotated); err == nil {
		t.Fatal("verified against a key the issuer had not published")
	}

	ks.body.Store(jwksFor(map[string]ed25519.PublicKey{"k1": oldPub, "k2": newPub}))
	now = now.Add(31 * time.Second) // past the refetch floor
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", rotated); err != nil {
		t.Fatalf("did not pick up a rotated key inside the TTL: %v", err)
	}
}

// The same unknown kid, arriving repeatedly, must not turn into one fetch per
// assertion: that is a free amplification path from an unauthenticated input.
func TestAnUnknownKidIsRateLimited(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, forgedPriv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))

	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "https://idp.example.org",
		jose.WithCacheTTL(time.Hour),
		jose.WithClock(func() time.Time { return now }))

	for i := range 20 {
		_ = j.VerifySignature(context.Background(), "https://idp.example.org",
			signed(t, forgedPriv, fmt.Sprintf("forged-%d", i)))
	}
	// One fetch to populate the cache, one refetch for the first unknown kid.
	if got := ks.hits.Load(); got > 2 {
		t.Fatalf("20 forged kids caused %d fetches", got)
	}
}

// A key endpoint that is down denies. The alternative is serving a key set
// that may have had a compromised key removed from it.
func TestAFailedFetchDeniesRatherThanAdmits(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "https://idp.example.org",
		jose.WithCacheTTL(time.Minute),
		jose.WithClock(func() time.Time { return now }))

	assertion := signed(t, priv, "k1")
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", assertion); err != nil {
		t.Fatal(err)
	}

	ks.code.Store(http.StatusInternalServerError)
	now = now.Add(2 * time.Minute)
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", assertion); err == nil {
		t.Fatal("kept verifying against an expired key set after the endpoint failed")
	}
}

func TestJWKSRejectsDocumentsItCannotSafelyUse(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)

	tests := map[string]string{
		"no keys at all":  `{"keys":[]}`,
		"not json":        `<html>404</html>`,
		"only RSA":        `{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"k1"}]}`,
		"only X25519":     `{"keys":[{"kty":"OKP","crv":"X25519","x":"` + b64url(pub) + `","kid":"k1"}]}`,
		"truncated key":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub[:16]) + `","kid":"k1"}]}`,
		"key for sealing": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub) + `","kid":"k1","use":"enc"}]}`,
		"wrong alg":       `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub) + `","kid":"k1","alg":"ES256"}]}`,
		"cannot verify":   `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub) + `","kid":"k1","key_ops":["sign"]}]}`,
		"two keys, one unidentified": `{"keys":[` +
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub) + `"},` +
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64url(other) + `","kid":"k2"}]}`,
		"same kid, different keys": `{"keys":[` +
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64url(pub) + `","kid":"k1"},` +
			`{"kty":"OKP","crv":"Ed25519","x":"` + b64url(other) + `","kid":"k1"}]}`,
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			ks := newKeyServer(t, body)
			j := resolverFor(t, ks, "https://idp.example.org")
			err := j.VerifySignature(context.Background(), "https://idp.example.org", signed(t, priv, "k1"))
			if err == nil {
				t.Fatal("accepted a key document that should have been refused")
			}
		})
	}
}

// A single-key issuer may sign without a kid; a multi-key one may not, and
// the verifier must not guess for it.
func TestKidIsOptionalOnlyForASingleKeyIssuer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)

	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	j := resolverFor(t, ks, "https://idp.example.org")
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", signed(t, priv, "")); err != nil {
		t.Fatalf("a single-key issuer's unlabelled assertion did not verify: %v", err)
	}

	ks2 := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub, "k2": other}))
	j2 := resolverFor(t, ks2, "https://idp.example.org")
	if err := j2.VerifySignature(context.Background(), "https://idp.example.org", signed(t, priv, "")); err == nil {
		t.Fatal("guessed which of two published keys an unlabelled assertion meant")
	}
}

// A SPIFFE trust domain bundle is a JWKS with extra members. Its sequence
// number is what stops an older bundle, with a key that has since been
// removed, replacing a newer one.
func TestASPIFFEBundleCannotGoBackwards(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(nil)
	newPub, _, _ := ed25519.GenerateKey(nil)

	bundle := func(seq int, keys map[string]ed25519.PublicKey) string {
		doc := map[string]any{"spiffe_sequence": seq, "spiffe_refresh_hint": 300}
		var raw map[string]any
		_ = json.Unmarshal([]byte(jwksFor(keys)), &raw)
		doc["keys"] = raw["keys"]
		b, _ := json.Marshal(doc)
		return string(b)
	}

	ks := newKeyServer(t, bundle(7, map[string]ed25519.PublicKey{"k2": newPub}))
	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "spiffe://example.org",
		jose.WithCacheTTL(time.Minute),
		jose.WithClock(func() time.Time { return now }))

	// Populate the cache at sequence 7.
	_ = j.VerifySignature(context.Background(), "spiffe://example.org", signed(t, oldPriv, "k2"))

	// The endpoint is rolled back to a bundle that still carries the retired
	// key. The verifier must refuse rather than accept the older document.
	ks.body.Store(bundle(3, map[string]ed25519.PublicKey{"k1": oldPub, "k2": newPub}))
	now = now.Add(2 * time.Minute)

	err := j.VerifySignature(context.Background(), "spiffe://example.org", signed(t, oldPriv, "k1"))
	if err == nil {
		t.Fatal("accepted a bundle whose sequence number went backwards")
	}
	if !strings.Contains(err.Error(), "backwards") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

// A hostile endpoint must not be able to make a verifier read forever.
func TestAnEnormousDocumentIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	padding := strings.Repeat("a", 2<<20)
	body := `{"padding":"` + padding + `","keys":[{"kty":"OKP","crv":"Ed25519","x":"` +
		b64url(pub) + `","kid":"k1"}]}`

	ks := newKeyServer(t, body)
	j := resolverFor(t, ks, "https://idp.example.org")
	if err := j.VerifySignature(context.Background(), "https://idp.example.org", signed(t, priv, "k1")); err == nil {
		t.Fatal("read a key document past the size cap")
	}
}

func TestFetchHonoursTheContext(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	ks.delay = 200 * time.Millisecond
	j := resolverFor(t, ks, "https://idp.example.org")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := j.VerifySignature(ctx, "https://idp.example.org", signed(t, priv, "k1")); err == nil {
		t.Fatal("ignored a cancelled context")
	}
}

// Lowering the sequence is the obvious replay. Stripping the member is the
// same replay with a different spelling: absent reads as zero, which is below
// every sequence ever published, so it must be refused too - and must not
// leave the ratchet at zero for everything that follows.
func TestADocumentWithNoSequenceCannotFollowOneThatHadIt(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(nil)
	newPub, newPriv, _ := ed25519.GenerateKey(nil)

	bundle := func(seq int, keys map[string]ed25519.PublicKey) string {
		var raw map[string]any
		_ = json.Unmarshal([]byte(jwksFor(keys)), &raw)
		b, _ := json.Marshal(map[string]any{"spiffe_sequence": seq, "keys": raw["keys"]})
		return string(b)
	}

	ks := newKeyServer(t, bundle(7, map[string]ed25519.PublicKey{"k2": newPub}))
	now := time.Unix(1789200000, 0)
	j := resolverFor(t, ks, "spiffe://example.org",
		jose.WithCacheTTL(time.Minute),
		jose.WithClock(func() time.Time { return now }))

	if err := j.VerifySignature(context.Background(), "spiffe://example.org", signed(t, newPriv, "k2")); err != nil {
		t.Fatal(err)
	}

	// The retired key comes back in a document that simply omits the member.
	ks.body.Store(jwksFor(map[string]ed25519.PublicKey{"k1": oldPub, "k2": newPub}))
	now = now.Add(2 * time.Minute)

	err := j.VerifySignature(context.Background(), "spiffe://example.org", signed(t, oldPriv, "k1"))
	if err == nil {
		t.Fatal("accepted a document with no sequence after one that declared 7")
	}
	if !strings.Contains(err.Error(), "backwards") {
		t.Errorf("unhelpful reason: %v", err)
	}

	// And the floor still holds: a declared-lower document is refused after
	// the attempt above, rather than the ratchet having been reset to zero.
	ks.body.Store(bundle(3, map[string]ed25519.PublicKey{"k1": oldPub}))
	now = now.Add(2 * time.Minute)
	if err := j.VerifySignature(context.Background(), "spiffe://example.org", signed(t, oldPriv, "k1")); err == nil {
		t.Fatal("the sequence floor was reset by a document that carried none")
	}
}

// A burst of assertions naming a key nobody published must cost one request,
// not one per assertion: otherwise an attacker points this resolver at the
// issuer it trusts and uses it as an amplifier.
func TestConcurrentResolutionsCoalesceIntoOneFetch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks := newKeyServer(t, jwksFor(map[string]ed25519.PublicKey{"k1": pub}))
	ks.delay = 50 * time.Millisecond

	j := resolverFor(t, ks, "https://idp.example.org", jose.WithCacheTTL(time.Hour))

	assertion := signed(t, priv, "k1")
	var wg sync.WaitGroup
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := j.VerifySignature(context.Background(), "https://idp.example.org", assertion); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if got := ks.hits.Load(); got != 1 {
		t.Errorf("25 concurrent resolutions caused %d fetches, want 1", got)
	}
}
