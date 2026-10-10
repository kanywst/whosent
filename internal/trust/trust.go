// Package trust loads verification keys for the issuers a chain is checked
// against: from a trust file, from --jwks flags, from local JWKS documents or
// from https URLs.
//
// Keys are read the way mandatum's own JWKS resolver reads them (which keys
// are usable, what makes a document unusable), so that a chain this tool
// shows as signed is a chain an enforcement point using that resolver
// accepts. A test serves the same documents to the library's resolver and
// compares.
package trust

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// The same bounds the library's resolver applies to a key document.
const (
	fetchTimeout = 5 * time.Second
	maxBytes     = 1 << 20
)

// Source names where one issuer's keys come from: a local file or an https
// URL.
type Source struct {
	Issuer   string
	Location string
}

// IsURL reports whether the source is fetched rather than read.
func (s Source) IsURL() bool {
	return strings.HasPrefix(s.Location, "https://") || strings.HasPrefix(s.Location, "http://")
}

// ParseFlag parses one --jwks value, ISSUER=PATH or ISSUER=URL. The split is
// at the first "=", since an issuer identifier never contains one and a URL's
// query string may.
func ParseFlag(v string) (Source, error) {
	iss, loc, ok := strings.Cut(v, "=")
	if !ok || iss == "" || loc == "" {
		return Source{}, fmt.Errorf("--jwks %q: want ISSUER=PATH or ISSUER=https://URL", v)
	}
	return Source{Issuer: iss, Location: loc}, nil
}

// File is the trust file format:
//
//	{"issuers": {
//	   "https://idp.example.org": {"jwks_file": "jwks/idp.json"},
//	   "spiffe://example.org/ns/agents/planner": {"jwks_url": "https://..."}
//	}}
//
// A relative jwks_file is resolved against the trust file's directory, so a
// fixture directory can be moved as a whole.
type File struct {
	Issuers map[string]FileIssuer `json:"issuers"`
}

// FileIssuer is one issuer's entry in a trust file.
type FileIssuer struct {
	JWKSFile string `json:"jwks_file,omitempty"`
	JWKSURL  string `json:"jwks_url,omitempty"`
}

// ReadFile reads a trust file into sources.
func ReadFile(path string) ([]Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust file: %w", err)
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing trust file %s: %w", path, err)
	}
	issuers := make([]string, 0, len(f.Issuers))
	for iss := range f.Issuers {
		issuers = append(issuers, iss)
	}
	sort.Strings(issuers)
	var out []Source
	for _, iss := range issuers {
		e := f.Issuers[iss]
		switch {
		case e.JWKSFile != "" && e.JWKSURL != "":
			return nil, fmt.Errorf("trust file %s: issuer %q names both jwks_file and jwks_url; give one", path, iss)
		case e.JWKSFile != "":
			loc := e.JWKSFile
			if !filepath.IsAbs(loc) {
				loc = filepath.Join(filepath.Dir(path), loc)
			}
			out = append(out, Source{Issuer: iss, Location: loc})
		case e.JWKSURL != "":
			out = append(out, Source{Issuer: iss, Location: e.JWKSURL})
		default:
			return nil, fmt.Errorf("trust file %s: issuer %q names neither jwks_file nor jwks_url", path, iss)
		}
	}
	return out, nil
}

// Loader fetches and reads key documents.
type Loader struct {
	// Client is used for https sources. Nil means a client with the
	// library's 5 second timeout.
	Client *http.Client
}

// Load reads every source into a diagnose.Trust.
//
// A local file that cannot be read is an error: it is almost always a typo,
// and answering it with "no key" would send someone chasing the wrong
// problem. A document that is read but cannot be used, or a URL that cannot
// be fetched, is recorded against the issuer instead, so every link that
// issuer signed shows as an Error: an enforcement point configured the same
// way would deny those links, and that is what the report has to say.
func (l Loader) Load(ctx context.Context, sources []Source) (*diagnose.Trust, error) {
	t := &diagnose.Trust{Issuers: map[string]*diagnose.IssuerKeys{}}
	for _, s := range sources {
		if _, dup := t.Issuers[s.Issuer]; dup {
			return nil, fmt.Errorf("keys for %q are configured twice; give each issuer one source", s.Issuer)
		}
		if strings.HasPrefix(s.Location, "http://") {
			// Refused as configuration, the way the library's AddSource
			// refuses it, rather than recorded as a key that failed to load.
			return nil, fmt.Errorf("keys for %q: %s is plaintext; key sources must be https", s.Issuer, s.Location)
		}
		ik := &diagnose.IssuerKeys{Source: s.Location}
		var data []byte
		var err error
		if s.IsURL() {
			data, err = l.fetch(ctx, s.Location)
		} else {
			ik.Source = filepath.Base(s.Location)
			data, err = os.ReadFile(s.Location)
			if err != nil {
				return nil, fmt.Errorf("reading keys for %q: %w", s.Issuer, err)
			}
		}
		if err == nil {
			ik.Keys, ik.Skipped, err = ParseDocument(data)
		}
		if err != nil {
			ik.Err = err.Error()
		}
		t.Issuers[s.Issuer] = ik
	}
	return t, nil
}

func (l Loader) fetch(ctx context.Context, src string) ([]byte, error) {
	u, err := url.Parse(src)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		// The library refuses plaintext key sources outright. A key document
		// fetched over plaintext is a forged chain waiting for a network
		// position.
		return nil, fmt.Errorf("key source must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("key source has no host")
	}
	client := &http.Client{Timeout: fetchTimeout}
	if l.Client != nil {
		c := *l.Client
		client = &c
	}
	// The https rule has to hold for every hop, not only the first. The
	// default client follows a redirect from https to plaintext, which would
	// make "key sources must be https" true only of the URL someone typed.
	// mandatum's own resolver follows such a redirect; refusing it here can
	// only turn a pass into an Error, never the other way round.
	client.CheckRedirect = checkRedirect
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching keys: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading keys: %w", err)
	}
	if len(body) > maxBytes {
		return nil, fmt.Errorf("key document is larger than %d bytes", maxBytes)
	}
	return body, nil
}

// maxRedirects bounds how many redirects a key fetch follows.
const maxRedirects = 5

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirected to %s, which is not https; key sources must be https at every hop", req.URL.Redacted())
	}
	return nil
}

type jwk struct {
	KeyType   string   `json:"kty"`
	Curve     string   `json:"crv"`
	X         string   `json:"x"`
	KeyID     string   `json:"kid"`
	Use       string   `json:"use"`
	Algorithm string   `json:"alg"`
	KeyOps    []string `json:"key_ops"`
}

// document mirrors the library's jwksDocument field for field. The
// spiffe_sequence member matters even though nothing here reads it: the
// library decodes it as a uint64, so a document where it is negative, a
// string or a fraction fails to decode and the library denies every link
// that issuer signed. Leaving it out would accept that document and show
// those signatures as passing.
type document struct {
	Keys           []jwk  `json:"keys"`
	SPIFFESequence uint64 `json:"spiffe_sequence"`
}

// ParseDocument reads a JWKS (or a SPIFFE bundle, which is a JWKS with extra
// members) the way mandatum's resolver does: unusable keys are skipped, a
// document with no usable key is refused, a key without a kid among several
// is refused, two different keys under one kid are refused, and a document
// with exactly one usable key also serves it as the issuer's default.
//
// Unlike the library, it says which keys it skipped and why. The library is
// silent about them, which is right for an enforcement point and unhelpful
// to someone working out why a rotation did not take.
func ParseDocument(data []byte) (map[string]ed25519.PublicKey, []string, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing keys: %w", err)
	}
	type identified struct {
		kid string
		key ed25519.PublicKey
	}
	var usable []identified
	var skipped []string
	for i, k := range doc.Keys {
		key, why := k.ed25519Key()
		if why != "" {
			name := k.KeyID
			if name == "" {
				name = fmt.Sprintf("keys[%d]", i)
			}
			skipped = append(skipped, name+": "+why)
			continue
		}
		usable = append(usable, identified{kid: k.KeyID, key: key})
	}
	if len(usable) == 0 {
		return nil, skipped, errors.New("the key document has no Ed25519 keys this verifier can use")
	}
	keys := map[string]ed25519.PublicKey{}
	for _, u := range usable {
		if u.kid == "" && len(usable) > 1 {
			return nil, skipped, fmt.Errorf("the key document has an unidentified key among %d", len(usable))
		}
		if existing, clash := keys[u.kid]; clash && !existing.Equal(u.key) {
			return nil, skipped, fmt.Errorf("the key document has two different keys with kid %q", u.kid)
		}
		keys[u.kid] = u.key
	}
	if len(usable) == 1 {
		keys[""] = usable[0].key
	}
	return keys, skipped, nil
}

// ed25519Key mirrors the library's rules for a usable key, returning why a
// key is not usable rather than only that it is not.
func (k jwk) ed25519Key() (ed25519.PublicKey, string) {
	if k.KeyType != "OKP" || k.Curve != "Ed25519" {
		return nil, fmt.Sprintf("kty %q crv %q is not an Ed25519 key", k.KeyType, k.Curve)
	}
	if k.Algorithm != "" && k.Algorithm != "EdDSA" {
		return nil, fmt.Sprintf("alg %q is not EdDSA", k.Algorithm)
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Sprintf("use %q is not sig", k.Use)
	}
	if len(k.KeyOps) > 0 {
		permitted := false
		for _, op := range k.KeyOps {
			if op == "verify" {
				permitted = true
				break
			}
		}
		if !permitted {
			return nil, "key_ops does not include verify"
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "x is not a 32-byte base64url key"
	}
	return ed25519.PublicKey(raw), ""
}
