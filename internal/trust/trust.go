// Package trust loads the key documents for the issuers a chain is checked
// against: from a trust file, from --jwks flags, from local JWKS documents or
// from https URLs. Each format parses the documents itself.
package trust

import (
	"context"
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
)

// Bounds on fetching a key document.
const (
	fetchTimeout = 5 * time.Second
	maxBytes     = 1 << 20
)

// Source names where one issuer's keys come from: a local file or an https
// URL. Actor is set for an actor's own keys, the ones it signs actor proofs
// with: an actor is named by the pair (act.iss, act.sub), so Issuer then
// holds act.iss and Actor act.sub. A bare act.sub would let one namespace's
// "planner" stand for another's.
type Source struct {
	Issuer   string
	Location string
	Actor    string
}

// Label names the source in messages: the issuer, or the actor within it.
func (s Source) Label() string {
	if s.Actor == "" {
		return fmt.Sprintf("%q", s.Issuer)
	}
	return fmt.Sprintf("actor %q of %q", s.Actor, s.Issuer)
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
//	 },
//	 "actors": [
//	   {"iss": "https://idp.example.org", "sub": "planner-agent", "jwks_file": "jwks/planner.json"}
//	 ]}
//
// A relative jwks_file is resolved against the trust file's directory, so a
// fixture directory can be moved as a whole. Actors are a list rather than a
// map because an actor is named by two strings, not one.
type File struct {
	Issuers map[string]FileIssuer `json:"issuers"`
	Actors  []FileActor           `json:"actors"`
}

// FileIssuer is one issuer's entry in a trust file.
type FileIssuer struct {
	JWKSFile string `json:"jwks_file,omitempty"`
	JWKSURL  string `json:"jwks_url,omitempty"`
}

// FileActor is one actor's entry: the keys it signs actor proofs with.
type FileActor struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
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
		src, err := source(path, fmt.Sprintf("issuer %q", iss), e.JWKSFile, e.JWKSURL)
		if err != nil {
			return nil, err
		}
		src.Issuer = iss
		out = append(out, src)
	}
	for i, a := range f.Actors {
		if a.Iss == "" || a.Sub == "" {
			return nil, fmt.Errorf("trust file %s: actor %d needs both iss and sub; an actor is named by the pair", path, i)
		}
		src, err := source(path, fmt.Sprintf("actor %q of %q", a.Sub, a.Iss), a.JWKSFile, a.JWKSURL)
		if err != nil {
			return nil, err
		}
		src.Issuer, src.Actor = a.Iss, a.Sub
		out = append(out, src)
	}
	return out, nil
}

// source reads one entry's key location, file or URL.
func source(path, who, file, url string) (Source, error) {
	switch {
	case file != "" && url != "":
		return Source{}, fmt.Errorf("trust file %s: %s names both jwks_file and jwks_url; give one", path, who)
	case file != "":
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		return Source{Location: file}, nil
	case url != "":
		return Source{Location: url}, nil
	}
	return Source{}, fmt.Errorf("trust file %s: %s names neither jwks_file nor jwks_url", path, who)
}

// Loader fetches and reads key documents.
type Loader struct {
	// Client is used for https sources. Nil means a client with the
	// library's 5 second timeout.
	Client *http.Client
}

// Document is one issuer's key document as read, before any format decides
// which keys in it it can use. Err is set, and Data empty, when a URL could
// not be fetched: an enforcement point configured the same way would deny,
// so the report shows it against the issuer rather than refusing to start.
type Document struct {
	Issuer string
	// Actor is the source's Actor: set for an actor's keys.
	Actor string
	// Source is what the report names the document by: the file's base
	// name, or the URL.
	Source string
	Data   []byte
	Err    string
}

// LoadDocuments reads every source, in order: one source per issuer, https
// only (at every redirect), at most a megabyte. A local file that cannot be
// read is an error, since it is almost always a typo; a URL that cannot be
// fetched is recorded against the issuer.
func (l Loader) LoadDocuments(ctx context.Context, sources []Source) ([]Document, error) {
	seen := map[Source]bool{}
	out := make([]Document, 0, len(sources))
	for _, s := range sources {
		k := Source{Issuer: s.Issuer, Actor: s.Actor}
		if seen[k] {
			return nil, fmt.Errorf("keys for %s are configured twice; give each one source", s.Label())
		}
		seen[k] = true
		if strings.HasPrefix(s.Location, "http://") {
			// Refused as configuration, the way the library's AddSource
			// refuses it, rather than recorded as a key that failed to load.
			return nil, fmt.Errorf("keys for %s: %s is plaintext; key sources must be https", s.Label(), s.Location)
		}
		d := Document{Issuer: s.Issuer, Actor: s.Actor, Source: s.Location}
		if s.IsURL() {
			data, err := l.fetch(ctx, s.Location)
			if err != nil {
				d.Err = err.Error()
			}
			d.Data = data
		} else {
			d.Source = filepath.Base(s.Location)
			data, err := os.ReadFile(s.Location)
			if err != nil {
				return nil, fmt.Errorf("reading keys for %s: %w", s.Label(), err)
			}
			d.Data = data
		}
		out = append(out, d)
	}
	return out, nil
}

func (l Loader) fetch(ctx context.Context, src string) ([]byte, error) {
	u, err := url.Parse(src)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		// A key document fetched over plaintext is a forged chain waiting
		// for a network position.
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
