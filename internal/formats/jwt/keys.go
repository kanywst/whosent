package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kanywst/whosent/internal/trust"
	"github.com/kanywst/whosent/pkg/chain"
)

// algorithms is every signature algorithm whosent verifies. Public-key
// algorithms only: alg "none" signs nothing, and an HMAC can be checked
// only by someone who could also forge it.
var algorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

func allowedAlg(alg string) bool {
	for _, a := range algorithms {
		if string(a) == alg {
			return true
		}
	}
	return false
}

func algNames() []string {
	out := make([]string, len(algorithms))
	for i, a := range algorithms {
		out[i] = string(a)
	}
	return out
}

// issuerKeys are the verification keys configured for one issuer.
type issuerKeys struct {
	Source string
	Keys   []jose.JSONWebKey
	// Skipped says which entries of the document were not usable, and why.
	Skipped []string
	// Err is set when the document could not be fetched or held no usable
	// key: every token that issuer signed then fails to verify, as it would
	// at an enforcement point configured the same way.
	Err string
}

// keyring maps issuers to their keys. Which document belongs to which
// issuer is configuration; it is never read from a token.
type keyring map[string]*issuerKeys

// loadKeys reads the key sources named on the command line.
func loadKeys(ctx context.Context, in chain.Inputs) (keyring, error) {
	var sources []trust.Source
	if in.TrustFile != "" {
		s, err := trust.ReadFile(in.TrustFile)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s...)
	}
	for _, v := range in.JWKS {
		s, err := trust.ParseFlag(v)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	if len(sources) == 0 {
		return nil, nil
	}
	docs, err := trust.Loader{}.LoadDocuments(ctx, sources)
	if err != nil {
		return nil, err
	}
	kr := keyring{}
	for _, d := range docs {
		ik := &issuerKeys{Source: d.Source, Err: d.Err}
		if d.Err == "" {
			ik.Keys, ik.Skipped, err = parseJWKS(d.Data)
			if err != nil {
				ik.Err = err.Error()
			}
		}
		kr[d.Issuer] = ik
	}
	return kr, nil
}

// parseJWKS reads a JWK Set (RFC 7517 section 5) and keeps the keys that can
// verify a signature: public RSA, EC and OKP keys meant for signing. Each
// entry is read on its own, so one key whosent cannot use does not hide the
// others, and the report says what was skipped.
func parseJWKS(data []byte) ([]jose.JSONWebKey, []string, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("the key document is not a JWK Set: %w", err)
	}
	var keys []jose.JSONWebKey
	var skipped []string
	kids := map[string]bool{}
	for i, raw := range doc.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil {
			skipped = append(skipped, fmt.Sprintf("key %d: %v", i, err))
			continue
		}
		label := k.KeyID
		if label == "" {
			label = fmt.Sprintf("key %d", i)
		}
		var ops struct {
			KeyOps []string `json:"key_ops"`
		}
		_ = json.Unmarshal(raw, &ops)
		switch {
		case k.Use != "" && k.Use != "sig":
			skipped = append(skipped, fmt.Sprintf("%s: use %q, not sig", label, k.Use))
			continue
		case len(ops.KeyOps) > 0 && !slices.Contains(ops.KeyOps, "verify"):
			// RFC 7517 section 4.3: key_ops lists what the key is for. A key
			// that does not list verify is not for checking signatures,
			// which is also how the Mandatum loader reads it.
			skipped = append(skipped, fmt.Sprintf("%s: key_ops %v does not include verify", label, ops.KeyOps))
			continue
		case !k.Valid():
			skipped = append(skipped, label+": not a valid key")
			continue
		}
		switch key := k.Key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			// A key document should never carry private keys. The public
			// half still verifies, but the report has to say so.
			pub := k.Public()
			k = pub
			skipped = append(skipped, label+": the document carries a private key; only its public half is used")
		case []byte:
			skipped = append(skipped, label+": a symmetric key cannot check a public-key signature")
			continue
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		default:
			skipped = append(skipped, fmt.Sprintf("%s: unsupported key type %T", label, key))
			continue
		}
		if k.KeyID != "" {
			if kids[k.KeyID] {
				return nil, skipped, fmt.Errorf("kid %q appears twice; a verifier could not tell which key is meant", k.KeyID)
			}
			kids[k.KeyID] = true
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, skipped, errors.New("the key document holds no usable signing key")
	}
	return keys, skipped, nil
}

// sigResult is what checking one token's signature established.
type sigResult struct {
	Status chain.Status
	Detail string
	// Key names the key that verified, for the report.
	Key string
}

// verifySig checks a token's signature against the keys configured for the
// issuer it names. A token whose issuer has no keys configured is
// unchecked, not failed: supplying the keys would check it.
func (kr keyring) verifySig(t *token) sigResult {
	if t.Problem != "" {
		return sigResult{Status: chain.StatusSkipped, Detail: "not checked: the token cannot be read"}
	}
	ik := kr[t.Iss]
	if ik == nil {
		return sigResult{Status: chain.StatusUnchecked, Detail: fmt.Sprintf("no keys for issuer %q; pass --jwks %s=PATH", t.Iss, issuerForFlag(t.Iss))}
	}
	if ik.Err != "" {
		return sigResult{Status: chain.StatusError, Detail: "keys for this issuer could not be used: " + ik.Err}
	}
	var candidates []jose.JSONWebKey
	for _, k := range ik.Keys {
		if t.Kid != "" && k.KeyID != t.Kid {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != t.Alg {
			continue
		}
		candidates = append(candidates, k)
	}
	switch {
	case len(candidates) == 0 && t.Kid != "":
		return sigResult{Status: chain.StatusFail, Detail: fmt.Sprintf("the issuer publishes no %s key with kid %q", t.Alg, t.Kid)}
	case len(candidates) == 0:
		return sigResult{Status: chain.StatusFail, Detail: fmt.Sprintf("the issuer publishes no key for alg %s", t.Alg)}
	case len(candidates) > 1 && t.Kid == "":
		return sigResult{Status: chain.StatusFail, Detail: "the token names no kid and the issuer publishes several keys; a verifier could not tell which is meant"}
	}
	key := candidates[0]
	jws, err := jose.ParseSigned(t.Raw, algorithms)
	if err != nil {
		return sigResult{Status: chain.StatusFail, Detail: "the signature cannot be read: " + err.Error()}
	}
	if len(jws.Signatures) != 1 {
		return sigResult{Status: chain.StatusFail, Detail: "a compact JWS carries exactly one signature"}
	}
	if _, err := jws.Verify(key.Key); err != nil {
		return sigResult{Status: chain.StatusFail, Detail: "the signature does not verify against " + keyLabel(ik, key)}
	}
	return sigResult{Status: chain.StatusPass, Detail: "verified with " + keyLabel(ik, key), Key: keyLabel(ik, key)}
}

func keyLabel(ik *issuerKeys, k jose.JSONWebKey) string {
	if k.KeyID != "" {
		return ik.Source + " kid " + k.KeyID
	}
	return ik.Source
}

// issuerForFlag shows an issuer the way it would be typed on the command
// line, quoting it when it would not survive a shell.
func issuerForFlag(iss string) string {
	if iss == "" {
		return "ISSUER"
	}
	if strings.ContainsAny(iss, " \t'\"$`\\;&|<>()") {
		return "'" + strings.ReplaceAll(iss, "'", `'\''`) + "'"
	}
	return iss
}

// summary lists the configured issuers for the report.
func (kr keyring) summary() []chain.KV {
	if len(kr) == 0 {
		return []chain.KV{{Key: "keys", Value: "none given: signatures were not checked", Tone: chain.ToneWarn}}
	}
	names := make([]string, 0, len(kr))
	for n := range kr {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []chain.KV
	for i, n := range names {
		ik := kr[n]
		key := ""
		if i == 0 {
			key = "keys"
		}
		v := n + "  " + ik.Source
		tone := chain.ToneText
		if ik.Err != "" {
			v += "  (unusable: " + ik.Err + ")"
			tone = chain.ToneBad
		} else {
			var kids []string
			for _, k := range ik.Keys {
				if k.KeyID != "" {
					kids = append(kids, k.KeyID)
				}
			}
			if len(kids) > 0 {
				v += "  " + strings.Join(kids, ", ")
			}
		}
		out = append(out, chain.KV{Key: key, Value: v, Tone: tone})
	}
	return out
}
