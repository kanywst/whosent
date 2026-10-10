package biscuit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/pkg/chain"
)

// The specification's samples are the reference implementation's own
// answers: for every token, how each block prints, and for every
// authorizer, which policy matched, which checks failed and in what order,
// and which facts the world held. This test holds whosent's decoder,
// verifier, printer and Datalog engine to all of them.

type sampleFile struct {
	RootPublicKey string       `json:"root_public_key"`
	Testcases     []sampleCase `json:"testcases"`
}

type sampleCase struct {
	Title       string                      `json:"title"`
	Filename    string                      `json:"filename"`
	Token       []sampleBlock               `json:"token"`
	Validations map[string]sampleValidation `json:"validations"`
}

type sampleBlock struct {
	Symbols     []string `json:"symbols"`
	PublicKeys  []string `json:"public_keys"`
	ExternalKey *string  `json:"external_key"`
	Code        string   `json:"code"`
	Version     uint32   `json:"version"`
}

type sampleValidation struct {
	World          *sampleWorld    `json:"world"`
	Result         json.RawMessage `json:"result"`
	AuthorizerCode string          `json:"authorizer_code"`
	RevocationIDs  []string        `json:"revocation_ids"`
}

type sampleWorld struct {
	Facts []struct {
		Origin []*int   `json:"origin"`
		Facts  []string `json:"facts"`
	} `json:"facts"`
}

func loadSamples(t *testing.T) sampleFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "samples", "samples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sf sampleFile
	if err := json.Unmarshal(data, &sf); err != nil {
		t.Fatal(err)
	}
	if len(sf.Testcases) < 38 {
		t.Fatalf("only %d sample cases; the corpus has 38", len(sf.Testcases))
	}
	return sf
}

func sampleRoot(t *testing.T, sf sampleFile) Key {
	t.Helper()
	b, err := hex.DecodeString(sf.RootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(datalog.PublicKey{Alg: datalog.Ed25519, Key: b})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func readSample(t *testing.T, name string) *Token {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "samples", name))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Decode(data)
	if err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return tok
}

// formatError reports whether the reference refused the token before any
// Datalog ran.
func formatError(result json.RawMessage) (string, bool) {
	var r struct {
		Err map[string]json.RawMessage `json:"Err"`
	}
	if json.Unmarshal(result, &r) != nil || r.Err == nil {
		return "", false
	}
	if f, ok := r.Err["Format"]; ok {
		return string(f), true
	}
	return "", false
}

func blockingRules(a *analysis) map[string]bool {
	out := map[string]bool{}
	for _, br := range a.blocks {
		for _, c := range br.checks {
			if c.Status.Blocking() {
				out[c.Rule] = true
			}
		}
	}
	return out
}

func TestSamplesDecodeVerifyAndPrintAsTheReferenceDoes(t *testing.T) {
	sf := loadSamples(t)
	root := sampleRoot(t, sf)
	for _, tc := range sf.Testcases {
		t.Run(tc.Filename, func(t *testing.T) {
			tok := readSample(t, tc.Filename)
			if len(tok.Blocks) != len(tc.Token) {
				t.Fatalf("%d blocks, the sample has %d", len(tok.Blocks), len(tc.Token))
			}
			a := analyze(tok, Options{RootKeys: []Key{root}, Limits: datalog.DefaultLimits}, time.Unix(0, 0), nil)
			for _, v := range tc.Validations {
				if want := v.RevocationIDs; len(want) > 0 {
					var got []string
					for _, br := range a.blocks {
						got = append(got, br.revokeID)
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("revocation ids\n got %v\nwant %v", got, want)
					}
				}
				refused, isFormat := formatError(v.Result)
				blocking := blockingRules(a)
				for _, r := range []string{RuleFormat, RuleVersion, RuleSignature, RuleThirdParty, RuleProof, RuleSymbols} {
					if blocking[r] && !isFormat {
						t.Errorf("rule %s fails, but the reference accepts the token", r)
					}
				}
				if isFormat && !blocking[RuleSignature] && !blocking[RuleFormat] && !blocking[RuleProof] && !blocking[RuleThirdParty] {
					t.Errorf("the reference refuses the token (%s), but no structural rule fails", refused)
				}
			}
			if _, isFormat := formatError(tc.Validations[firstKey(tc.Validations)].Result); isFormat {
				return
			}
			for i, want := range tc.Token {
				br := a.blocks[i]
				if !br.readable {
					t.Fatalf("block %d did not decode: %+v", i, br.checks)
				}
				if br.source != want.Code {
					t.Errorf("block %d prints\n%s\nthe reference printed\n%s", i, br.source, want.Code)
				}
				if br.block.Version != want.Version {
					t.Errorf("block %d version %d, want %d", i, br.block.Version, want.Version)
				}
				if !equalStrings(br.symbols, want.Symbols) {
					t.Errorf("block %d symbols %q, want %q", i, br.symbols, want.Symbols)
				}
				var keys []string
				for _, k := range br.keys {
					keys = append(keys, k.String())
				}
				if !equalStrings(keys, want.PublicKeys) {
					t.Errorf("block %d public keys %q, want %q", i, keys, want.PublicKeys)
				}
				ext := ""
				if br.signed.External != nil {
					ext = br.signed.External.Key.String()
				}
				if want.ExternalKey != nil && ext != *want.ExternalKey || want.ExternalKey == nil && ext != "" {
					t.Errorf("block %d external key %q, want %v", i, ext, want.ExternalKey)
				}
			}
		})
	}
}

func firstKey(m map[string]sampleValidation) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0]
}

func equalStrings(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

// referenceResult is the reference's answer in a comparable form.
type referenceResult struct {
	ok        bool
	policy    *datalog.PolicyMatch
	failed    []datalog.FailedCheck
	execution string
	invalid   string
	noPolicy  bool
}

func parseResult(t *testing.T, raw json.RawMessage) referenceResult {
	t.Helper()
	var r struct {
		Ok  *int `json:"Ok"`
		Err *struct {
			FailedLogic *struct {
				Unauthorized *struct {
					Policy map[string]int            `json:"policy"`
					Checks []map[string]sampleFailed `json:"checks"`
				} `json:"Unauthorized"`
				NoMatchingPolicy *struct {
					Checks []map[string]sampleFailed `json:"checks"`
				} `json:"NoMatchingPolicy"`
				InvalidBlockRule []json.RawMessage `json:"InvalidBlockRule"`
			} `json:"FailedLogic"`
			Execution *string `json:"Execution"`
		} `json:"Err"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("result %s: %v", raw, err)
	}
	var out referenceResult
	checks := func(cs []map[string]sampleFailed) {
		for _, c := range cs {
			for kind, f := range c {
				fc := datalog.FailedCheck{Block: -1, Check: f.CheckID, Rule: f.Rule}
				if kind == "Block" {
					fc.Block = f.BlockID
				}
				out.failed = append(out.failed, fc)
			}
		}
	}
	switch {
	case r.Ok != nil:
		out.ok = true
		out.policy = &datalog.PolicyMatch{Index: *r.Ok, Allow: true}
	case r.Err != nil && r.Err.Execution != nil:
		out.execution = *r.Err.Execution
	case r.Err != nil && r.Err.FailedLogic != nil && r.Err.FailedLogic.Unauthorized != nil:
		u := r.Err.FailedLogic.Unauthorized
		for kind, i := range u.Policy {
			out.policy = &datalog.PolicyMatch{Index: i, Allow: kind == "Allow"}
		}
		checks(u.Checks)
	case r.Err != nil && r.Err.FailedLogic != nil && r.Err.FailedLogic.NoMatchingPolicy != nil:
		out.noPolicy = true
		checks(r.Err.FailedLogic.NoMatchingPolicy.Checks)
	case r.Err != nil && r.Err.FailedLogic != nil && r.Err.FailedLogic.InvalidBlockRule != nil:
		var rule string
		if len(r.Err.FailedLogic.InvalidBlockRule) == 2 {
			_ = json.Unmarshal(r.Err.FailedLogic.InvalidBlockRule[1], &rule)
		}
		out.invalid = rule
	default:
		t.Fatalf("a result shape this test does not know: %s", raw)
	}
	return out
}

type sampleFailed struct {
	BlockID int    `json:"block_id"`
	CheckID int    `json:"check_id"`
	Rule    string `json:"rule"`
}

func TestSamplesAuthorizeAsTheReferenceDoes(t *testing.T) {
	sf := loadSamples(t)
	root := sampleRoot(t, sf)
	for _, tc := range sf.Testcases {
		for name, v := range tc.Validations {
			if _, isFormat := formatError(v.Result); isFormat {
				continue
			}
			t.Run(tc.Filename+"/"+name, func(t *testing.T) {
				tok := readSample(t, tc.Filename)
				a := analyze(tok, Options{RootKeys: []Key{root}, Limits: datalog.DefaultLimits}, time.Unix(0, 0), nil)
				if strings.HasPrefix(tc.Filename, "test035") {
					// The external functions this sample calls are the test
					// harness's own code. Nothing outside it can evaluate
					// them, so whosent must say so rather than guess.
					for _, br := range a.blocks {
						if br.status(RuleChecks) != chain.StatusUnchecked {
							t.Errorf("block %d's checks are %s; with external functions they cannot be evaluated", br.index, br.status(RuleChecks))
						}
					}
					return
				}
				prog, err := datalog.ParseProgram(v.AuthorizerCode)
				if err != nil {
					t.Fatalf("parsing the authorizer: %v\n%s", err, v.AuthorizerCode)
				}
				got := datalog.Authorize(a.tokenBlocks(), prog, datalog.DefaultLimits)
				want := parseResult(t, v.Result)
				switch {
				case want.execution != "":
					var ee *datalog.ExprError
					if !asExpr(got.Err, &ee) || ee.Kind != want.execution {
						t.Fatalf("error %v, the reference stopped on %s", got.Err, want.execution)
					}
					return
				case want.invalid != "":
					var ib *datalog.InvalidBlockRuleError
					if !asInvalid(got.Err, &ib) || ib.Rule != want.invalid {
						t.Fatalf("error %v, the reference refused the rule %q", got.Err, want.invalid)
					}
					return
				}
				if got.Err != nil {
					t.Fatalf("authorization stopped: %v", got.Err)
				}
				if fmt.Sprint(got.Failed) != fmt.Sprint(want.failed) {
					t.Errorf("failed checks\n got %v\nwant %v", got.Failed, want.failed)
				}
				switch {
				case want.noPolicy && got.Policy != nil:
					t.Errorf("policy %+v matched; the reference matched none", *got.Policy)
				case !want.noPolicy && (got.Policy == nil || *got.Policy != *want.policy):
					t.Errorf("policy %+v, the reference matched %+v", got.Policy, want.policy)
				}
				if v.World != nil {
					compareWorld(t, got, v.World)
				}
			})
		}
	}
}

func compareWorld(t *testing.T, got datalog.Result, want *sampleWorld) {
	t.Helper()
	gotBy := map[string][]string{}
	for _, of := range got.WorldFacts() {
		var ids []string
		for _, id := range of.Origin.IDs() {
			if id == datalog.AuthorizerID {
				ids = append(ids, "authorizer")
			} else {
				ids = append(ids, fmt.Sprint(id))
			}
		}
		gotBy[strings.Join(ids, ",")] = of.Facts
	}
	wantBy := map[string][]string{}
	for _, of := range want.Facts {
		var ids []string
		var auth bool
		for _, id := range of.Origin {
			if id == nil {
				auth = true
				continue
			}
			ids = append(ids, fmt.Sprint(*id))
		}
		sort.Slice(ids, func(i, j int) bool { return len(ids[i]) < len(ids[j]) || len(ids[i]) == len(ids[j]) && ids[i] < ids[j] })
		if auth {
			ids = append(ids, "authorizer")
		}
		facts := append([]string(nil), of.Facts...)
		sort.Strings(facts)
		wantBy[strings.Join(ids, ",")] = facts
	}
	if !reflect.DeepEqual(gotBy, wantBy) {
		t.Errorf("world facts\n got %v\nwant %v", gotBy, wantBy)
	}
}

func asExpr(err error, target **datalog.ExprError) bool { return errors.As(err, target) }

func asInvalid(err error, target **datalog.InvalidBlockRuleError) bool {
	return errors.As(err, target)
}
