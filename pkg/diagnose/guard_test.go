package diagnose_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// The guard is the reason a reader can trust this tool's explanation: it
// runs mandatum's verifier on the same inputs and checks the first failure
// agrees. These tests try hard to make the two disagree, by mutating chains
// in every way that reaches a different rule, under every combination of
// inputs, and fail on any disagreement.

type mutation struct {
	name  string
	apply func([][]byte) [][]byte
}

func clone(links [][]byte) [][]byte {
	out := make([][]byte, len(links))
	for i, l := range links {
		out[i] = append([]byte(nil), l...)
	}
	return out
}

// resign edits link i's claims and signs them again with the issuer's own
// key, so the edit reaches the rule it is about instead of stopping at V3.
func resign(i int, edit func(*mda.Claims)) func([][]byte) [][]byte {
	return func(links [][]byte) [][]byte {
		out := clone(links)
		if i >= len(out) {
			return out
		}
		c, err := mda.ParseClaims(out[i])
		if err != nil {
			return out
		}
		edit(&c)
		key, kid, ok := demo.Key(c.Issuer)
		if !ok {
			key, kid, _ = demo.Key(demo.Mallory)
		}
		raw, err := jose.Sign(c, key, kid)
		if err != nil {
			return out
		}
		out[i] = raw
		return out
	}
}

func mutations(n int) []mutation {
	var ms []mutation
	ms = append(ms, mutation{"unchanged", func(l [][]byte) [][]byte { return clone(l) }})
	for i := 0; i < n; i++ {
		i := i
		for _, pos := range []float64{0, 0.1, 0.25, 0.5, 0.75, 0.9, 1} {
			pos := pos
			ms = append(ms, mutation{fmt.Sprintf("flip link %d at %.0f%%", i, pos*100), func(l [][]byte) [][]byte {
				out := clone(l)
				p := int(pos * float64(len(out[i])-1))
				out[i][p] ^= 0x01
				return out
			}})
		}
		ms = append(ms,
			mutation{fmt.Sprintf("drop link %d", i), func(l [][]byte) [][]byte {
				out := clone(l)
				return append(out[:i], out[i+1:]...)
			}},
			mutation{fmt.Sprintf("duplicate link %d", i), func(l [][]byte) [][]byte {
				out := clone(l)
				return append(out[:i+1], out[i:]...)
			}},
			mutation{fmt.Sprintf("empty link %d", i), func(l [][]byte) [][]byte {
				out := clone(l)
				out[i] = nil
				return out
			}},
			mutation{fmt.Sprintf("garbage link %d", i), func(l [][]byte) [][]byte {
				out := clone(l)
				out[i] = []byte("not.a.jws")
				return out
			}},
			mutation{fmt.Sprintf("truncate link %d", i), func(l [][]byte) [][]byte {
				out := clone(l)
				out[i] = out[i][:len(out[i])/2]
				return out
			}},
		)
		edits := map[string]func(*mda.Claims){
			"exp +1h":           func(c *mda.Claims) { c.ExpiresAt += 3600 },
			"exp in the past":   func(c *mda.Claims) { c.ExpiresAt = c.IssuedAt - 60 },
			"iat in the future": func(c *mda.Claims) { c.IssuedAt += 7200 },
			"exp at skew edge":  func(c *mda.Claims) { c.ExpiresAt = demo.FixedBase.Add(time.Minute).Unix() + 10 },
			"max_depth +5":      func(c *mda.Claims) { c.Mandatum.MaxDepth += 5 },
			"max_depth -1":      func(c *mda.Claims) { c.Mandatum.MaxDepth = -1 },
			"aud changed":       func(c *mda.Claims) { c.Audience = "https://elsewhere.example.org" },
			"aud empty":         func(c *mda.Claims) { c.Audience = "" },
			"cap added": func(c *mda.Claims) {
				c.Mandatum.Capabilities = append(c.Mandatum.Capabilities, mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "*"}, Action: mda.ActionPattern{Name: "invoke"}})
			},
			"caps emptied": func(c *mda.Claims) { c.Mandatum.Capabilities = []mda.Capability{} },
			"caps nil":     func(c *mda.Claims) { c.Mandatum.Capabilities = nil },
			"condition dropped": func(c *mda.Claims) {
				for j := range c.Mandatum.Capabilities {
					c.Mandatum.Capabilities[j].Conditions = nil
				}
			},
			"tags dropped": func(c *mda.Claims) {
				for j := range c.Mandatum.Capabilities {
					c.Mandatum.Capabilities[j].Resource.Tags = nil
				}
			},
			"depth +1":       func(c *mda.Claims) { c.Mandatum.Depth++ },
			"parent cleared": func(c *mda.Claims) { c.Mandatum.Parent = "" },
			"parent garbage": func(c *mda.Claims) { c.Mandatum.Parent = "sha-256:AAAA" },
			"amr reversed": func(c *mda.Claims) {
				a := c.Mandatum.Root.AuthenticationMethods
				for x, y := 0, len(a)-1; x < y; x, y = x+1, y-1 {
					a[x], a[y] = a[y], a[x]
				}
			},
			"sponsor changed":   func(c *mda.Claims) { c.Mandatum.Root.Subject = "mallory@example.org" },
			"auth_time changed": func(c *mda.Claims) { c.Mandatum.Root.AuthenticatedAt++ },
			"jti empty":         func(c *mda.Claims) { c.ID = "" },
			"jti changed":       func(c *mda.Claims) { c.ID = "dlg-planner-002" },
			"seq dropped":       func(c *mda.Claims) { c.Mandatum.Sequence = nil },
			"seq budget raised": func(c *mda.Claims) {
				if c.Mandatum.Sequence != nil {
					c.Mandatum.Sequence.MaxInvocations = 9999
				}
			},
			"seq budget removed": func(c *mda.Claims) {
				if c.Mandatum.Sequence != nil {
					c.Mandatum.Sequence.MaxInvocations = 0
				}
			},
			"seq constraint redefined": func(c *mda.Claims) {
				if s := c.Mandatum.Sequence; s != nil && len(s.Constraints) > 0 {
					s.Constraints[0].Forbid.Action = "x"
				}
			},
			"seq constraint dropped": func(c *mda.Claims) {
				if s := c.Mandatum.Sequence; s != nil && len(s.Constraints) > 0 {
					s.Constraints = s.Constraints[1:]
					if len(s.Constraints) == 0 && s.MaxInvocations == 0 {
						s.MaxInvocations = 1
					}
				}
			},
			"issuer changed":  func(c *mda.Claims) { c.Issuer = demo.Mallory },
			"subject changed": func(c *mda.Claims) { c.Subject = demo.Mallory },
			"version 2":       func(c *mda.Claims) { c.Mandatum.Version = 2 },
		}
		for name, edit := range edits {
			ms = append(ms, mutation{fmt.Sprintf("re-signed link %d: %s", i, name), resign(i, edit)})
		}
	}
	if n > 1 {
		ms = append(ms,
			mutation{"reverse", func(l [][]byte) [][]byte { return diagnose.Reverse(clone(l)) }},
			mutation{"swap first two", func(l [][]byte) [][]byte {
				out := clone(l)
				out[0], out[1] = out[1], out[0]
				return out
			}},
			mutation{"leaf alone", func(l [][]byte) [][]byte { return clone(l)[n-1:] }},
		)
	}
	ms = append(ms, mutation{"no links", func([][]byte) [][]byte { return nil }})
	return ms
}

type variant struct {
	name string
	opts func(diagnose.Options) diagnose.Options
}

func variants(s demo.Scenario) []variant {
	vs := []variant{
		{"as given", func(o diagnose.Options) diagnose.Options { return o }},
		{"no trust", func(o diagnose.Options) diagnose.Options { o.Trust = nil; return o }},
		{"no revocation", func(o diagnose.Options) diagnose.Options { o.Revocation = nil; return o }},
		{"no audience", func(o diagnose.Options) diagnose.Options { o.Audience = nil; return o }},
		{"nothing", func(o diagnose.Options) diagnose.Options { return diagnose.Options{At: o.At} }},
		{"zero skew", func(o diagnose.Options) diagnose.Options { z := time.Duration(0); o.Skew = &z; return o }},
		{"two days on", func(o diagnose.Options) diagnose.Options { return o.WithAt(o.At.Add(48 * time.Hour)) }},
		{"broken key document", func(o diagnose.Options) diagnose.Options {
			if o.Trust == nil {
				return o
			}
			t := &diagnose.Trust{Issuers: map[string]*diagnose.IssuerKeys{}}
			for k, v := range o.Trust.Issuers {
				t.Issuers[k] = v
			}
			t.Issuers[demo.Planner] = &diagnose.IssuerKeys{Source: "planner.json", Err: "the key document has no Ed25519 keys this verifier can use"}
			o.Trust = t
			return o
		}},
		{"simulate revoking the grant", func(o diagnose.Options) diagnose.Options {
			return o.WithSimulatedRevocations([]string{"grant-alice-001"})
		}},
	}
	_ = s
	return vs
}

func TestGuardNeverDisagreesWithMandatum(t *testing.T) {
	all, err := demo.All(demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		// Two scenarios still reach every rule; the full matrix is for CI.
		all = []demo.Scenario{all[0], all[9]}
	}
	runs := 0
	for _, s := range all {
		for _, m := range mutations(len(s.Links)) {
			links := m.apply(s.Links)
			for _, v := range variants(s) {
				r, err := diagnose.Diagnose(context.Background(), links, v.opts(s.Options))
				if err != nil {
					t.Fatalf("%s / %s / %s: %v", s.Name, m.name, v.name, err)
				}
				runs++
				if !r.Library.Consistent {
					t.Errorf("%s / %s / %s: %s", s.Name, m.name, v.name, r.Library.Mismatch)
				}
				checkInvariants(t, fmt.Sprintf("%s / %s / %s", s.Name, m.name, v.name), r)
			}
		}
	}
	t.Logf("%d diagnoses, all consistent with mandatum", runs)
}

// checkInvariants asserts what must hold for any report whatsoever.
func checkInvariants(t *testing.T, where string, r *diagnose.Report) {
	t.Helper()
	blocking, unchecked := false, false
	for _, f := range r.Findings() {
		if f.Derived {
			continue
		}
		if f.Severity.Blocking() {
			blocking = true
		}
		if f.Severity == diagnose.SeverityUnchecked {
			unchecked = true
		}
	}
	switch {
	case blocking && r.Verdict != diagnose.VerdictInvalid:
		t.Errorf("%s: blocking findings but verdict %s", where, r.Verdict)
	case !blocking && unchecked && r.Verdict != diagnose.VerdictIncomplete:
		t.Errorf("%s: unchecked findings but verdict %s", where, r.Verdict)
	}
	if r.Verdict == diagnose.VerdictValid && r.Result == nil {
		t.Errorf("%s: VALID without a result", where)
	}
	if r.Verdict != diagnose.VerdictValid && r.Result != nil {
		t.Errorf("%s: %s with a result", where, r.Verdict)
	}
	if r.Verdict == diagnose.VerdictValid && !r.Library.Passed {
		t.Errorf("%s: VALID but mandatum refused it", where)
	}
	for _, l := range r.Links {
		for _, c := range l.Checks {
			if c.Status == diagnose.StatusPass && l.Claims == nil {
				t.Errorf("%s: link %d %s passes though the link does not parse", where, l.Index, c.Rule)
			}
		}
		if l.Unreached != (r.BreakAt >= 0 && l.Index > r.BreakAt) {
			t.Errorf("%s: link %d unreached=%v with BreakAt %d", where, l.Index, l.Unreached, r.BreakAt)
		}
	}
	if len(r.Hops) != max(len(r.Links)-1, 0) {
		t.Errorf("%s: %d hops for %d links", where, len(r.Hops), len(r.Links))
	}
	for _, row := range r.Matrix.Rows {
		if len(row.Cells) != len(r.Links) {
			t.Errorf("%s: matrix row %q has %d cells for %d links", where, row.Label, len(row.Cells), len(r.Links))
		}
	}
	_ = r.JSON()
}

// FuzzGuard drives arbitrary mutations of the healthy and widened chains
// from fuzz input: which link, which byte, what value, and when.
func FuzzGuard(f *testing.F) {
	healthy, err := demo.Build("healthy", demo.FixedBase)
	if err != nil {
		f.Fatal(err)
	}
	widened, err := demo.Build("widened", demo.FixedBase)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0, 0, 10, 0, 1, 5})
	f.Add([]byte{1, 2, 200, 1, 0xff, 0})
	f.Add([]byte{0, 1, 0, 0, '.', 99})
	f.Fuzz(func(t *testing.T, data []byte) {
		s := healthy
		if len(data) > 0 && data[0]%2 == 1 {
			s = widened
		}
		links := clone(s.Links)
		for len(data) >= 4 {
			i := int(data[1]) % len(links)
			if len(links[i]) > 0 {
				p := int(binary.BigEndian.Uint16([]byte{data[2], data[3]})) % len(links[i])
				if len(data) >= 5 {
					links[i][p] = data[4]
				}
			}
			data = data[min(5, len(data)):]
		}
		at := s.Options.At
		if len(data) > 0 {
			at = at.Add(time.Duration(int8(data[0])) * time.Minute)
		}
		r, err := diagnose.Diagnose(context.Background(), links, s.Options.WithAt(at))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Library.Consistent {
			t.Fatalf("guard: %s", r.Library.Mismatch)
		}
		checkInvariants(t, "fuzz", r)
	})
}
