package diagnose_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"

	"github.com/kanywst/whosent/pkg/diagnose"
)

// hostileSized signs n links of m capabilities each, every link granting
// capabilities its parent never held: the shape that makes every hop widen
// and sends every lineage lookup all the way back to the sponsor.
func hostileSized(tb testing.TB, n, m int) [][]byte {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}
	now := time.Now()
	root := mda.Sponsor{Issuer: "idp", Subject: "alice"}
	var out [][]byte
	parent := ""
	for i := 0; i < n; i++ {
		caps := make([]mda.Capability, m)
		for k := range caps {
			caps[k] = mda.Capability{Resource: mda.ResourcePattern{Type: "t", ID: fmt.Sprintf("r%d-%d", i, k)}, Action: mda.ActionPattern{Name: "a"}}
		}
		iss := "idp"
		if i > 0 {
			iss = fmt.Sprintf("a%d", i-1)
		}
		c := mda.Claims{Issuer: iss, Subject: fmt.Sprintf("a%d", i), Audience: "aud", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			ID: fmt.Sprintf("j%d", i), Mandatum: mda.Mandatum{Version: mda.Version, Root: root, Parent: parent, Depth: i, MaxDepth: n, Capabilities: caps}}
		raw, err := jose.Sign(c, priv, "")
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, raw)
		parent = mda.Digest(raw)
	}
	return out
}

// The limits exist so that the largest input whosent accepts diagnoses
// quickly, which matters wherever it checks chains it did not write (CI, an
// incident review). Each shape at the limits is timed, and each shape past
// them must be refused rather than diagnosed.
func TestTheLargestAcceptedChainsDiagnoseQuickly(t *testing.T) {
	// About half a second on a laptop; the budget leaves room for a slow CI
	// machine, and the race detector's several-fold slowdown.
	budget := 2 * time.Second
	if raceEnabled {
		budget = 15 * time.Second
	}
	shapes := []struct {
		name  string
		links [][]byte
	}{
		{"the most links, each with the most capabilities", hostileSized(t, diagnose.MaxLinks, diagnose.MaxCapabilities)},
		{"two links with the most set values", hugeSet(t, diagnose.MaxSetValues)},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			start := time.Now()
			if _, err := diagnose.Diagnose(context.Background(), s.links, diagnose.Options{}); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > budget {
				t.Errorf("took %s, budget %s", d, budget)
			} else {
				t.Logf("%s", d)
			}
		})
	}
	for _, s := range []struct {
		name, mention string
		links         [][]byte
	}{
		{"one link too many", "links", hostileSized(t, diagnose.MaxLinks+1, 1)},
		{"one capability too many", "capabilities", hostileSized(t, 2, diagnose.MaxCapabilities+1)},
		{"one set value too many", "set conditions", hugeSet(t, diagnose.MaxSetValues+1)},
	} {
		t.Run(s.name, func(t *testing.T) {
			_, err := diagnose.Diagnose(context.Background(), s.links, diagnose.Options{})
			if err == nil || !strings.Contains(err.Error(), s.mention) {
				t.Errorf("error %v, want a refusal naming %s", err, s.mention)
			}
		})
	}
}

func BenchmarkDiagnoseLargest(b *testing.B) {
	links := hostileSized(b, diagnose.MaxLinks, diagnose.MaxCapabilities)
	for b.Loop() {
		if _, err := diagnose.Diagnose(context.Background(), links, diagnose.Options{}); err != nil {
			b.Fatal(err)
		}
	}
}

// hugeSet signs a two-link chain whose single capability carries a set
// condition of n values on both sides: set inclusion is the costliest
// comparison the decidable fragment has.
func hugeSet(tb testing.TB, n int) [][]byte {
	tb.Helper()
	vals := make([]string, n)
	for i := range vals {
		vals[i] = fmt.Sprintf("v%d", i)
	}
	one := mda.Capability{Resource: mda.ResourcePattern{Type: "t", ID: "r"}, Action: mda.ActionPattern{Name: "a"},
		Conditions: map[string]mda.Condition{"k": {In: vals}}}
	return chainOf(tb.(*testing.T), [][]mda.Capability{{one}, {one}})
}
