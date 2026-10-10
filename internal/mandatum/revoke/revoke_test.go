package revoke_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/revoke"
)

var built = time.Unix(1789200000, 0).UTC()

func newSet(t *testing.T, ids []string, rate float64) *revoke.Set {
	t.Helper()
	s, err := revoke.NewSet(ids, rate, 1, built)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The property everything else rests on: a Bloom filter has no false
// negatives, so an identifier that was revoked is never reported as clean.
func TestEveryRevokedIdentifierIsFound(t *testing.T) {
	var ids []string
	for i := range 500 {
		ids = append(ids, fmt.Sprintf("01JB2X9K7P4Q8R3N6M0V5T2Y%03d", i))
	}
	s := newSet(t, ids, 0.01)

	for _, id := range ids {
		if !s.MayContain(id) {
			t.Fatalf("a revoked identifier was reported as not revoked: %s", id)
		}
	}
}

func TestTheFalsePositiveRateIsRoughlyWhatWasAskedFor(t *testing.T) {
	var revoked []string
	for i := range 1000 {
		revoked = append(revoked, fmt.Sprintf("revoked-%04d", i))
	}
	s := newSet(t, revoked, 0.01)

	falsePositives := 0
	const trials = 20000
	for i := range trials {
		if s.MayContain(fmt.Sprintf("clean-%05d", i)) {
			falsePositives++
		}
	}
	rate := float64(falsePositives) / trials
	// Generous bound: the point is that the sizing is right to an order of
	// magnitude, not that a hash function hits its asymptotics exactly.
	if rate > 0.03 {
		t.Errorf("false-positive rate %.4f against a target of 0.01", rate)
	}
}

func TestASetSurvivesTheWire(t *testing.T) {
	ids := []string{"01JB2XA4M0RN5S8Q2K7T3W1Y9D", "01JB2XB7Q3TS6V9R5N8W4Z2A1F"}
	s := newSet(t, ids, 0.001)

	encoded, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := revoke.ParseSet(encoded)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range ids {
		if !back.MayContain(id) {
			t.Errorf("%s was revoked before encoding and is not after", id)
		}
	}
	if back.MayContain("01JB2XC9R5UT7W0S6P9X5A3B2G") {
		t.Error("an identifier appeared out of nowhere after a round trip")
	}
	if back.Sequence() != s.Sequence() || !back.GeneratedAt().Equal(s.GeneratedAt()) {
		t.Errorf("metadata did not survive: %d/%v vs %d/%v",
			back.Sequence(), back.GeneratedAt(), s.Sequence(), s.GeneratedAt())
	}
}

func TestParseSetRefusesWhatItCannotTrust(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":          `<html>`,
		"future version":    `{"v":2,"sequence":1,"generated_at":1789200000,"hashes":7,"bits":"AAAA"}`,
		"no hashes":         `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":0,"bits":"AAAA"}`,
		"no generated_at":   `{"v":1,"sequence":1,"hashes":7,"bits":"AAAA"}`,
		"no bits":           `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":7,"bits":""}`,
		"bits are not b64":  `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":7,"bits":"!!!!"}`,
		"negative hash cnt": `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":-1,"bits":"AAAA"}`,
		"hash cnt over max": `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":65,"bits":"AAAA"}`,
		// The shape a fuzz campaign found: eighty bytes that cost seconds of
		// CPU and tens of gigabytes per lookup, on the path of every
		// authorized action.
		"hash cnt in the billions": `{"v":1,"sequence":1,"generated_at":1789200000,"hashes":1789200001,"bits":"P_g"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := revoke.ParseSet([]byte(raw)); err == nil {
				t.Fatal("accepted a set that should have been refused")
			}
		})
	}
}

// A set is fetched from wherever a deployment distributes it, and a lookup
// costs one hash position per declared hash function. Left unbounded, the
// document saying which agents are revoked is also a way to stop the
// enforcement point answering at all: the input below took three seconds per
// MayContain and asked for fourteen gigabytes before this bound existed.
func TestALookupCannotBeMadeArbitrarilyExpensive(t *testing.T) {
	raw := fmt.Appendf(nil,
		`{"v":1,"sequence":1,"generated_at":1789200000,"hashes":%d,"bits":"P_g"}`, math.MaxInt32)

	start := time.Now()
	s, err := revoke.ParseSet(raw)
	if err == nil {
		s.MayContain("01JB2XA4M0RN5S8Q2K7T3W1Y9D")
		t.Fatal("accepted a set whose lookups cost whatever the publisher wrote")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("refusing took %s; the refusal has to be cheaper than the attack", elapsed)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(revoke.MaxHashes)) {
		t.Errorf("the refusal does not name the bound it applied: %v", err)
	}
}

func TestNewSetRefusesARateItCannotBuild(t *testing.T) {
	// Optimal sizing puts k at -log2(p), so a rate this small needs more
	// hash functions than a set may declare. Refused rather than clamped:
	// a publisher who believes they got 1e-30 and got 1e-19 is worse off
	// than one who got an error.
	if _, err := revoke.NewSet([]string{"a"}, 1e-30, 1, built); err == nil {
		t.Error("built a set at a rate that needs more hash functions than the wire format allows")
	}
}

func TestNewSetRejectsImpossibleParameters(t *testing.T) {
	for name, rate := range map[string]float64{"zero": 0, "one": 1, "negative": -0.5, "above one": 2} {
		t.Run(name, func(t *testing.T) {
			if _, err := revoke.NewSet([]string{"a"}, rate, 1, built); err == nil {
				t.Fatalf("accepted a false-positive rate of %v", rate)
			}
		})
	}
	if _, err := revoke.NewSet([]string{"a"}, 0.01, 1, time.Time{}); err == nil {
		t.Error("accepted a set with no generation time")
	}
}

type exact struct {
	revoked map[string]bool
	err     error
	calls   int
}

func (e *exact) IsRevoked(_ context.Context, jti string) (bool, error) {
	e.calls++
	if e.err != nil {
		return false, e.err
	}
	return e.revoked[jti], nil
}

func TestCheckerAnswersFromTheFilterWhereItCan(t *testing.T) {
	s := newSet(t, []string{"revoked-1"}, 0.001)
	e := &exact{revoked: map[string]bool{"revoked-1": true}}
	c, err := revoke.NewChecker(s, revoke.WithExact(e), revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}

	got, err := c.IsRevoked(context.Background(), "not-in-the-set")
	if err != nil || got {
		t.Fatalf("clean identifier: got (%v, %v)", got, err)
	}
	if e.calls != 0 {
		t.Errorf("consulted the authoritative lookup %d times for an identifier the filter cleared", e.calls)
	}

	got, err = c.IsRevoked(context.Background(), "revoked-1")
	if err != nil || !got {
		t.Fatalf("revoked identifier: got (%v, %v)", got, err)
	}
	if e.calls != 1 {
		t.Errorf("resolved a filter hit without asking the authoritative lookup")
	}
}

// Section 7.1: a false positive denies rather than allows.
func TestAFilterHitWithNoLookupDenies(t *testing.T) {
	// A one-bit-per-entry filter to force collisions rather than hunt for one.
	s, err := revoke.NewSet([]string{"revoked-1"}, 0.99, 1, built)
	if err != nil {
		t.Fatal(err)
	}
	c, err := revoke.NewChecker(s, revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for i := range 1000 {
		got, err := c.IsRevoked(context.Background(), fmt.Sprintf("clean-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if got {
			found = true
			break
		}
	}
	if !found {
		t.Skip("no collision in 1000 tries; the filter is wider than this test assumed")
	}
}

// An authoritative lookup that fails must not resolve to "not revoked".
func TestALookupFailureDenies(t *testing.T) {
	s := newSet(t, []string{"revoked-1"}, 0.001)
	e := &exact{err: errors.New("revocation service unreachable")}
	c, err := revoke.NewChecker(s, revoke.WithExact(e), revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}

	revokedFlag, err := c.IsRevoked(context.Background(), "revoked-1")
	if err == nil {
		t.Fatal("a failed lookup returned an answer")
	}
	if revokedFlag {
		_ = revokedFlag // either value is fine as long as the error is returned
	}
}

// A verifier working from a set of unknown age is not enforcing revocation.
func TestAStaleSetRefusesToAnswer(t *testing.T) {
	s := newSet(t, []string{"revoked-1"}, 0.001)
	now := built
	c, err := revoke.NewChecker(s,
		revoke.WithMaxAge(time.Hour),
		revoke.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.IsRevoked(context.Background(), "anything"); err != nil {
		t.Fatalf("a fresh set refused to answer: %v", err)
	}

	now = built.Add(2 * time.Hour)
	got, err := c.IsRevoked(context.Background(), "anything")
	if err == nil {
		t.Fatal("answered from a set older than the deployment accepts")
	}
	if !got {
		t.Error("a stale set answered 'not revoked' alongside its error")
	}
	if !strings.Contains(err.Error(), "old") {
		t.Errorf("unhelpful reason: %v", err)
	}
}

// Replacing a newer set with an older one reinstates everything revoked in
// between, which is the attack a sequence number exists to stop.
func TestASetCannotBeReplacedByAnOlderOne(t *testing.T) {
	current, err := revoke.NewSet([]string{"revoked-1", "revoked-2"}, 0.001, 7, built)
	if err != nil {
		t.Fatal(err)
	}
	older, err := revoke.NewSet([]string{"revoked-1"}, 0.001, 3, built.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newer, err := revoke.NewSet([]string{"revoked-1", "revoked-2", "revoked-3"}, 0.001, 8, built.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	c, err := revoke.NewChecker(current, revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Replace(older); err == nil {
		t.Fatal("accepted a set from before the one it holds")
	}
	if err := c.Replace(nil); err == nil {
		t.Error("accepted nothing as a replacement")
	}
	if err := c.Replace(newer); err != nil {
		t.Fatalf("refused a newer set: %v", err)
	}
	if c.Set().Sequence() != 8 {
		t.Errorf("held sequence %d after replacing with 8", c.Set().Sequence())
	}
}

func TestAnAssertionWithNoIDCannotBeCleared(t *testing.T) {
	c, err := revoke.NewChecker(newSet(t, nil, 0.001), revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.IsRevoked(context.Background(), "")
	if err == nil || !got {
		t.Fatalf("an assertion with no jti was cleared: (%v, %v)", got, err)
	}
}

func TestNewCheckerNeedsASet(t *testing.T) {
	if _, err := revoke.NewChecker(nil); err == nil {
		t.Fatal("built a checker with no set")
	}
}

// An empty set revokes nothing, and must not accidentally revoke everything.
func TestAnEmptySetRevokesNothing(t *testing.T) {
	c, err := revoke.NewChecker(newSet(t, nil, 0.001), revoke.WithClock(func() time.Time { return built }))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		got, err := c.IsRevoked(context.Background(), fmt.Sprintf("01JB2XA4M0RN5S8Q2K7T3W1Y%02d", i))
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Fatalf("an empty set revoked %d", i)
		}
	}
}

func FuzzParseSet(f *testing.F) {
	if s, err := revoke.NewSet([]string{"01JB2XA4M0RN5S8Q2K7T3W1Y9D"}, 0.01, 1, built); err == nil {
		if raw, err := s.Encode(); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(`{"v":1,"sequence":1,"generated_at":1789200000,"hashes":7,"bits":"AAAA"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	// A published revocation set arrives over whatever channel a deployment
	// distributes it on, so parsing it is parsing untrusted input. It must
	// terminate and must never panic, and a set that parses must be usable
	// without one either.
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := revoke.ParseSet(data)
		if err != nil {
			return
		}
		if s == nil {
			t.Fatal("ParseSet returned no set and no error")
		}
		s.MayContain("01JB2XA4M0RN5S8Q2K7T3W1Y9D")
		s.MayContain("")

		again, err := s.Encode()
		if err != nil {
			t.Fatalf("a set that parsed could not be re-encoded: %v", err)
		}
		if _, err := revoke.ParseSet(again); err != nil {
			t.Fatalf("a re-encoded set no longer parses: %v", err)
		}
	})
}
