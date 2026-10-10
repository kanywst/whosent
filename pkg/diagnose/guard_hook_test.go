package diagnose_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/verify"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// swap replaces one of the guard's library entry points for the length of a
// test.
func swap[T any](t *testing.T, v *T, with T) {
	t.Helper()
	old := *v
	*v = with
	t.Cleanup(func() { *v = old })
}

func buildScenario(t *testing.T, name string) demo.Scenario {
	t.Helper()
	s, err := demo.Build(name, demo.FixedBase)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func diagnoseScenario(t *testing.T, s demo.Scenario) *diagnose.Report {
	t.Helper()
	r, err := diagnose.Diagnose(context.Background(), s.Links, s.Options)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Every other test asserts the guard agrees with the library, which it also
// would if it did nothing at all. These make the library disagree and
// require the guard to notice, and the library's verdict to stand.
func TestTheGuardNoticesWhenTheLibraryDisagrees(t *testing.T) {
	t.Run("the library rejects a chain this tool accepts", func(t *testing.T) {
		swap(t, diagnose.RunVerifierHook, func(context.Context, *verify.Verifier, mda.Chain) (*verify.Result, error) {
			return nil, &verify.Error{Rule: "V3", Depth: 1, Detail: "injected"}
		})
		r := diagnoseScenario(t, buildScenario(t, "healthy"))
		if r.Library.Consistent {
			t.Fatal("the library rejected the chain and the guard did not notice")
		}
		if r.Verdict != diagnose.VerdictInvalid || r.Result != nil {
			t.Errorf("verdict %s, result %v: the library's rejection must stand", r.Verdict, r.Result)
		}
		if !strings.Contains(r.Library.Mismatch, "V3 at link 1") {
			t.Errorf("mismatch %q does not say what the library reported", r.Library.Mismatch)
		}
	})
	t.Run("the library accepts a chain this tool rejects", func(t *testing.T) {
		swap(t, diagnose.RunVerifierHook, func(context.Context, *verify.Verifier, mda.Chain) (*verify.Result, error) {
			return &verify.Result{}, nil
		})
		r := diagnoseScenario(t, buildScenario(t, "widened"))
		if r.Library.Consistent {
			t.Fatal("the library accepted the chain and the guard did not notice")
		}
		if !strings.Contains(r.Library.Mismatch, "mandatum accepts the chain") {
			t.Errorf("mismatch %q", r.Library.Mismatch)
		}
		if r.Result != nil {
			t.Error("an inconsistent report must never carry a Result: nothing downstream may treat it as authoritative")
		}
	})
	t.Run("the library fails at a different rule", func(t *testing.T) {
		swap(t, diagnose.RunVerifierHook, func(context.Context, *verify.Verifier, mda.Chain) (*verify.Result, error) {
			return nil, &verify.Error{Rule: "V8", Depth: 0, Detail: "injected"}
		})
		r := diagnoseScenario(t, buildScenario(t, "widened"))
		if r.Library.Consistent || r.Verdict != diagnose.VerdictInvalid {
			t.Errorf("consistent %v verdict %s", r.Library.Consistent, r.Verdict)
		}
	})
	t.Run("Attenuates disagrees with its isolated sub-rules", func(t *testing.T) {
		swap(t, diagnose.RunAttenuatesHook, func(mda.Claims, mda.Claims) error { return errors.New("injected") })
		r := diagnoseScenario(t, buildScenario(t, "healthy"))
		if r.Library.Consistent || !strings.Contains(r.Library.Mismatch, "isolated sub-rules") {
			t.Errorf("consistent %v mismatch %q", r.Library.Consistent, r.Library.Mismatch)
		}
	})
}

// If the library's verifier cannot be built, there is no verdict to compare
// with, and the report must fail closed rather than vouch for the chain on
// this tool's word alone.
func TestTheGuardFailsClosedWhenTheLibraryCannotRun(t *testing.T) {
	swap(t, diagnose.NewVerifierHook, func(verify.SignatureVerifier, verify.RevocationChecker, string, ...verify.Option) (*verify.Verifier, error) {
		return nil, errors.New("injected")
	})
	for _, name := range []string{"healthy", "unchecked"} {
		t.Run(name, func(t *testing.T) {
			r := diagnoseScenario(t, buildScenario(t, name))
			if r.Library.Consistent {
				t.Error("no library run, yet the report claims consistency")
			}
			if r.Verdict != diagnose.VerdictInvalid || r.Result != nil {
				t.Errorf("verdict %s result %v: without the library's verdict the report must deny", r.Verdict, r.Result)
			}
		})
	}
}

func TestAnEmptyAudienceIsAnOptionError(t *testing.T) {
	empty := ""
	if _, err := diagnose.Diagnose(context.Background(), nil, diagnose.Options{Audience: &empty}); err == nil {
		t.Error("an empty audience was accepted; mandatum would refuse to build a verifier for it")
	}
}
