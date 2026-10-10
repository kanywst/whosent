package diagnose

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// sentinelAudience stands in for an audience nobody supplied when the leaf
// names none either. verify.New refuses an empty audience, and the V9 it then
// reports is discounted, since V9 was never going to be checked.
const sentinelAudience = "whosent:unchecked-audience"

// The library entry points the guard calls. They are variables only so that
// a test can make the library disagree, which is the one way to prove the
// guard notices a disagreement at all; nothing else assigns them.
var (
	newVerifier = verify.New
	runVerifier = func(ctx context.Context, v *verify.Verifier, c mda.Chain) (*verify.Result, error) {
		return v.Verify(ctx, c)
	}
	runAttenuates = verify.Attenuates
)

// guardSigs answers the library run's signature checks with exactly the
// answers the diagnosis saw. An issuer with no configured keys passes,
// because its links are already Unchecked and the library run exists to
// compare everything else.
type guardSigs struct {
	e     *engine
	stubs *bool
}

func (g guardSigs) VerifySignature(_ context.Context, issuer string, raw []byte) error {
	var ik *IssuerKeys
	if g.e.opts.Trust != nil {
		ik = g.e.opts.Trust.Issuers[issuer]
	}
	switch {
	case ik == nil:
		*g.stubs = true
		return nil
	case ik.Err != "":
		return errors.New(ik.Err)
	}
	return g.e.verifySig(issuer, raw)
}

// guardRevocation answers the library run's revocation checks the same way.
type guardRevocation struct {
	e     *engine
	stubs *bool
}

func (g guardRevocation) IsRevoked(_ context.Context, jti string) (bool, error) {
	if g.e.simulated[jti] {
		return true, nil
	}
	if g.e.checker == nil {
		*g.stubs = true
		return false, nil
	}
	a := g.e.isRevoked(jti)
	return a.revoked, a.err
}

// guard runs verify.Verify on the same chain with the same inputs and checks
// it agrees with the diagnosis on the first failure. It also checks, for
// every hop, that Attenuates accepts the pair exactly when every isolated
// sub-rule does, which is what the hop diff's verdicts rest on.
//
// A disagreement is a bug in this tool. It is reported loudly, and the
// library's verdict is the one that stands.
func (e *engine) guard() {
	lib := &e.rep.Library
	lib.Consistent = true
	lib.ToolLink = -1
	lib.Link = -1

	stubs := false
	audience := sentinelAudience
	audienceStubbed := true
	switch {
	case e.opts.Audience != nil:
		audience, audienceStubbed = *e.opts.Audience, false
	default:
		if leaf := e.claims(len(e.rep.Links) - 1); leaf != nil && leaf.Audience != "" {
			audience = leaf.Audience
		}
	}
	if audienceStubbed && len(e.rep.Links) > 0 {
		stubs = true
	}

	at := e.at
	v, err := newVerifier(guardSigs{e, &stubs}, guardRevocation{e, &stubs}, audience,
		verify.WithClock(func() time.Time { return at }), verify.WithSkew(e.skew))
	if err != nil {
		// Fail closed. Without the library's run there is no verdict to
		// stand behind, and a report that said VALID here would be vouching
		// for a chain nobody but this tool looked at.
		lib.Consistent = false
		lib.Mismatch = "could not construct the library verifier: " + err.Error()
		e.rep.Verdict = VerdictInvalid
		e.rep.Result = nil
		return
	}
	chain := make(mda.Chain, len(e.rep.Links))
	for i, l := range e.rep.Links {
		chain[i] = mda.Assertion{Raw: l.Raw}
	}
	res, verr := runVerifier(e.ctx, v, chain)
	lib.StubsUsed = stubs

	var ve *verify.Error
	switch {
	case verr == nil:
		lib.Passed = true
	case errors.As(verr, &ve):
		if ve.Rule == string(V9) && audienceStubbed {
			// V9 was never going to be checked; the sentinel is what failed.
			lib.Passed = true
			res = nil
			break
		}
		lib.Rule, lib.Link, lib.Detail = Rule(ve.Rule), ve.Depth, ve.Detail
	default:
		lib.Rule, lib.Detail = "?", verr.Error()
	}

	var first *Finding
	for _, f := range e.rep.Findings() {
		if f.Derived || !f.Severity.Blocking() {
			continue
		}
		if first == nil || f.order.less(first.order) {
			ff := f
			first = &ff
		}
	}
	if first != nil {
		lib.ToolRule, lib.ToolLink = first.Rule, first.Link
	}

	switch {
	case first == nil && !lib.Passed:
		lib.Consistent = false
		lib.Mismatch = fmt.Sprintf("this tool found nothing, but mandatum reports %s at link %d: %s", lib.Rule, lib.Link, lib.Detail)
	case first != nil && lib.Passed:
		lib.Consistent = false
		lib.Mismatch = fmt.Sprintf("this tool reports %s at link %d, but mandatum accepts the chain", first.Rule, first.Link)
	case first != nil && (first.Rule != lib.Rule || first.Link != lib.Link):
		lib.Consistent = false
		lib.Mismatch = fmt.Sprintf("this tool reports %s at link %d first, but mandatum reports %s at link %d: %s",
			first.Rule, first.Link, lib.Rule, lib.Link, lib.Detail)
	}

	for i, iso := range e.iso {
		hop := e.rep.Hops[i]
		if !hop.Evaluable {
			continue
		}
		if (hop.Verdict == "") != iso.ok() {
			lib.Consistent = false
			msg := fmt.Sprintf("hop %d to %d: Attenuates says %q, but the isolated sub-rules say %v",
				hop.Parent, hop.Child, hop.Verdict, iso.ok())
			if lib.Mismatch != "" {
				lib.Mismatch += "; " + msg
			} else {
				lib.Mismatch = msg
			}
		}
	}

	if !lib.Consistent {
		// The library's verdict stands.
		switch {
		case !lib.Passed:
			e.rep.Verdict = VerdictInvalid
		case stubs:
			e.rep.Verdict = VerdictIncomplete
		default:
			e.rep.Verdict = VerdictValid
		}
		return
	}
	if e.rep.Verdict == VerdictValid && lib.Passed && !stubs {
		e.rep.Result = res
	}
}
