package diagnose

import (
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// Authority says how much an answer to "would this chain permit X?" can be
// relied on.
type Authority string

const (
	// Authoritative means the chain verified with every input supplied, and the
	// answer comes from the library's own verification result.
	Authoritative Authority = "AUTHORITATIVE"
	// Conditional means nothing failed, but some rule was not checked. The
	// answer holds only if those rules pass.
	Conditional Authority = "CONDITIONAL"
	// Hypothetical means the chain does not verify, so it permits nothing. The
	// answer describes what the leaf claims, which nobody has vouched for.
	Hypothetical Authority = "HYPOTHETICAL"
	// NotEvaluable means the leaf does not parse, so there is no claim to read.
	NotEvaluable Authority = "NOT_EVALUABLE"
)

// TraceStep is the answer for one link's own capability set.
type TraceStep struct {
	Link      int
	Evaluable bool
	Permitted bool
	Reason    string
}

// Trace answers a permission question for a chain and shows the answer at
// every link, so that it is visible where authority for the request ends,
// or where it appears from nowhere.
type Trace struct {
	Request   verify.Request
	Authority Authority
	// Covered reports whether the leaf's capability set covers the request.
	Covered bool
	// Permitted is what an enforcement point would decide: covered, and the
	// chain verifies (or, for Conditional, would verify if the unchecked
	// rules pass). Never true for Hypothetical or NotEvaluable.
	Permitted bool
	// Reason is the library's explanation when the leaf does not cover the
	// request.
	Reason string
	Steps  []TraceStep
	// FirstRefused is the first link whose own grant does not cover the
	// request, or -1.
	FirstRefused int
	// OnlyThroughWidening is set when the leaf covers the request but some
	// link above it does not: the leaf holds it only because a hop widened
	// authority. WideningAt is the first link that holds it after the last
	// refusal.
	OnlyThroughWidening bool
	WideningAt          int
	// SponsorGranted reports whether the sponsor's own grant, link 0, covers
	// the request. With OnlyThroughWidening it separates two different
	// stories: authority the sponsor never granted, and authority the sponsor
	// granted that a link in between dropped. Saying "never granted" for the
	// second would send whoever reads it to the wrong person.
	SponsorGranted bool
}

// Ask answers whether the chain would permit req.
//
// The library's matcher reads only a result's capabilities, so it can be run
// on any link's capability set by building a result around it. Only the real
// result, from a chain that verified with every input, makes the answer
// authoritative; every other answer is labelled for what it is.
func (r *Report) Ask(req verify.Request) Trace {
	t := Trace{Request: req, FirstRefused: -1, WideningAt: -1}
	lastRefused := -1
	for _, l := range r.Links {
		s := TraceStep{Link: l.Index}
		if l.Claims != nil {
			s.Evaluable = true
			if err := permits(l.Claims.Mandatum.Capabilities, req); err != nil {
				s.Reason = err.Error()
				if t.FirstRefused < 0 {
					t.FirstRefused = l.Index
				}
				lastRefused = l.Index
			} else {
				s.Permitted = true
			}
		}
		t.Steps = append(t.Steps, s)
	}

	leaf := r.Leaf()
	if leaf == nil || leaf.Claims == nil {
		t.Authority = NotEvaluable
		t.Reason = "the leaf does not parse, so it claims nothing that can be read"
		return t
	}

	var err error
	switch {
	case r.Verdict == VerdictValid && r.Result != nil:
		t.Authority = Authoritative
		err = r.Result.Permits(req)
	case r.Verdict == VerdictInvalid:
		t.Authority = Hypothetical
		err = permits(leaf.Claims.Mandatum.Capabilities, req)
	default:
		t.Authority = Conditional
		err = permits(leaf.Claims.Mandatum.Capabilities, req)
	}
	t.Covered = err == nil
	if err != nil {
		t.Reason = err.Error()
	}
	t.Permitted = t.Covered && (t.Authority == Authoritative || t.Authority == Conditional)

	if len(t.Steps) > 0 && t.Steps[0].Link == 0 {
		t.SponsorGranted = t.Steps[0].Permitted
	}
	if t.Covered && lastRefused >= 0 && lastRefused < leaf.Index {
		t.OnlyThroughWidening = true
		t.WideningAt = lastRefused + 1
	}
	return t
}

func permits(caps []mda.Capability, req verify.Request) error {
	return (&verify.Result{Capabilities: caps}).Permits(req)
}
