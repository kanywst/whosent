package diagnose

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/revoke"
)

// The phases of verify.Verify, in the order it runs them. A finding's order
// key starts with its phase, so that the smallest key among the blocking
// findings is exactly the failure verify.Verify reports: the library runs
// each phase over every link before starting the next, so a phase-2 problem
// at link 3 is reported ahead of a phase-3 problem at link 1.
const (
	phaseEmpty       = iota // the chain has no links
	phaseParse              // per link: serialization present, claims parse
	phaseValidate           // per link: Claims.Validate
	phaseStructure          // link 0 shape, then per pair: digest, depth, custody
	phaseSignature          // V3
	phaseTime               // V4
	phaseAttenuation        // V5
	phaseRoot               // V6
	phaseDepth              // V7
	phaseRevocation         // V8
	phaseAudience           // V9
)

type orderKey struct{ phase, link, intra int }

func (a orderKey) less(b orderKey) bool {
	if a.phase != b.phase {
		return a.phase < b.phase
	}
	if a.link != b.link {
		return a.link < b.link
	}
	return a.intra < b.intra
}

// expiringSoon is when a passing link earns a warning that it is about to
// stop passing.
const expiringSoon = 5 * time.Minute

// Diagnose evaluates every rule for every link of a chain. links are the
// compact serializations in order, sponsor first, exactly as received.
//
// The only error is an invalid option. Anything wrong with the chain is a
// finding in the report, never an error: a chain that cannot be read is
// precisely what someone opening it wants explained.
func Diagnose(ctx context.Context, links [][]byte, opts Options) (*Report, error) {
	skew, err := opts.skew()
	if err != nil {
		return nil, err
	}
	if opts.Audience != nil && *opts.Audience == "" {
		// mandatum refuses to build a verifier for an empty audience, so no
		// verdict could be compared against the library's. Nil is how to
		// leave V9 unchecked.
		return nil, errors.New("an empty audience names no resource server; use nil to leave V9 unchecked")
	}
	if err := checkSize(links); err != nil {
		return nil, err
	}
	at := opts.At
	if at.IsZero() {
		at = time.Now()
	}
	e := &engine{
		ctx:       ctx,
		opts:      opts,
		at:        at,
		skew:      skew,
		simulated: map[string]bool{},
		sigMemo:   map[string]error{},
		revMemo:   map[string]revAnswer{},
	}
	for _, j := range opts.SimulatedRevocations {
		e.simulated[j] = true
	}
	if err := e.prepare(); err != nil {
		return nil, err
	}
	e.run(links)
	return e.rep, nil
}

type revAnswer struct {
	revoked bool
	err     error
}

type engine struct {
	ctx       context.Context
	opts      Options
	at        time.Time
	skew      time.Duration
	rep       *Report
	ring      *jose.KeyRing
	checker   *revoke.Checker
	simulated map[string]bool
	sigMemo   map[string]error
	revMemo   map[string]revAnswer
	// iso records each hop's isolated sub-rule verdicts for the guard.
	iso []isolated
}

func (e *engine) prepare() error {
	e.rep = &Report{
		At:      e.at,
		Skew:    e.skew,
		BreakAt: -1,
	}
	if e.opts.Audience != nil {
		e.rep.Audience = *e.opts.Audience
		e.rep.AudienceChecked = true
	}
	if len(e.opts.SimulatedRevocations) > 0 {
		e.rep.Simulated = append([]string(nil), e.opts.SimulatedRevocations...)
		sort.Strings(e.rep.Simulated)
	}

	if t := e.opts.Trust; t != nil {
		e.ring = jose.NewKeyRing()
		issuers := make([]string, 0, len(t.Issuers))
		for iss := range t.Issuers {
			issuers = append(issuers, iss)
		}
		sort.Strings(issuers)
		for _, iss := range issuers {
			ik := t.Issuers[iss]
			if ik == nil {
				continue
			}
			sum := IssuerSummary{Issuer: iss, Source: ik.Source, Skipped: ik.Skipped, Err: ik.Err}
			for kid, key := range ik.Keys {
				if err := e.ring.Add(iss, kid, key); err != nil {
					return fmt.Errorf("trust anchor %q: %w", iss, err)
				}
				if kid != "" {
					sum.KeyIDs = append(sum.KeyIDs, kid)
				}
			}
			sort.Strings(sum.KeyIDs)
			e.rep.Trust = append(e.rep.Trust, sum)
		}
	}

	if r := e.opts.Revocation; r != nil {
		if r.Set == nil {
			return errors.New("a revocation option needs a set")
		}
		at := e.at
		opts := []revoke.Option{
			revoke.WithClock(func() time.Time { return at }),
			revoke.WithMaxAge(r.maxAge()),
		}
		if r.Exact != nil {
			opts = append(opts, revoke.WithExact(r.Exact))
		}
		c, err := revoke.NewChecker(r.Set, opts...)
		if err != nil {
			return err
		}
		e.checker = c
		sum := &RevocationSummary{
			Source:      r.Source,
			Sequence:    r.Set.Sequence(),
			GeneratedAt: r.Set.GeneratedAt(),
			MaxAge:      r.maxAge(),
			Exact:       r.ExactSource,
		}
		if age := at.Sub(r.Set.GeneratedAt()); r.maxAge() > 0 && age > r.maxAge() {
			sum.Stale = true
			sum.StaleDetail = fmt.Sprintf("the set was generated %s before the evaluation time, older than the %s accepted",
				age.Round(time.Second), r.maxAge())
		}
		e.rep.Revocation = sum
	}
	return nil
}

func (e *engine) run(raws [][]byte) {
	n := len(raws)
	e.rep.Links = make([]Link, n)
	for i, raw := range raws {
		l := &e.rep.Links[i]
		l.Index = i
		l.Raw = append([]byte(nil), raw...)
		l.Digest = mda.Digest(l.Raw)
		l.UnreachedBy = -1
		for r, rule := range Rules {
			l.Checks[r] = Check{Rule: rule, Status: StatusNotApplicable}
		}
	}
	if n > 1 {
		e.rep.Hops = make([]Hop, n-1)
		e.iso = make([]isolated, n-1)
		for i := range e.rep.Hops {
			e.rep.Hops[i].Parent = i
			e.rep.Hops[i].Child = i + 1
		}
	}

	if n == 0 {
		e.add(Finding{
			Rule: V1, Code: "v1.empty_chain", Link: -1, Hop: -1, Severity: SeverityFail,
			Detail: "an empty chain establishes nothing",
			Spec:   "section 7 V1", order: orderKey{phaseEmpty, -1, 0},
		})
	}

	e.parse()
	e.validate()
	e.structure()
	e.signatures()
	e.times()
	e.attenuation()
	e.root()
	e.depth()
	e.revocation()
	e.audience()
	e.applicability()
	e.inputWarnings()
	e.derive()
	e.verdict()
	e.guard()
	e.rep.Matrix = buildMatrix(e.rep)
	if r0 := e.claims(0); r0 != nil {
		s := r0.Mandatum.Root
		e.rep.Sponsor = &s
	}
	for i := range e.rep.Links {
		sortFindings(e.rep.Links[i].Findings)
	}
	sortFindings(e.rep.ChainFindings)
}

// add records a finding against its link (or the chain) and folds it into
// that link's cell for the rule.
func (e *engine) add(f Finding) {
	if f.Link < 0 || f.Link >= len(e.rep.Links) {
		f.Link = -1
		e.rep.ChainFindings = append(e.rep.ChainFindings, f)
		return
	}
	l := &e.rep.Links[f.Link]
	l.Findings = append(l.Findings, f)
	if f.Derived || f.Rule == "" {
		return
	}
	var st Status
	switch f.Severity {
	case SeverityFail:
		st = StatusFail
	case SeverityError:
		st = StatusError
	case SeverityUnchecked:
		st = StatusUnchecked
	default:
		return
	}
	e.setCell(f.Link, f.Rule, st, f.Detail, f.Simulated)
}

// statusRank orders cell statuses so the worst one wins.
func statusRank(s Status) int {
	switch s {
	case StatusFail:
		return 5
	case StatusError:
		return 4
	case StatusUnchecked:
		return 3
	case StatusSkipped:
		return 2
	case StatusPass:
		return 1
	}
	return 0
}

func (e *engine) setCell(link int, rule Rule, st Status, detail string, simulated bool) {
	c := &e.rep.Links[link].Checks[rule.Index()]
	if statusRank(st) > statusRank(c.Status) {
		c.Status = st
		c.Detail = detail
		c.Simulated = simulated
	}
}

// pass marks a rule evaluated with nothing wrong, unless something already
// went wrong with it.
func (e *engine) pass(link int, rule Rule, detail string) {
	e.setCell(link, rule, StatusPass, detail, false)
}

func (e *engine) skip(link int, rule Rule, why string) {
	e.setCell(link, rule, StatusSkipped, why, false)
}

func (e *engine) claims(i int) *mda.Claims {
	if i < 0 || i >= len(e.rep.Links) {
		return nil
	}
	return e.rep.Links[i].Claims
}

// parse is phase 1: every link must have bytes and strictly parse.
func (e *engine) parse() {
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		if len(l.Raw) == 0 {
			e.add(Finding{
				Rule: V1, Code: "v1.empty_link", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: "assertion has no serialization to commit to",
				Spec:   "section 7 V1", order: orderKey{phaseParse, i, 0},
			})
			l.ParseError = "empty"
			continue
		}
		if h, _, err := jose.Parse(l.Raw); err == nil || errors.Is(err, jose.ErrHeader) {
			hh := h
			l.Header = &hh
		}
		claims, err := mda.ParseClaims(l.Raw)
		if err != nil {
			l.ParseError = err.Error()
			l.Untrusted = lenientPayload(l.Raw)
			f := Finding{
				Rule: V1, Code: "v1.parse", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: err.Error(), Spec: "section 5", order: orderKey{phaseParse, i, 0},
			}
			// The library files a refused header under V3, because the
			// algorithm allowlist and the media type are what the signature
			// rule protects. Everything else that fails to parse is V1.
			if errors.Is(err, jose.ErrHeader) {
				f.Rule, f.Code, f.Spec = V3, "v3.header", "section 7 V3"
			}
			e.add(f)
			continue
		}
		c := claims
		l.Claims = &c
		l.IssuedAt = time.Unix(c.IssuedAt, 0).UTC()
		l.ExpiresAt = time.Unix(c.ExpiresAt, 0).UTC()
		l.Remaining = l.ExpiresAt.Sub(e.at)
	}
}

// lenientPayload decodes a payload for display only. It accepts anything
// that is JSON, which is exactly why it must never feed a decision.
func lenientPayload(raw []byte) map[string]any {
	parts := strings.Split(string(raw), ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return nil
	}
	return m
}

// validate is phase 2: the structural rules a link can be judged on alone.
func (e *engine) validate() {
	for i := range e.rep.Links {
		c := e.claims(i)
		if c == nil {
			continue
		}
		if err := c.Validate(); err != nil {
			e.add(Finding{
				Rule: V1, SubRule: "section 5.2", Code: "v1.invalid", Link: i, Hop: -1,
				Severity: SeverityFail, Detail: err.Error(), Spec: "section 5.2",
				order: orderKey{phaseValidate, i, 0},
			})
		}
	}
}

// structure is phase 3: the first link starts a chain, and every later link
// commits to the bytes above it, sits one deeper, and was issued by the
// subject above it.
func (e *engine) structure() {
	if c := e.claims(0); c != nil {
		if c.Mandatum.Depth != 0 {
			e.add(Finding{
				Rule: V1, Code: "v1.root_depth", Link: 0, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("chain starts at depth %d, not 0", c.Mandatum.Depth),
				Spec:   "section 7 V1", order: orderKey{phaseStructure, 0, 0},
			})
		}
		if c.Mandatum.Parent != "" {
			e.add(Finding{
				Rule: V1, Code: "v1.root_parent", Link: 0, Hop: -1, Severity: SeverityFail,
				Detail: "the first link commits to a parent, so this is not the start of a chain",
				Spec:   "section 7 V1", order: orderKey{phaseStructure, 0, 1},
			})
		}
	}

	for i := 1; i < len(e.rep.Links); i++ {
		hop := &e.rep.Hops[i-1]
		child, parent := e.claims(i), e.claims(i-1)
		parentLink := &e.rep.Links[i-1]

		hop.Commitment = Check{Rule: V1, Status: StatusSkipped, Detail: "this link does not parse"}
		if child != nil {
			want := parentLink.Digest
			if got := child.Mandatum.Parent; got != want {
				d := fmt.Sprintf("parent commitment %q does not match the preceding assertion (%q); "+
					"this link was not issued against this chain", got, want)
				e.add(Finding{
					Rule: V1, SubRule: "section 5.1", Code: "v1.parent_mismatch", Link: i, Hop: i,
					Severity: SeverityFail, Detail: d, Spec: "section 5.1",
					order: orderKey{phaseStructure, i, 0},
				})
				hop.Commitment = Check{Rule: V1, Status: StatusFail, Detail: d}
			} else {
				hop.Commitment = Check{Rule: V1, Status: StatusPass, Detail: "commits to the exact bytes of the link above"}
			}
		}

		hop.DepthStep = Check{Rule: V1, Status: StatusSkipped, Detail: "a link of the pair does not parse"}
		hop.Custody = Check{Rule: V2, Status: StatusSkipped, Detail: "a link of the pair does not parse"}
		if child == nil || parent == nil {
			continue
		}
		if child.Mandatum.Depth != parent.Mandatum.Depth+1 {
			d := fmt.Sprintf("depth %d does not follow %d", child.Mandatum.Depth, parent.Mandatum.Depth)
			e.add(Finding{
				Rule: V1, SubRule: "section 6 rule 4", Code: "v1.depth_step", Link: i, Hop: i,
				Severity: SeverityFail, Detail: d, Spec: "section 6 rule 4",
				order: orderKey{phaseStructure, i, 1},
			})
			hop.DepthStep = Check{Rule: V1, Status: StatusFail, Detail: d}
		} else {
			hop.DepthStep = Check{Rule: V1, Status: StatusPass, Detail: fmt.Sprintf("depth %d follows %d", child.Mandatum.Depth, parent.Mandatum.Depth)}
		}
		if child.Issuer != parent.Subject {
			d := fmt.Sprintf("issued by %q, but the parent delegated to %q", child.Issuer, parent.Subject)
			e.add(Finding{
				Rule: V2, Code: "v2.custody", Link: i, Hop: i, Severity: SeverityFail,
				Detail: d, Spec: "section 7 V2", order: orderKey{phaseStructure, i, 2},
			})
			hop.Custody = Check{Rule: V2, Status: StatusFail, Detail: d}
		} else {
			d := fmt.Sprintf("issued by %s, who the link above delegated to", child.Issuer)
			hop.Custody = Check{Rule: V2, Status: StatusPass, Detail: d}
			e.pass(i, V2, d)
		}
	}
}

// verifySig answers V3 for one link, memoized so that the library run in the
// guard sees exactly the answer the diagnosis saw.
func (e *engine) verifySig(issuer string, raw []byte) error {
	key := issuer + "\x00" + string(raw)
	if err, ok := e.sigMemo[key]; ok {
		return err
	}
	err := e.ring.VerifySignature(e.ctx, issuer, raw)
	e.sigMemo[key] = err
	return err
}

// signatures is phase 4.
func (e *engine) signatures() {
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		c := l.Claims
		if c == nil {
			continue
		}
		kid := ""
		if l.Header != nil {
			kid = l.Header.KeyID
		}
		var ik *IssuerKeys
		if e.opts.Trust != nil {
			ik = e.opts.Trust.Issuers[c.Issuer]
		}
		key := orderKey{phaseSignature, i, 0}
		switch {
		case ik == nil:
			e.add(Finding{
				Rule: V3, Code: "v3.no_anchor", Link: i, Hop: -1, Severity: SeverityUnchecked,
				Detail: fmt.Sprintf("no trust anchor for %s (kid %q); pass --trust or --jwks to check it", c.Issuer, kid),
				Spec:   "section 7 V3", order: key,
			})
		case ik.Err != "":
			e.add(Finding{
				Rule: V3, Code: "v3.keys_unavailable", Link: i, Hop: -1, Severity: SeverityError,
				Detail: fmt.Sprintf("keys for %s could not be loaded from %s: %s", c.Issuer, ik.Source, ik.Err),
				Spec:   "section 7 V3", order: key,
			})
		default:
			err := e.verifySig(c.Issuer, l.Raw)
			switch {
			case err == nil:
				src := ik.Source
				if kid != "" {
					src += " kid " + kid
				}
				l.KeySource = src
				e.pass(i, V3, fmt.Sprintf("signed by %s (%s)", c.Issuer, src))
			case errors.Is(err, jose.ErrUnknownKey):
				e.add(Finding{
					Rule: V3, Code: "v3.unknown_kid", Link: i, Hop: -1, Severity: SeverityFail,
					Detail: fmt.Sprintf("%s is trusted, but %s publishes no key with kid %q", c.Issuer, ik.Source, kid),
					Spec:   "section 7 V3", order: key,
				})
			default:
				e.add(Finding{
					Rule: V3, Code: "v3.bad_signature", Link: i, Hop: -1, Severity: SeverityFail,
					Detail: fmt.Sprintf("signature by %q did not verify: %v", c.Issuer, err),
					Spec:   "section 7 V3", order: key,
				})
			}
		}
	}
}

// times is phase 5. It uses the library's exact comparisons, so the two can
// never disagree about a link sitting on the edge of the skew window.
func (e *engine) times() {
	for i := range e.rep.Links {
		c := e.claims(i)
		if c == nil {
			continue
		}
		iat := time.Unix(c.IssuedAt, 0)
		exp := time.Unix(c.ExpiresAt, 0)
		future := e.at.Add(e.skew).Before(iat)
		expired := !e.at.Add(-e.skew).Before(exp)
		if future {
			e.add(Finding{
				Rule: V4, Code: "v4.future", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("issued at %s, which is in the future", iat.UTC()),
				Spec:   "section 7 V4", order: orderKey{phaseTime, i, 0},
			})
		}
		if expired {
			e.add(Finding{
				Rule: V4, Code: "v4.expired", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("expired at %s", exp.UTC()),
				Spec:   "section 7 V4", order: orderKey{phaseTime, i, 1},
			})
		}
		if !future && !expired {
			left := exp.Sub(e.at)
			e.pass(i, V4, fmt.Sprintf("valid until %s (%s left)", exp.UTC().Format(time.RFC3339), human(left)))
			switch {
			case e.at.Before(iat) || !e.at.Before(exp):
				e.add(Finding{
					Rule: V4, Code: "v4.within_skew", Link: i, Hop: -1, Severity: SeverityWarn,
					Detail: fmt.Sprintf("passes only because of the %s clock skew tolerance", e.skew),
					Spec:   "section 7 V4",
				})
			case left < expiringSoon:
				e.add(Finding{
					Rule: V4, Code: "v4.expiring", Link: i, Hop: -1, Severity: SeverityWarn,
					Detail: fmt.Sprintf("expires in %s", human(left)),
					Spec:   "section 7 V4",
				})
			}
		}
		if p := e.claims(i - 1); p != nil && c.IssuedAt < p.IssuedAt {
			e.add(Finding{
				Rule: V4, Code: "v4.issued_before_parent", Link: i, Hop: i, Severity: SeverityInfo,
				Detail: fmt.Sprintf("issued %s before the link above it; no rule forbids this, but it usually means a clock or a script is wrong",
					human(time.Duration(p.IssuedAt-c.IssuedAt)*time.Second)),
			})
		}
	}
}

// attenuation is phase 6, and builds each hop's diff.
func (e *engine) attenuation() {
	for i := 1; i < len(e.rep.Links); i++ {
		parent, child := e.claims(i-1), e.claims(i)
		hop := &e.rep.Hops[i-1]
		if parent == nil || child == nil {
			continue
		}
		hop.Evaluable = true
		iso, err := diffHop(hop, *parent, *child)
		e.iso[i-1] = iso
		e.notePriorHolders(i, hop)
		if err != nil {
			hop.Verdict = err.Error()
			e.add(Finding{
				Rule: V5, SubRule: iso.firstFailure(), Code: "v5.widens", Link: i, Hop: i,
				Severity: SeverityFail, Detail: err.Error(), Spec: "section 6",
				order: orderKey{phaseAttenuation, i, 0},
			})
			continue
		}
		e.pass(i, V5, fmt.Sprintf("no wider than link %d", i-1))
	}
}

// notePriorHolders adds lineage to a widened capability: if a link further up
// held it, the authority was dropped on the way down and re-added here, which
// is a different story from authority nobody ever granted.
func (e *engine) notePriorHolders(child int, hop *Hop) {
	for ci := range hop.Capabilities {
		ch := &hop.Capabilities[ci]
		if ch.Kind != ChangeWidened || ch.Child == nil {
			continue
		}
		for j := child - 2; j >= 0; j-- {
			c := e.claims(j)
			if c == nil {
				break
			}
			if isoCaps(c.Mandatum.Capabilities, []mda.Capability{*ch.Child}) == nil {
				ch.Notes = append([]string{fmt.Sprintf("link %d held this, and it was dropped before link %d: re-adding it here does not bring it back", j, j+1)}, ch.Notes...)
				break
			}
		}
	}
}

// root is phase 7: the sponsor is copied into every link, and the copies must
// agree with the first.
func (e *engine) root() {
	r0 := e.claims(0)
	for i := 1; i < len(e.rep.Links); i++ {
		hop := &e.rep.Hops[i-1]
		c := e.claims(i)
		if r0 == nil || c == nil {
			hop.Sponsor = Check{Rule: V6, Status: StatusSkipped, Detail: "the first link or this one does not parse"}
			continue
		}
		want, got := r0.Mandatum.Root, c.Mandatum.Root
		bad := false
		if got.Issuer != want.Issuer || got.Subject != want.Subject {
			bad = true
			e.add(Finding{
				Rule: V6, Code: "v6.sponsor", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("names sponsor %s/%s, but the chain is rooted in %s/%s",
					got.Issuer, got.Subject, want.Issuer, want.Subject),
				Spec: "section 6 rule 6", order: orderKey{phaseRoot, i, 0},
			})
		}
		if got.AuthenticatedAt != want.AuthenticatedAt {
			bad = true
			e.add(Finding{
				Rule: V6, Code: "v6.auth_time", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: "sponsor authentication time differs from the root's",
				Spec:   "section 6 rule 6", order: orderKey{phaseRoot, i, 1},
			})
		}
		if !sameStrings(got.AuthenticationMethods, want.AuthenticationMethods) {
			bad = true
			e.add(Finding{
				Rule: V6, Code: "v6.amr", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("sponsor authentication methods %v differ from the root's %v",
					got.AuthenticationMethods, want.AuthenticationMethods),
				Spec: "section 6 rule 6", order: orderKey{phaseRoot, i, 2},
			})
		}
		if bad {
			hop.Sponsor = Check{Rule: V6, Status: StatusFail, Detail: "the sponsor differs from the first link's"}
			continue
		}
		d := fmt.Sprintf("sponsor %s matches the first link", want.Subject)
		hop.Sponsor = Check{Rule: V6, Status: StatusPass, Detail: d}
		e.pass(i, V6, d)
	}
}

// depth is phase 8. It is not reachable through verify.Verify on its own,
// because V5 forces max_depth down at every hop and fires first. It is
// reported anyway: showing every problem is the point of this tool.
func (e *engine) depth() {
	n := len(e.rep.Links)
	if n == 0 {
		return
	}
	leaf := n - 1
	r0 := e.claims(0)
	if r0 == nil {
		e.skip(leaf, V7, "the sponsor's grant does not parse, so the permitted depth is unknown")
		return
	}
	hops, limit := n-1, r0.Mandatum.MaxDepth
	if hops > limit {
		e.add(Finding{
			Rule: V7, Code: "v7.too_deep", Link: leaf, Hop: -1, Severity: SeverityFail,
			Detail: fmt.Sprintf("chain has %d delegation hops but the sponsor permitted at most %d", hops, limit),
			Spec:   "section 7 V7", order: orderKey{phaseDepth, leaf, 0},
		})
		return
	}
	if e.claims(leaf) == nil {
		// The count is right whatever the leaf says, but a tick on a link
		// that does not parse reads as "this link is fine".
		e.skip(leaf, V7, fmt.Sprintf("this link does not parse (the chain uses %d of %d permitted hops)", hops, limit))
		return
	}
	e.pass(leaf, V7, fmt.Sprintf("%d of %d permitted hops used", hops, limit))
}

// isRevoked answers V8 for one jti, memoized for the guard.
func (e *engine) isRevoked(jti string) revAnswer {
	if a, ok := e.revMemo[jti]; ok {
		return a
	}
	revoked, err := e.checker.IsRevoked(e.ctx, jti)
	a := revAnswer{revoked: revoked, err: err}
	e.revMemo[jti] = a
	return a
}

// revocation is phase 9.
func (e *engine) revocation() {
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		c := l.Claims
		if c == nil {
			continue
		}
		key := orderKey{phaseRevocation, i, 0}
		if e.simulated[c.ID] {
			l.Revoked, l.RevokedSimulated = true, true
			e.add(Finding{
				Rule: V8, Code: "v8.simulated", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("assertion %s is revoked (simulated)", c.ID),
				Spec:   "section 7 V8", Simulated: true, order: key,
			})
			continue
		}
		if e.checker == nil {
			e.add(Finding{
				Rule: V8, Code: "v8.no_set", Link: i, Hop: -1, Severity: SeverityUnchecked,
				Detail: "no revocation set; pass --revocations to check it",
				Spec:   "section 7 V8", order: key,
			})
			continue
		}
		a := e.isRevoked(c.ID)
		switch {
		case a.err != nil:
			e.add(Finding{
				Rule: V8, Code: "v8.unknown", Link: i, Hop: -1, Severity: SeverityError,
				Detail: fmt.Sprintf("revocation status is unknown (%v); an unanswerable check denies", a.err),
				Spec:   "section 7.1", order: key,
			})
		case a.revoked:
			l.Revoked = true
			e.add(Finding{
				Rule: V8, Code: "v8.revoked", Link: i, Hop: -1, Severity: SeverityFail,
				Detail: fmt.Sprintf("assertion %s is revoked", c.ID),
				Spec:   "section 7 V8", order: key,
			})
			if e.opts.Revocation.Exact == nil {
				e.add(Finding{
					Rule: V8, Code: "v8.bloom_hit", Link: i, Hop: -1, Severity: SeverityWarn,
					Detail: "the revocation set is a Bloom filter and no exact list was given, so this may be a false positive; section 7.1 says a hit denies either way",
					Spec:   "section 7.1",
				})
			}
		default:
			e.pass(i, V8, fmt.Sprintf("%s is not in the revocation set", c.ID))
		}
	}
}

// audience is phase 10. Only the leaf is presented to a resource server.
func (e *engine) audience() {
	n := len(e.rep.Links)
	if n == 0 {
		return
	}
	leaf := n - 1
	c := e.claims(leaf)
	if c == nil {
		return
	}
	key := orderKey{phaseAudience, leaf, 0}
	if e.opts.Audience == nil {
		e.add(Finding{
			Rule: V9, Code: "v9.no_audience", Link: leaf, Hop: -1, Severity: SeverityUnchecked,
			Detail: fmt.Sprintf("the leaf is addressed to %q; pass --audience to check it is this resource server", c.Audience),
			Spec:   "section 7 V9", order: key,
		})
		return
	}
	if c.Audience != *e.opts.Audience {
		e.add(Finding{
			Rule: V9, Code: "v9.audience", Link: leaf, Hop: -1, Severity: SeverityFail,
			Detail: fmt.Sprintf("addressed to %q, but this is %q", c.Audience, *e.opts.Audience),
			Spec:   "section 7 V9", order: key,
		})
		return
	}
	e.pass(leaf, V9, fmt.Sprintf("addressed to %s", c.Audience))
}

// applicability fills in every cell no phase touched: a rule that applies
// and found nothing passed, a rule whose link does not parse was skipped.
func (e *engine) applicability() {
	n := len(e.rep.Links)
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		parsed := l.Claims != nil
		parentParsed := i > 0 && e.claims(i-1) != nil
		for r, rule := range Rules {
			c := &l.Checks[r]
			if c.Status != StatusNotApplicable {
				continue
			}
			applies := true
			switch rule {
			case V2, V5, V6:
				applies = i > 0
			case V7, V9:
				applies = i == n-1
			}
			if !applies {
				continue
			}
			switch {
			case !parsed:
				// The parse failure itself is filed under V1 or V3; every
				// other cell of an unparsed link is skipped, not passed.
				c.Status, c.Detail = StatusSkipped, "this link does not parse"
			case (rule == V2 || rule == V5) && !parentParsed:
				c.Status, c.Detail = StatusSkipped, "the link above does not parse"
			case rule == V6 && e.claims(0) == nil:
				c.Status, c.Detail = StatusSkipped, "the first link does not parse"
			default:
				c.Status, c.Detail = StatusPass, passDetail(rule)
			}
		}
	}
}

func passDetail(r Rule) string {
	switch r {
	case V1:
		return "well formed, and in its place in the chain"
	case V2:
		return "issued by the subject above it"
	case V5:
		return "no wider than the link above"
	}
	return "holds"
}

// inputWarnings flags a chain that looks like it was handed over leaf first.
// It is never silently reordered: the order is part of what is signed.
func (e *engine) inputWarnings() {
	n := len(e.rep.Links)
	if n < 2 {
		return
	}
	first, last := e.claims(0), e.claims(n-1)
	if first == nil || last == nil {
		return
	}
	if first.Mandatum.Depth > last.Mandatum.Depth && last.Mandatum.Parent == "" {
		e.add(Finding{
			Code: "input.reversed", Link: -1, Hop: -1, Severity: SeverityWarn,
			Detail: "the chain looks reversed: depths descend and the last link has no parent; the wire form is sponsor first, so pass --reverse if it was handed over leaf first",
		})
	}
}

// derive marks the consequences of a failure: links below a revoked link are
// invalidated with it, links below a broken commitment are detached, and
// every link below the first break is unreached.
func (e *engine) derive() {
	lastRevoked, lastDetached := -1, -1
	simulatedRevocation := false
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		if lastRevoked >= 0 {
			e.add(Finding{
				Rule: V8, Code: "v8.ancestor_revoked", Link: i, Hop: -1, Severity: SeverityFail,
				Detail:  fmt.Sprintf("invalidated: link %d above it is revoked, and revocation reaches everything below", lastRevoked),
				Spec:    "section 7.1",
				Derived: true, Simulated: simulatedRevocation,
			})
		}
		if lastDetached >= 0 {
			e.add(Finding{
				Rule: V1, Code: "v1.detached", Link: i, Hop: -1, Severity: SeverityFail,
				Detail:  fmt.Sprintf("detached: link %d does not commit to the chain above it, so nothing below it is connected to the sponsor", lastDetached),
				Spec:    "section 5.1",
				Derived: true,
			})
		}
		for _, f := range l.Findings {
			if f.Derived {
				continue
			}
			if f.Rule == V8 && f.Severity == SeverityFail {
				lastRevoked, simulatedRevocation = i, f.Simulated
			}
			if f.Code == "v1.parent_mismatch" {
				lastDetached = i
			}
		}
	}

	breakAt := -1
	for i := range e.rep.Links {
		if hasBlocking(e.rep.Links[i].Findings) {
			breakAt = i
			break
		}
	}
	e.rep.BreakAt = breakAt
	for i := range e.rep.Links {
		l := &e.rep.Links[i]
		switch {
		case hasBlocking(l.Findings):
			l.State = LinkBroken
		case hasStatus(l, StatusUnchecked, StatusSkipped):
			l.State = LinkIncomplete
		default:
			l.State = LinkOK
		}
		if breakAt >= 0 && i > breakAt {
			l.Unreached = true
			l.UnreachedBy = breakAt
		}
	}
}

func hasBlocking(fs []Finding) bool {
	for _, f := range fs {
		if !f.Derived && f.Severity.Blocking() {
			return true
		}
	}
	return false
}

func hasStatus(l *Link, st ...Status) bool {
	for _, c := range l.Checks {
		for _, s := range st {
			if c.Status == s {
				return true
			}
		}
	}
	return false
}

func (e *engine) verdict() {
	blocking, unchecked := false, false
	for _, f := range e.rep.Findings() {
		if f.Derived {
			continue
		}
		switch {
		case f.Severity.Blocking():
			blocking = true
		case f.Severity == SeverityUnchecked:
			unchecked = true
		}
	}
	switch {
	case blocking:
		e.rep.Verdict = VerdictInvalid
	case unchecked:
		e.rep.Verdict = VerdictIncomplete
	default:
		e.rep.Verdict = VerdictValid
	}
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Derived != b.Derived {
			return !a.Derived
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.order.less(b.order)
	})
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// human formats a duration the way a person reads a countdown: "41m",
// "2h05m", "3d4h". Seconds only appear under a minute.
func human(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		s = fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
	if neg {
		return "-" + s
	}
	return s
}

// Human formats a duration as a compact countdown, for renderers that want
// the same wording as the report.
func Human(d time.Duration) string { return human(d) }
