package jwt

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"slices"
	"strings"
	"time"

	"github.com/kanywst/whosent/pkg/chain"
)

// Actor proofs (draft-mcguinness-oauth-actor-proofs-01) put each actor's
// own signature in the token: actor_proofs is an array of compact JWTs,
// newest first, one per covered hop of the act chain, each signed by the
// actor that hop added and hash-linked to the one before it. They are the
// first thing in a single JWT that can verify a prior actor at all: without
// them RFC 8693 leaves every actor but the current one the issuer's word.

const (
	typActorProof = "actor-proof+jwt"
	specProofs    = "draft-mcguinness-oauth-actor-proofs-01"
)

// proof is one actor_proofs entry as read, before anything about it is
// decided.
type proof struct {
	Raw     string
	Header  map[string]any
	Claims  map[string]any
	Alg     string
	Kid     string
	Iss     string
	Sub     string
	SubIss  string
	Actor   actor
	Aud     []string
	Res     []string
	HasRes  bool
	Prh     string
	HasPrh  bool
	PrhAlg  string
	HasAlg  bool
	Origin  string
	HasOrig bool
	JTI     string
	Iat     *time.Time
	Exp     *time.Time
	Nbf     *time.Time
	// Problem is why the proof is not a well-formed actor proof (section 4),
	// checked before its signature: a proof that fails it is rejected
	// whoever signed it.
	Problem string
}

// parseProof reads one proof and holds it to section 4 and step 5 of
// section 7: the header, the claims a proof must carry and their JSON
// types, the claims it must not carry, and a single-hop act.
func parseProof(raw string) *proof {
	p := &proof{Raw: raw}
	h, b, problem := segments(raw)
	if problem != "" {
		p.Problem = problem
		return p
	}
	var err error
	if p.Header, err = decodeObject(h); err != nil {
		p.Problem = "its header is not a JSON object: " + err.Error()
		return p
	}
	if p.Claims, err = decodeObject(b); err != nil {
		p.Problem = "its payload is not a JSON object: " + err.Error()
		return p
	}
	p.Alg, p.Kid = str(p.Header, "alg"), str(p.Header, "kid")
	switch {
	case p.Alg == "" || strings.EqualFold(p.Alg, "none") || strings.HasPrefix(strings.ToUpper(p.Alg), "HS") || !allowedAlg(p.Alg):
		p.Problem = fmt.Sprintf("alg %q is not an asymmetric signature algorithm whosent accepts", p.Alg)
	case normType(str(p.Header, "typ")) != typActorProof:
		p.Problem = fmt.Sprintf("typ %q, not %s", str(p.Header, "typ"), typActorProof)
	case p.Header["crit"] != nil:
		p.Problem = "its header marks extensions critical (crit), and whosent understands none"
	default:
		p.Problem = p.readClaims()
	}
	return p
}

// readClaims reads the claims and returns what is wrong with them, or "".
func (p *proof) readClaims() string {
	c := p.Claims
	for _, k := range []string{"iss", "sub", "jti"} {
		v, ok := c[k]
		if !ok {
			return "it has no " + k
		}
		if _, ok := v.(string); !ok {
			return k + " is " + jsonKind(v) + ", not a string"
		}
	}
	p.Iss, p.Sub, p.JTI = str(c, "iss"), str(c, "sub"), str(c, "jti")
	for _, k := range []string{"sub_iss", "prh", "prh_alg", "receipt_jti", "origin_jti"} {
		if v, ok := c[k]; ok {
			if _, ok := v.(string); !ok {
				return k + " is " + jsonKind(v) + ", not a string"
			}
		}
	}
	p.SubIss = str(c, "sub_iss")
	p.Prh, p.HasPrh = str(c, "prh"), c["prh"] != nil
	p.PrhAlg, p.HasAlg = str(c, "prh_alg"), c["prh_alg"] != nil
	p.Origin, p.HasOrig = str(c, "origin_jti"), c["origin_jti"] != nil
	if _, ok := c["aud"]; ok {
		return "it carries aud, which a proof must not (section 4.2.7)"
	}
	for _, d := range []struct {
		claim    string
		into     **time.Time
		required bool
	}{{"iat", &p.Iat, true}, {"exp", &p.Exp, true}, {"nbf", &p.Nbf, false}} {
		v, ok := c[d.claim]
		if !ok {
			if d.required {
				return "it has no " + d.claim
			}
			continue
		}
		when, problem := numericDate(v)
		if problem != "" {
			return d.claim + " " + problem
		}
		*d.into = when
	}

	a, ok := c["act"].(map[string]any)
	if !ok {
		if _, present := c["act"]; !present {
			return "it has no act"
		}
		return "act is not a JSON object"
	}
	for _, k := range []string{"sub", "iss"} {
		if s, ok := a[k].(string); !ok || s == "" {
			return "act names no " + k + "; a proof's act carries both"
		}
	}
	if _, ok := a["act"]; ok {
		return "act nests another act; a proof covers one hop"
	}
	if _, ok := a["cnf"]; ok {
		return "act carries cnf, which a proof's act must not"
	}
	if v, ok := a["sub_profile"]; ok {
		if _, ok := v.(string); !ok {
			return "act.sub_profile is not a string"
		}
	}
	p.Actor = actorFrom(a)
	if p.Iss != p.Actor.Sub {
		return fmt.Sprintf("iss %q is not act.sub %q: the actor signs as itself", p.Iss, p.Actor.Sub)
	}

	t, ok := c["target"].(map[string]any)
	if !ok {
		return "it has no target object"
	}
	switch aud := t["aud"].(type) {
	case string:
		p.Aud = []string{aud}
	case []any:
		for _, e := range aud {
			s, ok := e.(string)
			if !ok {
				return "target.aud holds " + jsonKind(e) + ", not only strings"
			}
			p.Aud = append(p.Aud, s)
		}
	default:
		return "target.aud is not a string or an array of strings"
	}
	if v, ok := t["resource"]; ok {
		arr, ok := v.([]any)
		if !ok {
			return "target.resource is not an array"
		}
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return "target.resource holds " + jsonKind(e) + ", not only strings"
			}
			p.Res = append(p.Res, s)
		}
		p.HasRes = true
	}
	return ""
}

// prhAlgs are the hashes a proof chain may be linked with: the RFC 6920
// names at least as strong as SHA-256. A truncated hash is not.
var prhAlgs = map[string]func() hash.Hash{
	"sha-256": sha256.New,
	"sha-384": sha512.New384,
	"sha-512": sha512.New,
}

// prhOf is the prh a newer proof carries for the exact compact bytes of the
// one it extends (section 4.3): no canonicalisation, so a proof re-encoded
// on the way breaks the link, as it should.
func prhOf(alg, raw string) string {
	h := prhAlgs[alg]()
	h.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// proofCheck is what one proof established on its own: its form, its
// alignment with the hop it covers, its signature and its time.
type proofCheck struct {
	Status chain.Status
	Detail string
	// NeedKeys is set when the actor's keys were not given.
	NeedKeys bool
}

// proofChain is the result of section 7 for one token.
type proofChain struct {
	// Present is set when the token carries actor_proofs at all.
	Present bool
	Proofs  []*proof
	Each    []proofCheck
	Status  chain.Status
	Detail  string
	// Notes are what holds but limits what the proofs show: partial
	// coverage, no instance binding, consent to audience only. Warns limit
	// it more: a proof the chain carries that cannot stand for its actor.
	Notes []string
	Warns []string
	// NeedActorKeys is set when a proof was unchecked for want of its
	// actor's keys.
	NeedActorKeys bool
	// Depth is the token's visible actor-chain depth.
	Depth int
}

// covers reports whether proof i of the chain is relied on to show the hop
// it covers: the whole chain holds, and the proof was signed for the same
// subject as the newest. A proof for another subject is the cross-subject
// graft section 7.1 warns about, so it never stands for an actor of this
// one.
func (pc proofChain) covers(i int) bool {
	return pc.Present && pc.Status == chain.StatusPass && i < len(pc.Proofs) && pc.sameSubject(i)
}

func (pc proofChain) sameSubject(i int) bool {
	return pc.Proofs[i].Sub == pc.Proofs[0].Sub && pc.Proofs[i].SubIss == pc.Proofs[0].SubIss
}

// evalProofs applies section 7 to token k. The proofs are checked at the
// same moment the token's own time rule uses: now for the token presented
// last, and for an earlier one the moment the next token was issued.
func (s *session) evalProofs(k int, at time.Time) proofChain {
	t := s.tokens[k]
	pc := proofChain{Status: chain.StatusNotApplicable}
	if t.Problem != "" {
		pc.Status, pc.Detail = chain.StatusSkipped, "not checked: the token cannot be read"
		return pc
	}
	v, present := t.Claims["actor_proofs"]
	complete, hasComplete := t.Claims["actor_proofs_complete"].(bool)
	if raw, ok := t.Claims["actor_proofs_complete"]; ok && !hasComplete {
		pc.Status, pc.Detail = chain.StatusFail, "actor_proofs_complete is "+jsonKind(raw)+", not a boolean"
		return pc
	}
	if !present {
		if complete {
			pc.Status, pc.Detail = chain.StatusFail, "actor_proofs_complete is true, but the token carries no actor_proofs"
			return pc
		}
		pc.Detail = "the token carries no actor_proofs: no actor signed its own hop"
		return pc
	}
	pc.Present = true
	fail := func(detail string) proofChain {
		pc.Status, pc.Detail = chain.StatusFail, detail
		return pc
	}

	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return fail("actor_proofs is not a non-empty array")
	}
	raws := make([]string, len(arr))
	for i, e := range arr {
		r, ok := e.(string)
		if !ok {
			return fail(fmt.Sprintf("actor_proofs[%d] is %s, not a compact JWT", i, jsonKind(e)))
		}
		raws[i] = r
	}
	if _, hasAct := t.Claims["act"]; !hasAct {
		return fail("the token carries actor_proofs but no act claim for them to cover")
	}
	if t.ActProblem != "" {
		pc.Present = false
		pc.Status, pc.Detail = chain.StatusSkipped, "not checked: the act chain the proofs cover cannot be read"
		return pc
	}
	pc.Depth = len(t.Actors)
	if len(raws) > pc.Depth {
		return fail(fmt.Sprintf("%d proofs for %d actors: a proof covers one visible hop", len(raws), pc.Depth))
	}
	if complete && len(raws) != pc.Depth {
		return fail(fmt.Sprintf("actor_proofs_complete is true, but %d proofs cover %d actors", len(raws), pc.Depth))
	}

	ref, refOK := at, true
	if k < len(s.tokens)-1 {
		next := s.tokens[k+1]
		refOK = next.Problem == "" && next.Iat != nil
		if refOK {
			ref = *next.Iat
		}
	}

	for i, r := range raws {
		p := parseProof(r)
		pc.Proofs = append(pc.Proofs, p)
		pc.Each = append(pc.Each, s.checkProof(t, i, p, ref, refOK))
	}
	worst := chain.StatusPass
	for i, e := range pc.Each {
		pc.NeedActorKeys = pc.NeedActorKeys || e.NeedKeys
		switch {
		case e.Status == chain.StatusFail:
			return fail(fmt.Sprintf("proof %d (%s): %s", i, pc.Proofs[i].label(), e.Detail))
		case e.Status == chain.StatusError && worst != chain.StatusError:
			worst, pc.Detail = chain.StatusError, fmt.Sprintf("proof %d (%s): %s", i, pc.Proofs[i].label(), e.Detail)
		case e.Status == chain.StatusUnchecked && worst == chain.StatusPass:
			worst, pc.Detail = chain.StatusUnchecked, fmt.Sprintf("proof %d (%s): %s", i, pc.Proofs[i].label(), e.Detail)
		}
	}

	// Step 6: the chain is linked by prh, all with one algorithm.
	alg := "sha-256"
	for i, p := range pc.Proofs {
		if p.HasAlg != pc.Proofs[0].HasAlg || p.PrhAlg != pc.Proofs[0].PrhAlg {
			return fail("the proofs do not all carry the same prh_alg; a mixed chain is rejected even where both select SHA-256")
		}
		if i == 0 && p.HasAlg {
			alg = p.PrhAlg
		}
	}
	if prhAlgs[alg] == nil {
		return fail(fmt.Sprintf("prh_alg %q is not a hash whosent supports (sha-256, sha-384, sha-512)", alg))
	}
	for i, p := range pc.Proofs {
		oldest := i == len(pc.Proofs)-1
		switch {
		case oldest && p.HasPrh:
			return fail(fmt.Sprintf("proof %d is the oldest but carries prh: it links to a proof that is not there", i))
		case !oldest && !p.HasPrh:
			return fail(fmt.Sprintf("proof %d has no prh, so nothing links it to proof %d", i, i+1))
		case !oldest && p.Prh != prhOf(alg, raws[i+1]):
			return fail(fmt.Sprintf("proof %d's prh is not the %s of proof %d: the chain was reordered, altered or spliced", i, alg, i+1))
		}
	}

	// Step 8: the newest proof was signed for this token's subject.
	newest := pc.Proofs[0]
	if newest.Sub != t.Sub {
		return fail(fmt.Sprintf("the newest proof was signed for subject %q, but the token's is %q", newest.Sub, t.Sub))
	}
	// The namespace of that subject is compared only against one the token
	// itself states: its iss is not one, since the draft's own example has
	// a token issued by one authorization server for a subject another
	// names.
	if newest.SubIss != "" {
		switch tokSubIss, ok := t.Claims["sub_iss"].(string); {
		case ok && tokSubIss != newest.SubIss:
			return fail(fmt.Sprintf("the newest proof's subject is %q under %q, but the token puts it under %q (sub_iss)", newest.Sub, newest.SubIss, tokSubIss))
		case !ok:
			pc.Notes = append(pc.Notes, fmt.Sprintf("the newest proof names %q as the subject's namespace (sub_iss), and the token states none to compare it with", newest.SubIss))
		}
	}
	for i, p := range pc.Proofs {
		if !pc.sameSubject(i) {
			pc.Warns = append(pc.Warns, fmt.Sprintf("proof %d was signed for subject %q, not %q: whether that is the same party is not checked, so it does not stand for its actor (section 7.1)", i, p.Sub, newest.Sub))
		}
	}

	// Step 9: the token stays within what the newest actor consented to.
	// A divergent chain is rejected: whosent has no trusted reissuing
	// issuers, so it is in strict mode (section 11.4.1).
	for _, a := range t.Aud {
		if !contains(newest.Aud, a) {
			return fail(fmt.Sprintf("the token is addressed to %s, which %s did not consent to (target.aud %s): it diverged from its proof", a, newest.Actor.name(), strings.Join(newest.Aud, ", ")))
		}
	}
	if newest.HasRes {
		if res, ok := t.Claims["resource"]; ok {
			for _, r := range strs(res) {
				if !contains(newest.Res, r) {
					return fail(fmt.Sprintf("the token names resource %s, which %s did not consent to: it diverged from its proof", r, newest.Actor.name()))
				}
			}
		} else {
			pc.Notes = append(pc.Notes, "the token names no resource, so the newest proof is consent to its audience only")
		}
	}
	switch {
	case newest.HasOrig && t.JTI == "":
		return fail("the newest proof is bound to token " + newest.Origin + " (origin_jti), and this token has no jti")
	case newest.HasOrig && newest.Origin != t.JTI:
		return fail(fmt.Sprintf("the newest proof is bound to token %s (origin_jti), not this one (%s)", newest.Origin, t.JTI))
	case !newest.HasOrig:
		pc.Notes = append(pc.Notes, "the proofs carry no origin_jti, so they are not bound to this token: they could be carried by another with the same subject, actor and target (section 11.4)")
	}

	// Section 6.2: an exchange keeps the proofs it inherits byte for byte.
	if k > 0 && len(raws) > 1 {
		if prev, ok := s.tokens[k-1].Claims["actor_proofs"].([]any); ok && !sameStrings(raws[1:], prev) {
			return fail(fmt.Sprintf("the proofs after the newest are not token %d's actor_proofs byte for byte (section 6.2)", k-1))
		}
	}

	if n := len(pc.Proofs); n < pc.Depth {
		pc.Notes = append(pc.Notes, fmt.Sprintf("the proofs cover the newest %d of %d actors; the rest are the issuer's word", n, pc.Depth))
	}
	pc.Status = worst
	if worst == chain.StatusPass {
		pc.Detail = fmt.Sprintf("%d of %d actor%s signed %s hop, linked by %s; %s consented to this token's audience",
			len(pc.Proofs), pc.Depth, plural(pc.Depth), map[bool]string{true: "its", false: "their"}[len(pc.Proofs) == 1], alg, newest.Actor.name())
	}
	return pc
}

// checkProof checks proof i of token t on its own: its form, that it
// covers the hop at its place in the act chain, its signature against the
// actor's configured keys, and its time.
func (s *session) checkProof(t *token, i int, p *proof, ref time.Time, refOK bool) proofCheck {
	if p.Problem != "" {
		return proofCheck{Status: chain.StatusFail, Detail: p.Problem}
	}
	// Step 7: proof i covers the i-th actor from the outermost.
	vis := t.Actors[len(t.Actors)-1-i]
	if p.Actor.Sub != vis.Sub || p.Actor.Iss != vis.Iss {
		return proofCheck{Status: chain.StatusFail, Detail: fmt.Sprintf("signed for actor %q of %q, but the act chain names %q of %q at that hop", p.Actor.Sub, p.Actor.Iss, vis.Sub, vis.Iss)}
	}
	if p.Actor.SubProfile != "" && !sameProfiles(p.Actor.SubProfile, vis.SubProfile) {
		return proofCheck{Status: chain.StatusFail, Detail: fmt.Sprintf("the actor signed sub_profile %q, but the act chain says %q", p.Actor.SubProfile, vis.SubProfile)}
	}

	sig := proofCheck{Status: chain.StatusPass}
	id := actorID{Iss: p.Actor.Iss, Sub: p.Actor.Sub}
	switch ik := s.actorKeys[id]; {
	case ik == nil:
		sig = proofCheck{Status: chain.StatusUnchecked, NeedKeys: true, Detail: fmt.Sprintf("no keys for actor %q of %q; add it under actors in the --trust file", id.Sub, id.Iss)}
	case ik.Err != "":
		sig = proofCheck{Status: chain.StatusError, Detail: "keys for this actor could not be used: " + ik.Err}
	default:
		r := verifyWith(ik, p.Raw, p.Alg, p.Kid, "the actor")
		if r.Status != chain.StatusPass {
			return proofCheck{Status: r.Status, Detail: r.Detail}
		}
		sig.Detail = "signed by the actor, " + r.Detail
	}

	switch {
	case !refOK:
		return proofCheck{Status: chain.StatusUnchecked, NeedKeys: sig.NeedKeys, Detail: "the next token has no iat, so whether this proof still held when it was exchanged is unknown"}
	case !ref.Add(-s.skew).Before(*p.Exp):
		return proofCheck{Status: chain.StatusFail, Detail: "expired at " + stamp(*p.Exp) + "; an expired proof is rejected even for an older hop"}
	case ref.Add(s.skew).Before(*p.Iat):
		return proofCheck{Status: chain.StatusFail, Detail: "signed at " + stamp(*p.Iat) + ", in the future"}
	case p.Nbf != nil && ref.Add(s.skew).Before(*p.Nbf):
		return proofCheck{Status: chain.StatusFail, Detail: "not valid before " + stamp(*p.Nbf)}
	}
	return sig
}

func (p *proof) label() string {
	if p.Problem != "" && p.Actor.Sub == "" {
		return "unreadable"
	}
	return p.Actor.name()
}

// sameProfiles compares sub_profile values the way step 7 asks: as sets of
// space-separated values, without case, order or duplicates.
func sameProfiles(a, b string) bool {
	set := func(s string) []string {
		out := strings.Fields(strings.ToLower(s))
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(set(a), set(b))
}

func sameStrings(a []string, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if s, ok := b[i].(string); !ok || s != a[i] {
			return false
		}
	}
	return true
}

// proofSections describe one proof for the inspector, and proofRaw shows
// it as signed.
func proofSections(p *proof, pc proofCheck) chain.Section {
	sec := chain.Section{Title: "ACTOR PROOF"}
	add := func(k, v string, tone chain.Tone) {
		if v != "" {
			sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
		}
	}
	tone := chain.ToneText
	switch pc.Status {
	case chain.StatusPass:
		tone = chain.ToneGood
	case chain.StatusFail, chain.StatusError:
		tone = chain.ToneBad
	case chain.StatusUnchecked:
		tone = chain.ToneWarn
	}
	add("signature", pc.Detail, tone)
	add("for subject", p.Sub, chain.ToneRoot)
	add("target aud", strings.Join(p.Aud, ", "), chain.ToneText)
	add("target resource", strings.Join(p.Res, ", "), chain.ToneText)
	if p.Iat != nil {
		add("signed", stamp(*p.Iat), chain.ToneMuted)
	}
	if p.Exp != nil {
		add("expires", stamp(*p.Exp), chain.ToneText)
	}
	add("jti", p.JTI, chain.ToneMuted)
	add("origin_jti", p.Origin, chain.ToneMuted)
	add("prh", p.Prh, chain.ToneMuted)
	if pc.Status == chain.StatusPass {
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Tone: chain.ToneMuted,
			Value: "The actor signed this itself (" + specProofs + "). It shows the actor took part and consented to the target; it does not show an authorization server checked the hop."})
	}
	return sec
}

func proofRaw(p *proof) []chain.Section {
	var out []chain.Section
	if p.Header != nil {
		out = append(out, chain.Section{Title: "PROOF HEADER", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(p.Header)}}})
	}
	if p.Claims != nil {
		out = append(out, chain.Section{Title: "PROOF CLAIMS", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(p.Claims)}}})
	}
	return append(out, chain.Section{Title: "PROOF COMPACT", Lines: []chain.Line{{Kind: chain.LineCode, Value: p.Raw}}})
}

// proofsSection summarises a token's proof chain on its own link.
func proofsSection(pc proofChain) chain.Section {
	sec := chain.Section{Title: "ACTOR PROOFS"}
	for i, p := range pc.Proofs {
		v := p.label()
		if i < len(pc.Each) && pc.Each[i].Detail != "" {
			v += ": " + pc.Each[i].Detail
		}
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: fmt.Sprintf("proof %d", i), Value: v})
	}
	for _, n := range pc.Notes {
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Value: n, Tone: chain.ToneMuted})
	}
	return sec
}

// whyNotRelied says why a prior actor's proof did not make it the actor's
// own word.
func whyNotRelied(pc proofChain, p plan) string {
	switch {
	case pc.Status != chain.StatusPass:
		return fmt.Sprintf("token %d's actor proofs are %s (see its J11)", p.named, pc.Status)
	case !pc.sameSubject(p.proof):
		return "it was signed for another subject (section 7.1)"
	}
	return fmt.Sprintf("token %d itself does not verify", p.named)
}
