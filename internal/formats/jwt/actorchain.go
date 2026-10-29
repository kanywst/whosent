package jwt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kanywst/whosent/pkg/chain"
)

// Actor Chain (draft-mw-oauth-actor-chain-02) is a different answer to the
// question actor proofs answer: the token carries a profile (actp), a
// workflow identifier (acti) and, in a Verified profile, the authorization
// server's signed acceptance of the latest hop (actc). Each actor's own
// signed step proof stays with the server unless the token also carries
// evidence (acte): the current step, the whole path, or a disclosed subset.
// Without evidence, actc shows only that the server accepted something; it
// does not show any actor signed anything.

const (
	typActStep = "oauth-act-step+jwt"
	typActc    = "oauth-actc+jwt"
	specChain  = "draft-mw-oauth-actor-chain-02"
	viewDomain = "urn:ietf:params:oauth:actor-chain:view:v1"
)

// The draft's recommended limits (section 22) and acceptance window
// (section 10). Exceeding one fails the profile rather than being read
// partly.
const (
	chainMaxDepth  = 10
	chainMaxBytes  = 32768
	chainMaxHeader = 1024
	chainMaxSteps  = 10
	acceptWindow   = 60 * time.Second
)

type chainProfile struct {
	verified   bool
	disclosure string
}

var chainProfiles = map[string]chainProfile{
	"declared-full": {false, "full"}, "declared-subset": {false, "subset"}, "declared-actor-only": {false, "actor-only"},
	"verified-full": {true, "full"}, "verified-subset": {true, "subset"}, "verified-actor-only": {true, "actor-only"},
}

// chainAlgs are the algorithms an Actor Chain artifact may be signed with
// (section 23): fully specified and asymmetric. The polymorphic EdDSA
// identifier is excluded, though whosent accepts it for the token itself.
var chainAlgs = []string{"ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"}

// artifact is a step proof or an acceptance as read, before its claims.
type artifact struct {
	Raw    string
	Header map[string]any
	Claims map[string]any
	Alg    string
	Kid    string
}

// readArtifact reads a compact JWS held to the closed header of section 23:
// exactly alg, kid and typ, and nothing a version 2 parser could ignore.
func readArtifact(raw, typ string) (*artifact, string) {
	if len(raw) > chainMaxBytes {
		return nil, fmt.Sprintf("it is %d bytes, past the %d a compact artifact may be (section 22)", len(raw), chainMaxBytes)
	}
	h, b, problem := segments(raw)
	if problem != "" {
		return nil, problem
	}
	if len(h) > chainMaxHeader {
		return nil, fmt.Sprintf("its header is %d bytes, past the %d a header may be (section 22)", len(h), chainMaxHeader)
	}
	for _, part := range []struct {
		name string
		data []byte
	}{{"header", h}, {"payload", b}} {
		if err := strictJSON(part.data); err != nil {
			return nil, "its " + part.name + " " + err.Error()
		}
	}
	a := &artifact{Raw: raw}
	var err error
	if a.Header, err = decodeObject(h); err != nil {
		return nil, "its header is not a JSON object: " + err.Error()
	}
	if a.Claims, err = decodeObject(b); err != nil {
		return nil, "its payload is not a JSON object: " + err.Error()
	}
	if p := exactly(a.Header, []string{"alg", "kid", "typ"}, nil); p != "" {
		return nil, "its header " + p + " (section 23)"
	}
	for _, k := range []string{"alg", "kid", "typ"} {
		if s, ok := a.Header[k].(string); !ok || s == "" {
			return nil, "its header's " + k + " is not a non-empty string"
		}
	}
	a.Alg, a.Kid = str(a.Header, "alg"), str(a.Header, "kid")
	if got := str(a.Header, "typ"); normType(got) != typ {
		return nil, fmt.Sprintf("typ %q, not %s", got, typ)
	}
	if !slices.Contains(chainAlgs, a.Alg) {
		return nil, fmt.Sprintf("alg %q is not a fully specified asymmetric algorithm (section 23 accepts %s)", a.Alg, strings.Join(chainAlgs, ", "))
	}
	return a, ""
}

// stepProof is an actor's signed request for one transition (section 10).
type stepProof struct {
	*artifact
	Kind       string
	Actp       string
	Acti       string
	Actor      actorID
	Sub        string
	Issuer     string
	Resource   string
	Scope      string
	HasScope   bool
	Commitment string
	Prev       string
	Iat        time.Time
}

func readStepProof(raw string) (*stepProof, string) {
	a, problem := readArtifact(raw, typActStep)
	if problem != "" {
		return nil, problem
	}
	c := a.Claims
	p := &stepProof{artifact: a}
	kind, problem := readKind(c)
	if problem != "" {
		return nil, problem
	}
	p.Kind = kind
	members := []string{"v", "kind", "actp", "acti", "actor", "sub", "accepting_issuer", "target_context", "view_commitment", "request_id", "iat"}
	if kind == "extend" {
		members = append(members, "prev")
	}
	if p := exactly(c, members, nil); p != "" {
		return nil, p + " for a " + kind + " step proof (section 10)"
	}
	if p := wantString(c, "actp", "acti", "sub", "accepting_issuer", "view_commitment", "request_id", "prev"); p != "" {
		return nil, p
	}
	p.Actp, p.Acti, p.Sub, p.Issuer = str(c, "actp"), str(c, "acti"), str(c, "sub"), str(c, "accepting_issuer")
	p.Commitment, p.Prev = str(c, "view_commitment"), str(c, "prev")
	if p.Actor, problem = readActorID(c["actor"]); problem != "" {
		return nil, "actor " + problem
	}
	if d, err := base64.RawURLEncoding.DecodeString(p.Commitment); err != nil || len(d) != sha256.Size {
		return nil, "view_commitment is not an unpadded base64url SHA-256"
	}
	if n := len(str(c, "request_id")); n == 0 || n > 128 {
		return nil, fmt.Sprintf("request_id is %d bytes; it is 1 to 128 (section 10)", n)
	}
	if kind == "extend" {
		if p := digestProblem("prev", p.Prev); p != "" {
			return nil, p
		}
	}
	tc, ok := c["target_context"].(map[string]any)
	if !ok {
		return nil, "target_context is not an object"
	}
	if p := exactly(tc, []string{"resource"}, []string{"scope"}); p != "" {
		return nil, "target_context " + p + " (section 8)"
	}
	if p := wantString(tc, "resource", "scope"); p != "" {
		return nil, "target_context." + p
	}
	p.Resource = str(tc, "resource")
	if problem := resourceProblem(p.Resource); problem != "" {
		return nil, "target_context.resource " + problem
	}
	if _, ok := tc["scope"]; ok {
		p.Scope, p.HasScope = str(tc, "scope"), true
		if problem := scopeProblem(p.Scope); problem != "" {
			return nil, "target_context.scope " + problem
		}
	}
	if p.Iat, problem = intDate(c["iat"]); problem != "" {
		return nil, "iat " + problem
	}
	return p, ""
}

// acceptance is the authorization server's signed acceptance of one step
// (section 11). The exact compact form of the latest one is the chain head.
type acceptance struct {
	*artifact
	Kind     string
	Iss      string
	Acti     string
	Actp     string
	StepHash string
	Prev     string
	At       time.Time
}

func readAcceptance(raw string) (*acceptance, string) {
	a, problem := readArtifact(raw, typActc)
	if problem != "" {
		return nil, problem
	}
	c := a.Claims
	acc := &acceptance{artifact: a}
	kind, problem := readKind(c)
	if problem != "" {
		return nil, problem
	}
	acc.Kind = kind
	members := []string{"v", "kind", "iss", "acti", "actp", "step_hash", "accepted_at"}
	if kind == "extend" {
		members = append(members, "prev")
	}
	if p := exactly(c, members, nil); p != "" {
		return nil, p + " for a " + kind + " acceptance (section 11)"
	}
	if p := wantString(c, "iss", "acti", "actp", "step_hash", "prev"); p != "" {
		return nil, p
	}
	acc.Iss, acc.Acti, acc.Actp = str(c, "iss"), str(c, "acti"), str(c, "actp")
	acc.StepHash, acc.Prev = str(c, "step_hash"), str(c, "prev")
	if p := digestProblem("step_hash", acc.StepHash); p != "" {
		return nil, p
	}
	if kind == "extend" {
		if p := digestProblem("prev", acc.Prev); p != "" {
			return nil, p
		}
	}
	if acc.At, problem = intDate(c["accepted_at"]); problem != "" {
		return nil, "accepted_at " + problem
	}
	return acc, ""
}

// readKind reads v, which must be 2, and kind, which must be root or
// extend: an unknown version or transition fails closed (section 6).
func readKind(c map[string]any) (string, string) {
	if n, ok := c["v"].(json.Number); !ok || n.String() != "2" {
		return "", fmt.Sprintf("v is %s, not 2", jsonValue(c["v"]))
	}
	switch k := c["kind"].(type) {
	case string:
		if k == "root" || k == "extend" {
			return k, ""
		}
		return "", fmt.Sprintf("kind %q is neither root nor extend", k)
	default:
		return "", "kind is " + jsonKind(k) + ", not a string"
	}
}

// opening is a path step's actor-view opening (section 9): the salt and
// the actor-visible chain its proof committed to.
type opening struct {
	Salt []byte
	Act  []actorID
}

func readOpening(v any) (*opening, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "is not an object"
	}
	if p := exactly(m, []string{"salt", "act"}, nil); p != "" {
		return nil, p
	}
	s, ok := m["salt"].(string)
	if !ok {
		return nil, "salt is not a string"
	}
	salt, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(salt) != 32 {
		return nil, "salt is not 32 octets in unpadded base64url"
	}
	arr, ok := m["act"].([]any)
	if !ok || len(arr) == 0 {
		return nil, "act is not a non-empty array"
	}
	o := &opening{Salt: salt}
	for i, e := range arr {
		id, problem := readActorID(e)
		if problem != "" {
			return nil, fmt.Sprintf("act[%d] %s", i, problem)
		}
		o.Act = append(o.Act, id)
	}
	return o, ""
}

// commitment is the view_commitment this opening produces.
func (o *opening) commitment() string {
	h := sha256.New()
	h.Write([]byte(viewDomain))
	h.Write([]byte{0})
	h.Write(o.Salt)
	h.Write([]byte{0})
	h.Write(jcsActors(o.Act))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// jcsActors is the RFC 8785 form of an ActorID array. encoding/json is not
// JCS: it escapes <, > and & and the line separators, which JCS writes
// as they are, so a commitment over an identifier holding one would never
// match.
func jcsActors(ids []actorID) []byte {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"iss":`)
		jcsString(&b, id.Iss)
		b.WriteString(`,"sub":`)
		jcsString(&b, id.Sub)
		b.WriteByte('}')
	}
	b.WriteByte(']')
	return b.Bytes()
}

func jcsString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// chainStep is one evidence entry and what checking it established.
type chainStep struct {
	Proof *stepProof
	Acc   *acceptance
	Open  *opening
	Check proofCheck
}

// actorChain is the result of the draft's validation (section 18) for one
// token.
type actorChain struct {
	// Present is set when the token names an actp at all.
	Present  bool
	Profile  string
	Verified bool
	// Coverage and Delivery describe acte; both are empty without it.
	Coverage string
	Delivery string
	Acc      *acceptance
	// AccCheck is what checking the token's actc on its own established.
	AccCheck proofCheck
	// Steps are the expanded evidence, oldest first: step i covers the
	// i-th disclosed actor.
	Steps  []chainStep
	Status chain.Status
	Detail string
	Notes  []string
	// Warns hold but should be looked at.
	Warns []string
	// NeedActorKeys and NeedServerKeys are set when a signature was
	// unchecked for want of an actor's or a server's keys, and OnlyKeys
	// when that is the only reason anything was.
	NeedActorKeys  bool
	NeedServerKeys bool
	OnlyKeys       bool
	Depth          int
}

// covers reports whether evidence step i is relied on to show the actor it
// covers: the token's chain holds, and the evidence names every disclosed
// actor (path or disclosed, not only the current one).
func (ac actorChain) covers(i int) bool {
	return ac.Present && ac.Status == chain.StatusPass && (ac.Coverage == "path" || ac.Coverage == "disclosed") &&
		i < len(ac.Steps) && ac.Steps[i].Check.Status == chain.StatusPass
}

// evalActorChain applies section 18 to token k.
func (s *session) evalActorChain(k int) actorChain {
	t := s.tokens[k]
	ac := actorChain{Status: chain.StatusNotApplicable}
	if t.Problem != "" {
		ac.Status, ac.Detail = chain.StatusSkipped, "not checked: the token cannot be read"
		return ac
	}
	raw, present := t.Claims["actp"]
	if !present {
		for _, c := range []string{"acti", "actc", "acte"} {
			if _, ok := t.Claims[c]; ok {
				ac.Status, ac.Detail = chain.StatusFail, c+" without actp: no profile may be inferred from the token's shape (section 6)"
				return ac
			}
		}
		ac.Detail = "the token names no actor chain profile (actp)"
		return ac
	}
	ac.Present = true
	fail := func(detail string) actorChain {
		ac.Status, ac.Detail = chain.StatusFail, detail
		return ac
	}
	if len(t.Raw) > chainMaxBytes {
		return fail(fmt.Sprintf("the token is %d bytes, past the %d section 22 allows", len(t.Raw), chainMaxBytes))
	}
	if err := strictJSON(t.ClaimsJSON); err != nil {
		return fail("the token's claims " + err.Error() + " (section 6)")
	}
	name, ok := raw.(string)
	prof, known := chainProfiles[name]
	if !ok || !known {
		return fail(fmt.Sprintf("actp %s is not a profile whosent knows; an unknown profile fails closed (section 6)", jsonValue(raw)))
	}
	ac.Profile, ac.Verified = name, prof.verified
	acti, ok := t.Claims["acti"].(string)
	if !ok || acti == "" {
		return fail("acti, the workflow identifier, is missing or not a non-empty string (section 7)")
	}
	for _, c := range []string{"iss", "sub", "aud", "iat", "exp", "jti"} {
		if _, ok := t.Claims[c]; !ok {
			return fail("a profiled token carries iss, sub, aud, iat, exp and jti (section 7); this one has no " + c)
		}
	}
	vis, problem := visibleChain(t.Claims["act"])
	if problem != "" {
		return fail(problem)
	}
	ac.Depth = len(vis)
	switch {
	case prof.disclosure != "subset" && len(vis) == 0:
		return fail(name + " discloses the current actor, and the token has no act")
	case prof.disclosure == "actor-only" && len(vis) != 1:
		return fail(fmt.Sprintf("%s discloses only the current actor, and act names %d", name, len(vis)))
	}

	_, hasActc := t.Claims["actc"]
	evidence, hasActe := t.Claims["acte"]
	if !prof.verified {
		if hasActc || hasActe {
			return fail("a Declared profile carries no actc or acte (section 7)")
		}
		if p := s.chainLinkage(k, nil, acti, name, &ac); p != "" {
			return fail(p)
		}
		ac.Status = chain.StatusPass
		ac.Detail = name + ": the actor chain is the issuer's assertion, with no actor proof or acceptance"
		return ac
	}
	head, ok := t.Claims["actc"].(string)
	if !ok {
		return fail("a Verified profile carries actc, the acceptance of its latest hop, as a compact JWS (section 7)")
	}
	acc, problem := readAcceptance(head)
	if problem != "" {
		return fail("actc: " + problem)
	}
	ac.Acc = acc
	switch {
	case acc.Acti != acti || acc.Actp != name:
		return fail(fmt.Sprintf("actc is for workflow %q under %s, not this token's %q under %s", acc.Acti, acc.Actp, acti, name))
	case t.Iat != nil && acc.At.After(t.Iat.Add(s.skew)):
		return fail(fmt.Sprintf("actc was accepted at %s, after the token was issued", stamp(acc.At)))
	}
	ac.AccCheck = s.verifyServer(acc)
	if ac.AccCheck.Status == chain.StatusFail || ac.AccCheck.Status == chain.StatusError {
		ac.Status, ac.Detail = ac.AccCheck.Status, "actc: "+ac.AccCheck.Detail
		return ac
	}
	if p := s.chainLinkage(k, acc, acti, name, &ac); p != "" {
		return fail(p)
	}

	if !hasActe {
		ac.Notes = append(ac.Notes, "the token carries no acte: actc shows the authorization server accepted the hop, and no actor's own signature is in the token (commitment only)")
		return s.settleChain(ac, fmt.Sprintf("%s, accepted by %s; no actor evidence in the token", name, acc.Iss))
	}
	env, problem := readEnvelope(evidence)
	if problem != "" {
		return fail("acte " + problem)
	}
	ac.Coverage, ac.Delivery = env.Coverage, env.Delivery
	// What the profile allows is checked before delivery: evidence whosent
	// does not fetch is still evidence the token may not promise.
	switch {
	case env.Coverage == "path" && name != "verified-full":
		return fail("path evidence is only for verified-full, not " + name + " (section 12)")
	case len(vis) == 0:
		return fail(env.Coverage + " evidence covers the current actor, and the token's act discloses none (section 12)")
	}
	if env.Delivery == "introspection" {
		ac.Notes = append(ac.Notes, fmt.Sprintf("the %s evidence is delivered by introspection, which whosent does not call: only actc is checked, and no actor's own signature", env.Coverage))
		return s.settleChain(ac, fmt.Sprintf("%s, accepted by %s; %s evidence not fetched", name, acc.Iss, env.Coverage))
	}

	switch env.Coverage {
	case "current":
		if len(env.Steps) != 1 {
			return fail(fmt.Sprintf("current evidence has exactly one step, not %d (section 12)", len(env.Steps)))
		}
	case "path", "disclosed":
		if len(env.Steps) != len(vis) {
			return fail(fmt.Sprintf("%s evidence has %d steps for %d disclosed actors: one per actor (section 18)", env.Coverage, len(env.Steps), len(vis)))
		}
	}
	if env.Steps[len(env.Steps)-1].acceptance != head {
		return fail("the last step's acceptance is not the token's actc, byte for byte: the evidence is for another head")
	}
	first := len(vis) - len(env.Steps)
	seen := map[string]bool{}
	for i, es := range env.Steps {
		st := chainStep{}
		if st.Proof, problem = readStepProof(es.proof); problem != "" {
			return fail(fmt.Sprintf("step %d's proof: %s", i, problem))
		}
		if st.Acc, problem = readAcceptance(es.acceptance); problem != "" {
			return fail(fmt.Sprintf("step %d's acceptance: %s", i, problem))
		}
		if es.opening != nil {
			if st.Open, problem = readOpening(es.opening); problem != "" {
				return fail(fmt.Sprintf("step %d's opening %s", i, problem))
			}
		}
		if seen[st.Acc.Raw] {
			return fail(fmt.Sprintf("step %d repeats an acceptance: each disclosed occurrence has its own (section 12.1)", i))
		}
		seen[st.Acc.Raw] = true
		last := i == len(env.Steps)-1
		st.Check = s.checkStep(t, k, st, vis[first+i], acti, name, last)
		if st.Check.Status == chain.StatusFail {
			return fail(fmt.Sprintf("step %d (%s): %s", i, st.Proof.Actor.label(), st.Check.Detail))
		}
		// The window is the server's configuration; 60 seconds is only the
		// draft's recommended default, so a longer one is said, not failed.
		if d := st.Acc.At.Sub(st.Proof.Iat); d > acceptWindow+s.skew {
			ac.Warns = append(ac.Warns, fmt.Sprintf("step %d was accepted %d seconds after its actor signed, past the %d-second window the draft recommends (section 10)", i, int(d.Seconds()), int(acceptWindow.Seconds())))
		}
		ac.Steps = append(ac.Steps, st)
	}
	if p := evidenceShape(env.Coverage, ac.Steps, vis); p != "" {
		return fail(p)
	}
	if env.Coverage == "disclosed" {
		ac.Notes = append(ac.Notes, "that the disclosed actors belong to this path, in this order, is the issuer's attestation (section 12.1): gaps are not shown, and hidden actors are not checked")
	}
	what := map[string]string{
		"current":   "the current actor signed its hop",
		"path":      fmt.Sprintf("all %d actors signed their hops, hash-linked from the root", len(ac.Steps)),
		"disclosed": fmt.Sprintf("the %d disclosed actor%s signed %s hops", len(ac.Steps), plural(len(ac.Steps)), map[bool]string{true: "its", false: "their"}[len(ac.Steps) == 1]),
	}[env.Coverage]
	return s.settleChain(ac, fmt.Sprintf("%s, accepted by %s; %s", name, acc.Iss, what))
}

// settleChain sets the chain's status from what its signatures
// established: the token's actc and every evidence step.
func (s *session) settleChain(ac actorChain, passDetail string) actorChain {
	checks := append([]proofCheck{ac.AccCheck}, mapSteps(ac.Steps)...)
	where := func(i int) string {
		if i == 0 {
			return "actc"
		}
		return fmt.Sprintf("step %d (%s)", i-1, ac.Steps[i-1].Proof.Actor.label())
	}
	ac.Status, ac.OnlyKeys = chain.StatusPass, true
	for i, c := range checks {
		ac.NeedActorKeys = ac.NeedActorKeys || c.NeedKeys
		ac.NeedServerKeys = ac.NeedServerKeys || c.NeedServerKeys
		switch {
		case c.Status == chain.StatusError && ac.Status != chain.StatusError:
			ac.Status, ac.Detail = chain.StatusError, where(i)+": "+c.Detail
		case c.Status == chain.StatusUnchecked && ac.Status == chain.StatusPass:
			ac.Status, ac.Detail = chain.StatusUnchecked, where(i)+": "+c.Detail
		}
		if c.Status != chain.StatusPass && !c.NeedKeys && !c.NeedServerKeys {
			ac.OnlyKeys = false
		}
	}
	if ac.Status == chain.StatusPass {
		ac.Detail = passDetail
	}
	return ac
}

func mapSteps(steps []chainStep) []proofCheck {
	out := make([]proofCheck, len(steps))
	for i, st := range steps {
		out[i] = st.Check
	}
	return out
}

// chainLinkage holds a token of a bundle to the one it was exchanged from:
// the same workflow and profile, and an acceptance that extends the one
// before it (section 13), or the same head when the exchange preserved the
// state without an actor step.
func (s *session) chainLinkage(k int, acc *acceptance, acti, actp string, ac *actorChain) string {
	if k == 0 {
		return ""
	}
	prev := s.tokens[k-1]
	if prev.Problem != "" {
		return ""
	}
	pActp, ok := prev.Claims["actp"].(string)
	if !ok {
		ac.Notes = append(ac.Notes, fmt.Sprintf("token %d names no actor chain profile, so this token's chain starts here", k-1))
		return ""
	}
	pActi, _ := prev.Claims["acti"].(string)
	pHead, _ := prev.Claims["actc"].(string)
	switch {
	case pActi != acti:
		return fmt.Sprintf("workflow %q, but token %d's is %q: acti is stable for a whole workflow (section 6)", acti, k-1, pActi)
	case pActp != actp:
		return fmt.Sprintf("profile %s, but token %d's is %s: actp is stable for a whole workflow (section 6)", actp, k-1, pActp)
	case pHead == "" || acc == nil:
		return ""
	case acc.Raw == pHead:
		ac.Notes = append(ac.Notes, fmt.Sprintf("the same actc as token %d: the exchange preserved the chain without an actor step (section 13)", k-1))
	case acc.Kind != "extend":
		return fmt.Sprintf("actc starts a new root, but token %d already carried one: an exchange extends it (section 13)", k-1)
	case acc.Prev != digest(pHead):
		return fmt.Sprintf("actc's prev is not the SHA-256 of token %d's actc: this hop was not accepted from that token", k-1)
	}
	return ""
}

// checkStep checks one evidence step against the actor it covers: the
// proof and acceptance agree with each other and the token (section 18.2
// steps 4 to 10), and both signatures verify.
func (s *session) checkStep(t *token, k int, st chainStep, want actorID, acti, actp string, last bool) proofCheck {
	p, a := st.Proof, st.Acc
	failf := func(format string, args ...any) proofCheck {
		return proofCheck{Status: chain.StatusFail, Detail: fmt.Sprintf(format, args...)}
	}
	switch {
	case p.Actor != want:
		return failf("signed by %s, but act names %s there", p.Actor.label(), want.label())
	case a.Iss != p.Issuer:
		return failf("accepted by %s, but the actor sent it to %s (accepting_issuer)", a.Iss, p.Issuer)
	case a.Kind != p.Kind || a.Prev != p.Prev:
		return failf("the acceptance's kind or prev differs from the proof's: it accepts another transition")
	case p.Acti != acti || p.Actp != actp || a.Acti != acti || a.Actp != actp:
		return failf("signed for workflow %q under %s, not this token's", p.Acti, p.Actp)
	case a.StepHash != digest(p.Raw):
		return failf("step_hash is not the SHA-256 of this proof: the acceptance is for another one")
	case a.At.Before(p.Iat.Add(-s.skew)):
		return failf("accepted at %s, before the actor signed at %s", stamp(a.At), stamp(p.Iat))
	case p.Sub != t.Sub:
		// whosent knows no cross-domain subject mapping, so an alias
		// cannot be told from another subject.
		return failf("signed for subject %q, but the token's is %q, and whosent knows no subject mapping between them", p.Sub, t.Sub)
	}
	out := proofCheck{Status: chain.StatusPass}
	var unchecked []string
	if last {
		switch r := s.targetCheck(t, k, p); r.Status {
		case chain.StatusFail:
			return r
		case chain.StatusUnchecked:
			unchecked = append(unchecked, r.Detail)
		}
	}
	switch ik := s.actorKeys[p.Actor]; {
	case ik == nil:
		out.NeedKeys = true
		unchecked = append(unchecked, fmt.Sprintf("no keys for actor %s; add it under actors in the --trust file", p.Actor.label()))
	case ik.Err != "":
		return proofCheck{Status: chain.StatusError, Detail: "keys for this actor could not be used: " + ik.Err}
	default:
		if r := verifyBound(ik, p.artifact, "the actor"); r.Status != chain.StatusPass {
			return proofCheck{Status: r.Status, Detail: r.Detail}
		}
	}
	srv := s.verifyServer(a)
	switch srv.Status {
	case chain.StatusFail, chain.StatusError:
		return proofCheck{Status: srv.Status, Detail: "its acceptance: " + srv.Detail}
	case chain.StatusUnchecked:
		out.NeedServerKeys = true
		unchecked = append(unchecked, srv.Detail)
	}
	if len(unchecked) > 0 {
		out.Status, out.Detail = chain.StatusUnchecked, strings.Join(unchecked, "; and ")
		return out
	}
	out.Detail = fmt.Sprintf("signed by %s, accepted by %s", p.Actor.label(), a.Iss)
	return out
}

// targetCheck compares the current step's target with the token presented
// (section 18.2 step 10): the resource exactly, and the token's scope a
// subset of what the actor asked for.
func (s *session) targetCheck(t *token, k int, p *stepProof) proofCheck {
	var asked []string
	if p.HasScope {
		asked = strings.Split(p.Scope, " ")
	}
	for _, sc := range t.Scopes {
		if !slices.Contains(asked, sc) {
			return proofCheck{Status: chain.StatusFail, Detail: fmt.Sprintf("the token holds scope %s, which the actor did not ask for", sc)}
		}
	}
	switch {
	case k != len(s.tokens)-1:
		// An earlier token's resource is the next hop's, not the one the
		// bundle is presented to.
	case s.audience == nil:
		return proofCheck{Status: chain.StatusUnchecked, Detail: fmt.Sprintf("the actor asked for resource %s; pass --audience to compare it", p.Resource)}
	case p.Resource != *s.audience:
		return proofCheck{Status: chain.StatusFail, Detail: fmt.Sprintf("the actor asked for resource %s, and the token is presented to %s: the draft compares them exactly (section 8)", p.Resource, *s.audience)}
	}
	return proofCheck{Status: chain.StatusPass}
}

// evidenceShape holds the steps to what their coverage promises (sections
// 18.3 and 18.4): a path is root then extends, each linked to the one
// before and opening to the actor-visible chain; a disclosed subset has at
// most one root, first.
func evidenceShape(coverage string, steps []chainStep, vis []actorID) string {
	switch coverage {
	case "path":
		for i, st := range steps {
			switch {
			case st.Open == nil:
				return fmt.Sprintf("path step %d has no opening", i)
			case i == 0 && st.Proof.Kind != "root":
				return "the path's first step is not its root"
			case i > 0 && st.Proof.Kind != "extend":
				return fmt.Sprintf("path step %d is a second root", i)
			case i > 0 && st.Proof.Prev != digest(steps[i-1].Acc.Raw):
				return fmt.Sprintf("step %d's prev is not the SHA-256 of step %d's acceptance: the path was reordered, altered or spliced", i, i-1)
			case st.Open.commitment() != st.Proof.Commitment:
				return fmt.Sprintf("step %d's opening does not match the view_commitment its actor signed", i)
			}
			want := []actorID{st.Proof.Actor}
			if i > 0 {
				want = append(slices.Clone(steps[i-1].Open.Act), st.Proof.Actor)
			}
			if !slices.Equal(st.Open.Act, want) {
				return fmt.Sprintf("step %d's opening is not the chain before it plus its own actor", i)
			}
		}
		if !slices.Equal(steps[len(steps)-1].Open.Act, vis) {
			return "the last opening is not the token's act chain"
		}
	case "current", "disclosed":
		for i, st := range steps {
			if st.Proof.Kind == "root" && i > 0 {
				return fmt.Sprintf("step %d is a root, and a root can only be the first disclosed record (section 18.4)", i)
			}
		}
	}
	return ""
}

// verifyServer checks an acceptance against the keys configured for the
// server it names. An acceptance's iss need not be the token's issuer
// after preservation, so its keys are looked up by its own iss.
func (s *session) verifyServer(a *acceptance) proofCheck {
	ik := s.keys[a.Iss]
	switch {
	case ik == nil:
		return proofCheck{Status: chain.StatusUnchecked, NeedServerKeys: true, Detail: fmt.Sprintf("no keys for authorization server %q; pass --jwks %s=PATH", a.Iss, issuerForFlag(a.Iss))}
	case ik.Err != "":
		return proofCheck{Status: chain.StatusError, Detail: "keys for this server could not be used: " + ik.Err}
	}
	r := verifyBound(ik, a.artifact, "the authorization server")
	return proofCheck{Status: r.Status, Detail: r.Detail}
}

// verifyBound checks an artifact against the one key its kid names and
// whose alg is bound to the artifact's (section 23): no match and an
// ambiguous match are both rejected, and a key without alg is not taken to
// allow every algorithm its type supports.
func verifyBound(ik *issuerKeys, a *artifact, who string) sigResult {
	var match []jose.JSONWebKey
	for _, k := range ik.Keys {
		if k.KeyID == a.Kid && k.Algorithm == a.Alg {
			match = append(match, k)
		}
	}
	switch len(match) {
	case 0:
		return sigResult{Status: chain.StatusFail, Detail: fmt.Sprintf("%s publishes no key with kid %q bound to alg %s", who, a.Kid, a.Alg)}
	case 1:
		return verifyWith(&issuerKeys{Source: ik.Source, Keys: match}, a.Raw, a.Alg, a.Kid, who)
	}
	return sigResult{Status: chain.StatusFail, Detail: fmt.Sprintf("%s publishes several keys with kid %q; the draft rejects an ambiguous match", who, a.Kid)}
}

// envelope is acte as read.
type envelope struct {
	Coverage string
	Delivery string
	Steps    []envStep
}

type envStep struct {
	proof, acceptance string
	opening           any
}

// readEnvelope reads acte (section 12): version 1 is current or path,
// version 2 is disclosed, and no other pairing is accepted.
func readEnvelope(v any) (*envelope, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "is not an object"
	}
	e := &envelope{}
	ver, _ := m["v"].(json.Number)
	e.Coverage, _ = m["coverage"].(string)
	e.Delivery, _ = m["delivery"].(string)
	switch {
	case ver.String() == "1" && (e.Coverage == "current" || e.Coverage == "path"):
	case ver.String() == "2" && e.Coverage == "disclosed":
	default:
		return nil, fmt.Sprintf("version %s with coverage %s is not a pairing the draft defines (section 12.1)", jsonValue(m["v"]), jsonValue(m["coverage"]))
	}
	members := []string{"v", "coverage", "delivery"}
	switch e.Delivery {
	case "inline":
		members = append(members, "steps")
	case "introspection":
	default:
		return nil, fmt.Sprintf("delivery %s is neither inline nor introspection", jsonValue(m["delivery"]))
	}
	if p := exactly(m, members, nil); p != "" {
		return nil, p + " for " + e.Delivery + " delivery"
	}
	if e.Delivery == "introspection" {
		return e, ""
	}
	arr, ok := m["steps"].([]any)
	if !ok || len(arr) == 0 {
		return nil, "steps is not a non-empty array"
	}
	if len(arr) > chainMaxSteps {
		return nil, fmt.Sprintf("has %d steps, past the %d section 22 allows", len(arr), chainMaxSteps)
	}
	for i, x := range arr {
		sm, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Sprintf("step %d is not an object", i)
		}
		want := []string{"proof", "acceptance"}
		if e.Coverage == "path" {
			want = append(want, "opening")
		}
		if p := exactly(sm, want, nil); p != "" {
			return nil, fmt.Sprintf("step %d %s", i, p)
		}
		pr, ok1 := sm["proof"].(string)
		ac, ok2 := sm["acceptance"].(string)
		if !ok1 || !ok2 {
			return nil, fmt.Sprintf("step %d's proof and acceptance are not both compact JWS strings", i)
		}
		e.Steps = append(e.Steps, envStep{proof: pr, acceptance: ac, opening: sm["opening"]})
	}
	return e, ""
}

// visibleChain reads act as the draft does (section 7): ActorIDs of
// exactly iss and sub, nested from the current actor inward, returned
// oldest first.
func visibleChain(v any) ([]actorID, string) {
	var out []actorID
	for v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, "an act member is not a JSON object"
		}
		if len(out) == chainMaxDepth {
			return nil, fmt.Sprintf("act nests more than %d actors, past the depth section 22 allows", chainMaxDepth)
		}
		inner := m["act"]
		node := without(m, "act")
		id, problem := readActorID(node)
		if problem != "" {
			return nil, fmt.Sprintf("act member %d %s", len(out), problem)
		}
		out = append(out, id)
		v = inner
	}
	slices.Reverse(out)
	return out, ""
}

// readActorID reads an ActorID: exactly two non-empty strings, iss an
// absolute URI.
func readActorID(v any) (actorID, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return actorID{}, "is not an object"
	}
	if p := exactly(m, []string{"iss", "sub"}, nil); p != "" {
		return actorID{}, p + "; an ActorID is exactly iss and sub (section 7)"
	}
	iss, ok1 := m["iss"].(string)
	sub, ok2 := m["sub"].(string)
	if !ok1 || !ok2 || iss == "" || sub == "" {
		return actorID{}, "has an iss or sub that is not a non-empty string"
	}
	if u, err := url.Parse(iss); err != nil || !u.IsAbs() {
		return actorID{}, fmt.Sprintf("has iss %q, not an absolute URI", iss)
	}
	return actorID{Iss: iss, Sub: sub}, ""
}

func (id actorID) label() string { return id.Sub + " of " + id.Iss }

// without returns m less one member.
func without(m map[string]any, drop string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k != drop {
			out[k] = v
		}
	}
	return out
}

// exactly reports a member m lacks or one it should not have.
func exactly(m map[string]any, required, optional []string) string {
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return "has no " + k
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return fmt.Sprintf("has member %q, which it may not", k)
		}
	}
	return ""
}

// wantString reports the first of the named members that is present and
// not a string.
func wantString(m map[string]any, names ...string) string {
	for _, k := range names {
		if v, ok := m[k]; ok {
			if _, ok := v.(string); !ok {
				return k + " is " + jsonKind(v) + ", not a string"
			}
		}
	}
	return ""
}

func digest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func digestProblem(name, v string) string {
	if d, err := base64.RawURLEncoding.DecodeString(v); err != nil || len(d) != sha256.Size {
		return name + " is not an unpadded base64url SHA-256"
	}
	return ""
}

// resourceProblem holds a signed resource to section 8: an HTTPS
// identifier with no fragment and no user information. It is parsed to
// check its syntax and never normalised: comparison is on the string.
func resourceProblem(r string) string {
	u, err := url.Parse(r)
	switch {
	case r == "":
		return "is empty"
	case err != nil:
		return "is not a URI"
	case u.Scheme != "https" || u.Host == "":
		return fmt.Sprintf("%q is not an https URI", r)
	case strings.Contains(r, "#"):
		return fmt.Sprintf("%q has a fragment", r)
	case u.User != nil:
		return fmt.Sprintf("%q carries user information", r)
	}
	return ""
}

// scopeProblem holds a signed scope to its canonical form (section 8):
// RFC 6749 scope tokens, sorted by ASCII value, no duplicates, single
// spaces. A proof in another form was not produced by a conforming actor.
func scopeProblem(sc string) string {
	if sc == "" {
		return "is empty; an empty scope set omits the member"
	}
	toks := strings.Split(sc, " ")
	for i, tok := range toks {
		if tok == "" {
			return "has a leading, trailing or repeated space"
		}
		for _, r := range tok {
			if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
				return fmt.Sprintf("token %q has a character RFC 6749 does not allow in a scope", tok)
			}
		}
		if i > 0 && toks[i-1] >= tok {
			return "is not canonical: tokens sorted by ASCII value, without duplicates (section 8)"
		}
	}
	return ""
}

// intDate reads a NumericDate the draft requires to be an integer.
func intDate(v any) (time.Time, string) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, "is " + jsonKind(v) + ", not an integer NumericDate"
	}
	i, err := n.Int64()
	if err != nil {
		return time.Time{}, "is " + n.String() + ", not an integer NumericDate"
	}
	if math.Abs(float64(i)) > maxNumericDate {
		return time.Time{}, "is " + n.String() + ", beyond the year 9999"
	}
	return time.Unix(i, 0).UTC(), ""
}

// jsonValue shows a scalar for a message.
func jsonValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "missing"
	case string:
		return fmt.Sprintf("%q", x)
	case json.Number:
		return x.String()
	}
	return jsonKind(v)
}

// strictJSON rejects what the draft says a parser must (sections 6 and 23)
// and encoding/json lets through: a repeated member, which two parsers can
// read two ways, and malformed UTF-8, which encoding/json quietly replaces.
func strictJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("has data after the object")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("nests more than 64 levels")
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("is not JSON: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if d == '{' {
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return fmt.Errorf("is not JSON: %w", err)
			}
			key, _ := k.(string)
			if seen[key] {
				return fmt.Errorf("repeats member %q, which parsers can read two ways", key)
			}
			seen[key] = true
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	} else {
		for dec.More() {
			if err := walkJSON(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("is not JSON: %w", err)
	}
	return nil
}

// chainSection summarises a token's Actor Chain on its own link.
func chainSection(ac actorChain) chain.Section {
	sec := chain.Section{Title: "ACTOR CHAIN"}
	add := func(k, v string, tone chain.Tone) {
		if v != "" {
			sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
		}
	}
	add("profile", ac.Profile, chain.ToneStrong)
	if ac.Acc != nil {
		add("workflow", ac.Acc.Acti, chain.ToneMuted)
		add("accepted by", ac.Acc.Iss, chain.ToneText)
		add("accepted", stamp(ac.Acc.At), chain.ToneMuted)
		add("kind", ac.Acc.Kind, chain.ToneMuted)
		add("actc", ac.AccCheck.Detail, toneOf(ac.AccCheck.Status))
	}
	switch {
	case ac.Coverage != "":
		add("evidence", ac.Coverage+", "+ac.Delivery, chain.ToneText)
	case ac.Verified:
		add("evidence", "none (commitment only)", chain.ToneWarn)
	}
	for i, st := range ac.Steps {
		add(fmt.Sprintf("step %d", i), st.Proof.Actor.label()+": "+st.Check.Detail, toneOf(st.Check.Status))
	}
	for _, n := range ac.Notes {
		sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Value: n, Tone: chain.ToneMuted})
	}
	return sec
}

// stepSection describes one evidence step for the inspector.
func stepSection(st chainStep, coverage string) chain.Section {
	sec := chain.Section{Title: "STEP PROOF"}
	add := func(k, v string, tone chain.Tone) {
		if v != "" {
			sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: tone})
		}
	}
	p, a := st.Proof, st.Acc
	add("signature", st.Check.Detail, toneOf(st.Check.Status))
	add("kind", p.Kind, chain.ToneMuted)
	add("for subject", p.Sub, chain.ToneRoot)
	add("resource", p.Resource, chain.ToneText)
	add("scope", p.Scope, chain.ToneText)
	add("signed", stamp(p.Iat), chain.ToneMuted)
	add("accepted by", a.Iss, chain.ToneText)
	add("accepted", stamp(a.At), chain.ToneMuted)
	add("prev", p.Prev, chain.ToneMuted)
	what := "The actor signed this request itself and the authorization server accepted it (" + specChain + ")."
	if coverage == "disclosed" {
		what += " Where it sits in the path is the issuer's attestation."
	}
	sec.Lines = append(sec.Lines, chain.Line{Kind: chain.LineText, Tone: chain.ToneMuted,
		Value: what + " It does not show the actor did the task, or that no other branch exists."})
	return sec
}

func stepRaw(st chainStep) []chain.Section {
	var out []chain.Section
	for _, part := range []struct {
		title string
		a     *artifact
	}{{"STEP PROOF", st.Proof.artifact}, {"ACCEPTANCE", st.Acc.artifact}} {
		out = append(out,
			chain.Section{Title: part.title + " HEADER", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(part.a.Header)}}},
			chain.Section{Title: part.title + " CLAIMS", Lines: []chain.Line{{Kind: chain.LineJSON, Value: pretty(part.a.Claims)}}},
			chain.Section{Title: part.title + " COMPACT", Lines: []chain.Line{{Kind: chain.LineCode, Value: part.a.Raw}}})
	}
	return out
}

func toneOf(st chain.Status) chain.Tone {
	switch st {
	case chain.StatusPass:
		return chain.ToneGood
	case chain.StatusFail, chain.StatusError:
		return chain.ToneBad
	case chain.StatusUnchecked:
		return chain.ToneWarn
	}
	return chain.ToneText
}
