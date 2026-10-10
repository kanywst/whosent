package biscuit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/internal/formats/biscuit/pb"
	"github.com/kanywst/whosent/pkg/chain"
)

// The rules, in the order every link lists them.
const (
	RuleFormat     = "B1"
	RuleVersion    = "B2"
	RuleSignature  = "B3"
	RuleThirdParty = "B4"
	RuleProof      = "B5"
	RuleSymbols    = "B6"
	RuleChecks     = "B7"
	RuleRevocation = "B8"
)

const specURL = "https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md"

var rules = []chain.RuleInfo{
	{ID: RuleFormat, Title: "format", Spec: specURL + "#format"},
	{ID: RuleVersion, Title: "version", Spec: specURL + "#blocks"},
	{ID: RuleSignature, Title: "signature", Spec: specURL + "#verifying"},
	{ID: RuleThirdParty, Title: "third party", Spec: specURL + "#verifying-external-signatures"},
	{ID: RuleProof, Title: "proof", Spec: specURL + "#verifying-sealed"},
	{ID: RuleSymbols, Title: "symbols", Spec: specURL + "#symbol-table"},
	{ID: RuleChecks, Title: "checks", Spec: specURL + "#authorizer"},
	{ID: RuleRevocation, Title: "revocation", Spec: specURL + "#revocation-identifiers"},
}

func ruleIndex(id string) int {
	for i, r := range rules {
		if r.ID == id {
			return i
		}
	}
	return -1
}

// Options are what a token is checked against.
type Options struct {
	// RootKeys are the keys the authority block may be signed with. None
	// leaves the authority block's signature unchecked.
	RootKeys []Key
	// RootSources name where each root key came from, for display.
	RootSources []string
	// Revoked is the set of revoked revocation identifiers (lower-case
	// hex), or nil when no list was given.
	Revoked map[string]bool
	// RevokedSource names the list.
	RevokedSource string
	// Facts and Program are the authorizer's own Datalog. HasAuthorizer is
	// false when neither was given: then only expiry checks are evaluated.
	Program       datalog.Program
	HasAuthorizer bool
	// AuthorizerSource describes the authorizer, for display.
	AuthorizerSource string
	// Ignored lists inputs given that Biscuit has no use for.
	Ignored []string
	// Limits bound the Datalog run.
	Limits datalog.Limits
}

// blockResult is everything known about one block.
type blockResult struct {
	index    int
	signed   SignedBlock
	proto    *pb.Block
	block    datalog.Block
	symbols  []string
	keys     []datalog.PublicKey
	readable bool
	third    bool
	checks   []chain.Check
	findings []chain.Finding
	// source is the block's Datalog as the reference prints it.
	source string
	// scopes is the block-level scope annotation, printed, if any.
	scopes string
	// checkSource are the block's checks, printed, with their outcome.
	checkResults []checkOutcome
	revokeID     string
	revoked      bool
	revokedSim   bool
	expires      time.Time
}

type checkOutcome struct {
	source string
	status chain.Status
	detail string
}

func (b *blockResult) set(rule string, s chain.Status, detail string) {
	i := ruleIndex(rule)
	if i < 0 {
		return
	}
	// A worse status wins: a later observation never hides a failure.
	if b.checks[i].Status == chain.StatusFail || (b.checks[i].Status == chain.StatusError && s != chain.StatusFail) {
		return
	}
	b.checks[i] = chain.Check{Rule: rule, Status: s, Detail: detail}
}

func (b *blockResult) status(rule string) chain.Status { return b.checks[ruleIndex(rule)].Status }

func (b *blockResult) find(rule string, sev chain.Severity, code, detail string) {
	b.findings = append(b.findings, chain.Finding{Rule: rule, Link: b.index, Hop: -1, Severity: sev, Code: code, Detail: detail, Spec: chain.Format{Rules: rules}.Rule(rule).Spec})
}

// analysis is a token checked against options at one time.
type analysis struct {
	tok          *Token
	opts         Options
	at           time.Time
	blocks       []*blockResult
	chainFinding []chain.Finding
	// tokenSyms is the token's symbol table, built from every first-party
	// block in order.
	tokenSyms *datalog.SymbolTable
	// rootUsed is the root key the authority block verified against.
	rootUsed   *Key
	authorized *datalog.Result
	// evaluated says whether checks were evaluated at all, and timeOnly
	// whether only expiry checks were.
	evaluated    bool
	timeOnly     bool
	b7Reason     string
	simulated    []string
	policyNote   string
	userTime     bool
	signaturesOK bool
}

func hexID(sig []byte) string { return hex.EncodeToString(sig) }

func analyze(tok *Token, opts Options, at time.Time, simRevoked []string) *analysis {
	a := &analysis{tok: tok, opts: opts, at: at, tokenSyms: datalog.NewSymbolTable()}
	sim := map[string]bool{}
	for _, id := range simRevoked {
		sim[id] = true
	}
	for i, sb := range tok.Blocks {
		br := &blockResult{index: i, signed: sb, checks: make([]chain.Check, len(rules)), third: i > 0 && sb.External != nil}
		for k, r := range rules {
			br.checks[k] = chain.Check{Rule: r.ID, Status: chain.StatusPass}
		}
		br.revokeID = hexID(sb.Signature)
		a.blocks = append(a.blocks, br)
	}
	a.decode()
	a.verifySignatures()
	a.revocation(sim)
	a.authorize()
	a.expiry()
	return a
}

// decode reads each block's Datalog and builds the token's symbol table.
func (a *analysis) decode() {
	for i, br := range a.blocks {
		sb := br.signed
		if _, err := ParseKey(sb.NextKey); err != nil {
			br.set(RuleFormat, chain.StatusFail, "the next key is unusable: "+err.Error())
			br.find(RuleFormat, chain.SeverityFail, "b1.next_key", fmt.Sprintf("block %d's next key is unusable (%v), so the block after it cannot be verified and the reference refuses the whole token", i, err))
		}
		pbb, err := datalog.DecodeBlock(sb.Data)
		if err != nil {
			br.set(RuleFormat, chain.StatusFail, err.Error())
			br.find(RuleFormat, chain.SeverityFail, "b1.decode", fmt.Sprintf("block %d's Datalog does not decode: %v", i, err))
			br.set(RuleVersion, chain.StatusSkipped, "the block does not decode")
			br.set(RuleSymbols, chain.StatusSkipped, "the block does not decode")
			continue
		}
		br.proto = pbb
		blk, syms, keys, err := datalog.FromProto(pbb, br.third)
		switch {
		case err == nil:
		case datalog.IsVersionError(err):
			br.set(RuleVersion, chain.StatusFail, err.Error())
			br.find(RuleVersion, chain.SeverityFail, "b2.version", fmt.Sprintf("block %d: %v", i, err))
		case errors.Is(err, datalog.ErrSymbolOverlap):
			br.set(RuleSymbols, chain.StatusFail, err.Error())
			br.find(RuleSymbols, chain.SeverityFail, "b6.overlap", fmt.Sprintf("block %d: %v", i, err))
		default:
			br.set(RuleFormat, chain.StatusFail, err.Error())
			br.find(RuleFormat, chain.SeverityFail, "b1.datalog", fmt.Sprintf("block %d's Datalog is malformed: %v", i, err))
		}
		if err != nil {
			continue
		}
		br.block, br.symbols, br.keys, br.readable = blk, syms, keys, true
		if !br.third {
			if err := a.tokenSyms.Extend(syms); err != nil {
				br.set(RuleSymbols, chain.StatusFail, err.Error())
				br.find(RuleSymbols, chain.SeverityFail, "b6.overlap", fmt.Sprintf("block %d redefines a symbol an earlier block defined (%v); the reference refuses the token", i, err))
			}
			if err := a.tokenSyms.ExtendKeys(keys); err != nil {
				br.set(RuleSymbols, chain.StatusFail, err.Error())
				br.find(RuleSymbols, chain.SeverityFail, "b6.keys", fmt.Sprintf("block %d: %v", i, err))
			}
		}
	}
	for _, br := range a.blocks {
		if !br.readable {
			continue
		}
		syms := a.symbolsFor(br)
		if missing := unknownSymbols(br.block, syms); len(missing) > 0 {
			br.set(RuleSymbols, chain.StatusFail, fmt.Sprintf("refers to symbol %d, which no block defines", missing[0]))
			br.find(RuleSymbols, chain.SeverityFail, "b6.unknown", fmt.Sprintf("block %d refers to symbol %d, which no block defines; no authorizer can load it", br.index, missing[0]))
		}
		br.source = syms.PrintBlock(br.block)
		if len(br.block.Scopes) > 0 {
			r := datalog.Rule{Scopes: br.block.Scopes}
			br.scopes = syms.PrintRuleBody(r)
		}
	}
}

// symbolsFor is the table a block's indices refer to: the token's, or for
// a third-party block its own.
func (a *analysis) symbolsFor(br *blockResult) *datalog.SymbolTable {
	if !br.third {
		return a.tokenSyms
	}
	t := datalog.NewSymbolTable()
	_ = t.Extend(br.symbols)
	_ = t.ExtendKeys(br.keys)
	return t
}

func unknownSymbols(b datalog.Block, syms *datalog.SymbolTable) []uint64 {
	var out []uint64
	seen := map[uint64]bool{}
	check := func(i uint64) {
		if _, ok := syms.Symbol(i); !ok && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	var term func(t datalog.Term)
	term = func(t datalog.Term) {
		switch t.Kind {
		case datalog.KindVariable, datalog.KindString:
			check(t.U)
		case datalog.KindSet, datalog.KindArray:
			for _, e := range t.Elems {
				term(e)
			}
		case datalog.KindMap:
			for _, e := range t.Map {
				if e.Key.IsString {
					check(e.Key.U)
				}
				term(e.Value)
			}
		}
	}
	pred := func(p datalog.Predicate) {
		check(p.Name)
		for _, t := range p.Terms {
			term(t)
		}
	}
	var ops func([]datalog.Op)
	ops = func(os []datalog.Op) {
		for _, op := range os {
			switch op.Kind {
			case datalog.OpValue:
				term(op.Value)
			case datalog.OpClosure:
				for _, p := range op.Params {
					check(p)
				}
				ops(op.Ops)
			}
		}
	}
	rule := func(r datalog.Rule) {
		pred(r.Head)
		for _, p := range r.Body {
			pred(p)
		}
		for _, e := range r.Expressions {
			ops(e.Ops)
		}
	}
	for _, f := range b.Facts {
		pred(f.Predicate)
	}
	for _, r := range b.Rules {
		rule(r)
	}
	for _, c := range b.Checks {
		for _, q := range c.Queries {
			rule(q)
		}
	}
	return out
}

// verifySignatures checks every block's signature, third-party signature
// and the proof, as the reference's verify does, but without stopping at
// the first failure.
func (a *analysis) verifySignatures() {
	n := len(a.blocks)
	for i, br := range a.blocks {
		sb := br.signed
		if sb.Version > 1 {
			br.set(RuleSignature, chain.StatusFail, fmt.Sprintf("signature payload version %d is not one the reference knows", sb.Version))
			br.find(RuleSignature, chain.SeverityFail, "b3.version", fmt.Sprintf("block %d says its signature uses payload version %d; only 0 and 1 exist", i, sb.Version))
			continue
		}
		if i == 0 {
			if sb.External != nil {
				br.set(RuleThirdParty, chain.StatusFail, "the authority block carries a third-party signature")
				br.find(RuleThirdParty, chain.SeverityFail, "b4.authority", "the authority block carries a third-party signature, which the reference refuses: it would let one party's signature be reused on any token")
			} else {
				br.set(RuleThirdParty, chain.StatusNotApplicable, "")
			}
			a.verifyAuthority(br)
		} else {
			a.verifyBlock(br, a.blocks[i-1])
		}
		if i != n-1 {
			br.set(RuleProof, chain.StatusNotApplicable, "")
		}
	}
	a.verifyProof(a.blocks[n-1])
	a.signaturesOK = true
	for _, br := range a.blocks {
		for _, r := range []string{RuleFormat, RuleVersion, RuleSignature, RuleThirdParty, RuleProof, RuleSymbols} {
			if br.status(r).Blocking() {
				a.signaturesOK = false
			}
		}
	}
}

func (a *analysis) verifyAuthority(br *blockResult) {
	sb := br.signed
	var payload []byte
	if sb.Version == 1 {
		payload = payloadAuthorityV1(sb.Data, sb.NextKey, sb.Version)
	} else {
		payload = payloadV0(sb.Data, sb.NextKey, nil)
	}
	if len(a.opts.RootKeys) == 0 {
		br.set(RuleSignature, chain.StatusUnchecked, "no root key given (--root-key)")
		br.find(RuleSignature, chain.SeverityUnchecked, "b3.no_root", "the authority block's signature was not checked: no root key was given. The links between later blocks were still checked, against each other")
		return
	}
	var lastErr error
	for i := range a.opts.RootKeys {
		k := a.opts.RootKeys[i]
		if err := k.Verify(payload, sb.Signature); err != nil {
			lastErr = err
			continue
		}
		a.rootUsed = &a.opts.RootKeys[i]
		detail := "signed by the root key " + shortKey(k.PublicKey)
		if len(a.opts.RootSources) > i && a.opts.RootSources[i] != "" {
			detail += " (" + a.opts.RootSources[i] + ")"
		}
		br.set(RuleSignature, chain.StatusPass, detail)
		return
	}
	var sf *sigFormatError
	if errors.As(lastErr, &sf) {
		br.set(RuleSignature, chain.StatusFail, sf.Error())
		br.find(RuleSignature, chain.SeverityFail, "b3.format", "the authority block's signature is malformed: "+sf.Error())
		return
	}
	what := "the root key you gave"
	if len(a.opts.RootKeys) > 1 {
		what = fmt.Sprintf("any of the %d root keys you gave", len(a.opts.RootKeys))
	}
	br.set(RuleSignature, chain.StatusFail, "does not verify against "+what)
	br.find(RuleSignature, chain.SeverityFail, "b3.root", "the authority block's signature does not verify against "+what+": this token was not issued by that key, or was altered")
}

func (a *analysis) verifyBlock(br, prev *blockResult) {
	sb := br.signed
	key, err := ParseKey(prev.signed.NextKey)
	if err != nil {
		br.set(RuleSignature, chain.StatusError, "the key it must be signed with is unusable")
		br.find(RuleSignature, chain.SeverityError, "b3.prev_key", fmt.Sprintf("block %d cannot be verified: block %d's next key is unusable", br.index, prev.index))
		if sb.External != nil {
			br.set(RuleThirdParty, chain.StatusError, "the block above it is unusable")
		} else {
			br.set(RuleThirdParty, chain.StatusNotApplicable, "")
		}
		return
	}
	var ext []byte
	if sb.External != nil {
		ext = sb.External.Signature
	}
	var payload []byte
	if sb.Version == 1 {
		payload = payloadBlockV1(sb.Data, sb.NextKey, ext, prev.signed.Signature, sb.Version)
	} else {
		payload = payloadV0(sb.Data, sb.NextKey, ext)
	}
	if err := key.Verify(payload, sb.Signature); err != nil {
		var sf *sigFormatError
		if errors.As(err, &sf) {
			br.set(RuleSignature, chain.StatusFail, sf.Error())
			br.find(RuleSignature, chain.SeverityFail, "b3.format", fmt.Sprintf("block %d's signature is malformed: %v", br.index, sf))
		} else {
			br.set(RuleSignature, chain.StatusFail, fmt.Sprintf("does not verify against block %d's next key", prev.index))
			br.find(RuleSignature, chain.SeverityFail, "b3.chain", fmt.Sprintf("block %d's signature does not verify against the key block %d handed on: it was not appended to this token, or it was altered", br.index, prev.index))
		}
	} else {
		br.set(RuleSignature, chain.StatusPass, fmt.Sprintf("signed with the key block %d handed on", prev.index))
	}
	if sb.External == nil {
		br.set(RuleThirdParty, chain.StatusNotApplicable, "")
		return
	}
	if sb.Version != 1 {
		br.set(RuleThirdParty, chain.StatusFail, "third-party signature uses payload version 0")
		br.find(RuleThirdParty, chain.SeverityFail, "b4.legacy", fmt.Sprintf("block %d's third-party signature uses the legacy payload, which does not bind it to this token; the reference refuses it", br.index))
		return
	}
	ek, err := ParseKey(sb.External.Key)
	if err != nil {
		br.set(RuleThirdParty, chain.StatusFail, "the third party's key is unusable: "+err.Error())
		br.find(RuleThirdParty, chain.SeverityFail, "b4.key", fmt.Sprintf("block %d's third-party key is unusable: %v", br.index, err))
		return
	}
	if err := ek.Verify(payloadExternalV1(sb.Data, prev.signed.Signature, sb.Version), sb.External.Signature); err != nil {
		br.set(RuleThirdParty, chain.StatusFail, "the third party's signature does not verify")
		br.find(RuleThirdParty, chain.SeverityFail, "b4.signature", fmt.Sprintf("block %d's third-party signature by %s does not verify for this token", br.index, shortKey(sb.External.Key)))
		return
	}
	br.set(RuleThirdParty, chain.StatusPass, "signed by "+shortKey(sb.External.Key))
}

func (a *analysis) verifyProof(last *blockResult) {
	tok := a.tok
	key, err := ParseKey(last.signed.NextKey)
	switch {
	case !tok.HasProof:
		last.set(RuleProof, chain.StatusFail, "the token has no proof")
		last.find(RuleProof, chain.SeverityFail, "b5.missing", "the token carries neither the last private key nor a seal; the reference refuses it")
	case err != nil:
		last.set(RuleProof, chain.StatusError, "the last next key is unusable")
	case tok.Sealed():
		if err := key.Verify(payloadSeal(last.signed.Data, last.signed.NextKey, last.signed.Signature), tok.FinalSignature); err != nil {
			last.set(RuleProof, chain.StatusFail, "the seal does not verify")
			last.find(RuleProof, chain.SeverityFail, "b5.seal", "the token's seal does not verify against the last block's next key: it was sealed over different blocks, or altered")
		} else {
			last.set(RuleProof, chain.StatusPass, "sealed: no block can be appended")
		}
	default:
		ok, err := secretMatches(key, tok.NextSecret)
		switch {
		case err != nil:
			last.set(RuleProof, chain.StatusFail, err.Error())
			last.find(RuleProof, chain.SeverityFail, "b5.secret", "the token's proof is not a usable private key: "+err.Error())
		case !ok:
			last.set(RuleProof, chain.StatusFail, "the proof's key is not the last block's next key")
			last.find(RuleProof, chain.SeverityFail, "b5.mismatch", "the private key the token carries does not match the last block's next key: blocks were removed or swapped after it was made")
		default:
			last.set(RuleProof, chain.StatusPass, "open: the holder can append blocks")
		}
	}
}

func (a *analysis) revocation(sim map[string]bool) {
	for _, br := range a.blocks {
		switch {
		case sim[br.revokeID]:
			br.revokedSim = true
			br.checks[ruleIndex(RuleRevocation)] = chain.Check{Rule: RuleRevocation, Status: chain.StatusFail, Detail: "revoked (simulated)", Simulated: true}
			br.findings = append(br.findings, chain.Finding{Rule: RuleRevocation, Link: br.index, Hop: -1, Severity: chain.SeverityFail, Code: "b8.revoked", Simulated: true,
				Detail: fmt.Sprintf("block %d's revocation id is revoked (simulated): an authorizer refuses the whole token", br.index), Spec: rules[ruleIndex(RuleRevocation)].Spec})
			a.simulated = append(a.simulated, br.revokeID)
		case a.opts.Revoked == nil:
			br.set(RuleRevocation, chain.StatusUnchecked, "no revocation list given")
		case a.opts.Revoked[br.revokeID]:
			br.revoked = true
			br.set(RuleRevocation, chain.StatusFail, "revoked")
			br.find(RuleRevocation, chain.SeverityFail, "b8.revoked", fmt.Sprintf("block %d's revocation id is on the revocation list: an authorizer refuses the whole token", br.index))
		default:
			br.set(RuleRevocation, chain.StatusPass, "not on the revocation list")
		}
	}
}

// pureTimeCheck reports whether every query of a check reads only the
// time fact: "check if time($t), $t <= 2026-...". Such a check's outcome
// depends only on the time the authorizer supplies, so it can be decided
// without the rest of the authorizer.
func pureTimeCheck(c datalog.Check, syms *datalog.SymbolTable) bool {
	if c.Kind != datalog.CheckOne || len(c.Queries) == 0 {
		return false
	}
	for _, q := range c.Queries {
		if len(q.Body) != 1 || len(q.Scopes) != 0 {
			return false
		}
		p := q.Body[0]
		name, _ := syms.Symbol(p.Name)
		if name != "time" || len(p.Terms) != 1 || p.Terms[0].Kind != datalog.KindVariable {
			return false
		}
	}
	return true
}

// tokenDerivesTime reports whether any rule in the token produces time
// facts, which would make a time check depend on more than the time.
func (a *analysis) tokenDerivesTime() bool {
	for _, br := range a.blocks {
		if !br.readable {
			continue
		}
		syms := a.symbolsFor(br)
		for _, r := range br.block.Rules {
			if n, _ := syms.Symbol(r.Head.Name); n == "time" {
				return true
			}
		}
	}
	return false
}

func (a *analysis) timeFact() datalog.Fact {
	return datalog.Fact{Predicate: datalog.Predicate{NameS: "time", Terms: []datalog.Term{datalog.Date(uint64(a.at.Unix()))}}}
}

func programHasTime(p datalog.Program) bool {
	for _, f := range p.Facts {
		if f.Predicate.NameS == "time" {
			return true
		}
	}
	return false
}

func (a *analysis) tokenBlocks() []datalog.TokenBlock {
	var out []datalog.TokenBlock
	for _, br := range a.blocks {
		tb := datalog.TokenBlock{Block: br.block, Symbols: a.symbolsFor(br)}
		if br.third {
			k := br.signed.External.Key
			tb.ExternalKey = &k
		}
		out = append(out, tb)
	}
	return out
}

// authorize evaluates the checks. With an authorizer, every check is
// evaluated as the reference's authorizer would; without one, only expiry
// checks are, against the evaluation time.
func (a *analysis) authorize() {
	setAll := func(s chain.Status, detail string) {
		for _, br := range a.blocks {
			if len(br.block.Checks) == 0 && br.readable {
				br.set(RuleChecks, chain.StatusNotApplicable, "")
				continue
			}
			br.set(RuleChecks, s, detail)
		}
	}
	for _, br := range a.blocks {
		if !br.readable {
			a.b7Reason = "a block does not decode, so no authorizer can load the token"
			setAll(chain.StatusSkipped, a.b7Reason)
			return
		}
	}
	if !a.signaturesOK {
		a.b7Reason = "the token does not verify, so no authorizer would evaluate its checks"
		setAll(chain.StatusSkipped, a.b7Reason)
		return
	}
	for _, br := range a.blocks {
		if br.block.UsesFfi() {
			a.b7Reason = fmt.Sprintf("block %d calls external functions (extern::), which only the authorizer that defines them can evaluate", br.index)
			setAll(chain.StatusUnchecked, a.b7Reason)
			a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityUnchecked, Code: "b7.ffi", Detail: "checks were not evaluated: " + a.b7Reason})
			return
		}
	}
	prog := a.opts.Program
	a.userTime = programHasTime(prog)
	if !a.userTime {
		prog.Facts = append(append([]datalog.Fact(nil), prog.Facts...), a.timeFact())
	}
	if !a.opts.HasAuthorizer {
		a.timeOnly = true
		prog.Policies = nil
	}
	res := datalog.Authorize(a.tokenBlocks(), prog, a.opts.Limits)
	a.authorized = &res
	a.evaluated = true

	if res.Err != nil {
		a.recordError(res)
		return
	}

	failed := map[int]map[int]string{}
	for _, f := range res.Failed {
		if failed[f.Block] == nil {
			failed[f.Block] = map[int]string{}
		}
		failed[f.Block][f.Check] = f.Rule
	}
	derivesTime := a.tokenDerivesTime()
	for _, br := range a.blocks {
		syms := a.symbolsFor(br)
		if len(br.block.Checks) == 0 {
			br.set(RuleChecks, chain.StatusNotApplicable, "the block has no checks")
			continue
		}
		var unchecked, fails int
		for j, c := range br.block.Checks {
			src := syms.PrintCheck(c)
			out := checkOutcome{source: src, status: chain.StatusPass}
			_, didFail := failed[br.index][j]
			switch {
			case a.timeOnly && (!pureTimeCheck(c, syms) || derivesTime):
				out.status, out.detail = chain.StatusUnchecked, "needs the authorizer's facts"
				unchecked++
			case didFail:
				out.status = chain.StatusFail
				fails++
			}
			br.checkResults = append(br.checkResults, out)
		}
		switch {
		case fails > 0:
			first := ""
			for _, o := range br.checkResults {
				if o.status == chain.StatusFail {
					first = o.source
					break
				}
			}
			br.set(RuleChecks, chain.StatusFail, first)
			br.find(RuleChecks, chain.SeverityFail, "b7.failed", fmt.Sprintf("block %d's check fails: %s", br.index, first))
			for _, o := range br.checkResults[1:] {
				if o.status == chain.StatusFail && o.source != first {
					br.find(RuleChecks, chain.SeverityFail, "b7.failed", fmt.Sprintf("block %d's check fails: %s", br.index, o.source))
				}
			}
		case unchecked > 0:
			br.set(RuleChecks, chain.StatusUnchecked, fmt.Sprintf("%d of %d checks need the authorizer's facts (--fact or --authorizer)", unchecked, len(br.block.Checks)))
		default:
			detail := fmt.Sprintf("all %d checks hold", len(br.block.Checks))
			if len(br.block.Checks) == 1 {
				detail = "its check holds"
			}
			br.set(RuleChecks, chain.StatusPass, detail)
		}
	}

	for _, f := range res.Failed {
		if f.Block == -1 {
			a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityFail, Code: "b7.authorizer_check",
				Detail: "the authorizer's own check fails: " + f.Rule})
		}
	}
	if a.timeOnly {
		return
	}
	switch {
	case len(prog.Policies) == 0:
		a.policyNote = "no policy given: the token's checks and the authorizer's checks were evaluated, and nothing decided allow or deny"
	case res.Policy == nil:
		a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityFail, Code: "b7.no_policy",
			Detail: "no policy matched, so the authorizer denies"})
	case !res.Policy.Allow:
		a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityFail, Code: "b7.deny",
			Detail: fmt.Sprintf("deny policy %d matched: %s", res.Policy.Index, res.Symbols.PrintPolicy(convertPolicy(prog.Policies[res.Policy.Index], res.Symbols)))})
	default:
		a.policyNote = fmt.Sprintf("allow policy %d matched: %s", res.Policy.Index, res.Symbols.PrintPolicy(convertPolicy(prog.Policies[res.Policy.Index], res.Symbols)))
	}
}

func convertPolicy(p datalog.Policy, syms *datalog.SymbolTable) datalog.Policy {
	return datalog.ConvertPolicy(p, syms)
}

func (a *analysis) recordError(res datalog.Result) {
	var ib *datalog.InvalidBlockRuleError
	if errors.As(res.Err, &ib) {
		br := a.blocks[ib.Block]
		br.set(RuleChecks, chain.StatusFail, "a rule's head uses a variable its body does not bind")
		br.find(RuleChecks, chain.SeverityFail, "b7.invalid_rule", fmt.Sprintf("block %d has a rule the reference refuses to load, so no authorizer can evaluate the token: %s", ib.Block, ib.Rule))
		for _, other := range a.blocks {
			if other != br {
				other.set(RuleChecks, chain.StatusSkipped, "the token cannot be loaded")
			}
		}
		return
	}
	detail := "evaluating the checks failed: " + res.Err.Error()
	if datalog.IsLimitError(res.Err) {
		// A run that hits its limits is refused by the reference whatever
		// facts the authorizer brings, so this is an error even when only
		// expiry was being evaluated. Never a pass, never "not checked".
		detail = "evaluating the token's checks hit the engine's limits (" + res.Err.Error() + "); the reference refuses a token that does this"
		a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityError, Code: "b7.limit", Detail: detail})
		for _, br := range a.blocks {
			if len(br.block.Checks) == 0 && len(br.block.Rules) == 0 {
				br.set(RuleChecks, chain.StatusNotApplicable, "")
				continue
			}
			br.set(RuleChecks, chain.StatusError, "the run hit its limits")
		}
		a.b7Reason = detail
		return
	}
	if a.timeOnly {
		// Without the authorizer's facts an error here may never happen
		// with them, so it decides nothing.
		for _, br := range a.blocks {
			br.set(RuleChecks, chain.StatusUnchecked, "needs the authorizer's facts")
		}
		a.b7Reason = detail
		return
	}
	if res.ErrOrigin >= 0 && res.ErrOrigin < len(a.blocks) {
		br := a.blocks[res.ErrOrigin]
		br.set(RuleChecks, chain.StatusError, res.Err.Error())
		br.find(RuleChecks, chain.SeverityError, "b7.error", fmt.Sprintf("block %d: %s; the reference stops the whole authorization on this", res.ErrOrigin, detail))
	} else {
		a.chainFinding = append(a.chainFinding, chain.Finding{Rule: RuleChecks, Link: -1, Hop: -1, Severity: chain.SeverityError, Code: "b7.error", Detail: detail})
	}
	for _, br := range a.blocks {
		if br.status(RuleChecks) == chain.StatusPass {
			br.set(RuleChecks, chain.StatusSkipped, "authorization stopped on an error")
		}
	}
}

// expiry reads each block's expiry from its time checks, the convention
// biscuit libraries write: "check if time($t), $t <= DATE".
func (a *analysis) expiry() {
	for _, br := range a.blocks {
		if !br.readable {
			continue
		}
		syms := a.symbolsFor(br)
		for _, c := range br.block.Checks {
			if !pureTimeCheck(c, syms) || len(c.Queries) != 1 {
				continue
			}
			if d, ok := expiryDate(c.Queries[0]); ok && (br.expires.IsZero() || d.Before(br.expires)) {
				br.expires = d
			}
		}
	}
}

// expiryDate recognises "$t <= DATE" and "$t < DATE" as the only
// expression of a time check.
func expiryDate(q datalog.Rule) (time.Time, bool) {
	if len(q.Expressions) != 1 {
		return time.Time{}, false
	}
	ops := q.Expressions[0].Ops
	if len(ops) != 3 || ops[0].Kind != datalog.OpValue || ops[0].Value.Kind != datalog.KindVariable ||
		ops[0].Value.U != q.Body[0].Terms[0].U || ops[1].Kind != datalog.OpValue || ops[1].Value.Kind != datalog.KindDate ||
		ops[2].Kind != datalog.OpBinary {
		return time.Time{}, false
	}
	switch ops[2].Binary {
	case datalog.LessOrEqual:
		return time.Unix(int64(ops[1].Value.U), 0).UTC(), true
	case datalog.LessThan:
		return time.Unix(int64(ops[1].Value.U)-1, 0).UTC(), true
	}
	return time.Time{}, false
}

func shortKey(k datalog.PublicKey) string {
	s := k.String()
	alg := k.Alg.String() + "/"
	h := s[len(alg):]
	if len(h) > 12 {
		h = h[:12] + "..."
	}
	return alg + h
}
