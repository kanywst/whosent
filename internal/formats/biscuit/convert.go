package biscuit

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/kanywst/whosent/internal/formats/biscuit/datalog"
	"github.com/kanywst/whosent/pkg/chain"
)

// chain describes the analysis in the neutral model.
func (a *analysis) chain(source string) *chain.Chain {
	c := &chain.Chain{
		Format:         format,
		Source:         source,
		InputFormat:    "biscuit (" + string(a.tok.Encoding) + ")",
		Normalizations: a.tok.Normalizations,
		At:             a.at,
		BreakAt:        -1,
		Simulated:      a.simulated,
	}
	n := len(a.blocks)
	c.Root = a.root()

	var expires time.Time
	for i, br := range a.blocks {
		if !br.expires.IsZero() && (expires.IsZero() || br.expires.Before(expires)) {
			expires = br.expires
		}
		l := chain.Link{
			Index:            i,
			From:             a.from(i),
			To:               a.name(br),
			Readable:         br.readable,
			Revoked:          br.revoked || br.revokedSim,
			RevokedSimulated: br.revokedSim,
			Checks:           append([]chain.Check(nil), br.checks...),
			Findings:         append([]chain.Finding(nil), br.findings...),
			RevokeID:         br.revokeID,
			Sections:         a.sections(br),
			Raw:              a.raw(br),
		}
		if !expires.IsZero() {
			l.ExpiresAt = expires
			l.Remaining = expires.Sub(a.at)
		}
		blocking, unchecked := false, false
		for _, ch := range l.Checks {
			switch {
			case ch.Status.Blocking():
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
		switch {
		case blocking:
			l.State = chain.LinkBroken
		case unchecked:
			l.State = chain.LinkIncomplete
		}
		if c.BreakAt < 0 && (blocking || l.Revoked) {
			c.BreakAt = i
		}
		c.Links = append(c.Links, l)
	}
	if c.BreakAt >= 0 {
		for i := c.BreakAt + 1; i < n; i++ {
			c.Links[i].Unreached = true
			c.Links[i].UnreachedBy = c.BreakAt
			if c.Links[c.BreakAt].Revoked {
				c.Links[i].Findings = append(c.Links[i].Findings, chain.Finding{
					Rule: RuleRevocation, Link: i, Hop: -1, Severity: chain.SeverityFail, Derived: true,
					Simulated: c.Links[c.BreakAt].RevokedSimulated,
					Detail:    fmt.Sprintf("refused with the token: block %d is revoked, and an authorizer refuses a token any of whose blocks is revoked", c.BreakAt),
				})
			}
		}
	}
	for i := 1; i < n; i++ {
		c.Hops = append(c.Hops, a.hop(i))
	}
	c.ChainFindings = append(c.ChainFindings, a.chainFinding...)
	c.Matrix = a.matrix()
	c.CheckedAgainst, c.Missing = a.checkedAgainst()
	a.verdict(c)
	c.Summary = a.summary()
	c.Describe = a.describe()
	c.Context = "at " + a.at.UTC().Format(time.RFC3339)
	if a.opts.AuthorizerSource != "" {
		c.Context += ", authorizer " + a.opts.AuthorizerSource
	}
	c.Native = a.native()
	return c
}

func (a *analysis) verdict(c *chain.Chain) {
	blocking, unchecked := false, false
	for _, l := range c.Links {
		for _, ch := range l.Checks {
			switch {
			case ch.Status.Blocking():
				blocking = true
			case ch.Status == chain.StatusUnchecked:
				unchecked = true
			}
		}
	}
	for _, f := range c.Findings() {
		switch {
		case f.Severity.Blocking() && !f.Derived:
			blocking = true
		case f.Severity == chain.SeverityUnchecked:
			unchecked = true
		}
	}
	switch {
	case blocking:
		c.Verdict = chain.VerdictInvalid
	case unchecked:
		c.Verdict = chain.VerdictIncomplete
		c.IncompleteReason = a.incompleteReason()
	default:
		c.Verdict = chain.VerdictValid
		last := c.Links[len(c.Links)-1].To
		c.Headline = fmt.Sprintf("The root key's grant reaches %s through %d block%s. Every rule was checked.", last, len(c.Links), map[bool]string{true: "", false: "s"}[len(c.Links) == 1])
	}
}

// rootLabel is a root key short enough for the rail: its algorithm and the
// first eight hex digits.
func rootLabel(k datalog.PublicKey) string {
	h := hex.EncodeToString(k.Key)
	if len(h) > 8 {
		h = h[:8]
	}
	return k.Alg.String() + "/" + h
}

// compactFact is a fact as a matrix label: strings without their quotes,
// so a right fits beside its cells. The full fact is in the row's lineage.
func compactFact(syms *datalog.SymbolTable, f datalog.Fact) string {
	name, _ := syms.Symbol(f.Predicate.Name)
	parts := make([]string, len(f.Predicate.Terms))
	for i, t := range f.Predicate.Terms {
		parts[i] = syms.PrintTerm(t)
		if t.Kind == datalog.KindString {
			parts[i] = strings.Trim(parts[i], `"`)
		}
	}
	return name + "(" + strings.Join(parts, ",") + ")"
}

// checkLabel is a check as a matrix label: an expiry check reads as when
// it expires, any other check as its body after "if".
func (a *analysis) checkLabel(syms *datalog.SymbolTable, c datalog.Check) string {
	if pureTimeCheck(c, syms) && len(c.Queries) == 1 {
		if d, ok := expiryDate(c.Queries[0]); ok {
			if d.UTC().YearDay() == a.at.UTC().YearDay() && d.UTC().Year() == a.at.UTC().Year() {
				return "expires " + d.UTC().Format("15:04")
			}
			return "expires " + d.UTC().Format("2006-01-02")
		}
	}
	src := syms.PrintCheck(c)
	for _, p := range []string{"check if ", "check all ", "reject if "} {
		if strings.HasPrefix(src, p) {
			kind := map[string]string{"check if ": "if ", "check all ": "all ", "reject if ": "reject if "}[p]
			return kind + strings.TrimPrefix(src, p)
		}
	}
	return src
}

// incompleteReason names, briefly, what would have let every rule be
// checked.
func (a *analysis) incompleteReason() string {
	var parts []string
	for _, br := range a.blocks {
		if br.index == 0 && br.status(RuleSignature) == chain.StatusUnchecked {
			parts = append(parts, "no root key")
		}
	}
	if a.opts.Revoked == nil {
		parts = append(parts, "no revocation list")
	}
	switch {
	case a.timeOnly && a.anyUncheckedChecks():
		parts = append(parts, "no authorizer facts")
	case !a.evaluated && a.b7Reason != "":
		parts = append(parts, "checks that cannot be evaluated here")
	}
	if len(parts) == 0 {
		return "some rules could not be checked"
	}
	return strings.Join(parts, ", ")
}

func (a *analysis) root() chain.Root {
	r := chain.Root{Kind: "key"}
	switch {
	case a.rootUsed != nil:
		r.Name = rootLabel(a.rootUsed.PublicKey)
		r.Details = append(r.Details, "verified root key")
	case len(a.opts.RootKeys) > 0:
		r.Name = rootLabel(a.opts.RootKeys[0].PublicKey)
		r.Details = append(r.Details, "did not sign this token")
	default:
		r.Name = "unknown root key"
		r.Details = append(r.Details, "no --root-key given")
	}
	if a.tok.RootKeyID != nil {
		r.Details = append(r.Details, fmt.Sprintf("root key id hint %d", *a.tok.RootKeyID))
	}
	return r
}

// name is what the rail calls the holder of block i's authority: the
// block's context string when it has one, since Biscuit blocks name no
// one; otherwise what kind of block it is.
func (a *analysis) name(br *blockResult) string {
	if br.readable && br.block.HasContext && strings.TrimSpace(br.block.Context) != "" {
		return br.block.Context
	}
	switch {
	case br.index == 0:
		return "authority"
	case br.third:
		return "third party " + shortKey(br.signed.External.Key)
	}
	return fmt.Sprintf("block %d", br.index)
}

func (a *analysis) from(i int) string {
	if i == 0 {
		return "root key"
	}
	return a.name(a.blocks[i-1])
}

func versionName(v uint32) string {
	if v >= 3 && v <= 6 {
		return fmt.Sprintf("v3.%d", v-3)
	}
	return fmt.Sprintf("%d (unknown)", v)
}

func (a *analysis) sections(br *blockResult) []chain.Section {
	var out []chain.Section
	info := chain.Section{Title: "BLOCK"}
	kind := "attenuation block: can only add checks"
	switch {
	case br.index == 0:
		kind = "authority block: the root key's grant"
	case br.third:
		kind = "third-party block, signed by " + shortKey(br.signed.External.Key)
	}
	info.Lines = append(info.Lines, chain.Line{Kind: chain.LineKV, Key: "kind", Value: kind})
	if br.readable {
		info.Lines = append(info.Lines, chain.Line{Kind: chain.LineKV, Key: "datalog", Value: versionName(br.block.Version), Tone: chain.ToneMuted})
		if br.block.HasContext {
			info.Lines = append(info.Lines, chain.Line{Kind: chain.LineKV, Key: "context", Value: br.block.Context})
		}
	}
	info.Lines = append(info.Lines,
		chain.Line{Kind: chain.LineKV, Key: "signature", Value: fmt.Sprintf("payload v%d", br.signed.Version), Tone: chain.ToneMuted},
		chain.Line{Kind: chain.LineKV, Key: "next key", Value: shortKey(br.signed.NextKey), Tone: chain.ToneMuted},
		chain.Line{Kind: chain.LineKV, Key: "revocation", Value: shortHex(br.revokeID), Tone: chain.ToneMuted},
	)
	if !br.expires.IsZero() {
		info.Lines = append(info.Lines, chain.Line{Kind: chain.LineKV, Key: "expires", Value: br.expires.UTC().Format("2006-01-02 15:04 UTC") + " (its own time check)"})
	}
	out = append(out, info)

	if br.readable {
		code := chain.Section{Title: "DATALOG"}
		if br.scopes != "" {
			code.Lines = append(code.Lines, chain.Line{Kind: chain.LineCode, Value: strings.TrimSpace(br.scopes) + ";"})
		}
		for _, line := range strings.Split(strings.TrimSuffix(br.display, "\n"), "\n") {
			if line != "" {
				code.Lines = append(code.Lines, chain.Line{Kind: chain.LineCode, Value: line})
			}
		}
		if len(code.Lines) == 0 {
			code.Lines = append(code.Lines, chain.Line{Kind: chain.LineText, Value: "an empty block", Tone: chain.ToneMuted})
		}
		out = append(out, code)
	}
	if len(br.checkResults) > 0 {
		cs := chain.Section{Title: "CHECKS"}
		for _, o := range br.checkResults {
			l := chain.Line{Kind: chain.LineText, Value: o.source}
			switch o.status {
			case chain.StatusPass:
				l.Mark, l.Tone = chain.MarkPass, chain.ToneGood
			case chain.StatusFail:
				l.Mark, l.Tone = chain.MarkFail, chain.ToneBad
			default:
				l.Mark, l.Tone = chain.MarkUnchecked, chain.ToneWarn
				if o.detail != "" {
					l.Value += "  (" + o.detail + ")"
				}
			}
			cs.Lines = append(cs.Lines, l)
		}
		out = append(out, cs)
	}
	return out
}

func shortHex(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func (a *analysis) raw(br *blockResult) []chain.Section {
	var out []chain.Section
	sig := chain.Section{Title: "SIGNED"}
	sig.Lines = append(sig.Lines,
		chain.Line{Kind: chain.LineKV, Key: "revocation id", Value: br.revokeID, Digest: br.index + 1},
		chain.Line{Kind: chain.LineKV, Key: "next key", Value: br.signed.NextKey.String()},
		chain.Line{Kind: chain.LineKV, Key: "payload", Value: fmt.Sprintf("version %d", br.signed.Version)},
	)
	if br.index > 0 && br.signed.Version == 1 {
		// A version 1 payload commits to the previous block's signature,
		// which is its revocation id: drawing it in that block's colour
		// shows which block this one was appended to.
		sig.Lines = append(sig.Lines, chain.Line{Kind: chain.LineKV, Key: "appended to", Value: a.blocks[br.index-1].revokeID, Digest: br.index})
	}
	if br.signed.External != nil {
		sig.Lines = append(sig.Lines,
			chain.Line{Kind: chain.LineKV, Key: "third party", Value: br.signed.External.Key.String()},
			chain.Line{Kind: chain.LineKV, Key: "third-party sig", Value: hex.EncodeToString(br.signed.External.Signature), Tone: chain.ToneMuted},
		)
	}
	out = append(out, sig)
	if br.index == len(a.blocks)-1 {
		p := chain.Section{Title: "PROOF"}
		switch {
		case a.tok.Sealed():
			p.Lines = append(p.Lines, chain.Line{Kind: chain.LineKV, Key: "seal", Value: hex.EncodeToString(a.tok.FinalSignature)})
		case a.tok.HasProof:
			p.Lines = append(p.Lines, chain.Line{Kind: chain.LineKV, Key: "next secret", Value: "present (" + fmt.Sprint(len(a.tok.NextSecret)) + " bytes, not shown)", Tone: chain.ToneMuted})
		default:
			p.Lines = append(p.Lines, chain.Line{Kind: chain.LineText, Value: "no proof", Tone: chain.ToneBad})
		}
		out = append(out, p)
	}
	// The decoded protobuf comes last: it is long, and what tells blocks
	// apart, the signatures, is above it.
	if br.proto != nil {
		js, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(br.proto)
		if err == nil {
			out = append(out, chain.Section{Title: "BLOCK (protobuf, strings as symbol indices)", Lines: []chain.Line{{Kind: chain.LineJSON, Value: string(js)}}})
		}
	}
	return out
}

func (a *analysis) hop(i int) chain.Hop {
	br, prev := a.blocks[i], a.blocks[i-1]
	h := chain.Hop{Parent: i - 1, Child: i, Evaluable: br.readable && prev.readable}
	if !br.readable {
		return h
	}
	syms := a.symbolsFor(br)
	if br.third {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "signed by a third party, " + shortKey(br.signed.External.Key),
			Notes: []string{"its facts count only where a rule trusts that key"}})
	}
	if br.scopes != "" {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: "the block " + strings.TrimSpace(br.scopes),
			Notes: []string{"its checks may read the facts of the blocks it trusts; nothing it adds reaches the authority"}})
	}
	for _, c := range br.block.Checks {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeNarrowed, Text: syms.PrintCheck(c)})
	}
	for _, f := range br.block.Facts {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: syms.PrintFact(f),
			Notes: []string{a.factNote(br)}})
	}
	for _, r := range br.block.Rules {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeInfo, Text: syms.PrintRule(r),
			Notes: []string{"its conclusions carry this block's origin, so they too stay out of the authority's reach"}})
	}
	if len(h.Changes) == 0 {
		h.Changes = append(h.Changes, chain.Change{Kind: chain.ChangeKept, Text: "adds nothing: the same authority, passed on"})
	}
	return h
}

func (a *analysis) factNote(br *blockResult) string {
	if br.third {
		return "an attestation: trusted only where a rule names " + shortKey(br.signed.External.Key)
	}
	return "visible only to this block's own checks: a later block cannot grant itself anything"
}

// matrix shows the authority the root key granted, and the checks each
// block adds on top of it. A Biscuit never removes a fact: a block narrows
// authority by adding a check every request must pass, so each check is a
// row that switches on at its block and stays on.
func (a *analysis) matrix() *chain.Matrix {
	n := len(a.blocks)
	if n == 0 || !a.blocks[0].readable {
		return nil
	}
	m := &chain.Matrix{Title: "AUTHORITY", Scope: "the root key's grant, and the checks narrowing it"}
	auth := a.blocks[0]
	syms := a.symbolsFor(auth)
	for _, f := range auth.block.Facts {
		row := chain.Row{Label: compactFact(syms, f), Cells: make([]chain.Cell, n)}
		for i := range row.Cells {
			row.Cells[i] = chain.Cell{Kind: chain.CellHeld}
			if !a.blocks[i].readable {
				row.Cells[i] = chain.Cell{Kind: chain.CellUnknown}
			}
		}
		row.Lineage = []chain.LineageEntry{{Link: 0, Kind: chain.CellHeld, Texts: []string{syms.PrintFact(f)}}}
		m.Rows = append(m.Rows, row)
	}
	m.RootRows = len(m.Rows)
	for _, r := range auth.block.Rules {
		row := chain.Row{Label: syms.PrintRule(r), Cells: make([]chain.Cell, n)}
		for i := range row.Cells {
			row.Cells[i] = chain.Cell{Kind: chain.CellHeld}
		}
		row.Lineage = []chain.LineageEntry{{Link: 0, Kind: chain.CellHeld, Texts: []string{syms.PrintRule(r), "a rule: grants what it derives from the authorizer's facts"}}}
		m.Rows = append(m.Rows, row)
	}
	firstCheck := -1
	for i, br := range a.blocks {
		if !br.readable {
			continue
		}
		s := a.symbolsFor(br)
		for j, c := range br.block.Checks {
			src := s.PrintCheck(c)
			row := chain.Row{Label: a.checkLabel(s, c), Cells: make([]chain.Cell, n)}
			for k := i; k < n; k++ {
				row.Cells[k] = chain.Cell{Kind: chain.CellNarrowed, Changed: k == i}
			}
			texts := []string{src}
			if j < len(br.checkResults) {
				switch br.checkResults[j].status {
				case chain.StatusPass:
					texts = append(texts, "holds for this request")
				case chain.StatusFail:
					texts = append(texts, "fails for this request")
				}
			}
			row.Lineage = []chain.LineageEntry{{Link: i, Kind: chain.CellNarrowed, Changed: true, Texts: texts}}
			if firstCheck < 0 {
				firstCheck = len(m.Rows)
			}
			m.Rows = append(m.Rows, row)
		}
	}
	if len(m.Rows) == 0 {
		return nil
	}
	if firstCheck >= 0 {
		m.DefaultRow = firstCheck
	}
	m.Retained = make([]int, n)
	checks := chain.SummaryRow{Label: "checks", Cells: make([]chain.SummaryCell, n)}
	total := 0
	for i, br := range a.blocks {
		m.Retained[i] = m.RootRows
		total += len(br.block.Checks)
		checks.Cells[i] = chain.SummaryCell{Text: fmt.Sprint(total)}
	}
	m.Extra = []chain.SummaryRow{checks}
	return m
}

func (a *analysis) checkedAgainst() ([]chain.KV, []string) {
	var kv []chain.KV
	var missing []string
	switch {
	case a.rootUsed != nil:
		kv = append(kv, chain.KV{Key: "root key", Value: a.rootUsed.String()})
	case len(a.opts.RootKeys) > 0:
		kv = append(kv, chain.KV{Key: "root key", Value: fmt.Sprintf("%d given, none signed this token", len(a.opts.RootKeys)), Tone: chain.ToneBad})
	default:
		kv = append(kv, chain.KV{Key: "root key", Value: "none given: the authority block's signature was not checked", Tone: chain.ToneWarn})
		missing = append(missing, "a root key (--root-key)")
	}
	switch {
	case a.opts.Revoked != nil:
		kv = append(kv, chain.KV{Key: "revocation", Value: fmt.Sprintf("%s, %d revoked id(s)", a.opts.RevokedSource, len(a.opts.Revoked))})
	default:
		kv = append(kv, chain.KV{Key: "revocation", Value: "no list given: revocation was not checked", Tone: chain.ToneWarn})
		missing = append(missing, "a revocation list (--revoked-jtis)")
	}
	switch {
	case a.b7Reason != "" && !a.evaluated:
		kv = append(kv, chain.KV{Key: "authorizer", Value: a.b7Reason, Tone: chain.ToneWarn})
	case a.timeOnly:
		kv = append(kv, chain.KV{Key: "authorizer", Value: "none given: only expiry checks were evaluated", Tone: chain.ToneWarn})
		if a.anyUncheckedChecks() {
			missing = append(missing, "the authorizer's facts (--fact or --authorizer)")
		}
	default:
		v := a.opts.AuthorizerSource
		if a.policyNote != "" {
			v += "; " + a.policyNote
		}
		kv = append(kv, chain.KV{Key: "authorizer", Value: v})
	}
	t := a.at.UTC().Format("2006-01-02 15:04 UTC")
	if a.userTime {
		t = "from the authorizer's own time fact"
	} else if a.evaluated {
		t += ", supplied to the checks as time(...)"
	}
	kv = append(kv, chain.KV{Key: "time", Value: t})
	for _, ig := range a.opts.Ignored {
		kv = append(kv, chain.KV{Key: "ignored", Value: ig, Tone: chain.ToneMuted})
	}
	return kv, missing
}

func (a *analysis) anyUncheckedChecks() bool {
	for _, br := range a.blocks {
		if br.status(RuleChecks) == chain.StatusUnchecked {
			return true
		}
	}
	return false
}

func (a *analysis) summary() []string {
	out := []string{fmt.Sprintf("%d blocks", len(a.blocks))}
	if a.tok.Sealed() {
		out = append(out, "sealed")
	} else {
		out = append(out, "open")
	}
	thirds := 0
	for _, br := range a.blocks {
		if br.third {
			thirds++
		}
	}
	if thirds > 0 {
		out = append(out, fmt.Sprintf("%d third-party", thirds))
	}
	return out
}

func (a *analysis) describe() string {
	parts := []string{fmt.Sprintf("%d blocks", len(a.blocks))}
	if a.tok.Sealed() {
		parts = append(parts, "sealed")
	} else {
		parts = append(parts, "open")
	}
	if a.rootUsed != nil {
		parts = append(parts, "root key "+shortKey(a.rootUsed.PublicKey))
	}
	return strings.Join(parts, ", ")
}

// nativeReport is Biscuit's own JSON report, for check --json --native.
type nativeReport struct {
	Schema   string        `json:"schema"`
	Sealed   bool          `json:"sealed"`
	RootKey  string        `json:"root_key,omitempty"`
	Blocks   []nativeBlock `json:"blocks"`
	Policy   string        `json:"policy,omitempty"`
	TimeOnly bool          `json:"time_only"`
}

type nativeBlock struct {
	Index        int      `json:"index"`
	Context      string   `json:"context,omitempty"`
	Datalog      string   `json:"datalog,omitempty"`
	Version      uint32   `json:"version,omitempty"`
	ThirdParty   string   `json:"third_party,omitempty"`
	RevocationID string   `json:"revocation_id"`
	Failed       []string `json:"failed_checks,omitempty"`
}

func (a *analysis) native() nativeReport {
	r := nativeReport{Schema: "whosent.biscuit/v1", Sealed: a.tok.Sealed(), Policy: a.policyNote, TimeOnly: a.timeOnly}
	if a.rootUsed != nil {
		r.RootKey = a.rootUsed.String()
	}
	for _, br := range a.blocks {
		nb := nativeBlock{Index: br.index, RevocationID: br.revokeID, Datalog: br.source}
		if br.readable {
			nb.Version = br.block.Version
			nb.Context = br.block.Context
		}
		if br.third {
			nb.ThirdParty = br.signed.External.Key.String()
		}
		for _, o := range br.checkResults {
			if o.status == chain.StatusFail {
				nb.Failed = append(nb.Failed, o.source)
			}
		}
		r.Blocks = append(r.Blocks, nb)
	}
	return r
}
