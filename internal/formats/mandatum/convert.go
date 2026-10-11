package mandatum

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/pkg/chain"
	"github.com/kanywst/whosent/pkg/diagnose"
)

// native wraps the engine's report as Chain.Native: it marshals as the
// whosent.report/v1 document, and lets the asker reach the report the chain
// was built from.
type native struct{ r *diagnose.Report }

func (n native) MarshalJSON() ([]byte, error) { return json.Marshal(n.r.JSON()) }

// reportOf returns the engine report behind a chain this adapter built.
func reportOf(c *chain.Chain) (*diagnose.Report, bool) {
	if c == nil {
		return nil, false
	}
	n, ok := c.Native.(native)
	return n.r, ok && n.r != nil
}

// Convert describes a diagnosis in the format-neutral model.
func Convert(r *diagnose.Report) *chain.Chain {
	cv := converter{r: r, compact: compactLabels(r)}
	return cv.chain()
}

type converter struct {
	r *diagnose.Report
	// compact is set when every capability is an MCP tool invocation, so
	// rows are labelled by tool alone and the action said once, in the
	// matrix title.
	compact bool
}

func compactLabels(r *diagnose.Report) bool {
	if len(r.Matrix.Rows) == 0 {
		return false
	}
	for _, row := range r.Matrix.Rows {
		if row.Root.Action.Name != "invoke" || row.Root.Resource.Type != "mcp_tool" {
			return false
		}
	}
	return true
}

func (cv converter) capLabel(c mda.Capability) string {
	if cv.compact {
		s := c.Resource.ID
		for _, t := range c.Resource.Tags {
			s += " #" + t
		}
		return s
	}
	return diagnose.CapLabel(c)
}

// capText is a capability with its conditions, as the lineage and the
// grants list write it.
func (cv converter) capText(c mda.Capability) string {
	s := cv.capLabel(c)
	if conds := diagnose.CondLabels(c); len(conds) > 0 {
		s += "  " + strings.Join(conds, "; ")
	}
	return s
}

func (cv converter) chain() *chain.Chain {
	r := cv.r
	c := &chain.Chain{
		Format:         format,
		Source:         r.Input.Source,
		InputFormat:    r.Input.Format,
		Normalizations: r.Input.Normalizations,
		Reversed:       r.Input.Reversed,
		Call:           call(r.Input.ToolCall),
		At:             r.At,
		Verdict:        chain.Verdict(r.Verdict),
		BreakAt:        r.BreakAt,
		Simulated:      r.Simulated,
		Native:         native{r},
	}
	if s := r.Sponsor; s != nil {
		c.Root = chain.Root{
			Name: diagnose.Short(s.Subject), Kind: "human",
			Details: []string{strings.Join(s.AuthenticationMethods, "+"), "via " + diagnose.Short(s.Issuer)},
		}
	}
	for _, l := range r.Links {
		c.Links = append(c.Links, cv.link(l))
	}
	for _, h := range r.Hops {
		c.Hops = append(c.Hops, cv.hop(h))
	}
	for _, f := range r.ChainFindings {
		c.ChainFindings = append(c.ChainFindings, finding(f))
	}
	c.Matrix = cv.matrix()
	c.CheckedAgainst = cv.checkedAgainst()
	c.Missing = cv.missing()
	c.IncompleteReason = cv.incompleteReason()
	c.Summary = cv.summary()
	c.Describe, c.Context = cv.describe()
	if !r.Library.Consistent {
		c.Inconsistency = &chain.Inconsistency{
			Banner: fmt.Sprintf("!! INTERNAL INCONSISTENCY  whosent says %s, mandatum says %s. Trust the library, and report this.",
				describeRuleAt(r.Library.ToolRule, r.Library.ToolLink), describeLibrary(r.Library)),
			Detail: r.Library.Mismatch,
		}
	}
	return c
}

func call(tc *diagnose.ToolCall) *chain.Call {
	if tc == nil {
		return nil
	}
	return &chain.Call{Name: tc.Name, Arguments: tc.Arguments}
}

func describeRuleAt(rule diagnose.Rule, link int) string {
	if rule == "" {
		return "the chain verifies"
	}
	if link < 0 {
		return string(rule) + " on the whole chain"
	}
	return fmt.Sprintf("%s at link %d", rule, link)
}

func describeLibrary(l diagnose.LibraryCheck) string {
	if l.Passed {
		return "the chain verifies"
	}
	return describeRuleAt(l.Rule, l.Link)
}

func finding(f diagnose.Finding) chain.Finding {
	return chain.Finding{
		Rule: string(f.Rule), SubRule: f.SubRule, Code: f.Code, Link: f.Link, Hop: f.Hop,
		Severity: chain.Severity(f.Severity), Detail: f.Detail, Spec: f.Spec,
		Derived: f.Derived, Simulated: f.Simulated,
	}
}

func check(c diagnose.Check) chain.Check {
	return chain.Check{Rule: string(c.Rule), Status: chain.Status(c.Status), Detail: c.Detail, Simulated: c.Simulated}
}

func (cv converter) link(l diagnose.Link) chain.Link {
	r := cv.r
	out := chain.Link{
		Index: l.Index, Readable: l.Claims != nil,
		State:     chain.LinkState(l.State),
		Unreached: l.Unreached, UnreachedBy: l.UnreachedBy,
		Revoked: l.Revoked, RevokedSimulated: l.RevokedSimulated,
		IssuedAt: l.IssuedAt, ExpiresAt: l.ExpiresAt, Remaining: l.Remaining,
	}
	for _, ch := range l.Checks {
		out.Checks = append(out.Checks, check(ch))
	}
	for _, f := range l.Findings {
		out.Findings = append(out.Findings, finding(f))
	}
	if c := l.Claims; c != nil {
		out.From, out.To = diagnose.Short(c.Issuer), diagnose.Short(c.Subject)
		out.RevokeID = c.ID
		total := c.Mandatum.MaxDepth
		if len(r.Links) > 0 && r.Links[0].Claims != nil {
			total = max(total, r.Links[0].Claims.Mandatum.MaxDepth)
		}
		total = min(total, 6)
		out.Depth = &chain.Pips{Left: max(min(c.Mandatum.MaxDepth, total), 0), Total: total}
	}
	out.Sections = cv.sections(l)
	out.Raw = cv.raw(l)
	return out
}

// sections are the inspector's account of a link after its checks: the
// sponsor and the grant for the first link, the assertion for every link.
func (cv converter) sections(l diagnose.Link) []chain.Section {
	r := cv.r
	var out []chain.Section
	if l.Index == 0 && r.Sponsor != nil {
		sp := r.Sponsor
		s := chain.Section{Title: "SPONSOR", Lines: []chain.Line{
			{Kind: chain.LineKV, Key: "human", Value: sp.Subject, Tone: chain.ToneRoot},
			{Kind: chain.LineKV, Key: "at", Value: sp.Issuer},
		}}
		if len(sp.AuthenticationMethods) > 0 {
			s.Lines = append(s.Lines, chain.Line{Kind: chain.LineKV, Key: "amr", Value: strings.Join(sp.AuthenticationMethods, ", ")})
		}
		out = append(out, s)
	}
	if l.Index == 0 && l.Claims != nil {
		s := chain.Section{Title: "GRANTS"}
		for _, c := range l.Claims.Mandatum.Capabilities {
			s.Lines = append(s.Lines, chain.Line{Kind: chain.LineChange, Change: chain.ChangeAdded, Value: cv.capText(c)})
		}
		out = append(out, s)
	}

	s := chain.Section{Title: "ASSERTION"}
	if c := l.Claims; c != nil {
		kv := func(k, v string, t chain.Tone) {
			s.Lines = append(s.Lines, chain.Line{Kind: chain.LineKV, Key: k, Value: v, Tone: t})
		}
		kv("grants to", c.Subject, chain.ToneText)
		kv("issued by", c.Issuer, chain.ToneText)
		kv("audience", c.Audience, chain.ToneText)
		rem, alive := remaining(l)
		exp := l.ExpiresAt.UTC().Format("15:04 UTC") + "  (" + rem + ")"
		tone := chain.ToneText
		if !alive {
			tone = chain.ToneBad
		}
		kv("expires", exp, tone)
		d := c.Mandatum.MaxDepth
		dl := fmt.Sprintf("%d more hop%s", d, plural(d))
		if d == 0 {
			dl = "no further: may act, may not delegate"
		}
		kv("delegates", dl, chain.ToneText)
		if sq := c.Mandatum.Sequence; sq != nil {
			var ids []string
			for _, con := range sq.Constraints {
				ids = append(ids, con.ID)
			}
			b := "unlimited"
			if sq.MaxInvocations > 0 {
				b = fmt.Sprintf("%d invocations", sq.MaxInvocations)
			}
			if len(ids) > 0 {
				b += "; " + strings.Join(ids, ", ")
			}
			kv("sequence", b, chain.ToneText)
		}
		kv("jti", c.ID, chain.ToneMuted)
		if l.KeySource != "" {
			kv("key", l.KeySource, chain.ToneMuted)
		}
	} else {
		s.Lines = append(s.Lines, chain.Line{Kind: chain.LineText, Mark: chain.MarkFail, Value: "this link does not parse", Tone: chain.ToneBad})
		s.Lines = append(s.Lines, chain.Line{Kind: chain.LineText, Value: l.ParseError, Tone: chain.ToneMuted, Indent: 2})
	}
	return append(out, s)
}

// remaining words a link's time left, or how long ago it expired.
func remaining(l diagnose.Link) (string, bool) {
	if l.ExpiresAt.IsZero() {
		return "", true
	}
	if l.Remaining <= 0 {
		return "expired " + diagnose.Human(-l.Remaining) + " ago", false
	}
	return diagnose.Human(l.Remaining) + " left", true
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// raw is the assertion as it was signed: the two digests that tie it into
// the chain, its header and its claims. A parent commitment takes the
// colour of the link it names, so a spliced link is the one whose colour
// matches nothing above it.
func (cv converter) raw(l diagnose.Link) []chain.Section {
	r := cv.r
	dig := chain.Section{Title: "DIGESTS", Lines: []chain.Line{
		{Kind: chain.LineKV, Key: "this link", Value: l.Digest, Digest: l.Index + 1},
	}}
	if c := l.Claims; c != nil && c.Mandatum.Parent != "" {
		match := -1
		for j := 0; j < l.Index; j++ {
			if r.Links[j].Digest == c.Mandatum.Parent {
				match = j
			}
		}
		if match >= 0 {
			dig.Lines = append(dig.Lines,
				chain.Line{Kind: chain.LineKV, Key: "parent", Value: c.Mandatum.Parent, Digest: match + 1},
				chain.Line{Kind: chain.LineKV, Mark: chain.MarkPass, Value: fmt.Sprintf("link %d", match), Digest: match + 1, DigestSoft: true})
		} else {
			dig.Lines = append(dig.Lines,
				chain.Line{Kind: chain.LineKV, Key: "parent", Value: c.Mandatum.Parent, Tone: chain.ToneBadStrong},
				chain.Line{Kind: chain.LineKV, Mark: chain.MarkFail, Value: "matches no link above: this link was issued against another chain", Tone: chain.ToneBad})
		}
	} else if l.Claims != nil {
		dig.Lines = append(dig.Lines, chain.Line{Kind: chain.LineKV, Key: "parent", Value: "none: this is the sponsor's grant", Tone: chain.ToneMuted})
	}
	out := []chain.Section{dig}
	head := chain.Section{Title: "HEADER"}
	if l.Header != nil {
		head.Lines = append(head.Lines, jsonLine(l.Header))
	}
	out = append(out, head)
	if l.Claims != nil {
		out = append(out, chain.Section{Title: "CLAIMS", Lines: []chain.Line{jsonLine(l.Claims)}})
	} else if l.Untrusted != nil {
		out = append(out, chain.Section{Title: "CLAIMS (UNTRUSTED: did not parse strictly)", Lines: []chain.Line{jsonLine(l.Untrusted)}})
	}
	return out
}

func jsonLine(v any) chain.Line {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return chain.Line{Kind: chain.LineText, Value: err.Error(), Tone: chain.ToneBad}
	}
	return chain.Line{Kind: chain.LineJSON, Value: string(b)}
}

// hop is the diff between a link and its parent. Changes is what the
// inspector shows; Summary is the command line's shorter account.
func (cv converter) hop(h diagnose.Hop) chain.Hop {
	out := chain.Hop{Parent: h.Parent, Child: h.Child, Evaluable: h.Evaluable}
	if !h.Evaluable {
		return out
	}
	for _, c := range h.Capabilities {
		ch := cv.capChange(c)
		ch.Notes = c.Notes
		out.Changes = append(out.Changes, ch)
	}
	for _, v := range []diagnose.ValueChange{h.Expiry, h.MaxDepth, h.Audience} {
		if v.Text != "" {
			out.Changes = append(out.Changes, chain.Change{Kind: chain.ChangeKind(v.Kind), Text: v.Text})
		}
	}
	if s := h.Sequence; s.Text != "" || len(s.Constraints) > 0 || s.Budget.Text != "" {
		if s.Budget.Text != "" {
			out.Changes = append(out.Changes, chain.Change{Kind: chain.ChangeKind(s.Budget.Kind), Text: s.Budget.Text})
		}
		for _, c := range s.Constraints {
			out.Changes = append(out.Changes, chain.Change{Kind: chain.ChangeKind(c.Kind), Text: c.Text})
		}
		if s.Text != "" && s.Budget.Text == "" && len(s.Constraints) == 0 {
			out.Changes = append(out.Changes, chain.Change{Kind: chain.ChangeKind(s.Kind), Text: s.Text})
		}
	}
	// The structural checks between the two, only when one failed: when
	// they hold, saying so adds nothing the grid did not.
	for _, c := range []diagnose.Check{h.Commitment, h.DepthStep, h.Custody, h.Sponsor} {
		if c.Status.Blocking() {
			out.Changes = append(out.Changes, chain.Change{Kind: chain.ChangeWidened, Text: string(c.Rule) + " " + c.Detail})
		}
	}
	if h.Verdict != "" && !cv.saidAlready(h.Child, h.Verdict) {
		out.Verdict = "mandatum: " + h.Verdict
	}

	// The command line's account: every capability in the engine's own
	// words, then expiry, depth and budget, the constraints that changed,
	// and the audience only when it widened.
	sum := []chain.Change{}
	for _, c := range h.Capabilities {
		sum = append(sum, chain.Change{Kind: chain.ChangeKind(c.Kind), Text: c.Text, Notes: c.Notes})
	}
	for _, v := range []diagnose.ValueChange{h.Expiry, h.MaxDepth, h.Sequence.Budget} {
		if v.Text != "" {
			sum = append(sum, chain.Change{Kind: chain.ChangeKind(v.Kind), Text: v.Text})
		}
	}
	for _, c := range h.Sequence.Constraints {
		if c.Kind != diagnose.ChangeKept {
			sum = append(sum, chain.Change{Kind: chain.ChangeKind(c.Kind), Text: c.Text})
		}
	}
	if h.Audience.Kind == diagnose.ChangeWidened {
		sum = append(sum, chain.Change{Kind: chain.ChangeKind(h.Audience.Kind), Text: h.Audience.Text})
	}
	out.Summary = sum
	return out
}

// saidAlready reports whether link i already has a finding carrying text,
// so the same sentence is not printed twice in one panel.
func (cv converter) saidAlready(i int, text string) bool {
	if i < 0 || i >= len(cv.r.Links) {
		return false
	}
	for _, f := range cv.r.Links[i].Findings {
		if strings.Contains(f.Detail, text) {
			return true
		}
	}
	return false
}

// capChange says what happened to one capability across a hop, in the same
// labels the matrix uses. The engine's own sentence is the fallback when
// either side is missing.
func (cv converter) capChange(c diagnose.CapChange) chain.Change {
	k := chain.ChangeKind(c.Kind)
	switch {
	case c.Kind == diagnose.ChangeKept && c.Child != nil:
		return chain.Change{Kind: k, Text: cv.capLabel(*c.Child)}
	case c.Kind == diagnose.ChangeNarrowed && c.Parent != nil && c.Child != nil:
		p, ch := cv.capLabel(*c.Parent), cv.capLabel(*c.Child)
		if p == ch {
			return chain.Change{Kind: k, Text: p + "  narrowed"}
		}
		return chain.Change{Kind: k, Before: p, Text: ch}
	case c.Kind == diagnose.ChangeDropped && c.Parent != nil:
		return chain.Change{Kind: k, Text: cv.capLabel(*c.Parent) + "  dropped"}
	case c.Kind == diagnose.ChangeWidened && c.Child != nil:
		return chain.Change{Kind: k, Text: cv.capLabel(*c.Child) + "  not covered by the parent's grant"}
	case c.Kind == diagnose.ChangeAdded && c.Child != nil:
		return chain.Change{Kind: k, Text: cv.capLabel(*c.Child)}
	}
	return chain.Change{Kind: k, Text: c.Text}
}

func (cv converter) matrix() *chain.Matrix {
	r := cv.r
	m := &chain.Matrix{Title: "AUTHORITY", RootRows: r.Matrix.RootRows, Retained: r.Matrix.Retained}
	if cv.compact {
		m.Scope = "invoke mcp_tool"
	}
	for _, row := range r.Matrix.Rows {
		out := chain.Row{Label: cv.capLabel(row.Root), Origin: row.Origin}
		for i, c := range row.Cells {
			out.Cells = append(out.Cells, chain.Cell{Kind: chain.CellKind(c.Kind), Changed: c.Changed})
			if i < row.Origin {
				continue
			}
			e := chain.LineageEntry{Link: i, Kind: chain.CellKind(c.Kind), Changed: c.Changed}
			switch c.Kind {
			case diagnose.CellAbsent, diagnose.CellUnknown:
			default:
				claims := r.Links[i].Claims
				for _, ci := range c.Caps {
					if claims == nil || ci >= len(claims.Mandatum.Capabilities) {
						continue
					}
					e.Texts = append(e.Texts, cv.capText(claims.Mandatum.Capabilities[ci]))
				}
			}
			out.Lineage = append(out.Lineage, e)
		}
		m.Rows = append(m.Rows, out)
	}

	budget := chain.SummaryRow{Label: "budget"}
	rules := chain.SummaryRow{Label: "seq rules"}
	for _, l := range r.Links {
		c := l.Claims
		if c == nil || c.Mandatum.Sequence == nil || c.Mandatum.Sequence.MaxInvocations == 0 {
			budget.Cells = append(budget.Cells, chain.SummaryCell{Infinite: true, Dim: true})
		} else {
			budget.Cells = append(budget.Cells, chain.SummaryCell{Text: fmt.Sprint(c.Mandatum.Sequence.MaxInvocations)})
		}
		if c == nil || c.Mandatum.Sequence == nil {
			rules.Cells = append(rules.Cells, chain.SummaryCell{Text: "0", Dim: true})
		} else {
			rules.Cells = append(rules.Cells, chain.SummaryCell{Text: fmt.Sprint(len(c.Mandatum.Sequence.Constraints))})
		}
	}
	m.Extra = []chain.SummaryRow{budget, rules}
	m.DefaultRow = defaultRow(r)
	return m
}

// defaultRow is the authority row to open on: authority that appeared from
// nowhere if any did, since that is the story; otherwise the first grant
// that reaches the leaf, so that asking about the selected row asks about
// something the chain was actually built to do.
func defaultRow(r *diagnose.Report) int {
	for i, row := range r.Matrix.Rows {
		if row.Origin > 0 {
			return i
		}
	}
	leaf := len(r.Links) - 1
	for i, row := range r.Matrix.Rows {
		if leaf >= 0 && leaf < len(row.Cells) {
			if k := row.Cells[leaf].Kind; k == diagnose.CellHeld || k == diagnose.CellNarrowed {
				return i
			}
		}
	}
	return 0
}

// checkedAgainst says what the chain was checked against. A verdict is only
// as good as its inputs, and an absent input is exactly what makes a rule
// unchecked, so the view says it in the same place as the findings.
func (cv converter) checkedAgainst() []chain.KV {
	r := cv.r
	var out []chain.KV
	if len(r.Trust) == 0 {
		out = append(out, chain.KV{Key: "keys", Value: "none given: no signature was checked", Tone: chain.ToneWarn})
	}
	for i, is := range r.Trust {
		key := ""
		if i == 0 {
			key = "keys"
		}
		v := diagnose.Short(is.Issuer)
		tone := chain.ToneText
		switch {
		case is.Err != "":
			v += "  ! " + is.Err
			tone = chain.ToneBad
		case len(is.KeyIDs) > 0:
			v += "  " + strings.Join(is.KeyIDs, ", ")
		}
		out = append(out, chain.KV{Key: key, Value: v, Tone: tone})
	}
	if rv := r.Revocation; rv != nil {
		v := fmt.Sprintf("%s · sequence %d · built %s", rv.Source, rv.Sequence, rv.GeneratedAt.UTC().Format("15:04 UTC"))
		tone := chain.ToneText
		if rv.Stale {
			v += "  ! " + rv.StaleDetail
			tone = chain.ToneBad
		}
		out = append(out, chain.KV{Key: "revocation", Value: v, Tone: tone})
	} else {
		out = append(out, chain.KV{Key: "revocation", Value: "none given: revocation was not checked", Tone: chain.ToneWarn})
	}
	if r.AudienceChecked {
		out = append(out, chain.KV{Key: "audience", Value: r.Audience})
	} else {
		out = append(out, chain.KV{Key: "audience", Value: "none given: V9 was not checked", Tone: chain.ToneWarn})
	}
	out = append(out, chain.KV{Key: "time", Value: r.At.UTC().Format("15:04 UTC") + " · skew " + r.Skew.String()})
	return out
}

// incompleteReason says what was missing, in terms of the inputs a person
// would supply rather than rule numbers.
func (cv converter) incompleteReason() string {
	r := cv.r
	keys := map[string]bool{}
	revocation, audience := false, false
	for _, l := range r.Links {
		for _, c := range l.Checks {
			if c.Status != diagnose.StatusUnchecked {
				continue
			}
			switch c.Rule {
			case diagnose.V3:
				if l.Claims != nil {
					keys[l.Claims.Issuer] = true
				} else {
					keys["?"] = true
				}
			case diagnose.V8:
				revocation = true
			case diagnose.V9:
				audience = true
			}
		}
	}
	var parts []string
	if n := len(keys); n > 0 {
		parts = append(parts, fmt.Sprintf("no keys for %d issuer%s", n, plural(n)))
	}
	if revocation {
		parts = append(parts, "no revocation set")
	}
	if audience {
		parts = append(parts, "no audience")
	}
	if len(parts) == 0 {
		return "some rules were not checked"
	}
	return strings.Join(parts, ", ")
}

// missing names the inputs whose absence left rules unchecked.
func (cv converter) missing() []string {
	seen := map[diagnose.Rule]bool{}
	for _, f := range cv.r.Findings() {
		if f.Severity == diagnose.SeverityUnchecked {
			seen[f.Rule] = true
		}
	}
	var out []string
	if seen[diagnose.V3] {
		out = append(out, "signatures (--trust or --jwks)")
	}
	if seen[diagnose.V8] {
		out = append(out, "revocation (--revocations)")
	}
	if seen[diagnose.V9] {
		out = append(out, "audience (--audience)")
	}
	return out
}

func (cv converter) summary() []string {
	r := cv.r
	parts := []string{fmt.Sprintf("%d link%s", len(r.Links), plural(len(r.Links)))}
	if r.Input.Format != "" {
		parts = append(parts, r.Input.Format)
	}
	if r.AudienceChecked {
		parts = append(parts, "audience "+r.Audience)
	}
	return append(parts, "skew "+r.Skew.String())
}

// describe is the command line report's header and its second line.
func (cv converter) describe() (string, string) {
	r := cv.r
	var head string
	if s := r.Sponsor; s != nil {
		head = fmt.Sprintf("sponsor %s via %s", s.Subject, s.Issuer)
		if len(s.AuthenticationMethods) > 0 {
			head += " (" + strings.Join(s.AuthenticationMethods, "+") + ")"
		}
	}
	aud := "not checked"
	if r.AudienceChecked {
		aud = r.Audience
	}
	return head, fmt.Sprintf("at %s · skew %s · audience %s", r.At.UTC().Format(time.RFC3339), r.Skew, aud)
}
