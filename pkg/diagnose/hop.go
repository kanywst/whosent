package diagnose

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kanywst/mandatum/pkg/mda"
	"github.com/kanywst/mandatum/pkg/verify"
)

// Every coverage fact in this file comes from verify.Attenuates. The library
// does not export its entailment helpers, and a second implementation of them
// would drift, and the direction it would drift in is towards telling someone
// a widening is fine. So each question ("does this capability cover that
// one?", "is this sequence no wider?") is asked by building a pair of
// synthetic claims that differ only in the dimension under test and handing
// them to Attenuates. The descriptions are this package's own words; the
// verdicts underneath them are always the library's.

// neutral returns a parent and child pair that Attenuates accepts, so that
// copying one dimension into it isolates that dimension.
func neutral() (mda.Claims, mda.Claims) {
	p := mda.Claims{Audience: "x", ExpiresAt: 1}
	p.Mandatum.MaxDepth = 1
	c := mda.Claims{Audience: "x", ExpiresAt: 1}
	c.Mandatum.MaxDepth = 0
	return p, c
}

func isoAudience(parent, child mda.Claims) error {
	p, c := neutral()
	p.Audience, c.Audience = parent.Audience, child.Audience
	return verify.Attenuates(p, c)
}

func isoExpiry(parent, child mda.Claims) error {
	p, c := neutral()
	p.ExpiresAt, c.ExpiresAt = parent.ExpiresAt, child.ExpiresAt
	return verify.Attenuates(p, c)
}

func isoMaxDepth(parent, child mda.Claims) error {
	p, c := neutral()
	p.Mandatum.MaxDepth, c.Mandatum.MaxDepth = parent.Mandatum.MaxDepth, child.Mandatum.MaxDepth
	return verify.Attenuates(p, c)
}

func isoCaps(parent, child []mda.Capability) error {
	p, c := neutral()
	p.Mandatum.Capabilities, c.Mandatum.Capabilities = parent, child
	return verify.Attenuates(p, c)
}

func isoSeq(parent, child *mda.Sequence) error {
	p, c := neutral()
	p.Mandatum.Sequence, c.Mandatum.Sequence = parent, child
	return verify.Attenuates(p, c)
}

// entails reports whether parent capability p covers child capability c, by
// asking the library.
func entails(p, c mda.Capability) bool {
	return isoCaps([]mda.Capability{p}, []mda.Capability{c}) == nil
}

// isolated records each sub-rule's verdict for one hop, for the guard's
// second assertion: Attenuates accepts a pair exactly when every sub-rule
// does.
type isolated struct {
	aud, exp, depth, caps, seq error
}

func (s isolated) ok() bool {
	return s.aud == nil && s.exp == nil && s.depth == nil && s.caps == nil && s.seq == nil
}

// firstFailure names the first sub-rule that fails, in the order Attenuates
// checks them, for a finding's SubRule.
func (s isolated) firstFailure() string {
	switch {
	case s.aud != nil:
		return "section 6 rule 7 (audience)"
	case s.exp != nil:
		return "section 6 rule 2 (expiry)"
	case s.depth != nil:
		return "section 6 rule 3 (max_depth)"
	case s.caps != nil:
		return "section 6 rule 1 (capabilities)"
	case s.seq != nil:
		return "section 6 rule 5 (sequence)"
	}
	return ""
}

// diffHop fills in hop's diff and returns the library's verdict for the pair
// along with each sub-rule's isolated verdict.
func diffHop(hop *Hop, parent, child mda.Claims) (isolated, error) {
	verdict := runAttenuates(parent, child)
	iso := isolated{
		aud:   isoAudience(parent, child),
		exp:   isoExpiry(parent, child),
		depth: isoMaxDepth(parent, child),
		caps:  isoCaps(parent.Mandatum.Capabilities, child.Mandatum.Capabilities),
		seq:   isoSeq(parent.Mandatum.Sequence, child.Mandatum.Sequence),
	}

	hop.Audience = audienceChange(parent, child, iso.aud)
	hop.Expiry = expiryChange(parent, child, iso.exp)
	hop.MaxDepth = depthChange(parent, child, iso.depth)
	hop.Capabilities = capChanges(parent.Mandatum.Capabilities, child.Mandatum.Capabilities)
	hop.Sequence = sequenceDiff(parent.Mandatum.Sequence, child.Mandatum.Sequence, iso.seq)
	return iso, verdict
}

func audienceChange(p, c mda.Claims, verdict error) ValueChange {
	v := ValueChange{Parent: p.Audience, Child: c.Audience}
	if verdict != nil {
		v.Kind = ChangeWidened
		v.Text = fmt.Sprintf("re-targeted from %s to %s; a chain is issued for one resource server", p.Audience, c.Audience)
		return v
	}
	v.Kind = ChangeKept
	v.Text = "same audience: " + c.Audience
	return v
}

func expiryChange(p, c mda.Claims, verdict error) ValueChange {
	pe, ce := time.Unix(p.ExpiresAt, 0).UTC(), time.Unix(c.ExpiresAt, 0).UTC()
	v := ValueChange{Parent: pe.Format(time.RFC3339), Child: ce.Format(time.RFC3339)}
	d := pe.Sub(ce)
	switch {
	case verdict != nil:
		v.Kind = ChangeWidened
		v.Text = fmt.Sprintf("outlives the link above by %s", human(-d))
	case d == 0:
		v.Kind = ChangeKept
		v.Text = "expires with the link above"
	default:
		v.Kind = ChangeNarrowed
		v.Text = fmt.Sprintf("expires %s sooner", human(d))
	}
	return v
}

func depthChange(p, c mda.Claims, verdict error) ValueChange {
	pd, cd := p.Mandatum.MaxDepth, c.Mandatum.MaxDepth
	v := ValueChange{Parent: strconv.Itoa(pd), Child: strconv.Itoa(cd)}
	if verdict != nil {
		v.Kind = ChangeWidened
		v.Text = fmt.Sprintf("max_depth %d does not decrease from %d", cd, pd)
		return v
	}
	v.Kind = ChangeNarrowed
	switch cd {
	case 0:
		v.Text = fmt.Sprintf("max_depth %d to 0: may act, may not delegate further", pd)
	default:
		v.Text = fmt.Sprintf("max_depth %d to %d", pd, cd)
	}
	return v
}

// capChanges classifies every capability on both sides of a hop.
//
// A child capability is attributed to the first parent capability that
// covers it, matching the library's first-match rule, unless some parent
// capability is equivalent to it, in which case it was kept as is.
func capChanges(parent, child []mda.Capability) []CapChange {
	attributed := make([]int, len(child))
	same := make([]int, len(child))
	for j, c := range child {
		attributed[j], same[j] = -1, -1
		for k, p := range parent {
			if !entails(p, c) {
				continue
			}
			if attributed[j] < 0 {
				attributed[j] = k
			}
			if same[j] < 0 && entails(c, p) {
				same[j] = k
			}
		}
	}
	owner := func(j int) int {
		if same[j] >= 0 {
			return same[j]
		}
		return attributed[j]
	}

	var out []CapChange
	for k := range parent {
		p := &parent[k]
		var rows []CapChange
		for j := range child {
			if owner(j) != k {
				continue
			}
			c := &child[j]
			if same[j] == k {
				rows = append(rows, CapChange{
					Kind: ChangeKept, ParentIndex: k, ChildIndex: j, Parent: p, Child: c,
					Text: CapLabel(*c) + " kept",
				})
				continue
			}
			rows = append(rows, CapChange{
				Kind: ChangeNarrowed, ParentIndex: k, ChildIndex: j, Parent: p, Child: c,
				Text:  narrowedText(*p, *c),
				Notes: narrowing(*p, *c),
			})
		}
		if len(rows) == 0 {
			// The parent capability owns no child capability. Before calling
			// it dropped, ask whether the child still holds it anyway: a
			// broader child capability that covers it (parent [docs.*,
			// docs.a], child [docs.*]), or a duplicate of one already
			// attributed (parent [A, A], child [A]). Either way the child
			// can still do everything it granted, and "dropped" would be a
			// lie a reader acts on. Only a child capability the parent
			// covers counts: one that widens is a violation, not a holding.
			for j := range child {
				if attributed[j] >= 0 && entails(child[j], *p) {
					c := &child[j]
					rows = append(rows, CapChange{
						Kind: ChangeKept, ParentIndex: k, ChildIndex: j, Parent: p, Child: c,
						Text:  CapLabel(*p) + " kept",
						Notes: []string{fmt.Sprintf("still covered by the child's cap[%d], %s", j, CapLabel(*c))},
					})
					break
				}
			}
		}
		if len(rows) == 0 {
			// Not held whole. Either it was narrowed into a child capability
			// that was attributed to an earlier parent capability that also
			// covers it, or it was dropped.
			for j := range child {
				if entails(*p, child[j]) {
					c := &child[j]
					rows = append(rows, CapChange{
						Kind: ChangeNarrowed, ParentIndex: k, ChildIndex: j, Parent: p, Child: c,
						Text:  narrowedText(*p, *c),
						Notes: append(narrowing(*p, *c), fmt.Sprintf("also covered by the parent's cap[%d]", owner(j))),
					})
					break
				}
			}
		}
		if len(rows) == 0 {
			d := CapChange{
				Kind: ChangeDropped, ParentIndex: k, ChildIndex: -1, Parent: p,
				Text: CapLabel(*p) + " dropped",
			}
			for j := range child {
				if attributed[j] < 0 && entails(child[j], *p) {
					d.Notes = append(d.Notes, fmt.Sprintf("the child's cap[%d] covers it, but only by widening past the parent's grant", j))
				}
			}
			rows = append(rows, d)
		}
		out = append(out, rows...)
	}
	for j := range child {
		if attributed[j] >= 0 {
			continue
		}
		c := &child[j]
		out = append(out, CapChange{
			Kind: ChangeWidened, ParentIndex: -1, ChildIndex: j, Child: c,
			Text:  CapLabel(*c) + " is not covered by the parent's grant",
			Notes: widening(parent, *c),
		})
	}
	return out
}

func narrowedText(p, c mda.Capability) string {
	if pl, cl := CapLabel(p), CapLabel(c); pl != cl {
		return pl + " narrowed to " + cl
	}
	return CapLabel(c) + " narrowed"
}

// narrowing describes how c is narrower than p, which it is known to be.
func narrowing(p, c mda.Capability) []string {
	var notes []string
	if p.Resource.ID != c.Resource.ID {
		_, pPrefix := trimStar(p.Resource.ID)
		_, cPrefix := trimStar(c.Resource.ID)
		switch {
		case pPrefix && !cPrefix:
			notes = append(notes, fmt.Sprintf("id pinned from %s to %s", p.Resource.ID, c.Resource.ID))
		case pPrefix && cPrefix:
			notes = append(notes, fmt.Sprintf("id prefix tightened from %s to %s", p.Resource.ID, c.Resource.ID))
		default:
			notes = append(notes, fmt.Sprintf("id %s to %s", p.Resource.ID, c.Resource.ID))
		}
	}
	var extra []string
	for _, t := range c.Resource.Tags {
		if !slices.Contains(p.Resource.Tags, t) && !slices.Contains(extra, t) {
			extra = append(extra, t)
		}
	}
	if len(extra) > 0 {
		notes = append(notes, fmt.Sprintf("now requires tags %s", strings.Join(extra, ", ")))
	}
	for _, key := range condKeys(p.Conditions, c.Conditions) {
		pc, inP := p.Conditions[key]
		cc, inC := c.Conditions[key]
		switch {
		case inP && inC:
			if condEquivalent(key, pc, cc) {
				continue
			}
			if cc.In != nil && len(cc.In) == 0 {
				notes = append(notes, fmt.Sprintf("%s: grants nothing (in [])", key))
				continue
			}
			note := fmt.Sprintf("%s: %s to %s", key, CondLabel(pc), CondLabel(cc))
			if pc.In != nil && cc.In != nil {
				var removed []string
				for _, v := range pc.In {
					if !slices.Contains(cc.In, v) {
						removed = append(removed, v)
					}
				}
				if len(removed) > 0 {
					note += " (removed " + strings.Join(removed, ", ") + ")"
				}
			}
			notes = append(notes, note)
		case inC:
			notes = append(notes, fmt.Sprintf("%s: new restriction, %s", key, CondLabel(cc)))
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "narrower than the parent's")
	}
	return notes
}

// widening explains why no parent capability covers c. It compares c with
// the parent capabilities that grant the same action on the same type, or
// with all of them when none do, and names every dimension that fails.
func widening(parent []mda.Capability, c mda.Capability) []string {
	if len(parent) == 0 {
		return []string{"the parent grants nothing at all"}
	}
	// Compare only with parent capabilities on the same action, type and
	// resource: those are the ones a reader would expect to cover it.
	// Listing every unrelated capability only buries the reason.
	var candidates []int
	for k, p := range parent {
		if p.Resource.Type == c.Resource.Type && p.Action.Name == c.Action.Name && idOracle(p.Resource.ID, c.Resource.ID) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		for k, p := range parent {
			if p.Resource.Type == c.Resource.Type && p.Action.Name == c.Action.Name && idOracle(c.Resource.ID, p.Resource.ID) {
				candidates = append(candidates, k)
			}
		}
	}
	if len(candidates) == 0 {
		return []string{fmt.Sprintf("the link above grants no %s on %s:%s at all", c.Action.Name, c.Resource.Type, c.Resource.ID)}
	}
	var notes []string
	for _, k := range candidates {
		p := parent[k]
		var why []string
		if !idOracle(p.Resource.ID, c.Resource.ID) {
			_, pPrefix := trimStar(p.Resource.ID)
			_, cPrefix := trimStar(c.Resource.ID)
			if !pPrefix && cPrefix {
				why = append(why, fmt.Sprintf("id pattern %s is wider than the literal %s", c.Resource.ID, p.Resource.ID))
			} else {
				why = append(why, fmt.Sprintf("id %s is outside %s", c.Resource.ID, p.Resource.ID))
			}
		}
		var missing []string
		for _, t := range p.Resource.Tags {
			if !slices.Contains(c.Resource.Tags, t) {
				missing = append(missing, t)
			}
		}
		if len(missing) > 0 {
			why = append(why, "no longer requires tags "+strings.Join(missing, ", "))
		}
		for _, key := range sortedKeys(p.Conditions) {
			pc := p.Conditions[key]
			cc, ok := c.Conditions[key]
			if !ok {
				why = append(why, fmt.Sprintf("drops the condition %s: %s", key, CondLabel(pc)))
				continue
			}
			if condOracle(key, pc, cc) {
				continue
			}
			w := fmt.Sprintf("loosens %s from %s to %s", key, CondLabel(pc), CondLabel(cc))
			if pc.Equals != nil && len(cc.In) == 1 && cc.In[0] == *pc.Equals {
				w += " (the same values, but eq can only be narrowed by the same eq; the comparison is deliberately syntactic)"
			}
			why = append(why, w)
		}
		if len(why) == 0 {
			why = append(why, "not covered")
		}
		notes = append(notes, fmt.Sprintf("against cap[%d] %s: %s", k, CapLabel(p), strings.Join(why, "; ")))
	}
	return notes
}

// idOracle asks the library whether pattern p covers pattern c, holding
// every other dimension equal.
func idOracle(p, c string) bool {
	return entails(
		mda.Capability{Resource: mda.ResourcePattern{Type: "t", ID: p}, Action: mda.ActionPattern{Name: "a"}},
		mda.Capability{Resource: mda.ResourcePattern{Type: "t", ID: c}, Action: mda.ActionPattern{Name: "a"}},
	)
}

// condOracle asks the library whether child condition c is at least as tight
// as parent condition p on one key.
func condOracle(key string, p, c mda.Condition) bool {
	mk := func(cond mda.Condition) mda.Capability {
		return mda.Capability{
			Resource:   mda.ResourcePattern{Type: "t", ID: "x"},
			Action:     mda.ActionPattern{Name: "a"},
			Conditions: map[string]mda.Condition{key: cond},
		}
	}
	return entails(mk(p), mk(c))
}

func condEquivalent(key string, a, b mda.Condition) bool {
	return condOracle(key, a, b) && condOracle(key, b, a)
}

func sequenceDiff(p, c *mda.Sequence, verdict error) SequenceDiff {
	var d SequenceDiff
	switch {
	case p == nil && c == nil:
		d.Kind, d.Text = ChangeKept, "no sequence constraints"
		return d
	case p == nil:
		d.Kind, d.Text = ChangeAdded, "adds sequence constraints"
		d.Budget = budgetChange(0, c.MaxInvocations)
		for _, cc := range c.Constraints {
			d.Constraints = append(d.Constraints, ConstraintChange{ID: cc.ID, Kind: ChangeAdded, Text: "adds " + cc.ID})
		}
		return d
	case c == nil:
		d.Kind, d.Text = ChangeWidened, "drops the parent's sequence constraints entirely"
		d.Budget = ValueChange{Kind: ChangeWidened, Parent: budgetLabel(p.MaxInvocations), Child: "none",
			Text: "budget removed with the constraints"}
		for _, pc := range p.Constraints {
			d.Constraints = append(d.Constraints, ConstraintChange{ID: pc.ID, Kind: ChangeWidened, Text: "drops inherited " + pc.ID})
		}
		return d
	}

	d.Budget = budgetChange(p.MaxInvocations, c.MaxInvocations)
	narrowed := d.Budget.Kind == ChangeNarrowed
	for _, pc := range p.Constraints {
		i := slices.IndexFunc(c.Constraints, func(x mda.Constraint) bool { return x.ID == pc.ID })
		switch {
		case i < 0:
			d.Constraints = append(d.Constraints, ConstraintChange{ID: pc.ID, Kind: ChangeWidened, Text: "drops inherited " + pc.ID})
		case isoSeq(&mda.Sequence{Constraints: []mda.Constraint{pc}}, &mda.Sequence{Constraints: []mda.Constraint{c.Constraints[i]}}) != nil:
			d.Constraints = append(d.Constraints, ConstraintChange{ID: pc.ID, Kind: ChangeWidened, Text: "redefines inherited " + pc.ID})
		default:
			d.Constraints = append(d.Constraints, ConstraintChange{ID: pc.ID, Kind: ChangeKept, Text: "inherits " + pc.ID})
		}
	}
	for _, cc := range c.Constraints {
		if !slices.ContainsFunc(p.Constraints, func(x mda.Constraint) bool { return x.ID == cc.ID }) {
			narrowed = true
			d.Constraints = append(d.Constraints, ConstraintChange{ID: cc.ID, Kind: ChangeAdded, Text: "adds " + cc.ID})
		}
	}
	switch {
	case verdict != nil:
		d.Kind, d.Text = ChangeWidened, verdict.Error()
	case narrowed:
		d.Kind, d.Text = ChangeNarrowed, "tightens the sequence constraints"
	default:
		d.Kind, d.Text = ChangeKept, "same sequence constraints"
	}
	return d
}

func budgetLabel(n int) string {
	if n <= 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

// budgetChange mirrors the library's reading of max_invocations: zero or less
// is unlimited, and a child under a positive parent budget must stay
// positive and no larger.
func budgetChange(p, c int) ValueChange {
	v := ValueChange{Parent: budgetLabel(p), Child: budgetLabel(c)}
	switch {
	case p <= 0 && c <= 0:
		v.Kind, v.Text = ChangeKept, "unlimited invocations"
	case p <= 0:
		v.Kind, v.Text = ChangeNarrowed, fmt.Sprintf("invocations capped at %d", c)
	case c <= 0:
		v.Kind, v.Text = ChangeWidened, fmt.Sprintf("removes the invocation budget of %d", p)
	case c > p:
		v.Kind, v.Text = ChangeWidened, fmt.Sprintf("raises the invocation budget from %d to %d", p, c)
	case c == p:
		v.Kind, v.Text = ChangeKept, fmt.Sprintf("%d invocations", c)
	default:
		v.Kind, v.Text = ChangeNarrowed, fmt.Sprintf("invocations %d to %d", p, c)
	}
	return v
}

func trimStar(s string) (string, bool) {
	if n := len(s); n > 0 && s[n-1] == '*' {
		return s[:n-1], true
	}
	return s, false
}

func condKeys(a, b map[string]mda.Condition) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys(m map[string]mda.Condition) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CapLabel is a compact one-line description of a capability's action and
// resource, such as "invoke mcp_tool:search.* #mutating".
func CapLabel(c mda.Capability) string {
	var b strings.Builder
	b.WriteString(c.Action.Name)
	b.WriteString(" ")
	b.WriteString(c.Resource.Type)
	b.WriteString(":")
	b.WriteString(c.Resource.ID)
	for _, t := range c.Resource.Tags {
		b.WriteString(" #")
		b.WriteString(t)
	}
	return b.String()
}

// CondLabel describes one condition, such as `prefix "docs."` or
// `in [public, docs]`.
func CondLabel(c mda.Condition) string {
	var parts []string
	if c.Equals != nil {
		parts = append(parts, fmt.Sprintf("eq %q", *c.Equals))
	}
	if c.In != nil {
		parts = append(parts, "in ["+strings.Join(c.In, ", ")+"]")
	}
	if c.Prefix != nil {
		parts = append(parts, fmt.Sprintf("prefix %q", *c.Prefix))
	}
	if c.Min != nil || c.Max != nil {
		lo, hi := "-inf", "+inf"
		if c.Min != nil {
			lo = strconv.FormatFloat(*c.Min, 'g', -1, 64)
		}
		if c.Max != nil {
			hi = strconv.FormatFloat(*c.Max, 'g', -1, 64)
		}
		parts = append(parts, "range ["+lo+", "+hi+"]")
	}
	if len(parts) == 0 {
		return "(no comparison)"
	}
	return strings.Join(parts, " and ")
}

// CondLabels describes every condition of a capability, keys sorted.
func CondLabels(c mda.Capability) []string {
	var out []string
	for _, k := range sortedKeys(c.Conditions) {
		out = append(out, k+" "+CondLabel(c.Conditions[k]))
	}
	return out
}

// DiffCapabilities classifies every capability across a hop, the same way a
// report's Hop.Capabilities is built. Exported for renderers that want to
// compare two arbitrary links.
func DiffCapabilities(parent, child []mda.Capability) []CapChange { return capChanges(parent, child) }

// DiffSequence describes sequence constraints across a hop.
func DiffSequence(parent, child *mda.Sequence) SequenceDiff {
	return sequenceDiff(parent, child, isoSeq(parent, child))
}
