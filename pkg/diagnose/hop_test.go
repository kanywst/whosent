package diagnose_test

import (
	"crypto/ed25519"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/issue"
	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"

	"github.com/kanywst/whosent/internal/demo"
	"github.com/kanywst/whosent/pkg/diagnose"
)

func kinds(cs []diagnose.CapChange) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c.Kind))
	}
	return out
}

func TestHealthyHopsNarrowEveryDimension(t *testing.T) {
	s := scenario(t, "healthy")
	r := diag(t, s.Links, s.Options)
	h0, h1 := r.Hops[0], r.Hops[1]
	if got := strings.Join(kinds(h0.Capabilities), ","); got != "narrowed,narrowed,dropped" {
		t.Errorf("hop 0 caps %s, want narrowed,narrowed,dropped", got)
	}
	if got := strings.Join(kinds(h1.Capabilities), ","); got != "dropped,narrowed" {
		t.Errorf("hop 1 caps %s, want dropped,narrowed", got)
	}
	for _, h := range r.Hops {
		if !h.Evaluable || h.Verdict != "" {
			t.Errorf("hop %d evaluable=%v verdict=%q", h.Child, h.Evaluable, h.Verdict)
		}
		for name, v := range map[string]diagnose.ValueChange{"expiry": h.Expiry, "max_depth": h.MaxDepth} {
			if v.Kind != diagnose.ChangeNarrowed {
				t.Errorf("hop %d %s %s, want narrowed", h.Child, name, v.Kind)
			}
		}
		if h.Audience.Kind != diagnose.ChangeKept {
			t.Errorf("hop %d audience %s", h.Child, h.Audience.Kind)
		}
		for _, c := range []diagnose.Check{h.Commitment, h.DepthStep, h.Custody, h.Sponsor} {
			if c.Status != diagnose.StatusPass {
				t.Errorf("hop %d %s positional check %s", h.Child, c.Rule, c.Status)
			}
		}
	}
	notes := strings.Join(h0.Capabilities[0].Notes, "|")
	if !strings.Contains(notes, "id pinned from search.* to search.query") || !strings.Contains(notes, "args.index: new restriction") {
		t.Errorf("search narrowing notes %q", notes)
	}
	if !strings.Contains(strings.Join(h0.Capabilities[1].Notes, "|"), `prefix "docs." to in [docs.example.org, docs.example.com]`) {
		t.Errorf("fetch narrowing notes %q", h0.Capabilities[1].Notes)
	}
	if h0.Sequence.Kind != diagnose.ChangeNarrowed || h0.Sequence.Budget.Text != "invocations 200 to 100" {
		t.Errorf("sequence %+v", h0.Sequence)
	}
}

func TestWidenedHopNamesTheCapabilityAndItsHistory(t *testing.T) {
	s := scenario(t, "widened")
	r := diag(t, s.Links, s.Options)
	h := r.Hops[1]
	var w *diagnose.CapChange
	for i := range h.Capabilities {
		if h.Capabilities[i].Kind == diagnose.ChangeWidened {
			w = &h.Capabilities[i]
		}
	}
	if w == nil {
		t.Fatalf("no widened row: %v", kinds(h.Capabilities))
	}
	if w.Child == nil || w.Child.Resource.ID != "docs.write" || w.ParentIndex != -1 {
		t.Errorf("widened row %+v", w)
	}
	notes := strings.Join(w.Notes, "|")
	if !strings.Contains(notes, "link 0 held this") {
		t.Errorf("a re-added capability should say it was dropped higher up: %q", notes)
	}
	if h.Verdict == "" {
		t.Error("hop verdict empty for a widening hop")
	}
}

func TestCapabilityClassification(t *testing.T) {
	c := func(id string, tags []string, conds map[string]mda.Condition) mda.Capability {
		return mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id, Tags: tags},
			Action: mda.ActionPattern{Name: "invoke"}, Conditions: conds}
	}
	str := func(s string) *string { return &s }
	tests := []struct {
		name   string
		parent []mda.Capability
		child  []mda.Capability
		want   string
		note   string
	}{
		{"an identical capability is kept", []mda.Capability{c("a", nil, nil)}, []mda.Capability{c("a", nil, nil)}, "kept", ""},
		{"reordered tags are still kept", []mda.Capability{c("a", []string{"x", "y"}, nil)}, []mda.Capability{c("a", []string{"y", "x"}, nil)}, "kept", ""},
		{"a prefix pinned to a literal is narrowed", []mda.Capability{c("a*", nil, nil)}, []mda.Capability{c("ab", nil, nil)}, "narrowed", "id pinned"},
		{"a longer prefix is narrowed", []mda.Capability{c("a*", nil, nil)}, []mda.Capability{c("ab*", nil, nil)}, "narrowed", "prefix tightened"},
		{"an added tag requirement is narrowed", []mda.Capability{c("a", nil, nil)}, []mda.Capability{c("a", []string{"t"}, nil)}, "narrowed", "now requires tags t"},
		{"in [] grants nothing on a key", []mda.Capability{c("a", nil, map[string]mda.Condition{"k": {Equals: str("v")}})},
			[]mda.Capability{c("a", nil, map[string]mda.Condition{"k": {In: []string{}}})}, "narrowed", "grants nothing"},
		{"a removed set member is named", []mda.Capability{c("a", nil, map[string]mda.Condition{"k": {In: []string{"x", "y"}}})},
			[]mda.Capability{c("a", nil, map[string]mda.Condition{"k": {In: []string{"x"}}})}, "narrowed", "removed y"},
		{"nothing in the child drops the parent's capability", []mda.Capability{c("a", nil, nil)}, nil, "dropped", ""},
		{"a literal parent cannot cover a prefix child", []mda.Capability{c("a", nil, nil)}, []mda.Capability{c("a*", nil, nil)}, "dropped,widened", "wider than the literal"},
		{"a dropped tag requirement widens", []mda.Capability{c("a", []string{"t"}, nil)}, []mda.Capability{c("a", nil, nil)}, "dropped,widened", "no longer requires tags t"},
		{"eq to a one-member in widens, and the note says why", []mda.Capability{c("a", nil, map[string]mda.Condition{"k": {Equals: str("v")}})},
			[]mda.Capability{c("a", nil, map[string]mda.Condition{"k": {In: []string{"v"}}})}, "dropped,widened", "deliberately syntactic"},
		{"a dropped condition widens", []mda.Capability{c("a", nil, map[string]mda.Condition{"k": {Equals: str("v")}})},
			[]mda.Capability{c("a", nil, nil)}, "dropped,widened", "drops the condition k"},
		{"a capability a broader child capability still covers is kept, not dropped",
			[]mda.Capability{c("a*", nil, nil), c("ab", nil, nil)}, []mda.Capability{c("a*", nil, nil)}, "kept,kept", "still covered by the child's cap[0]"},
		{"a duplicated parent capability is kept twice, not narrowed",
			[]mda.Capability{c("a", nil, nil), c("a", nil, nil)}, []mda.Capability{c("a", nil, nil)}, "kept,kept", ""},
		{"a widened child capability covering the parent's does not count as keeping it",
			[]mda.Capability{c("ab", nil, nil)}, []mda.Capability{c("a*", nil, nil)}, "dropped,widened", "only by widening"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mda.Claims{Audience: "x", ExpiresAt: 10}
			p.Mandatum.MaxDepth = 1
			p.Mandatum.Capabilities = tt.parent
			ch := p
			ch.Mandatum.MaxDepth = 0
			ch.Mandatum.Capabilities = tt.child
			changes := diagnose.DiffCapabilities(tt.parent, tt.child)
			if got := strings.Join(kinds(changes), ","); got != tt.want {
				t.Errorf("kinds %s, want %s", got, tt.want)
			}
			var notes []string
			for _, c := range changes {
				notes = append(notes, c.Notes...)
			}
			if tt.note != "" && !strings.Contains(strings.Join(notes, "|"), tt.note) {
				t.Errorf("notes %q do not mention %q", notes, tt.note)
			}
			widens := strings.Contains(tt.want, "widened")
			if lib := verify.Attenuates(p, ch); (lib != nil) != widens {
				t.Errorf("mandatum says %v, classification says widens=%v", lib, widens)
			}
		})
	}
}

func TestSequenceDiff(t *testing.T) {
	con := func(id string) mda.Constraint {
		return mda.Constraint{ID: id, Forbid: mda.ActionMatcher{Action: "w"}, After: mda.ActionMatcher{Action: "r"}}
	}
	tests := []struct {
		name   string
		p, c   *mda.Sequence
		kind   diagnose.ChangeKind
		budget diagnose.ChangeKind
	}{
		{"no sequence on either side", nil, nil, diagnose.ChangeKept, ""},
		{"adding constraints narrows", nil, &mda.Sequence{MaxInvocations: 5}, diagnose.ChangeAdded, diagnose.ChangeNarrowed},
		{"dropping them widens", &mda.Sequence{MaxInvocations: 5}, nil, diagnose.ChangeWidened, diagnose.ChangeWidened},
		{"raising the budget widens", &mda.Sequence{MaxInvocations: 5}, &mda.Sequence{MaxInvocations: 6}, diagnose.ChangeWidened, diagnose.ChangeWidened},
		{"removing the budget widens", &mda.Sequence{MaxInvocations: 5, Constraints: []mda.Constraint{con("a")}}, &mda.Sequence{Constraints: []mda.Constraint{con("a")}}, diagnose.ChangeWidened, diagnose.ChangeWidened},
		{"an inherited constraint kept and one added narrows", &mda.Sequence{Constraints: []mda.Constraint{con("a")}}, &mda.Sequence{Constraints: []mda.Constraint{con("a"), con("b")}}, diagnose.ChangeNarrowed, diagnose.ChangeKept},
		{"a dropped constraint widens", &mda.Sequence{Constraints: []mda.Constraint{con("a"), con("b")}}, &mda.Sequence{Constraints: []mda.Constraint{con("a")}}, diagnose.ChangeWidened, diagnose.ChangeKept},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := diagnose.DiffSequence(tt.p, tt.c)
			if d.Kind != tt.kind {
				t.Errorf("kind %s, want %s (%s)", d.Kind, tt.kind, d.Text)
			}
			if tt.budget != "" && d.Budget.Kind != tt.budget {
				t.Errorf("budget %s, want %s (%s)", d.Budget.Kind, tt.budget, d.Budget.Text)
			}
		})
	}
}

func TestMatrixTracesAuthorityDownTheChain(t *testing.T) {
	r := diag(t, scenario(t, "widened").Links, scenario(t, "widened").Options)
	m := r.Matrix
	if m.RootRows != 3 {
		t.Fatalf("root rows %d, want 3", m.RootRows)
	}
	want := map[string][]diagnose.CellKind{
		"invoke mcp_tool:search.*":             {diagnose.CellHeld, diagnose.CellNarrowed, diagnose.CellAbsent},
		"invoke mcp_tool:web.fetch":            {diagnose.CellHeld, diagnose.CellNarrowed, diagnose.CellNarrowed},
		"invoke mcp_tool:docs.write #mutating": {diagnose.CellHeld, diagnose.CellAbsent, diagnose.CellAbsent},
	}
	var widened *diagnose.Row
	for i, row := range m.Rows {
		if row.Origin == 2 {
			widened = &m.Rows[i]
			continue
		}
		w, ok := want[row.Label]
		if !ok {
			t.Errorf("unexpected row %q", row.Label)
			continue
		}
		for i, k := range w {
			if row.Cells[i].Kind != k {
				t.Errorf("%s link %d: %s, want %s", row.Label, i, row.Cells[i].Kind, k)
			}
		}
	}
	if widened == nil || widened.Cells[2].Kind != diagnose.CellWidened || !widened.Cells[2].Changed {
		t.Errorf("the re-added docs.write should start a widened row at link 2: %+v", widened)
	}
	if got := m.Retained; got[0] != 3 || got[1] != 2 || got[2] != 1 {
		t.Errorf("retained %v, want [3 2 1]", got)
	}
	// The drop of docs.write at link 1 is a change there.
	for _, row := range m.Rows {
		if row.Label == "invoke mcp_tool:docs.write #mutating" && row.Origin == 0 && !row.Cells[1].Changed {
			t.Error("dropping docs.write at link 1 should mark that cell changed")
		}
	}
}

func TestAskLabelsHowFarTheAnswerCanBeRelied(t *testing.T) {
	fetch := verify.Request{ResourceType: "mcp_tool", ResourceID: "web.fetch", Action: "invoke",
		ResourceTags: []string{"external-content"}, Attributes: map[string]any{"args.host": "docs.example.org"}}
	write := verify.Request{ResourceType: "mcp_tool", ResourceID: "docs.write", Action: "invoke", ResourceTags: []string{"mutating"}}
	tests := []struct {
		name      string
		scenario  string
		req       verify.Request
		authority diagnose.Authority
		permitted bool
		covered   bool
		widening  bool
	}{
		{"a valid chain answers authoritatively", "healthy", fetch, diagnose.Authoritative, true, true, false},
		{"a valid chain refuses what it does not grant", "healthy", write, diagnose.Authoritative, false, false, false},
		{"an unchecked chain answers conditionally", "unchecked", fetch, diagnose.Conditional, true, true, false},
		{"an invalid chain permits nothing, whatever its leaf claims", "expired", fetch, diagnose.Hypothetical, false, true, false},
		{"authority that exists only through widening is called out", "widened", write, diagnose.Hypothetical, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := scenario(t, tt.scenario)
			tr := diag(t, s.Links, s.Options).Ask(tt.req)
			if tr.Authority != tt.authority || tr.Permitted != tt.permitted || tr.Covered != tt.covered {
				t.Errorf("got %s permitted=%v covered=%v (%s)", tr.Authority, tr.Permitted, tr.Covered, tr.Reason)
			}
			if tr.OnlyThroughWidening != tt.widening {
				t.Errorf("only through widening = %v", tr.OnlyThroughWidening)
			}
			if tt.widening && tr.WideningAt != 2 {
				t.Errorf("widening at %d, want 2", tr.WideningAt)
			}
			// In the widened scenario the sponsor did grant docs.write and
			// link 1 dropped it, so "the sponsor never granted this" would
			// be false, and would point whoever reads it at the wrong link.
			if tt.widening && (!tr.SponsorGranted || tr.FirstRefused != 1) {
				t.Errorf("sponsor granted = %v, first refused = %d; want true, 1", tr.SponsorGranted, tr.FirstRefused)
			}
			if len(tr.Steps) != len(s.Links) {
				t.Errorf("%d steps for %d links", len(tr.Steps), len(s.Links))
			}
		})
	}
	t.Run("an unparsed leaf cannot be asked anything", func(t *testing.T) {
		s := scenario(t, "healthy")
		links := clone(s.Links)
		links[2] = []byte("a.b.c")
		tr := diag(t, links, s.Options).Ask(fetch)
		if tr.Authority != diagnose.NotEvaluable || tr.Permitted {
			t.Errorf("got %s permitted=%v", tr.Authority, tr.Permitted)
		}
	})
}

// issue.Delegate checks attenuation against the parent.Claims it is handed,
// not against claims re-derived from parent.Raw, so a caller holding doctored
// claims can get it to sign a widened child. The verifier re-derives claims
// from the bytes and refuses the result. This pins both halves of that, so a
// change in either is noticed.
func TestIssueDelegateTrustsTheCallersParentClaims(t *testing.T) {
	s := scenario(t, "healthy")
	root, err := mda.ParseAssertion(s.Links[0])
	if err != nil {
		t.Fatal(err)
	}
	doctored := root
	doctored.Claims.Mandatum.Capabilities = append(append([]mda.Capability(nil), root.Claims.Mandatum.Capabilities...),
		mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "admin.wipe"}, Action: mda.ActionPattern{Name: "invoke"}})
	key, kid, _ := demo.Key(demo.Planner)
	child, err := issue.Delegate(issue.Signer{ID: demo.Planner, KeyID: kid, Key: key}, doctored, issue.Grant{
		Subject: demo.Retriever, ID: "widened-by-doctored-parent", IssuedAt: demo.FixedBase, Lifetime: 10 * 60e9,
		Capabilities: []mda.Capability{{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: "admin.wipe"}, Action: mda.ActionPattern{Name: "invoke"}}},
	})
	if err != nil {
		t.Skipf("issue.Delegate now refuses a doctored parent (%v); the quirk is fixed upstream", err)
	}
	r := diag(t, [][]byte{root.Raw, child.Raw}, s.Options)
	if r.Library.Rule != diagnose.V5 || r.Library.Link != 1 {
		t.Errorf("the verifier should refuse the widened child at V5 link 1, got %s at %d", r.Library.Rule, r.Library.Link)
	}
}

// ChainMetaKey is the key mandatum's MCP enforcement point reads a chain
// from. The oracle in mcp_oracle_test.go carries the v0.2.0 value; this keeps
// the tool's copy equal to it.
func TestChainMetaKeyMatchesMandatum(t *testing.T) {
	if diagnose.ChainMetaKey != mcpChainMetaKey {
		t.Errorf("ChainMetaKey is %q, mandatum's enforcement point reads %q", diagnose.ChainMetaKey, mcpChainMetaKey)
	}
}

// The binary must not link a CEL evaluator it never uses, and must not
// depend on the archived mandatum module: the reference code it needs lives
// in internal/mandatum.
func TestBinaryDoesNotImportCEL(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/kanywst/whosent/cmd/whosent").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "cel.dev/") || strings.HasPrefix(dep, "github.com/kanywst/mandatum") {
			t.Errorf("whosent imports %s", dep)
		}
	}
}

// instance is a concrete request a capability permits: the least a holder
// of it can do. It reports false when the capability permits nothing (an
// empty set condition).
func instance(p mda.Capability) (verify.Request, bool) {
	id := p.Resource.ID
	if strings.HasSuffix(id, "*") {
		id = strings.TrimSuffix(id, "*") + "zz"
	}
	attrs := map[string]any{}
	for k, c := range p.Conditions {
		switch {
		case c.Equals != nil:
			attrs[k] = *c.Equals
		case c.In != nil:
			if len(c.In) == 0 {
				return verify.Request{}, false
			}
			attrs[k] = c.In[0]
		case c.Prefix != nil:
			attrs[k] = *c.Prefix + "zz"
		case c.Min != nil:
			attrs[k] = *c.Min
		case c.Max != nil:
			attrs[k] = *c.Max
		}
	}
	return verify.Request{ResourceType: p.Resource.Type, ResourceID: id, ResourceTags: p.Resource.Tags,
		Action: p.Action.Name, Attributes: attrs}, true
}

// "Dropped" and "kept" are claims about what the child can still do, and a
// reader acts on them. They are checked here against mandatum's own matcher,
// over every pairing of a set of capabilities: whatever a parent capability
// permits, the child (counting only capabilities its parent covers) must
// still permit when the diff says kept, and must not when it says dropped.
func TestDroppedAndKeptAgreeWithPermits(t *testing.T) {
	str := func(s string) *string { return &s }
	c := func(id string, tags []string, conds map[string]mda.Condition) mda.Capability {
		return mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id, Tags: tags},
			Action: mda.ActionPattern{Name: "invoke"}, Conditions: conds}
	}
	pool := []mda.Capability{
		c("docs.*", nil, nil),
		c("docs.a", nil, nil),
		c("docs.a", []string{"t"}, nil),
		c("d*", nil, nil),
		c("docs.*", nil, map[string]mda.Condition{"host": {In: []string{"x", "y"}}}),
		c("docs.*", nil, map[string]mda.Condition{"host": {Equals: str("x")}}),
		c("docs.a", nil, map[string]mda.Condition{"host": {Prefix: str("x")}}),
		c("other", nil, nil),
	}
	checked := 0
	for i := range pool {
		for j := range pool {
			for k := range pool {
				parent := []mda.Capability{pool[i], pool[j]}
				child := []mda.Capability{pool[k]}
				changes := diagnose.DiffCapabilities(parent, child)
				var legit []mda.Capability
				for _, ch := range changes {
					if ch.Kind != diagnose.ChangeWidened && ch.Child != nil {
						legit = append(legit, *ch.Child)
					}
				}
				holder := &verify.Result{Capabilities: legit}
				for _, ch := range changes {
					if ch.Parent == nil {
						continue
					}
					req, ok := instance(*ch.Parent)
					if !ok {
						continue
					}
					err := holder.Permits(req)
					switch ch.Kind {
					case diagnose.ChangeDropped:
						checked++
						if err == nil {
							t.Errorf("parent %v child %v: %q is called dropped, but the child still permits %+v",
								labels(parent), labels(child), ch.Text, req)
						}
					case diagnose.ChangeKept:
						checked++
						if err != nil {
							t.Errorf("parent %v child %v: %q is called kept, but the child refuses %+v: %v",
								labels(parent), labels(child), ch.Text, req, err)
						}
					}
				}
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d verdicts were checked; the test is not exercising the diff", checked)
	}
}

// The matrix says the same thing as the diff: a parent capability a broader
// child capability still covers stays held, and keeps being traced below.
func TestMatrixKeepsAuthorityABroaderCapabilityStillCovers(t *testing.T) {
	c := func(id string) mda.Capability {
		return mda.Capability{Resource: mda.ResourcePattern{Type: "mcp_tool", ID: id}, Action: mda.ActionPattern{Name: "invoke"}}
	}
	links := chainOf(t, [][]mda.Capability{
		{c("docs.*"), c("docs.a")},
		{c("docs.*")},
		{c("docs.*")},
		{c("docs.b")},
	})
	r := diag(t, links, diagnose.Options{})
	var row *diagnose.Row
	for i := range r.Matrix.Rows {
		if r.Matrix.Rows[i].Label == "invoke mcp_tool:docs.a" {
			row = &r.Matrix.Rows[i]
		}
	}
	if row == nil {
		t.Fatal("no row for docs.a")
	}
	want := []diagnose.CellKind{diagnose.CellHeld, diagnose.CellHeld, diagnose.CellHeld, diagnose.CellAbsent}
	for i, k := range want {
		if row.Cells[i].Kind != k {
			t.Errorf("docs.a at link %d: %s, want %s", i, row.Cells[i].Kind, k)
		}
	}
	if got := r.Matrix.Retained; got[1] != 2 || got[2] != 2 || got[3] != 1 {
		t.Errorf("retained %v, want [2 2 2 1]: docs.a is still held at links 1 and 2", got)
	}
}

func labels(cs []mda.Capability) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = diagnose.CapLabel(c)
	}
	return out
}

// chainOf signs a structurally valid chain whose links grant caps[i], so a
// test can describe a chain by its capabilities alone.
func chainOf(t *testing.T, caps [][]mda.Capability) [][]byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := mda.Sponsor{Issuer: "idp", Subject: "alice"}
	var out [][]byte
	parent := ""
	for i, cs := range caps {
		iss := "idp"
		if i > 0 {
			iss = fmt.Sprintf("agent-%d", i-1)
		}
		c := mda.Claims{
			Issuer: iss, Subject: fmt.Sprintf("agent-%d", i), Audience: "aud",
			IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(len(caps)-i) * time.Hour).Unix(), ID: fmt.Sprintf("jti-%d", i),
			Mandatum: mda.Mandatum{Version: mda.Version, Root: root, Parent: parent, Depth: i, MaxDepth: len(caps) - 1 - i, Capabilities: cs},
		}
		raw, err := jose.Sign(c, priv, "")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
		parent = mda.Digest(raw)
	}
	return out
}
