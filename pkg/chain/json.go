package chain

import "time"

// SchemaVersion names the JSON document JSON returns. A breaking change to
// its shape changes the version.
const SchemaVersion = "whosent.chain/v1"

// JSONChain is the machine-readable report: the same facts the view draws,
// without anything that only exists to be drawn.
type JSONChain struct {
	Schema           string      `json:"schema"`
	Format           string      `json:"format"`
	Source           string      `json:"source"`
	InputFormat      string      `json:"input_format,omitempty"`
	Normalizations   []string    `json:"normalizations,omitempty"`
	Reversed         bool        `json:"reversed,omitempty"`
	At               time.Time   `json:"at"`
	Verdict          Verdict     `json:"verdict"`
	BreakAt          int         `json:"break_at"`
	IncompleteReason string      `json:"incomplete_reason,omitempty"`
	Root             JSONRoot    `json:"root"`
	Rules            []JSONRule  `json:"rules"`
	Links            []JSONLink  `json:"links"`
	Hops             []JSONHop   `json:"hops"`
	Findings         []JSONFind  `json:"findings"`
	CheckedAgainst   []JSONKV    `json:"checked_against"`
	Missing          []string    `json:"missing,omitempty"`
	Simulated        []string    `json:"simulated,omitempty"`
	Inconsistency    *JSONIncons `json:"inconsistency,omitempty"`
}

// JSONRoot is the root principal.
type JSONRoot struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind,omitempty"`
	Details []string `json:"details,omitempty"`
}

// JSONRule is one of the format's rules.
type JSONRule struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Spec  string `json:"spec,omitempty"`
}

// JSONLink is one link.
type JSONLink struct {
	Index            int               `json:"index"`
	From             string            `json:"from"`
	To               string            `json:"to"`
	Readable         bool              `json:"readable"`
	State            string            `json:"state"`
	Unreached        bool              `json:"unreached"`
	UnreachedBy      *int              `json:"unreached_by,omitempty"`
	Revoked          bool              `json:"revoked"`
	RevokedSimulated bool              `json:"revoked_simulated,omitempty"`
	Asserted         bool              `json:"asserted"`
	Checks           map[string]string `json:"checks"`
	IssuedAt         *time.Time        `json:"issued_at,omitempty"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	RevokeID         string            `json:"revoke_id,omitempty"`
}

// JSONHop is one hop's diff.
type JSONHop struct {
	Parent    int          `json:"parent"`
	Child     int          `json:"child"`
	Evaluable bool         `json:"evaluable"`
	Changes   []JSONChange `json:"changes"`
	Verdict   string       `json:"verdict,omitempty"`
}

// JSONChange is one line of a diff.
type JSONChange struct {
	Kind   ChangeKind `json:"kind"`
	Before string     `json:"before,omitempty"`
	Text   string     `json:"text"`
	Notes  []string   `json:"notes,omitempty"`
}

// JSONFind is one finding.
type JSONFind struct {
	Rule      string `json:"rule"`
	SubRule   string `json:"sub_rule,omitempty"`
	Code      string `json:"code,omitempty"`
	Link      int    `json:"link"`
	Hop       int    `json:"hop"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Spec      string `json:"spec,omitempty"`
	Derived   bool   `json:"derived,omitempty"`
	Simulated bool   `json:"simulated,omitempty"`
}

// JSONKV is one input the chain was checked against.
type JSONKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// JSONIncons is a disagreement with the reference implementation.
type JSONIncons struct {
	Detail string `json:"detail"`
}

// JSON returns the machine-readable report.
func (c *Chain) JSON() JSONChain {
	out := JSONChain{
		Schema: SchemaVersion, Format: c.Format.ID, Source: c.Source, InputFormat: c.InputFormat,
		Normalizations: c.Normalizations, Reversed: c.Reversed, At: c.At.UTC(), Verdict: c.Verdict,
		BreakAt: c.BreakAt, IncompleteReason: c.IncompleteReason,
		Root:     JSONRoot{Name: c.Root.Name, Kind: c.Root.Kind, Details: c.Root.Details},
		Rules:    []JSONRule{},
		Links:    []JSONLink{},
		Hops:     []JSONHop{},
		Findings: []JSONFind{},
		Missing:  c.Missing, Simulated: c.Simulated,
		CheckedAgainst: []JSONKV{},
	}
	for _, r := range c.Format.Rules {
		out.Rules = append(out.Rules, JSONRule(r))
	}
	for _, l := range c.Links {
		jl := JSONLink{
			Index: l.Index, From: l.From, To: l.To, Readable: l.Readable, State: linkState(l),
			Unreached: l.Unreached, Revoked: l.Revoked, RevokedSimulated: l.RevokedSimulated,
			Asserted: l.Asserted, Checks: map[string]string{}, RevokeID: l.RevokeID,
		}
		if l.Unreached {
			by := l.UnreachedBy
			jl.UnreachedBy = &by
		}
		for _, ch := range l.Checks {
			jl.Checks[ch.Rule] = ch.Status.String()
		}
		if !l.IssuedAt.IsZero() {
			t := l.IssuedAt.UTC()
			jl.IssuedAt = &t
		}
		if !l.ExpiresAt.IsZero() {
			t := l.ExpiresAt.UTC()
			jl.ExpiresAt = &t
		}
		out.Links = append(out.Links, jl)
	}
	for _, h := range c.Hops {
		jh := JSONHop{Parent: h.Parent, Child: h.Child, Evaluable: h.Evaluable, Verdict: h.Verdict, Changes: []JSONChange{}}
		for _, ch := range h.Changes {
			jh.Changes = append(jh.Changes, JSONChange(ch))
		}
		out.Hops = append(out.Hops, jh)
	}
	for _, f := range c.Findings() {
		out.Findings = append(out.Findings, JSONFind{
			Rule: f.Rule, SubRule: f.SubRule, Code: f.Code, Link: f.Link, Hop: f.Hop,
			Severity: f.Severity.String(), Detail: f.Detail, Spec: f.Spec, Derived: f.Derived, Simulated: f.Simulated,
		})
	}
	for _, kv := range c.CheckedAgainst {
		out.CheckedAgainst = append(out.CheckedAgainst, JSONKV{Key: kv.Key, Value: kv.Value})
	}
	if c.Inconsistency != nil {
		out.Inconsistency = &JSONIncons{Detail: c.Inconsistency.Detail}
	}
	return out
}

// linkState is a link's state as one word, after what happened above it.
func linkState(l Link) string {
	switch {
	case l.Unreached:
		return "unreached"
	case l.Revoked:
		return "revoked"
	case l.State == LinkBroken:
		return "broken"
	case l.Asserted:
		return "asserted"
	case l.State == LinkIncomplete:
		return "incomplete"
	}
	return "ok"
}
