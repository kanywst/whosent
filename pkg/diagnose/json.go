package diagnose

import (
	"time"

	"github.com/kanywst/mandatum/pkg/mda"
)

// SchemaVersion identifies the JSON report format. It changes only when a
// field is removed or changes meaning; adding a field does not change it.
const SchemaVersion = "whosent.report/v1"

// JSONReport is the machine-readable report. Field names are part of the
// contract; nothing in it is decoration, and no field ever carries emoji or
// terminal escapes.
type JSONReport struct {
	Schema     string          `json:"schema"`
	Verdict    Verdict         `json:"verdict"`
	BreakAt    int             `json:"break_at"`
	At         time.Time       `json:"at"`
	SkewSec    float64         `json:"skew_seconds"`
	Audience   JSONAud         `json:"audience"`
	Input      JSONInput       `json:"input"`
	Sponsor    *JSONSponsor    `json:"sponsor"`
	Library    JSONLibrary     `json:"library"`
	Trust      []JSONIssuer    `json:"trust"`
	Revocation *JSONRevocation `json:"revocation"`
	Simulated  []string        `json:"simulated_revocations"`
	Links      []JSONLink      `json:"links"`
	Hops       []JSONHop       `json:"hops"`
	Findings   []JSONFinding   `json:"findings"`
	Counts     JSONCounts      `json:"counts"`
}

// JSONAud is the audience the leaf was checked against.
type JSONAud struct {
	Value   string `json:"value"`
	Checked bool   `json:"checked"`
}

// JSONInput describes the input.
type JSONInput struct {
	Source         string        `json:"source"`
	Format         string        `json:"format"`
	Normalizations []string      `json:"normalizations"`
	Reversed       bool          `json:"reversed"`
	ToolCall       *JSONToolCall `json:"tool_call"`
}

// JSONToolCall is the tools/call request the chain came in, if any.
type JSONToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// JSONSponsor is the human the chain is rooted in. Untrusted unless the
// verdict is VALID.
type JSONSponsor struct {
	Issuer                string   `json:"iss"`
	Subject               string   `json:"sub"`
	AuthenticationMethods []string `json:"amr"`
	AuthenticatedAt       int64    `json:"auth_time"`
}

// JSONLibrary is the consistency guard's record.
type JSONLibrary struct {
	Passed     bool   `json:"passed"`
	Rule       string `json:"rule"`
	Link       int    `json:"link"`
	Detail     string `json:"detail"`
	Consistent bool   `json:"consistent"`
	Mismatch   string `json:"mismatch"`
	StubsUsed  bool   `json:"stubs_used"`
}

// JSONIssuer is one configured trust anchor.
type JSONIssuer struct {
	Issuer  string   `json:"issuer"`
	Source  string   `json:"source"`
	KeyIDs  []string `json:"kids"`
	Skipped []string `json:"skipped"`
	Error   string   `json:"error"`
}

// JSONRevocation is the revocation set in use.
type JSONRevocation struct {
	Source      string    `json:"source"`
	Sequence    uint64    `json:"sequence"`
	GeneratedAt time.Time `json:"generated_at"`
	MaxAgeSec   float64   `json:"max_age_seconds"`
	Exact       string    `json:"exact"`
	Stale       bool      `json:"stale"`
	StaleDetail string    `json:"stale_detail"`
}

// JSONCheck is one cell of the grid.
type JSONCheck struct {
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Simulated bool   `json:"simulated,omitempty"`
}

// JSONLink is one link.
type JSONLink struct {
	Index       int                  `json:"index"`
	State       string               `json:"state"`
	Unreached   bool                 `json:"unreached"`
	UnreachedBy int                  `json:"unreached_by"`
	Digest      string               `json:"digest"`
	KeyID       string               `json:"kid"`
	KeySource   string               `json:"key_source"`
	ParseError  string               `json:"parse_error"`
	Revoked     bool                 `json:"revoked"`
	Claims      *mda.Claims          `json:"claims"`
	Checks      map[string]JSONCheck `json:"checks"`
}

// JSONChange is a change in one dimension across a hop.
type JSONChange struct {
	Kind   ChangeKind `json:"kind"`
	Parent string     `json:"parent"`
	Child  string     `json:"child"`
	Text   string     `json:"text"`
}

// JSONCapChange is one row of a hop's capability diff.
type JSONCapChange struct {
	Kind        ChangeKind `json:"kind"`
	ParentIndex int        `json:"parent_index"`
	ChildIndex  int        `json:"child_index"`
	Text        string     `json:"text"`
	Notes       []string   `json:"notes"`
}

// JSONConstraint is one sequence constraint across a hop.
type JSONConstraint struct {
	ID   string     `json:"id"`
	Kind ChangeKind `json:"kind"`
	Text string     `json:"text"`
}

// JSONSequence is the sequence diff of a hop.
type JSONSequence struct {
	Kind        ChangeKind       `json:"kind"`
	Text        string           `json:"text"`
	Budget      JSONChange       `json:"budget"`
	Constraints []JSONConstraint `json:"constraints"`
}

// JSONHop compares one link with its parent.
type JSONHop struct {
	Parent       int             `json:"parent"`
	Child        int             `json:"child"`
	Evaluable    bool            `json:"evaluable"`
	Attenuates   bool            `json:"attenuates"`
	Verdict      string          `json:"verdict"`
	Audience     JSONChange      `json:"audience"`
	Expiry       JSONChange      `json:"expiry"`
	MaxDepth     JSONChange      `json:"max_depth"`
	Capabilities []JSONCapChange `json:"capabilities"`
	Sequence     JSONSequence    `json:"sequence"`
	Commitment   JSONCheck       `json:"commitment"`
	DepthStep    JSONCheck       `json:"depth_step"`
	Custody      JSONCheck       `json:"custody"`
	Sponsor      JSONCheck       `json:"sponsor"`
}

// JSONFinding is one finding.
type JSONFinding struct {
	Rule      string `json:"rule"`
	SubRule   string `json:"sub_rule"`
	Code      string `json:"code"`
	Link      int    `json:"link"`
	Severity  string `json:"severity"`
	Detail    string `json:"detail"`
	Spec      string `json:"spec"`
	Derived   bool   `json:"derived"`
	Simulated bool   `json:"simulated"`
}

// JSONCounts counts non-derived findings by severity.
type JSONCounts struct {
	Fail      int `json:"fail"`
	Error     int `json:"error"`
	Unchecked int `json:"unchecked"`
	Warn      int `json:"warn"`
	Info      int `json:"info"`
}

func jsonCheck(c Check) JSONCheck {
	return JSONCheck{Status: c.Status.String(), Detail: c.Detail, Simulated: c.Simulated}
}

func jsonChange(v ValueChange) JSONChange {
	return JSONChange{Kind: v.Kind, Parent: v.Parent, Child: v.Child, Text: v.Text}
}

// JSON converts the report to its machine-readable form. Slices are never
// nil, so a consumer sees [] rather than null.
func (r *Report) JSON() JSONReport {
	out := JSONReport{
		Schema:    SchemaVersion,
		Verdict:   r.Verdict,
		BreakAt:   r.BreakAt,
		At:        r.At.UTC(),
		SkewSec:   r.Skew.Seconds(),
		Audience:  JSONAud{Value: r.Audience, Checked: r.AudienceChecked},
		Simulated: nonNil(r.Simulated),
		Input: JSONInput{
			Source:         r.Input.Source,
			Format:         r.Input.Format,
			Normalizations: nonNil(r.Input.Normalizations),
			Reversed:       r.Input.Reversed,
		},
		Library: JSONLibrary{
			Passed:     r.Library.Passed,
			Rule:       string(r.Library.Rule),
			Link:       r.Library.Link,
			Detail:     r.Library.Detail,
			Consistent: r.Library.Consistent,
			Mismatch:   r.Library.Mismatch,
			StubsUsed:  r.Library.StubsUsed,
		},
		Trust:    []JSONIssuer{},
		Links:    []JSONLink{},
		Hops:     []JSONHop{},
		Findings: []JSONFinding{},
	}
	if tc := r.Input.ToolCall; tc != nil {
		out.Input.ToolCall = &JSONToolCall{Name: tc.Name, Arguments: tc.Arguments}
	}
	if s := r.Sponsor; s != nil {
		out.Sponsor = &JSONSponsor{
			Issuer: s.Issuer, Subject: s.Subject,
			AuthenticationMethods: nonNil(s.AuthenticationMethods), AuthenticatedAt: s.AuthenticatedAt,
		}
	}
	for _, t := range r.Trust {
		out.Trust = append(out.Trust, JSONIssuer{
			Issuer: t.Issuer, Source: t.Source, KeyIDs: nonNil(t.KeyIDs), Skipped: nonNil(t.Skipped), Error: t.Err,
		})
	}
	if rv := r.Revocation; rv != nil {
		out.Revocation = &JSONRevocation{
			Source: rv.Source, Sequence: rv.Sequence, GeneratedAt: rv.GeneratedAt.UTC(),
			MaxAgeSec: rv.MaxAge.Seconds(), Exact: rv.Exact, Stale: rv.Stale, StaleDetail: rv.StaleDetail,
		}
	}
	for _, l := range r.Links {
		jl := JSONLink{
			Index: l.Index, State: l.State.String(), Unreached: l.Unreached, UnreachedBy: l.UnreachedBy,
			Digest: l.Digest, KeySource: l.KeySource, ParseError: l.ParseError, Revoked: l.Revoked,
			Claims: l.Claims, Checks: map[string]JSONCheck{},
		}
		if l.Header != nil {
			jl.KeyID = l.Header.KeyID
		}
		for _, c := range l.Checks {
			jl.Checks[string(c.Rule)] = jsonCheck(c)
		}
		out.Links = append(out.Links, jl)
	}
	for _, h := range r.Hops {
		jh := JSONHop{
			Parent: h.Parent, Child: h.Child, Evaluable: h.Evaluable,
			Attenuates: h.Evaluable && h.Verdict == "", Verdict: h.Verdict,
			Audience: jsonChange(h.Audience), Expiry: jsonChange(h.Expiry), MaxDepth: jsonChange(h.MaxDepth),
			Capabilities: []JSONCapChange{},
			Sequence: JSONSequence{
				Kind: h.Sequence.Kind, Text: h.Sequence.Text, Budget: jsonChange(h.Sequence.Budget),
				Constraints: []JSONConstraint{},
			},
			Commitment: jsonCheck(h.Commitment), DepthStep: jsonCheck(h.DepthStep),
			Custody: jsonCheck(h.Custody), Sponsor: jsonCheck(h.Sponsor),
		}
		for _, c := range h.Capabilities {
			jh.Capabilities = append(jh.Capabilities, JSONCapChange{
				Kind: c.Kind, ParentIndex: c.ParentIndex, ChildIndex: c.ChildIndex, Text: c.Text, Notes: nonNil(c.Notes),
			})
		}
		for _, c := range h.Sequence.Constraints {
			jh.Sequence.Constraints = append(jh.Sequence.Constraints, JSONConstraint{ID: c.ID, Kind: c.Kind, Text: c.Text})
		}
		out.Hops = append(out.Hops, jh)
	}
	for _, f := range r.Findings() {
		out.Findings = append(out.Findings, JSONFinding{
			Rule: string(f.Rule), SubRule: f.SubRule, Code: f.Code, Link: f.Link, Severity: f.Severity.String(),
			Detail: f.Detail, Spec: f.Spec, Derived: f.Derived, Simulated: f.Simulated,
		})
	}
	c := r.Counts()
	out.Counts = JSONCounts{
		Fail: c[SeverityFail], Error: c[SeverityError], Unchecked: c[SeverityUnchecked],
		Warn: c[SeverityWarn], Info: c[SeverityInfo],
	}
	return out
}

// JSONTrace is the machine-readable answer to a permission question.
type JSONTrace struct {
	Schema              string          `json:"schema"`
	Request             JSONRequest     `json:"request"`
	Authority           Authority       `json:"authority"`
	Covered             bool            `json:"covered"`
	Permitted           bool            `json:"permitted"`
	Reason              string          `json:"reason"`
	FirstRefused        int             `json:"first_refused"`
	OnlyThroughWidening bool            `json:"only_through_widening"`
	WideningAt          int             `json:"widening_at"`
	SponsorGranted      bool            `json:"sponsor_granted"`
	Steps               []JSONTraceStep `json:"steps"`
	Verdict             Verdict         `json:"verdict"`
}

// JSONRequest is the request asked about.
type JSONRequest struct {
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceTags []string       `json:"resource_tags"`
	Action       string         `json:"action"`
	Attributes   map[string]any `json:"attributes"`
}

// JSONTraceStep is one link's answer.
type JSONTraceStep struct {
	Link      int    `json:"link"`
	Evaluable bool   `json:"evaluable"`
	Permitted bool   `json:"permitted"`
	Reason    string `json:"reason"`
}

// TraceSchemaVersion identifies the JSON permission-check format.
const TraceSchemaVersion = "whosent.ask/v1"

// JSON converts a trace to its machine-readable form.
func (t Trace) JSON(v Verdict) JSONTrace {
	out := JSONTrace{
		Schema: TraceSchemaVersion,
		Request: JSONRequest{
			ResourceType: t.Request.ResourceType, ResourceID: t.Request.ResourceID,
			ResourceTags: nonNil(t.Request.ResourceTags), Action: t.Request.Action,
			Attributes: t.Request.Attributes,
		},
		Authority: t.Authority, Covered: t.Covered, Permitted: t.Permitted, Reason: t.Reason,
		FirstRefused: t.FirstRefused, OnlyThroughWidening: t.OnlyThroughWidening, WideningAt: t.WideningAt,
		SponsorGranted: t.SponsorGranted,
		Steps:          []JSONTraceStep{}, Verdict: v,
	}
	if out.Request.Attributes == nil {
		out.Request.Attributes = map[string]any{}
	}
	for _, s := range t.Steps {
		out.Steps = append(out.Steps, JSONTraceStep{Link: s.Link, Evaluable: s.Evaluable, Permitted: s.Permitted, Reason: s.Reason})
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
