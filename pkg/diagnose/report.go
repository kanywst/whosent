// Package diagnose explains a Mandatum delegation chain: every rule of the
// specification evaluated for every link, how authority narrows at every hop,
// and where the chain stops carrying any authority at all.
//
// verify.Verify answers one question, "does this chain grant anything?", and
// stops at the first rule that says no. That is the right shape for an
// enforcement point and the wrong one for a person trying to understand a
// chain: a chain with three problems shows one, and fixing it reveals the
// next. Diagnose evaluates everything, and then runs verify.Verify on the same
// inputs and checks that the two agree, so that the explanation can never
// drift from the verdict an enforcement point would reach.
//
// The package is deliberately honest about what it did not check. A rule that
// could not be evaluated because an input was not supplied (no keys, no
// revocation set, no audience) is Unchecked, never Pass, and a chain with any
// Unchecked rule is INCOMPLETE rather than VALID.
package diagnose

import (
	"strings"
	"time"

	"github.com/kanywst/whosent/internal/mandatum/jose"
	"github.com/kanywst/whosent/internal/mandatum/mda"
	"github.com/kanywst/whosent/internal/mandatum/verify"
)

// Rule is a verification rule of the specification, "V1" through "V9". The
// identifiers are the library's, not the section numbers: a denial from an
// enforcement point names V5, so the explanation has to as well.
type Rule string

// The nine verification rules of specification section 7.
const (
	V1 Rule = "V1" // structure and parent commitment
	V2 Rule = "V2" // custody: each link issued by the subject above it
	V3 Rule = "V3" // signature
	V4 Rule = "V4" // time
	V5 Rule = "V5" // attenuation (section 6 rules 1, 2, 3, 5, 7)
	V6 Rule = "V6" // the sponsor is the same in every link
	V7 Rule = "V7" // the chain is no longer than the sponsor allowed
	V8 Rule = "V8" // revocation
	V9 Rule = "V9" // the leaf names this resource server
)

// Rules lists every rule in order. Link.Checks is indexed the same way.
var Rules = [...]Rule{V1, V2, V3, V4, V5, V6, V7, V8, V9}

// Index returns the rule's position in Rules, or -1 for an unknown rule.
func (r Rule) Index() int {
	for i, x := range Rules {
		if x == r {
			return i
		}
	}
	return -1
}

// Title is a short human name for the rule, for column headers and lists.
func (r Rule) Title() string {
	switch r {
	case V1:
		return "structure"
	case V2:
		return "custody"
	case V3:
		return "signature"
	case V4:
		return "time"
	case V5:
		return "attenuation"
	case V6:
		return "sponsor"
	case V7:
		return "depth"
	case V8:
		return "revocation"
	case V9:
		return "audience"
	}
	return string(r)
}

// Status is the outcome of one rule for one link.
//
// It is not a boolean because "not checked" and "checked and fine" must never
// render the same. A tool that shows a green tick for a signature it had no
// key for is worse than no tool.
type Status int

const (
	// StatusPass means the rule was evaluated and holds.
	StatusPass Status = iota
	// StatusFail means the rule was evaluated and is violated.
	StatusFail
	// StatusError means the rule could not be evaluated although its inputs
	// were supplied (a key document that does not parse, a revocation set
	// that is too old). An enforcement point denies in this case, so it
	// counts as a failure for the verdict.
	StatusError
	// StatusUnchecked means an input the rule needs was not supplied: no
	// trust anchor for the issuer, no revocation set, no audience.
	StatusUnchecked
	// StatusSkipped means the rule could not be evaluated because the link
	// itself (or the one it is compared with) does not parse.
	StatusSkipped
	// StatusNotApplicable means the rule does not apply at this position,
	// such as custody for the sponsor's grant or audience above the leaf.
	StatusNotApplicable
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusFail:
		return "fail"
	case StatusError:
		return "error"
	case StatusUnchecked:
		return "unchecked"
	case StatusSkipped:
		return "skipped"
	case StatusNotApplicable:
		return "n/a"
	}
	return "unknown"
}

// Blocking reports whether the status alone stops the chain carrying
// authority. Fail and Error both do: an enforcement point denies in either.
func (s Status) Blocking() bool { return s == StatusFail || s == StatusError }

// Severity ranks a Finding.
type Severity int

const (
	// SeverityFail is a violated rule.
	SeverityFail Severity = iota
	// SeverityError is a rule that could not be evaluated and so denies.
	SeverityError
	// SeverityUnchecked is a rule left unevaluated for want of an input.
	SeverityUnchecked
	// SeverityWarn does not change the verdict but is worth acting on.
	SeverityWarn
	// SeverityInfo is context.
	SeverityInfo
)

func (s Severity) String() string {
	switch s {
	case SeverityFail:
		return "fail"
	case SeverityError:
		return "error"
	case SeverityUnchecked:
		return "unchecked"
	case SeverityWarn:
		return "warn"
	case SeverityInfo:
		return "info"
	}
	return "unknown"
}

// Blocking reports whether a finding of this severity denies the chain.
func (s Severity) Blocking() bool { return s == SeverityFail || s == SeverityError }

// Finding is one thing Diagnose has to say about a chain.
type Finding struct {
	// Rule is the verification rule the finding belongs to, or "" for a
	// finding about the input rather than a rule (a reversed chain, say).
	Rule Rule
	// SubRule narrows Rule to the clause that fired, such as "section 6
	// rule 2" inside V5.
	SubRule string
	// Code is a stable machine identifier, such as "v4.expired".
	Code string
	// Link is the index of the link the finding is about, or -1 for the
	// chain as a whole.
	Link int
	// Hop is the index of the child link when the finding compares a link
	// with its parent, or -1.
	Hop int
	// Severity ranks the finding.
	Severity Severity
	// Detail says what is wrong in terms of the chain. Where the library has
	// its own wording (attenuation, structural validation, JOSE) it is used
	// verbatim, so the text matches what an enforcement point logs.
	Detail string
	// Spec points at the clause of the specification.
	Spec string
	// Derived marks a consequence of a failure elsewhere, such as a link
	// below a revoked one. Derived findings explain; they never decide the
	// verdict or where the chain breaks.
	Derived bool
	// Simulated marks a finding caused by a simulated revocation rather
	// than by any input.
	Simulated bool

	order orderKey
}

// Check is the outcome of one rule for one link: one cell of the grid.
type Check struct {
	Rule   Rule
	Status Status
	// Detail is one line: why it passed, or the first reason it did not.
	Detail string
	// Simulated is set when the outcome comes from a simulated revocation.
	Simulated bool
}

// LinkState summarizes a link's own checks.
type LinkState int

const (
	// LinkOK means every rule that applies to the link was evaluated and
	// holds.
	LinkOK LinkState = iota
	// LinkIncomplete means nothing failed but at least one rule was not
	// checked.
	LinkIncomplete
	// LinkBroken means at least one rule failed or could not be evaluated.
	LinkBroken
)

func (s LinkState) String() string {
	switch s {
	case LinkOK:
		return "ok"
	case LinkIncomplete:
		return "incomplete"
	case LinkBroken:
		return "broken"
	}
	return "unknown"
}

// Link is everything known about one assertion in the chain.
type Link struct {
	Index int
	// Raw is the compact serialization exactly as received.
	Raw []byte
	// Digest is the parent commitment a child of this link must carry.
	Digest string
	// Header is the decoded JOSE header, or nil if it did not decode. It is
	// untrusted until V3 passes.
	Header *jose.Header
	// Claims are the strictly parsed claims, or nil when the link does not
	// parse. Untrusted until the chain verifies.
	Claims *mda.Claims
	// ParseError says why Claims is nil.
	ParseError string
	// Untrusted is a lenient decode of the payload for display when the
	// strict parse fails. It must never be used for a decision.
	Untrusted map[string]any

	// Checks holds one cell per rule, indexed like Rules.
	Checks [len(Rules)]Check
	// Findings lists everything said about this link, including findings
	// about the hop from its parent.
	Findings []Finding

	// State is the link's own outcome.
	State LinkState
	// Unreached is set for every link strictly below the first broken
	// link. No authority reaches it, whatever its own checks say.
	Unreached bool
	// UnreachedBy is the index of the link that cuts this one off, when
	// Unreached.
	UnreachedBy int

	// Revoked is set when V8 failed for this link; RevokedSimulated when
	// that failure is a simulation.
	Revoked          bool
	RevokedSimulated bool

	// KeySource names where the signature was checked against, such as
	// "idp.jwks.json kid idp-2026", or "" when it was not.
	KeySource string

	// IssuedAt and ExpiresAt are copied from Claims for convenience; zero
	// when the link does not parse.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Remaining is ExpiresAt minus the evaluation time. Negative once
	// expired.
	Remaining time.Duration
}

// Check returns the cell for rule r.
func (l *Link) Check(r Rule) Check {
	if i := r.Index(); i >= 0 {
		return l.Checks[i]
	}
	return Check{Rule: r, Status: StatusNotApplicable}
}

// ChangeKind classifies how one dimension of authority changed across a hop.
type ChangeKind string

// The kinds of change a hop can make. Only Widened is a violation.
const (
	ChangeKept     ChangeKind = "kept"
	ChangeNarrowed ChangeKind = "narrowed"
	ChangeDropped  ChangeKind = "dropped"
	ChangeWidened  ChangeKind = "widened"
	ChangeAdded    ChangeKind = "added"
	// ChangeUnknown is used when one side of the hop does not parse.
	ChangeUnknown ChangeKind = "unknown"
)

// Violation reports whether the change widens authority.
func (k ChangeKind) Violation() bool { return k == ChangeWidened }

// CapChange is one row of a hop's capability diff.
type CapChange struct {
	Kind ChangeKind
	// ParentIndex and ChildIndex index the capability slices of the two
	// links, or -1 where that side is absent (dropped, or widened).
	ParentIndex int
	ChildIndex  int
	Parent      *mda.Capability
	Child       *mda.Capability
	// Text is the one-line summary, such as "search.* narrowed to
	// search.query".
	Text string
	// Notes are the individual narrowings, or the reasons a widened
	// capability is not covered.
	Notes []string
}

// ValueChange describes a scalar dimension across a hop: audience, expiry,
// max_depth, invocation budget.
type ValueChange struct {
	Kind   ChangeKind
	Parent string
	Child  string
	Text   string
}

// ConstraintChange is one sequence constraint across a hop.
type ConstraintChange struct {
	ID   string
	Kind ChangeKind // kept (inherited), added, dropped, widened (redefined)
	Text string
}

// SequenceDiff describes the sequence constraints across a hop.
type SequenceDiff struct {
	Kind        ChangeKind
	Budget      ValueChange
	Constraints []ConstraintChange
	Text        string
}

// Hop compares a link with its parent.
type Hop struct {
	Parent int
	Child  int
	// Evaluable is false when either side does not parse; the diff fields
	// are then empty.
	Evaluable bool
	// Verdict is "" when verify.Attenuates accepts the pair, otherwise its
	// error text verbatim.
	Verdict string

	Audience     ValueChange
	Expiry       ValueChange
	MaxDepth     ValueChange
	Capabilities []CapChange
	Sequence     SequenceDiff

	// The positional rules shown alongside the diff. They are separate rules
	// in the library (V1, V2, V6), so they carry their own status.
	Commitment Check // V1: the child commits to this parent's bytes
	DepthStep  Check // V1: depth increments by one
	Custody    Check // V2: the child is issued by the parent's subject
	Sponsor    Check // V6: the sponsor is unchanged
}

// CellKind is one cell of the authority matrix.
type CellKind int

const (
	// CellAbsent means the link holds nothing on this row.
	CellAbsent CellKind = iota
	// CellHeld means the link holds the row's authority exactly as the
	// sponsor granted it.
	CellHeld
	// CellNarrowed means the link holds a narrower form of it.
	CellNarrowed
	// CellWidened means the link claims authority its parent did not hold.
	CellWidened
	// CellUnknown means the link does not parse.
	CellUnknown
	// CellOrphan means the link claims it, but its parent does not parse, so
	// where it came from cannot be said.
	CellOrphan
)

func (k CellKind) String() string {
	switch k {
	case CellAbsent:
		return "absent"
	case CellHeld:
		return "held"
	case CellNarrowed:
		return "narrowed"
	case CellWidened:
		return "widened"
	case CellUnknown:
		return "unknown"
	case CellOrphan:
		return "orphan"
	}
	return "unknown"
}

// Cell is one link's holding on one row of the matrix.
type Cell struct {
	Kind CellKind
	// Changed is set when this hop changed the holding (narrowed it,
	// dropped it, or widened it), as opposed to passing it on unchanged.
	Changed bool
	// Caps indexes the link's capabilities that fall on this row. A parent
	// capability can split into several narrower ones.
	Caps []int
}

// Row is one line of authority traced down the chain.
type Row struct {
	// Label is a compact description, such as "invoke mcp_tool search.*".
	Label string
	// Origin is the link where the row starts: 0 for the sponsor's grant,
	// later for authority that appears from nowhere.
	Origin int
	// Root is the capability the row was granted as, at Origin.
	Root  mda.Capability
	Cells []Cell
}

// Matrix traces each capability from the link that grants it to the leaf.
type Matrix struct {
	Rows []Row
	// RootRows is the number of rows the sponsor granted. A link's Retained
	// is how many of those still reach it.
	RootRows int
	Retained []int
}

// Verdict is the outcome for the chain as a whole.
type Verdict string

const (
	// VerdictValid means every rule was evaluated for every link and holds.
	VerdictValid Verdict = "VALID"
	// VerdictInvalid means at least one rule failed or could not be
	// evaluated. The chain grants nothing.
	VerdictInvalid Verdict = "INVALID"
	// VerdictIncomplete means nothing failed but something was not checked.
	// It is not a pass.
	VerdictIncomplete Verdict = "INCOMPLETE"
)

// LibraryCheck records the consistency guard: what verify.Verify said about
// the same chain with the same inputs, and whether Diagnose agrees.
type LibraryCheck struct {
	// Passed is set when verify.Verify returned no error.
	Passed bool
	// Rule, Link and Detail are the library's error when it did not pass.
	Rule   Rule
	Link   int
	Detail string
	// ToolRule and ToolLink are what Diagnose found first, in the order the
	// library evaluates, or "" and -1 when it found nothing.
	ToolRule Rule
	ToolLink int
	// Consistent is false when the two disagree. That is a bug in this
	// tool, never in the chain, and the library's verdict is the one that
	// stands.
	Consistent bool
	Mismatch   string
	// StubsUsed is set when an input was missing and the library run had to
	// be told to pass the unchecked rule. A library pass with stubs is not a
	// VALID chain.
	StubsUsed bool
}

// InputInfo describes where the chain came from and how it was read.
type InputInfo struct {
	Source string
	// Format is "json-array", "json-object", "jsonrpc", "lines" or "" for
	// links handed in directly.
	Format string
	// Normalizations lists anything done to the input before parsing, such
	// as trimmed whitespace. Bytes inside a serialization are never changed:
	// the parent commitment is a digest over them.
	Normalizations []string
	// ToolCall is set when the input was a tools/call request.
	ToolCall *ToolCall
	// Reversed is set when the links were reversed on request.
	Reversed bool
}

// ToolCall is the part of an MCP tools/call request a permission check uses.
type ToolCall struct {
	Name      string
	Arguments map[string]any
}

// IssuerSummary describes one configured trust anchor for display.
type IssuerSummary struct {
	Issuer  string
	Source  string
	KeyIDs  []string
	Skipped []string
	Err     string
}

// RevocationSummary describes the revocation set in use.
type RevocationSummary struct {
	Source      string
	Sequence    uint64
	GeneratedAt time.Time
	MaxAge      time.Duration
	Exact       string
	// Stale is set when the set is older than MaxAge at the evaluation time,
	// in which case every link's V8 is an Error.
	Stale       bool
	StaleDetail string
}

// Report is everything Diagnose found.
type Report struct {
	Input InputInfo
	// At is the evaluation time and Skew the tolerance applied to it.
	At   time.Time
	Skew time.Duration
	// Audience is the resource server the leaf was checked against;
	// AudienceChecked is false when none was supplied.
	Audience        string
	AudienceChecked bool

	Trust      []IssuerSummary
	Revocation *RevocationSummary
	// Simulated lists the jtis treated as revoked by simulation. Non-empty
	// means this report describes a hypothetical, not the chain as it is.
	Simulated []string

	// Sponsor is the human the chain is rooted in, from the first link,
	// when it parses. Untrusted unless Verdict is VALID.
	Sponsor *mda.Sponsor

	Links []Link
	// Hops has one entry per adjacent pair: Hops[i] compares Links[i] with
	// Links[i+1].
	Hops []Hop
	// ChainFindings are findings about the chain as a whole.
	ChainFindings []Finding
	Matrix        Matrix

	// BreakAt is the first link with a blocking finding of its own, or -1.
	// Every link after it is unreached.
	BreakAt int
	Verdict Verdict
	Library LibraryCheck
	// Result is the library's verification result. It is set only when the
	// chain is VALID and the guard agrees: anything else would hand a caller
	// a result built on stubs.
	Result *verify.Result
}

// Findings returns every finding, chain-level first, then link by link in
// the order the library evaluates.
func (r *Report) Findings() []Finding {
	out := append([]Finding(nil), r.ChainFindings...)
	for _, l := range r.Links {
		out = append(out, l.Findings...)
	}
	return out
}

// Counts returns how many findings there are of each severity, ignoring
// derived ones.
func (r *Report) Counts() map[Severity]int {
	c := map[Severity]int{}
	for _, f := range r.Findings() {
		if !f.Derived {
			c[f.Severity]++
		}
	}
	return c
}

// Leaf returns the last link, or nil for an empty chain.
func (r *Report) Leaf() *Link {
	if len(r.Links) == 0 {
		return nil
	}
	return &r.Links[len(r.Links)-1]
}

// Short is a compact name for a principal, for places with no room for the
// whole identifier: the last path segment of a SPIFFE ID, the host of an
// https issuer, anything else as it is.
func Short(id string) string {
	switch {
	case strings.HasPrefix(id, "spiffe://"):
		rest := strings.TrimPrefix(id, "spiffe://")
		if i := strings.LastIndex(rest, "/"); i >= 0 && i < len(rest)-1 {
			return rest[i+1:]
		}
		return rest
	case strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://"):
		rest := id[strings.Index(id, "://")+3:]
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		return rest
	}
	return id
}
