// Package chain is the format-neutral model of a delegation chain that
// whosent's interactive view and command line render.
//
// A format adapter (Mandatum, Biscuit, a JWT carrying RFC 8693 `act`) reads
// its own token format, checks it by that format's own rules, and describes
// the result in these types. Nothing here knows what a capability or a
// signature looks like in any particular format: the adapter decides what the
// rows of the authority matrix are, what each rule is called, and what the
// inspector says about a link. The view only decides how it looks.
//
// Two rules hold for every adapter, and the types are shaped to make them
// hard to break:
//
//   - Nothing unchecked looks checked. A rule that could not be evaluated, or
//     that needed an input nobody gave, is StatusUnchecked or StatusError,
//     never StatusPass, and a link whose place in the chain is only asserted
//     by someone else (a prior actor in a JWT's `act`) is marked Asserted and
//     drawn apart from a verified one.
//
//   - Adapters write no glyphs. Arrows, ticks and dots belong to the view,
//     which swaps them for ASCII under --ascii; a "→" an adapter wrote into
//     a string would survive that switch. Where a relation needs an arrow
//     the types carry both ends (Change.Before) and the view draws it. The
//     command line's own fields (Describe, Context, AskResult.Report) are
//     the exception: they are printed as they are.
//
//   - Adapters never sanitise. Every string in a Chain may come from the
//     token, which is attacker-controlled; the view and the command line
//     neutralise terminal control characters at the one place text reaches
//     the terminal. An adapter that escaped strings itself would make that
//     choke point look optional.
package chain

import "time"

// Status is the outcome of one rule for one link.
type Status int

// The statuses. Blocking says which of them deny.
const (
	// StatusPass: the rule was evaluated and holds.
	StatusPass Status = iota
	// StatusFail: the rule was evaluated and does not hold.
	StatusFail
	// StatusError: the rule could not be evaluated (a key document failed
	// to load, a revocation set is stale). An enforcement point denies.
	StatusError
	// StatusUnchecked: the rule needs an input that was not supplied.
	StatusUnchecked
	// StatusSkipped: the rule could not run because the link did not parse.
	StatusSkipped
	// StatusNotApplicable: the rule does not apply to this link (custody
	// on the first link, audience on any link but the last).
	StatusNotApplicable
)

// Blocking reports whether a status means the chain grants nothing.
func (s Status) Blocking() bool { return s == StatusFail || s == StatusError }

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
	}
	return "n/a"
}

// Severity ranks a finding. Lower is worse, so sorting by severity puts the
// failures first.
type Severity int

// The severities.
const (
	SeverityFail Severity = iota
	SeverityError
	SeverityUnchecked
	SeverityWarn
	SeverityInfo
)

// Blocking reports whether a finding of this severity denies the chain.
func (s Severity) Blocking() bool { return s == SeverityFail || s == SeverityError }

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
	}
	return "info"
}

// Verdict is what the chain amounts to.
type Verdict string

// The verdicts. Only VALID means every rule was evaluated and held.
const (
	VerdictValid      Verdict = "VALID"
	VerdictInvalid    Verdict = "INVALID"
	VerdictIncomplete Verdict = "INCOMPLETE"
)

// RuleInfo names one of a format's rules.
type RuleInfo struct {
	// ID is short and stable, such as "V4" or "B-SIG"; it is what a finding
	// and a check carry.
	ID string
	// Title is a word or two, such as "time" or "signature".
	Title string
	// Spec points at where the rule is defined: a section, or a URL.
	Spec string
}

// Capabilities says which of the view's interactive features a format
// supports. A feature a format cannot honestly support is switched off
// rather than faked: a time scrub over a token with no lifetimes would only
// show nothing changing.
type Capabilities struct {
	// TimeScrub: re-evaluating at another time is meaningful.
	TimeScrub bool
	// RevokeSim: links have identifiers that can be revoked, and
	// re-evaluating with one revoked shows what it cuts off.
	RevokeSim bool
	// Ask: the session can answer "would this chain permit X".
	Ask bool
	// PerHopSignatures: each link is signed by the one before it, so a
	// break can be located cryptographically. Without it, the chain is one
	// issuer's assertion about who acted.
	PerHopSignatures bool
}

// Format describes a token format.
type Format struct {
	// ID is the --format name, such as "mandatum".
	ID string
	// Name is how it is written in prose, such as "Mandatum".
	Name string
	// Rules are the format's rules in the order the view lists them. A
	// link's Checks follow the same order.
	Rules []RuleInfo
	// Caps are the features the view may offer.
	Caps Capabilities
	// RootRole is what the root of a chain is called under its name on the
	// rail: "sponsor", "issuer", "root key".
	RootRole string
}

// Rule returns the RuleInfo for id, or one carrying only the id.
func (f Format) Rule(id string) RuleInfo {
	for _, r := range f.Rules {
		if r.ID == id {
			return r
		}
	}
	return RuleInfo{ID: id}
}

// Chain is one chain, checked. It is everything the view and the command
// line render, and it is rebuilt from scratch on every evaluation.
type Chain struct {
	Format Format

	// Source names where the chain came from: a file, "stdin", a scenario.
	Source string
	// InputFormat is how the input was recognised, such as "json-array".
	InputFormat string
	// Normalizations lists anything the reader did to the input before
	// checking it.
	Normalizations []string
	// Reversed is set when the chain was reversed on request.
	Reversed bool
	// Call is the request the chain arrived with, when the input carried
	// one (an MCP tools/call), so a question about it can start from it.
	Call *Call
	// At is the time the chain was evaluated at.
	At time.Time

	Verdict Verdict
	// BreakAt is the first link that fails, or -1. No authority reaches
	// below it.
	BreakAt int
	// Headline, when set, replaces the view's own one-sentence verdict.
	// Most adapters leave it empty and let the view word it from Root,
	// Links and BreakAt.
	Headline string
	// IncompleteReason says, in terms of inputs a person would supply, why
	// an INCOMPLETE chain is not verified: "no keys for 2 issuers, no
	// revocation set".
	IncompleteReason string
	// Summary describes what was checked and how, in short parts the view
	// joins into one line under the verdict when nothing else is shown
	// there: "3 links", "json-array", "skew 30s".
	Summary []string
	// Describe is the command line report's header after the source and
	// link count: "sponsor alice@example.org via https://idp (pwd+hwk)".
	Describe string
	// Context is the command line report's second line: the time, the
	// tolerances and the inputs it was checked against.
	Context string

	Root  Root
	Links []Link
	// Hops describe how authority changes between each link and the one
	// before it; Hops[i] is between Links[i] and Links[i+1].
	Hops []Hop
	// ChainFindings are findings about the chain as a whole.
	ChainFindings []Finding
	// Matrix is the authority matrix, or nil when the format has nothing
	// to tabulate.
	Matrix *Matrix
	// CheckedAgainst lists the inputs the chain was checked against, and
	// says plainly when one is missing. A row keyed "time" gets the view's
	// scrub label appended.
	CheckedAgainst []KV
	// Missing names the inputs whose absence left rules unchecked, as flags
	// a person can pass: "signatures (--trust or --jwks)".
	Missing []string
	// Ignored names the inputs that were given but that this format has no
	// use for, each with why: "--revocations (a JWT has no revocation
	// list)". A flag that silently does nothing reads as one that was
	// checked, so every format says so, in the same words everywhere.
	Ignored []string
	// Simulated lists the identifiers whose revocation is being simulated.
	// A simulation never changes what `check` reports for real.
	Simulated []string

	// Inconsistency is set when the adapter's own evaluation and the
	// format's reference implementation disagree about the chain. The
	// reference verdict stands; this is a bug to report.
	Inconsistency *Inconsistency

	// Native is the adapter's own report, for `check --json --native`.
	// Nil when the adapter has none beyond this model.
	Native any
}

// Call is a request a chain was presented with.
type Call struct {
	// Name is what was called, such as an MCP tool's name.
	Name string
	// Arguments are its arguments, as decoded JSON.
	Arguments map[string]any
}

// Root is what the chain is rooted in: a human sponsor, an issuer, a key.
type Root struct {
	// Name is short, for the rail: "alice@example.org".
	Name string
	// Kind is "human", "issuer" or "key".
	Kind string
	// Details are up to two short lines under the name on the rail, such as
	// how the sponsor authenticated and where.
	Details []string
}

// LinkState is a link's own state, before what happened above it.
type LinkState int

// The link states.
const (
	LinkOK LinkState = iota
	LinkIncomplete
	LinkBroken
)

// Pips is a link's remaining delegation depth, drawn as filled and empty
// dots.
type Pips struct {
	Left, Total int
}

// Link is one hop of the chain: authority handed from From to To.
type Link struct {
	Index int
	// From and To are short display names for who handed authority over
	// and who received it. Empty when the link could not be read.
	From, To string
	// Readable reports whether the link parsed at all.
	Readable bool

	State LinkState
	// Unreached is set when a link above this one is broken, so no
	// authority reaches here whatever this link says. UnreachedBy is that
	// link.
	Unreached   bool
	UnreachedBy int
	// Revoked is set when the link is revoked; RevokedSimulated when that
	// is only a simulation.
	Revoked, RevokedSimulated bool
	// Asserted is set when the link's place in the chain is only the
	// issuer's say-so and nothing verifies it hop by hop, such as a prior
	// actor in a JWT's `act` claim (RFC 8693 section 4.1 calls them
	// informational). It is never drawn as verified. Rules nothing could
	// check for such a link, whatever was supplied, are
	// StatusNotApplicable; StatusUnchecked would claim an input could have
	// checked them.
	Asserted bool

	// Checks are the format's rules for this link, in Format.Rules order.
	Checks []Check
	// Findings are the findings about this link.
	Findings []Finding

	IssuedAt, ExpiresAt time.Time
	// Remaining is ExpiresAt minus the evaluation time; negative once
	// expired. Meaningless when ExpiresAt is zero.
	Remaining time.Duration
	// Depth is how many further delegations the link permits, or nil when
	// the format has no such limit.
	Depth *Pips
	// RevokeID is what a revocation simulation of this link revokes, or
	// empty when this link cannot be revoked on its own. The view passes it
	// back in EvalOptions.SimRevoked exactly as given and never draws it.
	RevokeID string `whosent:"raw"`

	// Sections are what the inspector says about the link, after the
	// state, the checks and the findings, which the view draws itself.
	// For a link after the first, the view puts the hop against the link
	// above before them.
	Sections []Section
	// Raw is the raw view: the bytes as they were signed, decoded.
	Raw []Section
}

// Check is one rule's outcome for one link.
type Check struct {
	Rule   string
	Status Status
	Detail string
	// Simulated is set when the outcome comes from a simulation.
	Simulated bool
}

// Check returns the outcome of rule id, or a not-applicable one.
func (l Link) Check(id string) Check {
	for _, c := range l.Checks {
		if c.Rule == id {
			return c
		}
	}
	return Check{Rule: id, Status: StatusNotApplicable}
}

// Finding is one thing the adapter has to say.
type Finding struct {
	// Rule is the rule it comes from; empty for one about the input.
	Rule string
	// SubRule and Code are finer, stable identifiers for scripts.
	SubRule, Code string
	// Link is the link it is about, or -1 for the whole chain. Hop is the
	// hop, or -1.
	Link, Hop int
	Severity  Severity
	Detail    string
	// Spec is where the rule is defined.
	Spec string
	// Derived is set for a consequence of another finding, such as every
	// link below a revoked one.
	Derived bool
	// Simulated is set when the finding comes from a simulation.
	Simulated bool
}

// ChangeKind is what happened to a piece of authority across a hop.
type ChangeKind string

// The change kinds.
const (
	ChangeKept     ChangeKind = "kept"
	ChangeNarrowed ChangeKind = "narrowed"
	ChangeDropped  ChangeKind = "dropped"
	ChangeWidened  ChangeKind = "widened"
	ChangeAdded    ChangeKind = "added"
	ChangeInfo     ChangeKind = "info"
	ChangeUnknown  ChangeKind = "unknown"
)

// Violation reports whether the change breaks the chain.
func (k ChangeKind) Violation() bool { return k == ChangeWidened }

// Change is one line of a hop's diff.
type Change struct {
	Kind ChangeKind
	// Before, when set, is what Text replaced: the view draws
	// "Before → Text".
	Before string
	// Text is the line itself.
	Text string
	// Notes are indented under it.
	Notes []string
}

// Hop is how authority changes from Parent to Child.
type Hop struct {
	Parent, Child int
	// Evaluable is false when one side could not be read, so there is
	// nothing to compare.
	Evaluable bool
	// Changes is the diff the inspector shows, in order.
	Changes []Change
	// Summary is the shorter diff the command line report prints. Nil means
	// the same as Changes.
	Summary []Change
	// Verdict is the format's own sentence about the hop when it fails. It
	// is empty when the hop holds, and when a finding on the child already
	// says the same thing, so a panel never prints a sentence twice.
	Verdict string
}

// CellKind is what one link holds of one row of authority.
type CellKind int

// The cell kinds.
const (
	CellAbsent CellKind = iota
	CellHeld
	CellNarrowed
	CellWidened
	// CellUnknown: the link could not be read.
	CellUnknown
	// CellOrphan: held below a link that could not be read, so its origin
	// cannot be traced.
	CellOrphan
)

// Matrix is authority as a table: one row per thing granted, one column
// per link, and in each cell what that link holds of it.
type Matrix struct {
	// Title heads the panel, such as "AUTHORITY". Scope, when set, follows
	// it: what every row shares and so is said once, such as
	// "invoke mcp_tool".
	Title, Scope string
	Rows         []Row
	// RootRows is how many rows the root granted; rows past it appeared
	// later, which is itself the story.
	RootRows int
	// Retained is, per link, how many of the root's rows it still holds.
	Retained []int
	// Extra are summary rows under the matrix, such as an invocation
	// budget per link.
	Extra []SummaryRow
	// DefaultRow is the row to select when the chain opens.
	DefaultRow int
	// UnknownLabel is what the legend calls CellUnknown, such as "not in
	// the token" for a prior actor whose authority a JWT does not state.
	// Empty means "unreadable": a link that does not parse.
	UnknownLabel string
}

// Row is one thing granted, followed down the chain.
type Row struct {
	Label string
	// Origin is the link it first appears at: 0 for the root's grant, more
	// for authority that appeared from nowhere.
	Origin int
	Cells  []Cell
	// Lineage is the row read out in full, one entry per link from Origin
	// on, for the panel under the matrix.
	Lineage []LineageEntry
}

// Cell is what one link holds of one row.
type Cell struct {
	Kind CellKind
	// Changed is set when this link changed the row: narrowed it, dropped
	// it, or widened it.
	Changed bool
}

// LineageEntry is what one link holds of a row, in words.
type LineageEntry struct {
	Link    int
	Kind    CellKind
	Changed bool
	// Texts are the link's own grants that make up the cell, written out.
	Texts []string
}

// SummaryRow is one row of per-link figures under the matrix.
type SummaryRow struct {
	Label string
	Cells []SummaryCell
}

// SummaryCell is one figure.
type SummaryCell struct {
	Text string
	// Infinite replaces Text with an infinity mark.
	Infinite bool
	// Dim draws it as unremarkable (a default, a zero).
	Dim bool
}

// Tone is what a line of text means, which the view turns into a colour.
type Tone int

// The tones.
const (
	ToneText Tone = iota
	ToneMuted
	ToneStrong
	// ToneRoot is the root principal's own colour.
	ToneRoot
	ToneGood
	ToneWarn
	ToneBad
	ToneBadStrong
	ToneDim
	// ToneAdded, ToneNarrowed: the diff colours, for a grant.
	ToneAdded
	ToneNarrowed
)

// KV is one key and value, such as one input the chain was checked against.
type KV struct {
	Key, Value string
	Tone       Tone
}

// LineKind is how a line of a section is laid out.
type LineKind int

// The line kinds.
const (
	// LineKV is a key in a fixed column and a value wrapped beside it.
	LineKV LineKind = iota
	// LineText is a sentence, wrapped, at Indent.
	LineText
	// LineChange is a diff line: Change's mark, then Value.
	LineChange
	// LineJSON is a JSON document, already indented, drawn with keys and
	// values coloured apart.
	LineJSON
	// LineCode is source text, such as Datalog, one line per line,
	// wrapped under itself when too long.
	LineCode
	// LineBlank is an empty line.
	LineBlank
)

// Mark is a glyph a line starts with.
type Mark int

// The marks.
const (
	MarkNone Mark = iota
	MarkPass
	MarkFail
	MarkUnchecked
	MarkWarn
)

// Line is one line of an inspector or raw section.
type Line struct {
	Kind LineKind
	Key  string
	// Value may hold several lines for LineJSON and LineCode; every other
	// kind draws it as one paragraph.
	Value string `whosent:"lines"`
	Tone  Tone
	// Mark, when set, is drawn before Value.
	Mark Mark
	// Change is the mark of a LineChange.
	Change ChangeKind
	// Indent is how far a LineText is indented.
	Indent int
	// Digest, when 1 or more, draws the value in that link's digest colour
	// (link Digest-1), so values naming the same link match; DigestSoft
	// drops the emphasis.
	Digest     int
	DigestSoft bool
}

// Section is a titled block of lines.
type Section struct {
	Title string
	Lines []Line
}

// Inconsistency is a disagreement between the adapter and the reference
// implementation of its format.
type Inconsistency struct {
	// Banner is the one line the view puts across the top.
	Banner string
	// Detail is the full mismatch, for the command line and stderr.
	Detail string
}

// Findings returns every finding: the chain's, then each link's, in order.
func (c *Chain) Findings() []Finding {
	out := append([]Finding(nil), c.ChainFindings...)
	for _, l := range c.Links {
		out = append(out, l.Findings...)
	}
	return out
}

// Counts tallies the findings by severity. Consequences (Derived) are not
// counted: one revoked link is one failure, however many links hang below
// it.
func (c *Chain) Counts() map[Severity]int {
	n := map[Severity]int{}
	for _, f := range c.Findings() {
		if !f.Derived {
			n[f.Severity]++
		}
	}
	return n
}

// Leaf returns the last link, or nil.
func (c *Chain) Leaf() *Link {
	if len(c.Links) == 0 {
		return nil
	}
	return &c.Links[len(c.Links)-1]
}
