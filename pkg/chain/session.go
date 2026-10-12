package chain

import (
	"context"
	"time"
)

// Inputs is everything a person supplied about a chain: the chain itself
// and what to check it against. Each adapter reads the fields that mean
// something for its format and says, in its own Chain, which of the rest it
// ignored.
type Inputs struct {
	// Data is the chain as read, at most a megabyte. Source names it.
	Data   []byte
	Source string

	// At is the time to evaluate at. Zero means now.
	At time.Time
	// Skew is the clock tolerance, or nil for the format's default.
	Skew *time.Duration
	// Audience is the party the chain is presented to, or nil when not
	// given. Never a pointer to "": the command line refuses that.
	Audience *string

	// TrustFile maps issuers to their key documents; JWKS are
	// ISSUER=PATH|URL pairs. Both name keys for formats whose links are
	// signed by named issuers (Mandatum, JWT).
	TrustFile string
	JWKS      []string
	// RootKeys are public keys a chain may be rooted in, for formats whose
	// root is a key rather than a named issuer (Biscuit): hex, or a file.
	RootKeys []string

	// Revocations names a published revocation set, RevokedIDs an exact
	// list of revoked identifiers, MaxAge the oldest set accepted (zero
	// accepts any age).
	Revocations string
	RevokedIDs  string
	MaxAge      time.Duration

	// Facts are statements an authorizer adds to evaluate checks against
	// (Biscuit's `resource("file1")`), and Authorizer names a file of
	// authorizer code.
	Facts      []string
	Authorizer string

	// Reverse is set when the chain was handed over leaf first.
	Reverse bool
}

// EvalOptions are what can change between evaluations of one session.
type EvalOptions struct {
	// At is the evaluation time. Never zero.
	At time.Time
	// SimRevoked are Link.RevokeID values whose revocation is being
	// simulated.
	SimRevoked []string
}

// Info describes a session.
type Info struct {
	Format Format
	// At is the evaluation time the session opens at; zero means now.
	At time.Time
}

// Session is one chain with the inputs it is checked against. The view
// calls Evaluate again whenever the time or the simulated revocations
// change, so a session holds inputs, not results.
type Session interface {
	Info() Info
	// Evaluate checks the chain and returns a new Chain the caller owns:
	// the view rewrites its strings in place before drawing them. An error
	// means the options themselves are unusable; a chain that fails its
	// rules is a Chain with Verdict INVALID, not an error.
	Evaluate(ctx context.Context, opts EvalOptions) (*Chain, error)
}

// AskField is one field of the question form.
type AskField struct {
	// Key names the field to Ask; Label is shown beside it, Hint under it
	// while it is being edited.
	Key, Label, Hint string
	// Required fields must be given: a question that leaves one out is
	// refused rather than answered from a default.
	Required bool
}

// Outcome is how one link answers a question.
type Outcome int

// The outcomes.
const (
	OutcomeCovers Outcome = iota
	OutcomeRefuses
	OutcomeUnreadable
)

// AskStep is one link's answer.
type AskStep struct {
	Link    int
	Outcome Outcome
	Reason  string
	// ShowReason asks the view to print Reason under the step. Usually
	// only the first refusal's reason is worth the room.
	ShowReason bool
}

// AskResult answers a question.
type AskResult struct {
	// Inconsistency is set when the format's reference implementation and
	// whosent's own reading answer the question differently; ask exits 70.
	Inconsistency *Inconsistency

	// Request is the question, restated, one line per entry.
	Request []string
	// Verdict is one or two words: "PERMITTED", "DENIED", "PERMITTED IF".
	Verdict string
	// Permitted is the answer an enforcement point would give.
	Permitted bool
	// Conditional is set when Permitted holds only if rules that were not
	// checked pass.
	Conditional bool
	// Judged is the verdict of the chain the answer rests on, when the
	// question itself supplies what the open chain lacked (a Fly.io
	// request). Empty means the open chain's own verdict.
	Judged Verdict
	// Tone is how the verdict is drawn, and Mark its glyph.
	Tone Tone
	Mark Mark
	// Authority is how far the answer can be relied on, such as
	// "AUTHORITATIVE" or "HYPOTHETICAL".
	Authority string
	// Why explains the verdict in a sentence; Reason is the format's own
	// explanation, when there is one.
	Why, Reason string
	// Warning is a sentence that must not be missed, such as authority
	// that exists only because a link widened it.
	Warning string
	// StepsTitle heads Steps: "asked of each link's own grant".
	StepsTitle string
	Steps      []AskStep
	// Values refill the form when the question is edited. They are drawn
	// only through the form, which cleans what it draws, and are passed
	// back to Ask as given.
	Values map[string]string `whosent:"raw"`
	// Report is the command line's human answer, one line per entry.
	Report []string
	// Native is the adapter's own JSON answer, for `ask --json`.
	Native any
}

// Asker is implemented by sessions that can answer "would this chain
// permit X".
type Asker interface {
	// AskFields are the form's fields, in order.
	AskFields() []AskField
	// AskPrefill proposes values for the form from the chain on screen and
	// the selected matrix row, so the first question is already a real one.
	AskPrefill(c *Chain, row int) map[string]string
	// Ask answers with a new AskResult the caller owns. An error names
	// what is wrong with the values.
	Ask(ctx context.Context, c *Chain, values map[string]string) (*AskResult, error)
}

// Confidence is how sure an adapter is that some input is in its format.
type Confidence int

// The confidences.
const (
	// NotMine: the input is not in this format.
	NotMine Confidence = iota
	// Plausible: the input has the right shape, but so might another
	// format's.
	Plausible
	// Certain: the input carries this format's own marker, such as a
	// media type in its header.
	Certain
)

// Scenario is a demo: a chain minted with throwaway keys.
type Scenario struct {
	Name, Title, Summary string
	// Format is the adapter's Format.ID.
	Format string
	// Open mints the chain at base and returns it with every input it
	// needs, so a demo shows no unchecked rule it did not mean to.
	Open func(base time.Time) (Session, error)
	// Emit writes the scenario's fixture files into dir and returns the
	// command that checks them, or is nil when the format has no fixtures.
	Emit func(dir string, force bool) (string, error)
}

// Adapter is a token format.
type Adapter interface {
	Format() Format
	// Detect looks at an input and says whether it is in this format. It
	// must be cheap, must not verify anything, and must not claim Certain
	// for an input another format could also claim Certain for.
	Detect(data []byte) Confidence
	// Open reads the chain and the inputs it is checked against. Errors are
	// the person's to fix: a file that cannot be read, a malformed flag.
	Open(ctx context.Context, in Inputs) (Session, error)
	// Scenarios are the format's demos.
	Scenarios() []Scenario
}

// inputFlags are the input flags in the order IgnoredInputs reports them.
var inputFlags = []string{"trust", "jwks", "root-key", "revocations", "revoked-jtis", "audience", "fact", "authorizer"}

// given reports whether the input a flag sets was given.
func (in Inputs) given(flag string) bool {
	switch flag {
	case "trust":
		return in.TrustFile != ""
	case "jwks":
		return len(in.JWKS) > 0
	case "root-key":
		return len(in.RootKeys) > 0
	case "revocations":
		return in.Revocations != ""
	case "revoked-jtis":
		return in.RevokedIDs != ""
	case "audience":
		return in.Audience != nil
	case "fact":
		return len(in.Facts) > 0
	case "authorizer":
		return in.Authorizer != ""
	}
	return false
}

// IgnoredInputs lists the inputs given that a format has no use for, as
// "--flag (why)", from reasons keyed by flag name. A format passes a
// reason for every input flag it does not read.
func IgnoredInputs(in Inputs, reasons map[string]string) []string {
	var out []string
	for _, f := range inputFlags {
		if why, ok := reasons[f]; ok && in.given(f) {
			out = append(out, "--"+f+" ("+why+")")
		}
	}
	return out
}
