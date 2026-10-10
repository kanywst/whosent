package verify

import (
	"errors"
	"fmt"
)

// Error reports a failed verification, naming the specification rule that
// rejected the chain.
//
// Denials carry the rule identifier because an operator asking "why was this
// denied?" needs an answer that points at a clause they can read, not a
// message someone wrote in a hurry. Rule identifiers match the headings in
// docs/spec/delegation-assertion.md §7.
type Error struct {
	// Rule is the specification rule, for example "V5".
	Rule string
	// Depth is the index of the offending link, or -1 for the whole chain.
	Depth int
	// Detail describes what was wrong, in terms of the chain rather than
	// the implementation.
	Detail string
}

func (e *Error) Error() string {
	if e.Depth < 0 {
		return fmt.Sprintf("mandatum: %s: %s", e.Rule, e.Detail)
	}
	return fmt.Sprintf("mandatum: %s at link %d: %s", e.Rule, e.Depth, e.Detail)
}

// Rule reports the specification rule that rejected a chain, or "" if err is
// not a verification failure. Callers use it to classify denials without
// matching on message text.
func Rule(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Rule
	}
	return ""
}

// ruleErr builds a verification failure. With no arguments the detail is used
// verbatim rather than as a format string, so a detail carrying a literal '%'
// - an identifier from an untrusted assertion, for instance - cannot turn into
// a mangled error message.
func ruleErr(rule string, depth int, detail string, args ...any) *Error {
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	return &Error{Rule: rule, Depth: depth, Detail: detail}
}
