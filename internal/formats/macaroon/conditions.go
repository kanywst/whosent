package macaroon

import (
	"strings"
	"time"
)

// Predicates belong to each application, so whosent judges only time
// conventions (`time < T` from the libmacaroons README, `time-before T` from
// go-macaroon's bakery, Fly.io's ValidityWindow) and exact predicates given
// with --fact, as libmacaroons' satisfy_exact does. Anything else is
// unchecked without --fact and refused with it.

// timeCaveat reads a time convention and returns the instant the caveat
// stops holding.
func timeCaveat(cond string) (time.Time, bool) {
	var rest string
	switch {
	case strings.HasPrefix(cond, "time < "):
		rest = strings.TrimPrefix(cond, "time < ")
	case strings.HasPrefix(cond, "time-before "):
		rest = strings.TrimPrefix(cond, "time-before ")
	default:
		return time.Time{}, false
	}
	rest = strings.TrimSpace(rest)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, rest); err == nil {
			// A time without a zone, as in libmacaroons' example, is UTC.
			return t, true
		}
	}
	return time.Time{}, false
}

// holdsBefore reports whether "now is before end" holds at at, with skew
// tolerance on the side that keeps a token alive. A caveat that names an
// end means the token is good while now < end.
func holdsBefore(end, at time.Time, skew time.Duration) bool {
	return at.Add(-skew).Before(end)
}

// holdsAfter reports whether a not-before bound has been reached.
func holdsAfter(start, at time.Time, skew time.Duration) bool {
	return !at.Add(skew).Before(start)
}
