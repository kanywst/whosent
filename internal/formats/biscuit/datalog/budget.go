package datalog

import (
	"context"
	"regexp"
	"time"
)

// budget bounds one authorization from the inside. The reference checks
// its limits between fixpoint iterations, which is enough for it because
// its default time limit is one millisecond and an iteration of a real
// token is far shorter. It is not enough here: a single join over a few
// dozen facts, or a few nested closures, is exponential in the size of a
// token under a kilobyte, so one iteration (or one check, which is not an
// iteration at all) can run for hours before the next limit check. Every
// unit of work therefore ticks the budget, and the first tick past the
// deadline, or after the context is done, stops the run with a LimitError.
type budget struct {
	ctx      context.Context
	deadline time.Time
	steps    uint64
	err      error
	// regex caches compiled patterns: the same pattern is matched once per
	// combination, and compiling it each time is most of the cost.
	regex map[string]*regexp.Regexp
}

// tickEvery is how many units of work pass between clock reads. A unit is
// a fact tried in a join or an opcode evaluated, each well under a
// microsecond, so a run overshoots its deadline by far less than a
// millisecond.
const tickEvery = 256

func newBudget(ctx context.Context, limits Limits) *budget {
	if ctx == nil {
		ctx = context.Background()
	}
	return &budget{ctx: ctx, deadline: time.Now().Add(limits.MaxTime), regex: map[string]*regexp.Regexp{}}
}

// tick records one unit of work and reports whether the run may go on.
// A nil budget never stops anything, for code that evaluates outside an
// authorization.
func (b *budget) tick() bool {
	if b == nil {
		return true
	}
	if b.err != nil {
		return false
	}
	b.steps++
	if b.steps%tickEvery != 0 {
		return true
	}
	if b.ctx.Err() != nil {
		b.err = &LimitError{"Cancelled"}
		return false
	}
	if time.Now().After(b.deadline) {
		b.err = &LimitError{"Timeout"}
		return false
	}
	return true
}

// compile returns a compiled pattern, from the cache when it has one.
func (b *budget) compile(pattern string) (*regexp.Regexp, error) {
	if b == nil {
		return regexp.Compile(pattern)
	}
	if re, ok := b.regex[pattern]; ok {
		if re == nil {
			return nil, errBadPattern
		}
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		b.regex[pattern] = nil
		return nil, err
	}
	b.regex[pattern] = re
	return re, nil
}

// errBadPattern is a cached compile failure.
var errBadPattern = &ExprError{"InvalidRegex"}
