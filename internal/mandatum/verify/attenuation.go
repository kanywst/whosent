package verify

import (
	"fmt"
	"slices"

	"github.com/kanywst/whosent/internal/mandatum/mda"
)

// checkAttenuation implements the part of V5 that Attenuates covers. V5 is
// defined as "every rule in section 6 holds"; rules 4 and 6 are checked as
// V1 and V6 instead, because they are about position in a chain rather than
// about a pair of links.
//
// The rules are deliberately one-directional. There is no path in this file
// that lets a child hold authority its parent did not, which is what makes
// "the sponsor's grant bounds everything below it" a property rather than a
// convention.
func checkAttenuation(chain mda.Chain) error {
	for i := 1; i < len(chain); i++ {
		if err := Attenuates(chain[i-1].Claims, chain[i].Claims); err != nil {
			return ruleErr("V5", i, err.Error())
		}
	}
	return nil
}

// Attenuates reports whether child is no wider than parent, for the five
// rules of specification section 6 that compare a pair of links on their own:
// capability entailment, expiry, the depth budget, sequence constraints, and
// the audience.
//
// It does not cover rule 4, that depth increments by one, or rule 6, that the
// sponsor is byte-identical. Those are properties of a link's position in a
// chain rather than of the pair, and are checked as V1 and V6 during chain
// verification. An issuer calling this must therefore derive depth and the
// sponsor from the parent rather than accept them from a caller, which is
// what pkg/issue does.
//
// It is exported so that an issuer can apply the same rules before signing.
// Two implementations of these rules - one to issue, one to verify - would
// drift, and the direction they drift in is that the issuer becomes more
// permissive than the verifier, producing chains that fail at a resource
// server instead of at the desk of whoever wrote them.
//
// A nil return means every rule holds. The error names the rule that failed
// in terms a delegator can act on.
func Attenuates(parent, child mda.Claims) error {
	// Rule 7. The audience is fixed at the root: a chain is issued for one
	// resource server and is evidence at that one only. Without this, an
	// agent holding a chain for one server mints itself a leaf naming
	// another and presents it there. Every other rule passes - it delegates
	// only what it holds, to itself, with the same capabilities - and V9 at
	// the target compares the leaf's audience against itself, so it passes
	// too. That is the confused deputy this format exists to prevent,
	// assembled entirely out of valid links.
	if child.Audience != parent.Audience {
		return fmt.Errorf("names audience %q, and the parent names %q; a chain is issued for one resource server",
			child.Audience, parent.Audience)
	}

	if child.ExpiresAt > parent.ExpiresAt {
		return fmt.Errorf("outlives its parent (exp %d > %d)", child.ExpiresAt, parent.ExpiresAt)
	}

	if child.Mandatum.MaxDepth > parent.Mandatum.MaxDepth-1 {
		return fmt.Errorf("max_depth %d does not decrease from the parent's %d",
			child.Mandatum.MaxDepth, parent.Mandatum.MaxDepth)
	}

	if err := capsEntailed(parent.Mandatum.Capabilities, child.Mandatum.Capabilities); err != nil {
		return err
	}

	return seqNoWider(parent.Mandatum.Sequence, child.Mandatum.Sequence)
}

// capsEntailed reports whether every child capability is covered by some
// parent capability. A child capability matched by no parent capability is
// authority the parent never held.
func capsEntailed(parent, child []mda.Capability) error {
	for ci, c := range child {
		covered := false
		for _, p := range parent {
			if entails(p, c) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("cap[%d] (%s on %s/%s) is not covered by the parent's grant",
				ci, c.Action.Name, c.Resource.Type, c.Resource.ID)
		}
	}
	return nil
}

// entails reports whether parent capability p covers child capability c.
func entails(p, c mda.Capability) bool {
	if p.Resource.Type != c.Resource.Type {
		return false
	}
	if !idCovers(p.Resource.ID, c.Resource.ID) {
		return false
	}
	// Tags in a pattern are requirements. Requiring more tags matches fewer
	// resources, so the child must require at least everything the parent did.
	if !coversTags(p.Resource.Tags, c.Resource.Tags) {
		return false
	}
	if p.Action.Name != c.Action.Name {
		return false
	}
	// Every restriction the parent imposed must still be imposed, at least as
	// tightly. The child may add restrictions on keys the parent left free;
	// that narrows, so it is allowed.
	for key, pc := range p.Conditions {
		cc, ok := c.Conditions[key]
		if !ok {
			return false
		}
		if !condCovers(pc, cc) {
			return false
		}
	}
	return true
}

// idCovers reports whether pattern p covers pattern c. A trailing "*" makes a
// prefix pattern; anything else is a literal.
func idCovers(p, c string) bool {
	pPrefix, pIsPrefix := trimStar(p)
	cPrefix, cIsPrefix := trimStar(c)

	switch {
	case !pIsPrefix && !cIsPrefix:
		return p == c
	case pIsPrefix && !cIsPrefix:
		return hasPrefix(c, pPrefix)
	case pIsPrefix && cIsPrefix:
		// A longer prefix matches a subset of a shorter one.
		return hasPrefix(cPrefix, pPrefix)
	default:
		// A literal parent cannot cover a prefix child: the child would match
		// identifiers the parent never granted.
		return false
	}
}

func trimStar(s string) (string, bool) {
	if n := len(s); n > 0 && s[n-1] == '*' {
		return s[:n-1], true
	}
	return s, false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// coversTags reports whether child requires at least every tag parent required.
func coversTags(parent, child []string) bool {
	for _, want := range parent {
		if !slices.Contains(child, want) {
			return false
		}
	}
	return true
}

// condCovers reports whether child condition c is at least as restrictive as
// parent condition p.
//
// Comparison is only defined within the decidable fragment, and only between
// compatible kinds. Where restrictiveness cannot be decided, the answer is
// false: refusing a delegation the issuer believed was valid is recoverable,
// and accepting one that widens authority is not.
func condCovers(p, c mda.Condition) bool {
	// An empty `in` matches nothing, so it is the narrowest restriction
	// expressible and every parent in the fragment entails it. This is
	// checked before the per-kind comparisons below, which compare like with
	// like and would otherwise reject it under an `eq` or range parent - the
	// specification says a delegator can always grant nothing on a key, and
	// that has to hold whatever the parent restricted.
	if c.In != nil && len(c.In) == 0 {
		return p.InFragment()
	}

	switch {
	case p.Equals != nil:
		// Nothing is narrower than a fixed value except the same fixed value.
		return c.Equals != nil && *c.Equals == *p.Equals

	case p.In != nil:
		if c.Equals != nil {
			return inSet(p.In, *c.Equals)
		}
		if c.In != nil {
			for _, v := range c.In {
				if !inSet(p.In, v) {
					return false
				}
			}
			return true
		}
		return false

	case p.Prefix != nil:
		if c.Equals != nil {
			return hasPrefix(*c.Equals, *p.Prefix)
		}
		if c.Prefix != nil {
			return hasPrefix(*c.Prefix, *p.Prefix)
		}
		if c.In != nil {
			for _, v := range c.In {
				if !hasPrefix(v, *p.Prefix) {
					return false
				}
			}
			return true
		}
		return false

	case p.Min != nil || p.Max != nil:
		// A range child must be contained in the parent's range. An
		// unbounded child side is only acceptable where the parent is also
		// unbounded on that side.
		if c.Min == nil && c.Max == nil {
			return false
		}
		if p.Min != nil && (c.Min == nil || *c.Min < *p.Min) {
			return false
		}
		if p.Max != nil && (c.Max == nil || *c.Max > *p.Max) {
			return false
		}
		return true

	default:
		// A parent condition outside the fragment cannot be reasoned about.
		return false
	}
}

func inSet(set []string, v string) bool {
	return slices.Contains(set, v)
}

// seqNoWider reports whether the child's sequence constraints are at least as
// restrictive as the parent's.
//
// A parent that constrains a sequence binds every delegation below it; a child
// cannot drop the constraint by omitting the field, which is the obvious way
// someone would try.
func seqNoWider(parent, child *mda.Sequence) error {
	if parent == nil {
		return nil // The parent imposed no sequence limits; anything narrows.
	}
	if child == nil {
		return fmt.Errorf("drops the parent's sequence constraints entirely")
	}

	// MaxInvocations of 0 means unlimited, so a child may only be 0 if the
	// parent was. Anything non-positive is treated the same way: structural
	// validation refuses a negative budget before this runs, and this does
	// not rely on that, because "child > parent" is false for every negative
	// child and a comparison that reads -1 as narrower is an escape.
	switch {
	case parent.MaxInvocations <= 0:
		// Parent unlimited: any child budget narrows.
	case child.MaxInvocations <= 0:
		return fmt.Errorf("removes the parent's invocation budget of %d (child budget %d)",
			parent.MaxInvocations, child.MaxInvocations)
	case child.MaxInvocations > parent.MaxInvocations:
		return fmt.Errorf("raises the invocation budget from %d to %d",
			parent.MaxInvocations, child.MaxInvocations)
	}

	for _, pc := range parent.Constraints {
		found := false
		for _, cc := range child.Constraints {
			if cc.ID == pc.ID {
				found = true
				if !sameMatcher(cc.Forbid, pc.Forbid) || !sameMatcher(cc.After, pc.After) {
					return fmt.Errorf("redefines inherited sequence constraint %q", pc.ID)
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("drops inherited sequence constraint %q", pc.ID)
		}
	}
	return nil
}

func sameMatcher(a, b mda.ActionMatcher) bool {
	return a.Action == b.Action &&
		a.ResourceType == b.ResourceType &&
		sameStrings(a.ResourceTags, b.ResourceTags)
}
