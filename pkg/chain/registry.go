package chain

import (
	"errors"
	"fmt"
	"strings"
)

// Registry is the set of formats a program understands, in the order it
// lists them. It is a value rather than a package-level table, so a test can
// build one with exactly the adapters it means to exercise.
type Registry struct {
	adapters []Adapter
}

// NewRegistry returns a registry of the given adapters, in order. Two
// adapters with the same format ID are a programming error.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	seen := map[string]bool{}
	for _, a := range adapters {
		id := a.Format().ID
		if id == "" {
			return nil, errors.New("chain: an adapter has no format ID")
		}
		if seen[id] {
			return nil, fmt.Errorf("chain: format %q registered twice", id)
		}
		seen[id] = true
	}
	return &Registry{adapters: append([]Adapter(nil), adapters...)}, nil
}

// Adapters returns the registered adapters, in order.
func (r *Registry) Adapters() []Adapter { return append([]Adapter(nil), r.adapters...) }

// IDs returns the registered format IDs, in order.
func (r *Registry) IDs() []string {
	ids := make([]string, len(r.adapters))
	for i, a := range r.adapters {
		ids[i] = a.Format().ID
	}
	return ids
}

// Lookup returns the adapter for a format ID.
func (r *Registry) Lookup(id string) (Adapter, error) {
	for _, a := range r.adapters {
		if a.Format().ID == id {
			return a, nil
		}
	}
	return nil, fmt.Errorf("unknown format %q; known formats: %s", id, strings.Join(r.IDs(), ", "))
}

// Detect picks the adapter for an input. One Certain claim wins outright;
// otherwise exactly one Plausible claim wins. Anything else is an error
// that names the candidates, because guessing between two formats would
// check a chain by the wrong rules and report the result with confidence.
func (r *Registry) Detect(data []byte) (Adapter, error) {
	var certain, plausible []Adapter
	for _, a := range r.adapters {
		switch a.Detect(data) {
		case Certain:
			certain = append(certain, a)
		case Plausible:
			plausible = append(plausible, a)
		}
	}
	switch {
	case len(certain) == 1:
		return certain[0], nil
	case len(certain) > 1:
		return nil, fmt.Errorf("the input looks like more than one format (%s); pass --format", names(certain))
	case len(plausible) == 1:
		return plausible[0], nil
	case len(plausible) > 1:
		return nil, fmt.Errorf("the input could be %s; pass --format to say which", names(plausible))
	}
	return nil, fmt.Errorf("could not tell what this is: it is not a %s chain; pass --format if it is one of them", names(r.adapters))
}

// Scenarios returns every adapter's demos, adapter by adapter.
func (r *Registry) Scenarios() []Scenario {
	var out []Scenario
	for _, a := range r.adapters {
		out = append(out, a.Scenarios()...)
	}
	return out
}

// Scenario returns the demo called name.
func (r *Registry) Scenario(name string) (Scenario, error) {
	var all []string
	for _, s := range r.Scenarios() {
		if s.Name == name {
			return s, nil
		}
		all = append(all, s.Name)
	}
	return Scenario{}, fmt.Errorf("unknown scenario %q; choose one of: %s", name, strings.Join(all, ", "))
}

func names(as []Adapter) string {
	n := make([]string, len(as))
	for i, a := range as {
		n[i] = a.Format().Name
	}
	switch len(n) {
	case 0:
		return "known"
	case 1:
		return n[0]
	}
	return strings.Join(n[:len(n)-1], ", ") + " or " + n[len(n)-1]
}
