package all

import (
	"testing"

	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

// Every registered format passes the conformance suite, and the registry
// builds: no two formats share an ID, and no two demos share a name.
func TestEveryFormatConforms(t *testing.T) {
	r := Registry()
	names := map[string]string{}
	for _, sc := range r.Scenarios() {
		if other, ok := names[sc.Name]; ok {
			t.Errorf("demo %q is both %s's and %s's; `whosent demo NAME` could not tell them apart", sc.Name, other, sc.Format)
		}
		names[sc.Name] = sc.Format
	}
	for _, a := range Adapters() {
		t.Run(a.Format().ID, func(t *testing.T) { chaintest.Run(t, a) })
	}
}
