// Package all is the list of formats whosent understands. Adding a format
// is adding its adapter here, and nowhere else: the view and the command
// line render whatever the adapters describe.
package all

import (
	"github.com/kanywst/whosent/internal/formats/biscuit"
	"github.com/kanywst/whosent/internal/formats/jwt"
	"github.com/kanywst/whosent/internal/formats/mandatum"
	"github.com/kanywst/whosent/pkg/chain"
)

// Adapters returns every format, in the order --format lists them and the
// demo tour visits them.
func Adapters() []chain.Adapter {
	return []chain.Adapter{
		jwt.New(),
		biscuit.New(),
		mandatum.New(),
	}
}

// Registry returns a registry of every format.
func Registry() *chain.Registry {
	r, err := chain.NewRegistry(Adapters()...)
	if err != nil {
		// Two adapters claiming one ID is a build mistake, caught by this
		// package's own test.
		panic(err)
	}
	return r
}
