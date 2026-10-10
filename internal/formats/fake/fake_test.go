package fake

import (
	"testing"

	"github.com/kanywst/whosent/pkg/chain/chaintest"
)

// The test adapter keeps the promises a real one does; otherwise the view's
// tests would be exercising shapes no adapter is allowed to produce.
func TestTheFakeFormatConforms(t *testing.T) { chaintest.Run(t, New()) }
