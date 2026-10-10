package diagnose

// The guard's library entry points, for diagnose_test, which cannot be an
// internal test: the demo fixtures it needs import this package.
var (
	NewVerifierHook   = &newVerifier
	RunVerifierHook   = &runVerifier
	RunAttenuatesHook = &runAttenuates
)
