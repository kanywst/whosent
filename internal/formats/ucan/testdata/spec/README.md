# UCAN specification fixtures

These are the 1.0.0 fixtures of the UCAN specification, copied from [ucan-wg/spec](https://github.com/ucan-wg/spec) at commit `a73ee55ec82a90004227034873095e080d0df619` (`fixtures/1.0.0`). They are licensed as that repository says; see [LICENSE.md](LICENSE.md).

`invocation.json` holds invocations with their proofs, the time to check them at, and the error each invalid one must raise. `delegation.json` holds a delegation with its CID and decoded payload. `policy.json` holds arguments and policies that must, or must not, match. The tests in the parent package check whosent against all three.

`delegation.json` and `invocation.json` are unchanged. `policy.json` is changed in one place: upstream wraps the `christmas` entry of a `newsletters` map in an extra pair of braces, which is not JSON, and the copy here drops that pair.
