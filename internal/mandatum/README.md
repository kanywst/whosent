# internal/mandatum

These packages are the Mandatum reference implementation, copied from [kanywst/mandatum](https://github.com/kanywst/mandatum) at **v0.2.0** (commit `ebb3fb8`). That repository is archived, so this is the last version there will be.

| Package | What it is |
| --- | --- |
| `mda` | the Delegation Assertion types and strict parsing |
| `verify` | the chain verifier, rules V1 to V9, and `Attenuates` |
| `jose` | EdDSA JWS signing and verification, key rings, JWKS resolution |
| `revoke` | the compact revocation set and its checker |
| `issue` | building and signing chains (used by the demo and by tests) |

The specification these implement is [docs/mandatum-spec.md](../../docs/mandatum-spec.md), a copy of [the original](https://github.com/kanywst/mandatum/blob/v0.2.0/docs/spec/delegation-assertion.md).

## Rules for changing this code

`pkg/diagnose` checks every diagnosis against `verify.Verify` and calls any disagreement an internal inconsistency. That guarantee is only worth something because this verifier is the reference one. So:

- Do not change what the verifier accepts or refuses to make whosent's own output look better. A behaviour change here changes what "agrees with the reference verifier" means.
- Import paths were rewritten, em dashes in comments became hyphens, and three test-local names were renamed for the linter (`min`, an unused `t`, `false_`). Nothing else differs from v0.2.0. Keep it that way unless fixing a real bug, and say so in the commit when you do.
- Only the packages whosent uses came along. `authzen`, `mcp` and `sequence` stayed behind, and with them the CEL dependency. The part of `mcp` that decides which chain a `tools/call` request carries is copied as a test oracle in `pkg/diagnose/mcp_oracle_test.go`.

## License

Apache License 2.0, the same as whosent. Mandatum's NOTICE is carried in whosent's [NOTICE](../../NOTICE).
