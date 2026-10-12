# Contributing

Bug reports and patches are welcome. For a suspected vulnerability, use the [security policy](SECURITY.md), not a public issue.

## Getting set up

Go 1.27+ is the only prerequisite. `golangci-lint` and `govulncheck` are pinned as `tool` directives in `go.mod`, so there is nothing separate to install.

```bash
git clone https://github.com/kanywst/whosent
cd whosent
make run    # builds and takes the demo tour
```

## Before you open a pull request

```bash
make lint       # must report 0 issues
make test       # must pass
make vulncheck  # must be clean
```

CI runs the same three, plus the race detector on Linux, macOS and Windows. `make test-coverage` gates at 85%; a patch that drops below it will fail.

## What gets merged

- One commit per logical change. A refactor and a behaviour change belong in separate commits.
- Commit messages in English, conventional-commits style. The subject says what changed, the body says why.
- New behaviour needs a test. Chains are minted at run time with throwaway keys, never checked in, because a committed assertion expires on its own. `internal/demo` builds every scenario the tour shows and is the quickest way to a chain of the shape you need.

## Things worth knowing about the codebase

- `pkg/diagnose` evaluates every rule with the reference verifier's own comparisons (`internal/mandatum`, Mandatum v0.2.0). Where it exports a function (`verify.Attenuates`, `Result.Permits`, `mda.Digest`), it is called rather than reimplemented. Where it does not, the expression is copied exactly and the guard checks the result.
- The guard (`pkg/diagnose/guard.go`) runs `verify.Verify` on every diagnosis and fails closed. A change that makes it pass more often needs a very good reason.
- Not checked is never pass. `StatusUnchecked`, `StatusError` and `StatusSkipped` each have their own glyph and colour, and none of them looks like a pass.
- Every string from a chain, a key document or a library error goes through `internal/termsafe` before it is printed or rendered. In `internal/cmd` that is `print.go`; in `internal/ui` it is `clean` in `text.go`. Do not print around them.
- `View()` is pure, and every rendered line must fit the terminal. The size sweep in `internal/ui` renders every scenario and view at many sizes; keep it passing rather than narrowing it.
- The `--json` schemas are translation layers, not json tags on the internal types: `whosent.chain/v1` in `pkg/chain/json.go` (every format), and Mandatum's own `whosent.report/v1` and `whosent.ask/v1` in `pkg/diagnose/json.go` (`--native`, and `ask --json`). Changing a field there changes a contract.
- A new token format is an adapter under `internal/formats/<id>`, added to `internal/formats/all` and nowhere else. [docs/adapters.md](docs/adapters.md) is the contract; `pkg/chain/chaintest` is the suite it must pass.
- Each format has its own reference to agree with. Mandatum: the embedded v0.2.0 verifier, checked on every run by the guard. Biscuit: the specification's 38 sample tokens in `internal/formats/biscuit/testdata/samples`, which every printer and authorizer change must keep matching. JWT: RFC 8693 and the drafts in [docs/jwt.md](docs/jwt.md); rules J7 to J10 are whosent's own and are labelled so. Macaroon: go-macaroon and superfly/macaroon, compared on every run, and libmacaroons' verifier tests in `internal/formats/macaroon/testdata/libmacaroons`.

## Reporting a bug

Attach the chain if you can. If you would rather not (a chain names people and may still be live), reproduce the shape with `whosent demo --emit DIR <scenario>` and say how yours differs.
