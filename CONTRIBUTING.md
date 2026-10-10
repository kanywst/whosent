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
- The `--json` schemas (`whosent.report/v1`, `whosent.ask/v1`) are a translation layer in `pkg/diagnose/json.go`, not json tags on the internal types. Changing a field there changes a contract.

## Reporting a bug

Attach the chain if you can. If you would rather not (a chain names people and may still be live), reproduce the shape with `whosent demo --emit DIR <scenario>` and say how yours differs.
