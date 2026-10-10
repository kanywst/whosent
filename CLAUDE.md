# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

whosent reads Mandatum delegation chains (signed JWS links from a human sponsor down to an acting agent) and shows where trust breaks and how authority narrows. It is a TUI (`whosent [FILE]`, `whosent demo`) and a CLI (`check`, `ask`) over one engine, `pkg/diagnose`. The specification and the verifier live in [mandatum](https://github.com/kanywst/mandatum), which this module imports and is pinned to (`v0.2.0`). Pre-1.0, any mandatum minor release may change its API or its verdicts.

## Commands

Requires Go 1.27+ (see `go.mod`). `golangci-lint` and `govulncheck` are `tool` directives, so `make lint` / `make vulncheck` need no separate install.

```bash
make build          # ./whosent with version info via -ldflags
make run            # the demo tour
make test           # go test -v ./...
make test-race      # GOTEST_ARGS=-short trims the guard property matrix
make test-coverage  # gated at 85%, fails closed
make lint
make vulncheck
make fuzz           # FuzzGuard, FuzzText, FuzzJSON for FUZZTIME each
make completions    # after changing a flag or a subcommand
```

Single test:

```bash
go test ./pkg/diagnose -run TestEveryScenarioIsDiagnosedAsItPromises -v
go test ./internal/ui -run TestEveryLineFitsTheTerminal -v
```

Look at the TUI without a terminal: `WHOSENT_DUMP=DIR go test ./internal/ui -run TestDump -v` writes rendered frames into DIR. To see what a user sees, record with `vhs` and read the PNGs; text dumps miss colour and spacing problems.

## Layout

- `pkg/diagnose`: the engine. `Diagnose(ctx, links, opts)` evaluates V1 to V9 for every link without stopping, builds the per-hop attenuation diff (`hop.go`), the authority matrix (`matrix.go`), the permission trace (`trace.go`), the JSON schemas (`json.go`), input detection (`input.go`), and the consistency guard (`guard.go`).
- `internal/cmd`: cobra. `print.go` is the only path to the terminal.
- `internal/ui`: Bubble Tea v2 (`charm.land/...`; anything under `github.com/charmbracelet/bubbletea` is stale). `text.go` holds `clean`, the only path for chain text into a view.
- `internal/trust`: trust file and `--jwks` loader, mirroring mandatum's `pkg/jose/jwks.go`.
- `internal/demo`: mints every scenario with deterministic keys; `Emit` writes fixtures.
- `internal/termsafe`: escapes untrusted text for terminals and JSON.

## Invariants (do not break these)

- **Agreement with mandatum.** The guard runs `verify.Verify` with the same memoized signature and revocation answers the diagnosis used, and compares the first failure `(Rule, Link)`. On disagreement, or if the library cannot run, mandatum's verdict wins, `Library.Consistent` is false, and the CLI exits 70. Tests inject disagreements to prove the guard is live (`guard_hook_test.go`); keep them. Call mandatum's exported functions (`verify.Attenuates`, `Result.Permits`, `mda.Digest`, `mda.ParseClaims`) instead of reimplementing them; where something must be copied (V1 structure, V4 time, V6 root, V9), copy the expression exactly.
- **Parity at the edges.** `internal/trust` must accept and refuse exactly the key documents `jose.NewJWKS` does, and `pkg/diagnose/input.go` must read a tools/call body exactly as `pkg/mcp/http.go` does. Both have tests that run mandatum's own code on the same input. Fix the code, not the test.
- **Not checked is never pass.** Missing keys, revocation set or audience make a rule UNCHECKED. VALID needs every rule checked; AUTHORITATIVE needs VALID with no stubbed input. UNCHECKED, ERROR and SKIPPED never render green and never use the pass glyph. No state is signalled by colour alone (NO_COLOR, `--ascii`).
- **Untrusted text is escaped at the boundary.** Every string from a chain, a key document, a library error or user input goes through `termsafe.Text` (`print.go` in cmd, `clean` in ui) or `termsafe.JSON`. `hostile_test.go` in both packages feeds escape sequences, OSC 52, CR/LF and bidi through every field and view; extend it when you add a field.
- **The chain never drives the network.** Issuer to key mapping comes from flags and the trust file only. Fetches are https-only including redirects, 1 MiB, 5s.
- **Width.** `View()` is pure and every line fits the terminal at every size in the sweep. Sizing lives in one place.
- **Motion is optional.** Animation is a `tea.Tick` frame counter, deterministic per frame, off with `--no-motion`, when not a TTY, and in tests. The idle screen does not redraw.
- **Fixtures are never committed.** Chains are minted per run; a committed assertion expires on its own.
- **Bytes inside a JWS are never altered.** Parent commitments are digests over the exact bytes.

## Style

- Comments explain why, naming what a naive version would get wrong. Errors are lowercase and say what to do.
- No em dashes anywhere: code, comments, docs, commit messages. Use a colon, parentheses or a plain hyphen.
- Commits: English, conventional commits with a scope (`feat(ui): ...`, `fix(diagnose): ...`), one logical change each.
- A flag, key, exit code or JSON field change also updates README.md, `man/man1/whosent.1`, and `make completions`.
