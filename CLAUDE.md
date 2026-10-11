# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

whosent reads delegation chains and shows who they are rooted in, where trust breaks and how authority narrows. It is a TUI (`whosent [FILE]`, `whosent demo`) and a CLI (`check`, `ask`) over a format-neutral model, `pkg/chain`. Each token format is an adapter that checks its own rules and describes the result in that model; the view and the CLI render only the model. Three formats exist: `jwt` (RFC 8693 `act` chains, ID-JAG, Txn-Token, Entra agent tokens, and bundles of exchanged tokens), `biscuit` (own protobuf decoding, signature verification and Datalog engine), and `mandatum` (engine `pkg/diagnose`, built on the Mandatum v0.2.0 reference verifier embedded in `internal/mandatum`; the upstream repo is archived).

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
make fuzz           # every fuzzer (diagnose, termsafe, jwt, biscuit, datalog, trust, mandatum) for FUZZTIME each
make completions    # after changing a flag or a subcommand
```

Single test:

```bash
go test ./pkg/diagnose -run TestEveryScenarioIsDiagnosedAsItPromises -v
go test ./internal/ui -run TestEveryLineFitsTheTerminal -v
```

Look at the TUI without a terminal: `WHOSENT_DUMP=DIR go test ./internal/ui -run TestDump -v` writes rendered frames into DIR. To see what a user sees, record with `vhs` and read the PNGs; text dumps miss colour and spacing problems.

## Layout

- `pkg/chain`: the neutral model (`Chain`, `Link`, `Hop`, `Matrix`, sections), the `Adapter` / `Session` / `Asker` interfaces, the format `Registry` and its detection, and the `whosent.chain/v1` JSON. `pkg/chain/chaintest` is the conformance suite every adapter passes.
- `internal/formats/<id>`: one adapter per format. `jwt` (go-jose v4 for signatures; rules J1 to J10, see `docs/jwt.md`), `biscuit` (generated `pb/` from the spec's `schema.proto`, `datalog/` ported from biscuit-rust, `testdata/samples` vendored from eclipse-biscuit/biscuit at b3d3fe2), `mandatum` (wraps `pkg/diagnose`). `internal/formats/all` lists them, and is the only place a format is added. `internal/formats/fake` is a test-only adapter with shapes no real format has produced yet (asserted links, no matrix, no time); the view's tests render it. How to write one: [docs/adapters.md](docs/adapters.md).
- `pkg/diagnose`: the Mandatum engine. `Diagnose(ctx, links, opts)` evaluates V1 to V9 for every link without stopping, builds the per-hop attenuation diff (`hop.go`), the authority matrix (`matrix.go`), the permission trace (`trace.go`), the JSON schemas (`json.go`), input detection (`input.go`), and the consistency guard (`guard.go`).
- `internal/cmd`: cobra. `print.go` is the only path to the terminal.
- `internal/ui`: Bubble Tea v2 (`charm.land/...`; anything under `github.com/charmbracelet/bubbletea` is stale). Renders `pkg/chain` only. `scrub.go` rewrites every string of a chain or an answer the moment an adapter hands it over; `text.go` holds `clean`, which every renderer also applies.
- `internal/trust`: trust file and `--jwks` loader, mirroring `internal/mandatum/jose/jwks.go`.
- `internal/mandatum`: the Mandatum v0.2.0 reference packages (`mda`, `verify`, `jose`, `revoke`, `issue`), copied from the archived kanywst/mandatum. Do not change what they accept or refuse; see `internal/mandatum/README.md`.
- `internal/demo`: mints every scenario with deterministic keys; `Emit` writes fixtures.
- `internal/termsafe`: escapes untrusted text for terminals and JSON.

## Invariants (do not break these)

- **Agreement with the reference verifier (Mandatum).** The guard runs `verify.Verify` with the same memoized signature and revocation answers the diagnosis used, and compares the first failure `(Rule, Link)`. On disagreement, or if the library cannot run, mandatum's verdict wins, `Library.Consistent` is false, and the CLI exits 70. Tests inject disagreements to prove the guard is live (`guard_hook_test.go`); keep them. Call mandatum's exported functions (`verify.Attenuates`, `Result.Permits`, `mda.Digest`, `mda.ParseClaims`) instead of reimplementing them; where something must be copied (V1 structure, V4 time, V6 root, V9), copy the expression exactly.
- **Parity at the edges.** `internal/trust` must accept and refuse exactly the key documents `jose.NewJWKS` does, and `pkg/diagnose/input.go` must read a tools/call body exactly as mandatum v0.2.0's `pkg/mcp/http.go` did (its parsing path is copied as the oracle in `pkg/diagnose/mcp_oracle_test.go`). Both have tests that run the reference code on the same input. Fix the code, not the test.
- **Not checked is never pass.** Missing keys, revocation set or audience make a rule UNCHECKED. VALID needs every rule checked; AUTHORITATIVE needs VALID with no stubbed input. UNCHECKED, ERROR and SKIPPED never render green and never use the pass glyph. No state is signalled by colour alone (NO_COLOR, `--ascii`).
- **Untrusted text is escaped at the boundary, never by adapters.** Every string from a chain, a key document, a library error or user input goes through `termsafe.Text` (`print.go` in cmd; `scrub` on ingest and `clean` on render in ui) or `termsafe.JSON`. `scrub` walks the model by reflection, so a new field is covered without anyone remembering; a field it must not touch is tagged `whosent:"raw"` (an opaque handle passed back to the adapter, never drawn) or `whosent:"lines"` (multi-line, scrubbed per line). `hostile_test.go` in both packages feeds escape sequences, OSC 52, CR/LF and bidi through every field and view, including an adapter whose every string is hostile; extend it when you add a field.
- **Biscuit agrees with the sample corpus.** All 38 official sample tokens must print block by block exactly as the reference printed them and reach the same authorizer result, failed checks and world. Never edit the vendored samples to make a test pass; a feature the corpus does not cover is reported unchecked rather than guessed.
- **JWT prior actors are asserted.** Per RFC 8693 section 4.1 only the current actor is authoritative; earlier actors are `Asserted`, never drawn as verified. Bundle rules J7 to J10 are whosent's own; keep saying so in their spec strings and docs. Keys come only from configured issuers: never `jku`, `x5u`, `x5c` or `jwk` headers.
- **Adapters pass `chaintest`.** It encodes what the view cannot check for itself: VALID only with every rule checked and holding, an OK link has no unchecked rule (or it would be drawn as verified), an asserted link's unverifiable rules are not-applicable rather than unchecked, everything below a break is unreached, the matrix has a cell per link, and the format's demos open, scrub and simulate. A failing suite is a bug in the adapter.
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
- Demo scenario names are unique across formats; a new format's scenarios start with its ID (`biscuit-...`).
