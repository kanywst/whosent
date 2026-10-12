# Writing a format adapter

whosent shows delegation chains in any token format that has an adapter. An adapter reads its format, checks it by that format's own rules, and describes the result in the neutral model in [`pkg/chain`](../pkg/chain). The interactive view and the command line render only that model, so a new format needs no change to either.

This document is the contract. [`pkg/chain/chaintest`](../pkg/chain/chaintest) is the same contract as code; an adapter is done when it passes.

## Where it goes

- The adapter lives in `internal/formats/<id>`, where `<id>` is the name typed after `--format` (`jwt`, `biscuit`, `ucan`, `mandatum`, `macaroon`).
- It is added to `Adapters()` in [`internal/formats/all`](../internal/formats/all/all.go), and nowhere else. That list is the order `--format` names formats in and the order the demo tour visits them.
- Its test calls `chaintest.Run(t, New())`. `internal/formats/all` runs the suite over every registered format too.

## The interfaces

```go
type Adapter interface {
    Format() chain.Format
    Detect(data []byte) chain.Confidence
    Open(ctx context.Context, in chain.Inputs) (chain.Session, error)
    Scenarios() []chain.Scenario
}

type Session interface {
    Info() chain.Info
    Evaluate(ctx context.Context, opts chain.EvalOptions) (*chain.Chain, error)
}

// Optional: a session that can answer "would this chain permit X".
type Asker interface {
    AskFields() []chain.AskField // Required fields must be given; nothing is filled from a default
    AskPrefill(c *chain.Chain, row int) map[string]string
    Ask(ctx context.Context, c *chain.Chain, values map[string]string) (*chain.AskResult, error)
}
```

### Format

- `ID`, `Name`, `RootRole` ("sponsor", "issuer", "root key") and `Rules`.
- `Rules` are the format's checks, in the order the view lists them. IDs are short and stable (`B3`, `J3`); a title is a word or two (`signature`, `time`). Every link's `Checks` has exactly one entry per rule, in this order.
- `Caps` switches the view's features on. Switch off what the format cannot honestly support: `TimeScrub` only when links have lifetimes, `RevokeSim` only when links have identifiers a revocation names, `Ask` only when the session implements `Asker`, `PerHopSignatures` only when each link is signed by the one before it.

### Detect

- Must be cheap and must not verify anything. It only looks.
- `Certain` only when the input carries the format's own marker (a media type, a magic prefix). Never claim `Certain` for something another format could also claim `Certain` for: a plain JWT is `Plausible` at most, unless its `typ` says otherwise.
- `Plausible` when the input has the right shape. One `Certain` claim wins; otherwise exactly one `Plausible` claim wins; anything else is an error that asks for `--format`.

### Open

- Reads the chain from `Inputs.Data` and whatever inputs the format uses: `JWKS` and `TrustFile` for issuer keys, `RootKeys` for a root public key, `Revocations`, `RevokedIDs` and `MaxAge`, `Audience`, `Facts` and `Authorizer` for an authorizer, `At` and `Skew`.
- An error is a usage error (exit 3): a file that cannot be read, a malformed value. A chain that fails its rules is not an error.
- The command line has already checked what every format shares: `--at` parses, `--skew` is within 5m, `--audience` is not empty, `--jwks` has the `ISSUER=LOCATION` shape. An adapter may narrow these, never widen them.
- Inputs a format has no use for are listed in `Chain.Ignored` (`chain.IgnoredInputs`), which `check`, `--json` and the view all show.

### Evaluate

- Returns a new `*Chain` every call. The view rewrites the chain's strings in place before drawing them, so never return a cached one.
- `EvalOptions.At` is the evaluation time. `EvalOptions.SimRevoked` lists `Link.RevokeID` values whose revocation to simulate; a simulation is marked (`Link.RevokedSimulated`, `Check.Simulated`, `Finding.Simulated`, `Chain.Simulated`) and never leaks into what `check` reports.

## The model, and its honesty rules

These are the promises the view relies on and cannot check itself. `chaintest` checks each of them.

- **VALID means every rule was checked and holds.** Any `StatusFail` or `StatusError` makes the chain INVALID; any `StatusUnchecked` without a failure makes it INCOMPLETE, with `IncompleteReason` naming the missing input. If VALID covers less than it sounds (a Fly.io token whose request caveats were not tested), say so in `ValidScope`.
- **Unchecked never looks checked.** A link with an unchecked rule is `LinkIncomplete`, never `LinkOK`, or the rail draws it as verified.
- **Asserted is not unchecked.** When a link's place in the chain is only the issuer's say-so, such as a prior actor in a JWT's nested `act` (RFC 8693 section 4.1: informational), set `Link.Asserted`. The rules nothing could check for that link, whatever was supplied, are `StatusNotApplicable`: `StatusUnchecked` would claim an input could have checked them. The view draws an asserted link amber and dashed, labelled "asserted", never like a verified one.
- **Everything below a break is unreached.** `BreakAt` is the first link that fails (or is revoked); every link after it has `Unreached` set and `UnreachedBy` naming the link above. The view greys them and their matrix columns out.
- **A failure is located.** A broken link has a failing check; a finding about link i is in `Links[i].Findings`; a finding about the whole chain is in `ChainFindings` with `Link` -1. A consequence of another finding (every link below a revoked one) is `Derived`, and is not counted as a failure of its own.
- **Disagreement is loud.** If the adapter checks a chain with its own code and a reference implementation exists, run both. On disagreement set `Inconsistency` (a one-line `Banner` and the full `Detail`): the view puts the banner first, and every command exits 70.

## What the view draws from what

| View | Fields |
| --- | --- |
| Header and verdict | `Verdict`, `BreakAt`, `Root.Name`, each link's `To`, the failing rules' titles; `Headline` replaces the sentence if set |
| Line under the verdict | the scenario's summary, or `Summary` parts |
| Rail | `Root` (name, `RootRole`, up to two `Details`), each link's `From`, `To`, state, `Depth` pips, `ExpiresAt`, `Remaining` |
| Timeline (`t`) | `IssuedAt`, `ExpiresAt` |
| Matrix panel | `Matrix`: `Title` and `Scope`, `Rows` (label, `Origin` above 0 for authority that appeared later, one `Cell` per link, `Lineage`), `RootRows`, `Retained`, `Extra` summary rows, `UnknownLabel` (what the legend calls `CellUnknown`). An asserted link's reach reads `?`, never `0/n`. Nil: the findings take the panel |
| Findings panel | every finding, worst first, then `CheckedAgainst` |
| Link inspector | the state, the rule grid, the link's findings, the hop from the link above (`Hops`), then `Sections` |
| Raw view (`r`) | `Raw` sections |
| Ask (`a`) | `Asker` |
| `check` | `Describe`, `Context`, the rule grid, findings, each hop's `Summary` (or `Changes`), `Missing` |
| `check --json` | `JSON()` (`whosent.chain/v1`); `--native` prints `Native` |

Sections are lists of `Line`s: `LineKV` (key and wrapped value), `LineText` (a sentence at `Indent`), `LineChange` (a diff line with a `ChangeKind` mark), `LineJSON` (an indented document, keys coloured apart), `LineCode` (source such as Datalog, one line per line). `Tone` says what a line means, never what colour it is. `Digest` above 0 draws a value in a link's own colour, so values naming the same link match (Mandatum's parent commitments use it to make a spliced link stand out).

## Strings

- **Adapters never sanitise.** Every string may come from the token and is attacker-controlled. The view scrubs every string of a chain the moment it receives it, by reflection, and cleans again as it draws; the command line escapes every argument it prints. An adapter that escaped strings itself would make that choke point look optional.
- **Adapters write no glyphs into strings the view draws.** Arrows, ticks and dots belong to the view, which swaps them for ASCII under `--ascii`. Where a change needs an arrow, set `Change.Before` and the view draws `Before -> Text`. The command line's own fields (`Describe`, `Context`, `AskResult.Report`) are printed as they are.
- A field that must reach the adapter unchanged and is never drawn is tagged `whosent:"raw"` (`Link.RevokeID`, `AskResult.Values`).

## Demos

- Every format has at least one scenario, and its names start with the format ID (`biscuit-healthy`). Names are unique across formats.
- `Scenario.Open(base)` mints the chain at `base` with every input it needs, so a demo shows no unchecked rule it did not mean to. Keys are deterministic from fixed seeds, so a demo is the same bytes on every run.
- `Scenario.Emit`, when set, writes fixture files through [`internal/safewrite`](../internal/safewrite) and returns the `whosent check` command that checks them. Fixtures are never committed: a committed token expires on its own.

## Test checklist

- `chaintest.Run(t, New())` passes.
- Each scenario's verdict, break and failing rules are asserted, not only that it opens.
- Detection: the format's own inputs are claimed, other formats' demo inputs are not claimed `Certain`, and garbage is `NotMine`.
- If a reference implementation exists, a test injects a disagreement and checks `Inconsistency` is set.
- The view's sweeps (`internal/ui`) pick the new scenarios up through `internal/formats/all`: every line fits at every size, `--ascii` is pure ASCII, `NO_COLOR` has no colour, and a hostile chain cannot reach the terminal. They must pass without changes to the view.
