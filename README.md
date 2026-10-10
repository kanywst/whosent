# whosent

[![Test](https://github.com/kanywst/whosent/actions/workflows/test.yml/badge.svg)](https://github.com/kanywst/whosent/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

Who sent this agent, and what is it still allowed to do? A TUI for [Mandatum](https://github.com/kanywst/mandatum) delegation chains. It shows the human a chain is rooted in, how authority narrows at every hop, and exactly where trust breaks.

![whosent demo](demo.gif)

AI agents mostly act on credentials they inherited: a service account, an API key, someone's session. A Mandatum chain replaces that with signed links from a named human down to the acting agent, where each hop can only narrow what it was given and any link can be revoked. whosent opens such a chain and shows, at a glance, whether it holds and what the agent at the end of it can actually do.

## Install

```bash
# Go 1.27+
go install github.com/kanywst/whosent/cmd/whosent@latest
```

```bash
# Homebrew (macOS), available from the first release
brew install kanywst/tap/whosent
```

Releases will also ship binaries for macOS, Linux and Windows, `.deb` and `.rpm` packages, checksums, cosign signatures and an SBOM.

## Usage

Start with the tour. It mints example chains with throwaway keys, one per failure mode, and opens them; `n` and `p` switch between them.

```bash
whosent demo              # every scenario
whosent demo multifault   # one of them
whosent demo --list
```

Then open a real chain. Give it the keys, the revocation set and the audience, or the rules that need them are reported as not checked:

```bash
whosent chain.json --trust trust.json --revocations revocation.json --audience https://mcp.example.org
cat call.json | whosent   # an MCP tools/call request carrying the chain
```

### Checking from a script

`check` prints the same diagnosis without the interactive view. To try it on a known chain, write a demo scenario out as files:

```bash
whosent demo --emit fixture widened
cd fixture
whosent check chain.json --trust trust.json --revocations revocation.json --audience https://mcp.example.org --at 2026-09-12T08:01:00Z
```

```text
=== chain.json · 3 links · sponsor alice@example.org via https://idp.example.org (pwd+hwk)
    at 2026-09-12T08:01:00Z · skew 30s · audience https://mcp.example.org

❌ INVALID: the chain breaks at link 2, and no authority reaches below it

  #  issuer → subject                   V1 V2 V3 V4 V5 V6 V7 V8 V9
  0  idp.example.org → planner           ✓  ·  ✓  ✓  ·  ·  ·  ✓  ·
  1  planner → retriever                 ✓  ✓  ✓  ✓  ✓  ✓  ·  ✓  ·
  2  retriever → fetcher                 ✓  ✓  ✓  ✓  ✗  ✓  ✓  ✓  ✓
     ✓ pass  ✗ fail  ! could not evaluate  ? not checked  - skipped  · does not apply

Findings
  ✗ V5 link 2: cap[1] (invoke on mcp_tool/docs.write) is not covered by the parent's grant [section 6]

How authority narrows
  0 → 1  planner → retriever
      ~ invoke mcp_tool:search.* narrowed to invoke mcp_tool:search.query
          id pinned from search.* to search.query
          args.index: new restriction, in [public, docs]
      ~ invoke mcp_tool:web.fetch narrowed
          args.host: prefix "docs." to in [docs.example.org, docs.example.com]
      - invoke mcp_tool:docs.write #mutating dropped
      ~ expires 20m sooner
      ~ max_depth 3 to 1
      ~ invocations 200 to 100
      + adds no-fetch-after-mutation
  1 → 2  retriever → fetcher
      - invoke mcp_tool:search.query dropped
      ~ invoke mcp_tool:web.fetch narrowed to invoke mcp_tool:web.fetch #external-content
          now requires tags external-content
          args.host: in [docs.example.org, docs.example.com] to eq "docs.example.org"
      ✗ invoke mcp_tool:docs.write #mutating is not covered by the parent's grant
          link 0 held this, and it was dropped before link 1: re-adding it here does not bring it back
          the link above grants no invoke on mcp_tool:docs.write at all
      ~ expires 20m sooner
      ~ max_depth 1 to 0: may act, may not delegate further
      ~ invocations 100 to 20
      = kept  ~ narrowed  - dropped  + added  ✗ widened (violation)
```

A verifier stops at the first failure. `check` evaluates every rule for every link, so a chain with three faults shows all three. `--json` prints the report as schema `whosent.report/v1` and nothing else on stdout.

| Verdict | Exit | Meaning |
| :--- | :--: | :--- |
| VALID | 0 | every rule was checked for every link, and holds |
| INVALID | 1 | a rule failed, or could not be evaluated, so an enforcement point denies |
| INCOMPLETE | 2 | nothing failed, but something was not checked (1 with `--strict`) |
| | 3 | the command line or an input file is wrong |
| | 70 | whosent's diagnosis and the embedded Mandatum reference verifier disagree about the chain; a bug in whosent, please report it |

### Asking about one request

`ask` runs a request through mandatum's own matcher at every link, so you see where authority for it ends:

```bash
whosent ask chain.json --trust trust.json --revocations revocation.json --audience https://mcp.example.org \
  --at 2026-09-12T08:01:00Z --resource-id web.fetch --tag external-content --attr args.host=evil.example.net
```

```text
=== chain.json
    invoke mcp_tool:web.fetch #external-content {args.host=evil.example.net}

❌ DENIED (AUTHORITATIVE): not covered by the chain's grant
    mandatum: "invoke" on mcp_tool/web.fetch is outside the chain's grant (cap[0]: condition on "args.host" is not met by evil.example.net)

  link by link
  0  planner        ✗  "invoke" on mcp_tool/web.fetch is outside the chain's grant (cap[0]: grants "search.*", not "web.fetch"; cap[1]: condition on "args.host" is not met by evil.example.net; cap[2]: grants "docs.write", not "web.fetch")
  1  retriever      ✗  "invoke" on mcp_tool/web.fetch is outside the chain's grant (cap[0]: grants "search.query", not "web.fetch"; cap[1]: condition on "args.host" is not met by evil.example.net)
  2  fetcher        ✗  "invoke" on mcp_tool/web.fetch is outside the chain's grant (cap[0]: condition on "args.host" is not met by evil.example.net)
```

The answer says how far it can be relied on: `AUTHORITATIVE` (the chain verified with every input), `CONDITIONAL` (nothing failed, but some rules were not checked) or `HYPOTHETICAL` (the chain does not verify, so it permits nothing; this is only what the leaf claims). Given a `tools/call` request, `ask` takes the tool name from it, and `--attr-from-args` maps its arguments to `args.<name>`.

### Input

The chain is read from a file, or from stdin with `-` or a pipe. The format is recognised by its shape:

- a JSON array of compact JWS strings, sponsor first (the wire form)
- an MCP `tools/call` request with the chain in `params._meta["io.github.kanywst.mandatum/chain"]`, read exactly as Mandatum v0.2.0's MCP middleware reads it
- one serialization per line

Keys come from a trust file or from `--jwks ISSUER=PATH` / `--jwks ISSUER=https://URL`:

```json
{"issuers": {
  "https://idp.example.org": {"jwks_file": "jwks/idp.json"},
  "spiffe://example.org/ns/agents/planner": {"jwks_url": "https://keys.example.org/planner.json"}
}}
```

`--at` evaluates at another time (RFC 3339, unix seconds, or `+25m` / `-1h`), and `--reverse` reads a chain that was handed over leaf first.

## What it checks

Rules V1 to V9 of the [Delegation Assertion specification](docs/mandatum-spec.md), for every link:

| Rule | Checks |
| :--: | :--- |
| V1 | the link parses, is well formed, commits to its parent's digest, and its depth follows the parent's |
| V2 | custody: each link is issued by the subject of the link above it |
| V3 | the issuer signed these exact bytes, with a key you supplied |
| V4 | not issued in the future and not expired, within the skew |
| V5 | attenuation: capabilities, expiry, depth, sequence constraints and audience only narrow |
| V6 | every link names the same human sponsor, authenticated the same way |
| V7 | the chain is no deeper than the sponsor allowed |
| V8 | no link is revoked; revoking one revokes everything below it |
| V9 | the leaf is addressed to this resource server |

Two rules hold everywhere in the tool:

- **Not checked is never green.** A rule that needs an input you did not give is shown as not checked, with its own glyph and colour. VALID means every rule was checked. `AUTHORITATIVE` means a VALID chain with no missing input.
- **It agrees with the reference verifier.** Every diagnosis also runs the Mandatum v0.2.0 reference verifier, embedded unchanged in `internal/mandatum`, on the same chain with the same answers. If the two disagree, or the verifier cannot run, the reference verdict wins, the screen says so, and the exit code is 70.

## Keybindings

| Key | Action |
| :---: | :--- |
| `←/h` `→/l` | select a link (an arrow on the rail) |
| `↑/k` `↓/j` | select a row of authority |
| `J` `K` `pgup` `pgdn` | scroll the link panel |
| `tab` | switch panel, when they do not fit side by side |
| `r` | the raw assertion: header, claims, digests |
| `space` | replay authority flowing down the chain |
| `t` | time mode: a timeline of every link, and `←` `→` move the clock |
| `[` `]` `shift+←` `shift+→` | move the clock in big steps |
| `0` | back to the time the chain was opened at |
| `x` | simulate revoking the selected link; again to undo |
| `X` | clear every simulated revocation |
| `a` | ask whether the chain would permit a request |
| `n` `p` | next or previous scenario, in the demo tour |
| `?` | help |
| `q` `esc` | quit, back |

Time mode and the revocation simulation re-run the whole diagnosis, so what you see at `+40m` is what `check --at +40m` would report. A simulated revocation is labelled as one everywhere, and never reaches `check` or `ask`.

`NO_COLOR` is respected; every state also has its own glyph. `--ascii` (or `WHOSENT_ASCII=1`) uses ASCII only, and `--no-motion` turns the animation off.

## Security

- Every string that comes from a chain, a key document or a library error is escaped before it reaches the terminal. Control characters, escape sequences and bidi overrides are shown as visible escapes, so a chain cannot clear the screen, print a fake verdict, write your clipboard over OSC 52, or disguise a name. `--json` output is escaped the same way.
- whosent touches the network only to fetch key documents from the https URLs you configure. Which keys belong to which issuer comes from your flags or trust file, never from the chain. Fetches must stay on https through any redirect, and are capped at 1 MiB and 5 seconds.
- Input is capped at 1 MiB and 64 links, the same body limit mandatum's enforcement point applies.

Report a vulnerability through a [private advisory](https://github.com/kanywst/whosent/security/advisories/new). See [SECURITY.md](SECURITY.md).

## Related

- [mandatum](https://github.com/kanywst/mandatum) is the specification and its reference Go library, now archived. whosent embeds the v0.2.0 verifier, attenuation rules and matcher in [`internal/mandatum`](internal/mandatum) rather than reimplementing them, and carries a copy of the [specification](docs/mandatum-spec.md).
- [y509](https://github.com/kanywst/y509) does the same job for X.509 certificate chains.

## Development

```bash
make build       # Build with version info
make test        # Run tests
make lint        # Run golangci-lint
make vulncheck   # Run govulncheck
make run         # Take the demo tour
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a patch.

## Verifying releases

Releases include Sigstore-signed checksums, a CycloneDX SBOM and SLSA build provenance.

```bash
gh attestation verify whosent-<version>-<os>-<arch>.tar.gz -R kanywst/whosent
```

```bash
TAG=v<version>
gh release download "$TAG" -R kanywst/whosent -p '*-checksums.txt*'

cosign verify-blob \
  --bundle "whosent-${TAG#v}-checksums.txt.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/kanywst/whosent/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "whosent-${TAG#v}-checksums.txt"

sha256sum -c "whosent-${TAG#v}-checksums.txt" --ignore-missing
```

## License

Apache License 2.0
