# whosent

[![Test](https://github.com/kanywst/whosent/actions/workflows/test.yml/badge.svg)](https://github.com/kanywst/whosent/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

Who sent this agent? A terminal viewer for delegation chains: OAuth token exchange (RFC 8693 `act`, ID-JAG, Txn-Token, Entra agent tokens), [Biscuit](https://www.biscuitsec.org), and Mandatum. It shows the human at the root, how authority narrows hop by hop, and exactly where trust breaks.

![whosent demo](demo.gif)

An agent acting for a person rarely holds a credential of its own. It holds a token someone exchanged for it, often several hops away from the human who started the work. whosent opens that token, or the series of tokens, and answers three questions at a glance: who is this rooted in, what can the agent at the end still do, and if the chain does not hold, at which hop it stops holding.

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

## Quick start

Start with the tour. It mints example chains in every format with throwaway keys, one per failure mode, and opens them; `n` and `p` switch between them.

```bash
whosent demo                       # every scenario
whosent demo jwt-bundle-widened    # one of them
whosent demo --list
```

Then open your own:

```bash
whosent token.jwt --jwks https://idp.example.com=jwks.json --audience https://api.example.com
pbpaste | whosent --jwks https://idp.example.com=jwks.json    # a pasted token, "Bearer " prefix and all
whosent token.b64 --root-key root.pub --fact 'operation("read")' --fact 'resource("orders")'
```

Without keys the chain still opens. The rules that need them are shown as not checked, never as passing.

## Formats

The format is recognised from the input. `--format jwt|biscuit|mandatum` says it when the input could be more than one.

### JWT token exchange

A single JWT names its subject and, in nested `act` claims, who acted for it. whosent draws the subject as the root and the actors oldest first, with the current actor (the outermost `act`) last. It understands the profiles built on RFC 8693: ID-JAG (`typ: oauth-id-jag+jwt`, the grant behind MCP's enterprise-managed authorization), Txn-Tokens (`typ: txntoken+jwt`), and Microsoft Entra agent tokens, which have no `act` but name the acting application and its agent facets.

What one token can prove is limited, and whosent says so. RFC 8693 section 4.1 makes only the token's own claims and the current actor authoritative; prior actors are the issuer's word, with no signature of theirs in the token. They are drawn as **asserted**, in amber and never ticked, and a VALID single token says in its headline that the prior actors are not a verified chain.

Given the tokens of successive exchanges instead (a JSON array of compact JWS strings, or one per line, oldest first), each token is checked on its own and each exchange against the token it replaced. That turns a list of actors into a chain that breaks at a specific hop. **Rules J7 to J10 are whosent's own consistency checks, derived from RFC 8693 and the drafts built on it; no specification defines them as a verification procedure.** See [docs/jwt.md](docs/jwt.md).

| Rule | Checks |
| :--: | :--- |
| J1 | a compact JWS with a JSON header and claims, signed with RS, PS, ES or EdDSA. `alg: none`, HMAC and unknown critical headers are refused |
| J2 | the signature verifies against the keys you configured for the issuer the token names |
| J3 | `iat`, `nbf` and `exp` within the skew. The last token must hold now; an earlier one, when the next was issued |
| J4 | the last token is addressed to `--audience` |
| J5 | the current actor is an object with a `sub`; a missing `iss` is a warning, a missing `sub_profile` a note |
| J6 | an exchanged token's actor is the party the previous token's `may_act` names |
| J7 | an exchanged token's `act` chain is the previous one plus exactly one new actor |
| J8 | an exchanged token's scope is a subset of the previous token's |
| J9 | the subject does not change across an exchange |
| J10 | an exchanged token expires no later than the token it replaced |

### Biscuit

A Biscuit token is a chain of signed blocks: the authority block, signed by the root key, then attenuation blocks, each signed with the key the block before it named. A block cannot add rights; it can only add checks. whosent draws one link per block, named by the block's `context` string, and shows authority narrowing as the checks pile up.

Signatures (v0 and v1 payloads, Ed25519 and P-256, third-party blocks, open and sealed tokens) are verified by whosent's own code, and the checks are evaluated by its own Datalog engine, ported from the Rust reference. Agreement with the reference rests on the official sample corpus: for all 38 sample tokens, every block prints byte for byte as the reference prints it, and every authorizer reaches the same policy, the same failed checks in the same order and the same facts. Where the corpus does not reach (exotic regular expressions, Datalog that runs longer than the reference's default time limit), the two could differ.

| Rule | Checks |
| :--: | :--- |
| B1 | the token and every block decode, and each next key is valid |
| B2 | the block's Datalog version is 3.0 to 3.3, and it uses only what that version allows |
| B3 | each block's signature verifies; the authority block needs `--root-key`, the later blocks are verified against each other without it |
| B4 | a third-party block's external signature verifies (v1; the legacy v0 form is refused, as the reference does by default) |
| B5 | the proof: an open token's secret matches the last next key, or a sealed token's seal verifies |
| B6 | the block's symbols and keys do not overlap earlier ones and every reference resolves |
| B7 | the authorizer's facts and policies satisfy the token's checks. Without `--fact` or `--authorizer`, only expiry checks are evaluated, against the evaluation time |
| B8 | no block's revocation id is on the `--revoked-jtis` list |

Get a token to inspect with the [biscuit CLI](https://github.com/eclipse-biscuit/biscuit-cli):

```bash
biscuit keypair --only-private-key > root.key
biscuit keypair --from-file root.key --only-public-key > root.pub
echo 'right("orders", "read");' | biscuit generate --private-key-file root.key - > token.b64
biscuit attenuate token.b64 --block 'check if operation("read");' > attenuated.b64
whosent attenuated.b64 --root-key root.pub
```

### Mandatum

[Mandatum](https://github.com/kanywst/mandatum) chains are signed links from a named human down to the acting agent, where each link commits to its parent by digest, may only narrow what it was given, and can be revoked on its own. It is the format with the most to check per hop, rules V1 to V9 of the [specification](docs/mandatum-spec.md).

Every diagnosis also runs the Mandatum v0.2.0 reference verifier, embedded unchanged in [`internal/mandatum`](internal/mandatum), on the same chain with the same answers. If the two disagree, or the verifier cannot run, the reference verdict wins, the screen says so, and the exit code is 70.

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

A Mandatum chain is read as a JSON array of compact JWS strings, as an MCP `tools/call` request carrying it in `params._meta["io.github.kanywst.mandatum/chain"]`, or one serialization per line.

## Checking from a script

`check` prints the same diagnosis without the interactive view. A verifier stops at the first failure; `check` evaluates every rule for every link, so a chain with three faults shows all three. To try it on a known chain, write a demo scenario out as files. `--emit` prints the command that checks them.

A bundle of three exchanged JWTs, where the last exchange gained a scope:

```bash
whosent demo --emit fixture jwt-bundle-widened
cd fixture
whosent check tokens.json --trust trust.json --audience https://api.acme.example --at 2026-09-12T08:01:00Z
```

```text
=== tokens.json · 3 links · JWT · issuer https://acme.okta.example, access token (RFC 9068)
    at 2026-09-12T08:01:00Z, skew 30s, audience https://api.acme.example

❌ INVALID: the chain breaks at link 2, and no authority reaches below it

  #  issuer → subject                   J1 J2 J3 J4 J5 J6 J7 J8 J9 J10
  0  alice@acme.example → chat-ui        ✓  ✓  ✓  ·  ✓  ·  ·  ·  ·   ·
  1  chat-ui → planner-agent             ✓  ✓  ✓  ·  ✓  ✓  ✓  ✓  ✓   ✓
  2  planner-agent → research-agent      ✓  ✓  ✓  ✓  ✓  ✓  ✓  ✗  ✓   ✓
     ✓ pass  ✗ fail  ! could not evaluate  ? not checked  - skipped  · does not apply

Findings
  ✗ J8 link 2: adds files:write, which token 1 did not hold [whosent bundle rule, derived from RFC 8693; not a procedure any specification defines (section 4.2, scope)]

How authority narrows
  0 → 1  chat-ui → planner-agent
      + exchanged: planner-agent now acts for alice@acme.example
      = scope files:read
      - scope files:write dropped
      = scope calendar:read
      ~ expires 20m sooner
  1 → 2  planner-agent → research-agent
      + exchanged: research-agent now acts for alice@acme.example
      = scope files:read
      - scope calendar:read dropped
      ✗ scope files:write was not in the token exchanged
      ~ expires 20m sooner
      i https://acme.okta.example → https://api.acme.example
          audience
      = kept  ~ narrowed  - dropped  + added  ✗ widened (violation)
```

A Biscuit token whose second block only allows reads, asked to authorize a write:

```bash
whosent demo --emit fixture biscuit-denied
cd fixture
whosent check token.b64 --root-key root.pub --authorizer authorizer.datalog --revoked-jtis revoked-ids.txt --at 2026-09-12T08:01:00Z
```

```text
=== token.b64 · 3 links · Biscuit · 3 blocks, open, root key ed25519/705fbac01f55...
    at 2026-09-12T08:01:00Z, authorizer authorizer.datalog

❌ INVALID: the chain breaks at link 1, and no authority reaches below it

  #  issuer → subject                   B1 B2 B3 B4 B5 B6 B7 B8
  0  root key → billing service          ✓  ✓  ✓  ·  ·  ✓  ✓  ✓
  1  billing service → payments team     ✓  ✓  ✓  ·  ·  ✓  ✗  ✓
  2  payments team → reporting bot       ✓  ✓  ✓  ·  ✓  ✓  ✓  ✓   (no authority reaches here)
     ✓ pass  ✗ fail  ! could not evaluate  ? not checked  - skipped  · does not apply

Findings
  ✗ B7 link 1: block 1's check fails: check if operation("read") [https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md#authorizer]

How authority narrows
  0 → 1  billing service → payments team
      ~ check if operation("read")
      ~ check if time($t), $t <= 2026-09-12T08:40:00Z
  1 → 2  payments team → reporting bot
      ~ check if resource($r), {"orders", "invoices"}.contains($r)
      ~ check if time($t), $t <= 2026-09-12T08:20:00Z
      = kept  ~ narrowed  - dropped  + added  ✗ widened (violation)
```

`--json` prints the report as schema `whosent.chain/v1`, the same shape for every format (`format`, `verdict`, `break_at`, `root`, `rules`, `links`, `hops`, `findings`, `checked_against`), and nothing else on stdout. `--json --native` prints the format's own report instead; Mandatum's is `whosent.report/v1`.

| Verdict | Exit | Meaning |
| :--- | :--: | :--- |
| VALID | 0 | every rule was checked for every link, and holds |
| INVALID | 1 | a rule failed, or could not be evaluated, so an enforcement point denies |
| INCOMPLETE | 2 | nothing failed, but something was not checked (1 with `--strict`) |
| | 3 | the command line or an input file is wrong |
| | 70 | whosent disagrees with a format's reference implementation (Mandatum's embedded verifier); a bug in whosent, please report it |

### Asking about one request

In the interactive view, `a` asks whether the chain would permit a request, in that format's terms: a scope and an audience for a JWT, facts and a policy for Biscuit, an action on a resource for Mandatum. The answer is traced link by link, so you see where authority for it ends or where it appeared from nowhere, and it says how far it can be relied on: `AUTHORITATIVE` (the chain verified with every input), `CONDITIONAL` (nothing failed, but some rules were not checked) or `HYPOTHETICAL` (the chain does not verify, so it permits nothing; this is only what the leaf claims).

From a script, `whosent ask` asks the same question and exits 0 only when a VALID chain permits it. Each format takes its own question, a flag it has no use for is refused, and nothing a question needs is filled in from a default:

| Format | Question |
| --- | --- |
| JWT | `--scope files:read`, used at `--audience` |
| Biscuit | the authorizer (`--authorizer`, `--fact`) runs over the token for a request: `--resource-id` and `--action` become `resource(...)` and `operation(...)` facts; it decides with the authorizer's own policies unless `--policy` gives others, which makes the answer at most `CONDITIONAL` |
| Mandatum | `--resource-id`, `--action`, `--resource-type`, `--tag`, `--attr`, or a `tools/call` request with `--attr-from-args` |

`--field KEY=VALUE` sets any of a format's question fields by name.

## Inputs

| Flag | For | What it supplies |
| :--- | :--- | :--- |
| `--jwks ISSUER=PATH` or `ISSUER=https://URL` | JWT, Mandatum | an issuer's key document; repeatable |
| `--trust FILE` | JWT, Mandatum | a file mapping issuers to key documents (below) |
| `--root-key KEY` | Biscuit | a root public key, as hex (`ed25519/...`, `secp256r1/...`) or a file; repeatable |
| `--audience AUD` | JWT, Mandatum | the party the chain is presented to |
| `--fact FACT`, `--authorizer FILE` | Biscuit | the authorizer's facts and policies the token's checks run against |
| `--revocations FILE` | Mandatum | a published revocation set |
| `--revoked-jtis FILE` | Biscuit, Mandatum | for Biscuit, revoked block revocation ids, one per line; for Mandatum, the exact jti list that resolves a hit in the revocation set's filter |
| `--at TIME` | all | evaluate at another time: RFC 3339, unix seconds, or `+25m` / `-1h` |
| `--skew DURATION` | all | clock skew tolerance, at most 5m (default 30s) |
| `--reverse` | Mandatum | the chain was handed over leaf first |

Flags a format does not use have no effect. The Biscuit format lists them under "checked against" in the view and in `--json`.

```json
{"issuers": {
  "https://idp.example.com": {"jwks_file": "jwks/idp.json"},
  "https://login.example.org": {"jwks_url": "https://login.example.org/.well-known/jwks.json"}
}}
```

## Keybindings

| Key | Action |
| :---: | :--- |
| `←/h` `→/l` | select a link (an arrow on the rail) |
| `↑/k` `↓/j` | select a row of authority |
| `J` `K` `pgup` `pgdn` | scroll the link panel |
| `tab` | switch panel, when they do not fit side by side |
| `r` | the raw link: header, claims or Datalog, digests |
| `space` | replay authority flowing down the chain |
| `t` | time mode: a timeline of every link, and `←` `→` move the clock |
| `[` `]` `shift+←` `shift+→` | move the clock in big steps |
| `0` | back to the time the chain was opened at |
| `x` | simulate revoking the selected link; again to undo (Biscuit and Mandatum) |
| `X` | clear every simulated revocation |
| `a` | ask whether the chain would permit a request |
| `n` `p` | next or previous scenario, in the demo tour |
| `?` | help |
| `q` `esc` | quit, back |

Time mode and the revocation simulation re-run the whole diagnosis, so what you see at `+40m` is what `check --at +40m` would report. A simulated revocation is labelled as one everywhere, and never reaches `check` or `ask`. JWTs have no standard revocation, so the JWT format offers no revocation simulation.

`NO_COLOR` is respected; every state also has its own glyph. `--ascii` (or `WHOSENT_ASCII=1`) uses ASCII only, and `--no-motion` turns the animation off.

## Two rules everywhere

- **Not checked is never green.** A rule that needs an input you did not give is shown as not checked, with its own glyph and colour. VALID means every rule was checked. `AUTHORITATIVE` means a VALID chain with no missing input.
- **Asserted is not verified.** A link nothing could verify (a prior JWT actor) is drawn as asserted, and its unverifiable rules read as not applicable rather than as passing.

## Security

- Every string that comes from a chain, a key document or a library error is escaped before it reaches the terminal. Control characters, escape sequences and bidi overrides are shown as visible escapes, so a chain cannot clear the screen, print a fake verdict, write your clipboard over OSC 52, or disguise a name. `--json` output is escaped the same way.
- whosent touches the network only to fetch key documents from the https URLs you configure. Which keys belong to which issuer comes from your flags or trust file, never from the chain: a JWT's `jku`, `x5u`, `x5c` and `jwk` headers are not used. Fetches must stay on https through any redirect, and are capped at 1 MiB and 5 seconds.
- Input is capped at 1 MiB. A Mandatum chain is read to at most 64 links, a JWT bundle to 64 tokens and 64 nested actors, a Biscuit token to 32 blocks of 256 KiB.

Report a vulnerability through a [private advisory](https://github.com/kanywst/whosent/security/advisories/new). See [SECURITY.md](SECURITY.md).

## Related

- [mandatum](https://github.com/kanywst/mandatum) is the Mandatum specification and its reference Go library, now archived. whosent embeds the v0.2.0 verifier, attenuation rules and matcher in [`internal/mandatum`](internal/mandatum) rather than reimplementing them, and carries a copy of the [specification](docs/mandatum-spec.md).
- [biscuit-cli](https://github.com/eclipse-biscuit/biscuit-cli) creates, attenuates and inspects Biscuit tokens; its `inspect` prints each block. whosent's Biscuit test corpus is the specification's own [samples](https://github.com/eclipse-biscuit/biscuit/tree/main/samples/current), vendored with their license.
- [y509](https://github.com/kanywst/y509) does the same job for X.509 certificate chains.

## Development

```bash
make build       # Build with version info
make test        # Run tests
make lint        # Run golangci-lint
make vulncheck   # Run govulncheck
make run         # Take the demo tour
```

A new token format is an adapter under `internal/formats/<id>`; [docs/adapters.md](docs/adapters.md) is the contract it must meet. See [CONTRIBUTING.md](CONTRIBUTING.md) before sending a patch.

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
