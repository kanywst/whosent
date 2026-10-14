# whosent

[![Test](https://github.com/kanywst/whosent/actions/workflows/test.yml/badge.svg)](https://github.com/kanywst/whosent/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

Who sent this agent? A TUI for delegation chains: JWT token exchange (RFC 8693 `act`), [Biscuit](https://www.biscuitsec.org), [UCAN](https://github.com/ucan-wg/spec) and macaroons. It shows the human at the root, how authority narrows hop by hop, and where the chain breaks.

![whosent demo](demo.gif)

## Install

```bash
# Go 1.27+
go install github.com/kanywst/whosent/cmd/whosent@latest
```

```bash
# Homebrew (macOS)
brew install --cask kanywst/tap/whosent
```

```bash
# Scoop (Windows)
scoop bucket add kanywst https://github.com/kanywst/scoop-bucket
scoop install kanywst/whosent
```

[Releases](https://github.com/kanywst/whosent/releases) also carry binaries for macOS, Linux and Windows, `.deb` and `.rpm` packages, checksums, cosign signatures and an SBOM.

## Quick start

```bash
whosent demo                       # example chains in every format; n and p switch
whosent demo --list
whosent token.jwt --jwks https://idp.example.com=jwks.json --audience https://api.example.com
pbpaste | whosent --jwks https://idp.example.com=jwks.json    # "Bearer " prefix is fine
whosent token.b64 --root-key root.pub --fact 'operation("read")'
```

Without keys the chain still opens. Rules that need them are shown as not checked, never as passing.

## Formats

The format is recognised from the input; `--format` picks one when it is ambiguous. [docs/formats.md](docs/formats.md) has the details of each.

### JWT token exchange

One token with nested `act` claims, or a bundle of exchanged tokens, oldest first. Also ID-JAG, Txn-Tokens and Entra agent tokens. Prior actors in one token are the issuer's word (RFC 8693 section 4.1), so they are drawn as asserted, not verified, unless the token carries actor proofs (draft-mcguinness-oauth-actor-proofs): then each covered actor signed its own hop, and with its keys in the trust file it is drawn as the actor's own word. J7 to J10 are whosent's own checks between exchanges, not a standard procedure.

| Rule | Checks |
| :--: | :--- |
| J1 | a compact JWS signed with RS, PS, ES or EdDSA; `alg: none`, HMAC and unknown critical headers are refused |
| J2 | the signature verifies against the keys you configured for the issuer the token names |
| J3 | `iat`, `nbf` and `exp` within the skew; an earlier token must have held when the next was issued |
| J4 | the last token is addressed to `--audience` |
| J5 | the current actor is an object with a `sub`; a missing `iss` is a warning, a missing `sub_profile` a note |
| J6 | an exchanged token's actor is the party the previous token's `may_act` names |
| J7 | an exchanged token's `act` chain is the previous one plus exactly one new actor |
| J8 | an exchanged token's scope is a subset of the previous token's |
| J9 | the subject does not change across an exchange |
| J10 | an exchanged token expires no later than the token it replaced |
| J11 | the token's `actor_proofs`: each proof signed by its actor's own key, hash-linked by `prh`, aligned with the `act` chain, unexpired, and the token within the newest actor's consented `target`. A rejected chain fails the token; the draft itself only drops the evidence |

### Biscuit

One link per block. Signatures and the Datalog authorizer are whosent's own code, checked against the specification's 38 sample tokens.

| Rule | Checks |
| :--: | :--- |
| B1 | the token and every block decode, and each next key is valid |
| B2 | the block's Datalog version is 3.0 to 3.3, and it uses only what that version allows |
| B3 | each block's signature verifies, from `--root-key` down; without it nothing is vouched for, though a tampered block still fails |
| B4 | a third-party block's external signature verifies (v1 only, as the reference does by default) |
| B5 | the proof: an open token's secret matches the last next key, or a sealed token's seal verifies |
| B6 | the block's symbols and keys do not overlap earlier ones and every reference resolves |
| B7 | the authorizer's facts and policies satisfy the token's checks; without `--fact` or `--authorizer`, only expiry checks |
| B8 | no block's revocation id is on the `--revoked-jtis` list |

### UCAN

UCAN 1.0 delegations from the subject down to an invocation, checked against the specification's 1.0.0 fixtures.

| Rule | Checks |
| :--: | :--- |
| U1 | canonical DAG-CBOR envelope with a varsig header and a well-formed `ucan/dlg@1.0.0` or `ucan/inv@1.0.0` payload |
| U2 | the signature verifies against the issuer's `did:key` (Ed25519, P-256, secp256k1); other DID methods are not checked |
| U3 | `nbf` and `exp` hold at the evaluation time, within the skew |
| U4 | the first delegation is issued by its subject, and each token by the audience of the delegation above it |
| U5 | every token is about the same subject; a powerline (`sub: null`) may not be the root |
| U6 | each command is the one above it or nested under it |
| U7 | the invocation's arguments satisfy every delegation's policy |
| U8 | the invocation names its proofs and every one is supplied, or the invoker is the subject |
| U9 | no delegation's CID is on the `--revoked-jtis` list |

### Macaroons

libmacaroons tokens and Fly.io tokens (`FlyV1 fm2_...`), one link per caveat. Cross-checked on every run with go-macaroon or superfly/macaroon. A Fly.io token's Organization and App caveats restrict requests: without one they are not checked, and `--fact org=ID --fact action=r` gives one.

| Rule | Checks |
| :--: | :--- |
| M1 | the macaroons decode; a Fly.io attestation appears only in a proof |
| M2 | the HMAC chain matches under `--root-key`; a discharge's, bound to its root |
| M3 | every third-party caveat has its discharge, used once, and no discharge is left over |
| M4 | the caveat's sealed key opens under the chain; a Fly.io discharge is bound to its token |
| M5 | time caveats (`time < T`, `time-before T`, Fly.io `ValidityWindow`) hold at the evaluation time |
| M6 | libmacaroons predicates are among the `--fact` predicates; Fly.io caveats allow the `--fact` request. Without `--fact` they are not checked |

## Checking from a script

`check` prints the same diagnosis without the view. It evaluates every rule for every link, so a chain with three faults shows all three. `demo --emit` writes a scenario out as files with the command that checks them.

Three exchanged JWTs, where the last exchange gained a scope:

```bash
whosent demo --emit fixture jwt-bundle-widened
cd fixture
whosent check tokens.json --trust trust.json --audience https://api.acme.example --at 2026-09-12T08:01:00Z
```

```text
=== tokens.json · 3 links · JWT · issuer https://acme.okta.example, access token (RFC 9068)
    at 2026-09-12T08:01:00Z, skew 30s, audience https://api.acme.example

❌ INVALID: the chain breaks at link 2, and no authority reaches below it

  #  issuer → subject                   J1 J2 J3 J4 J5 J6 J7 J8 J9 J10 J11
  0  alice@acme.example → chat-ui        ✓  ✓  ✓  ·  ✓  ·  ·  ·  ·   ·   ·
  1  chat-ui → planner-agent             ✓  ✓  ✓  ·  ✓  ✓  ✓  ✓  ✓   ✓   ·
  2  planner-agent → research-agent      ✓  ✓  ✓  ✓  ✓  ✓  ✓  ✗  ✓   ✓   ·
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

`--json` prints schema `whosent.chain/v1`, the same for every format. `--json --native` prints the format's own report. A flag the format does not use is reported as `Ignored: --flag (why)`.

| Verdict | Exit | Meaning |
| :--- | :--: | :--- |
| VALID | 0 | every rule was checked and holds |
| INVALID | 1 | a rule failed or could not be evaluated |
| INCOMPLETE | 2 | nothing failed, but something was not checked (1 with `--strict`) |
| | 3 | the command line or an input file is wrong |
| | 70 | whosent disagrees with a format's reference implementation; please report it |

### Asking about one request

`a` in the view, or `whosent ask`, asks whether the chain permits one request, traced link by link. The answer is `AUTHORITATIVE` (the chain verified with every input), `CONDITIONAL` (some rules were not checked) or `HYPOTHETICAL` (the chain does not verify). `ask` exits 0 only for a VALID chain that permits the request. Each format takes its own question:

| Format | Question |
| --- | --- |
| JWT | `--scope files:read`, used at `--audience` |
| Biscuit | `--resource-id` and `--action` become `resource(...)` and `operation(...)` facts for the authorizer; `--policy` replaces its policies (the answer is then at most `CONDITIONAL`) |
| UCAN | `--action /msg/send` as the command, with `--field 'args={...}'` for its arguments |
| Macaroon | Fly.io: `--action rw --field org=ID [--field app=ID]`. libmacaroons: `--field 'predicates=a; b'` |

## Inputs

| Flag | For | What it supplies |
| :--- | :--- | :--- |
| `--jwks ISSUER=PATH` or `ISSUER=https://URL` | JWT | an issuer's key document; repeatable |
| `--trust FILE` | JWT | a file mapping issuers, and actors that sign actor proofs, to key documents (below) |
| `--root-key KEY` | Biscuit, Macaroon | Biscuit: a root public key (`ed25519/...`, `secp256r1/...`, or a file). Macaroon: the root key (hex, `text:SECRET`, or a file) |
| `--audience AUD` | JWT | the party the chain is presented to |
| `--fact FACT`, `--authorizer FILE` | Biscuit, Macaroon | authorizer facts and policies; for a macaroon, a satisfied predicate |
| `--revoked-jtis FILE` | Biscuit, UCAN | revoked ids, one per line: block revocation ids or delegation CIDs |
| `--at TIME` | all | evaluate at another time: RFC 3339, unix seconds, or `+25m` / `-1h` |
| `--skew DURATION` | all | clock skew tolerance, at most 5m (default 30s) |
| `--reverse` | JWT | the tokens were handed over newest first |

The trust file:

```json
{"issuers": {
  "https://idp.example.com": {"jwks_file": "jwks/idp.json"},
  "https://login.example.org": {"jwks_url": "https://login.example.org/.well-known/jwks.json"}
},
 "actors": [
  {"iss": "https://idp.example.com", "sub": "planner-agent", "jwks_file": "jwks/planner.json"}
]}
```

`actors` is optional. An actor is named by the pair (`act.iss`, `act.sub`), and its keys are the ones it signs actor proofs with; they must come from somewhere other than the issuer, or the proofs cannot expose an issuer that invents an actor.

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
| `x` | simulate revoking the selected link; again to undo (Biscuit and UCAN) |
| `X` | clear every simulated revocation |
| `a` | ask whether the chain would permit a request |
| `n` `p` | next or previous scenario, in the demo tour |
| `?` | help |
| `q` `esc` | quit, back |

Time mode shows what `check --at` would report. A simulated revocation is labelled as one and never reaches `check` or `ask`. `NO_COLOR`, `--ascii` (or `WHOSENT_ASCII=1`) and `--no-motion` are respected.

## Security

- Strings from a chain, a key document or a library error are escaped before they reach the terminal, so a chain cannot clear the screen, print a fake verdict or write the clipboard. `--json` is escaped the same way.
- The network is used only to fetch key documents from https URLs you configure. Keys never come from the chain (a JWT's `jku`, `x5u`, `x5c` and `jwk` are ignored). Fetches stay on https through redirects and are capped at 1 MiB and 5 seconds.
- Input is capped at 1 MiB, with per-format limits on links, blocks and caveats.

Report a vulnerability through a [private advisory](https://github.com/kanywst/whosent/security/advisories/new). See [SECURITY.md](SECURITY.md).

## Related

- [biscuit-cli](https://github.com/eclipse-biscuit/biscuit-cli) creates and attenuates Biscuit tokens.
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
