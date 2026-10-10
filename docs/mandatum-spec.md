# Mandatum Delegation Assertion (MDA)

> [!NOTE]
> This is a copy of the Mandatum Delegation Assertion specification from [kanywst/mandatum v0.2.0](https://github.com/kanywst/mandatum/tree/v0.2.0) (commit `ebb3fb8`), which is archived. whosent embeds that release's reference verifier in `internal/mandatum` and checks every diagnosis against it, so this document describes exactly the rules whosent applies. The text is unchanged apart from this note, links that now point at the archived repository, and em dashes written as hyphens. A Japanese translation is in the [archived repository](https://github.com/kanywst/mandatum/blob/v0.2.0/docs/spec/delegation-assertion.ja.md).

Status: **Draft 0.1**. Implemented, and not yet reviewed by anyone outside the project. Last updated: 2026-09-16

## 1. Problem

An AI agent that acts for a person today almost always does so by *inheriting a credential*: a service account, an API key, a shared OAuth token, or the human's own session. Three failures follow directly from that. The first is measured; the second and third are consequences of how the credential is shared and how authorization is evaluated, and are argued rather than surveyed.

1. **No attribution.** 28% of organizations can reliably trace agent actions to a human or system across all environments (Cloud Security Alliance and Strata Identity, *Securing Autonomous AI Agents*, February 2026; n=285), and 68% cannot clearly distinguish AI agent activity from human activity (Cloud Security Alliance and Aembit, *Identity and Access Gaps in the Age of Autonomous AI*, March 2026; n=228). Both are vendor-commissioned self-reported surveys, and neither says "human sponsor" - the first says "human or system".
2. **No selective revocation.** Because agents share the credential they inherited, revoking one agent revokes every principal using that credential. This is the *credential piggybacking* failure mode.
3. **No sequence-level control.** Authorization is evaluated per call. An agent can be individually authorized for every request in a series while the *series* produces an outcome nobody authorized. Current protocols cannot express a constraint over a sequence of actions, only over one action.

The Model Context Protocol's own authorization specification covers the transport: it defines how a client obtains a token for a server, and it defines nothing about which tool that token may call, which agent is holding it, or who delegated to whom. It does not declare those out of scope - it does not mention them, and MCP's authorization interest group has active work on per-tool scopes and on consent across chains of agents. The Enterprise-Managed Authorization extension (stable, 2026-06-18) is about obtaining an access token from an enterprise identity assertion, so what it produces is scoped to a server rather than to a call. Neither document claims a limit; the limit is what they define.

Mandatum addresses exactly that gap and nothing else.

## 2. Non-goals

Stating these first, because the failure mode for a project in this space is scope creep into territory that is already occupied.

- **Not a new authorization engine.** Mandatum never decides. It carries the facts a decision needs and calls a Policy Decision Point that already exists (OPA, Cedar, OpenFGA, SpiceDB, Cerbos, or any AuthZEN-conformant PDP).
- **Not a new wire protocol.** Delegation is expressed with JOSE, issued with RFC 8693 token exchange, and evaluated with the OpenID AuthZEN Authorization API 1.0. Where an existing standard fits, Mandatum uses it unchanged. The one place it deliberately goes beyond a standard is §3.1.
- **Not a gateway.** Mandatum ships as a library, and is meant to run *inside* agentgateway, ToolHive, an MCP server, or an agent runtime rather than replace any of them. The middleware that plugs it into an HTTP-based MCP server is `pkg/mcp`, which enforces `tools/call` and forwards every other method to the server it fronts.
- **Not a registry, sandbox, or agent runtime.** Those categories are occupied.
- **Not a blockchain.** The audit log is an RFC 6962-style Merkle tree. There is no consensus protocol, no network, and no token.

## 3. Prior art

Mandatum's attenuation model is not novel and does not claim to be. Capability attenuation that can be delegated offline, without contacting the issuer, is the contribution of macaroons (Birgisson et al., 2014) and, in a modern form, Biscuit. Macaroon *verification* is not offline: it is HMAC-chained and the verifier holds the root secret. SPIFFE established cryptographic workload identity. RFC 8693 established token exchange with delegation semantics (`actor_token`, the `act` claim), and drew a line Mandatum sits outside of: §4.1 requires a consumer to consider only the current actor, and treats prior actors in nested `act` claims as informational. RFC 6962 established tamper-evident logging; it is Experimental and obsoleted by RFC 9162, and "RFC 6962-style" here means the tree construction both share.

What Mandatum adds to that body of work is narrow and specific:

- a chain **rooted in an authenticated human sponsor**, carried unmodified to every leaf, so attribution survives arbitrary sub-delegation;
- **sequence-scoped constraints** evaluated across a chain's whole action history, not per call;
- a **binding to the AuthZEN Authorization API**, so the chain becomes input to any conformant PDP rather than to one vendor's engine.

If a reviewer concludes that an existing project already does these three things, that is a reason to contribute there instead. See `docs/alternatives.md`.

### 3.1 Relationship to RFC 8693 §4.1

Mandatum authorizes on a delegation history at the resource server. RFC 8693 §4.1 says not to do that with nested `act` claims: a consumer "MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim", and prior actors are "informational only and are not to be considered in access control decisions".

There is no conflict, because Mandatum does not use `act` for this. A chain is a separate credential whose links are independently signed, commit to their parents by hash, and are checked to have narrowed at every hop. RFC 8693 asks a resource server to trust the authorization server's judgement, recorded once at issuance and gated by `may_act`; a Mandatum chain carries evidence the resource server checks for itself.

An implementation using both should be clear about which is doing what: RFC 8693 for obtaining a token, Mandatum for the delegation history any policy decision rests on. Presenting chain-based authorization as RFC 8693 conformance would be wrong, and this specification does not.

## 4. Terminology

| Term | Meaning |
| --- | --- |
| Sponsor | The authenticated human principal at the root of a chain. |
| Agent | A non-human principal holding a delegated capability set. |
| MDA | Mandatum Delegation Assertion - one signed link in a chain. |
| Chain | An ordered list of MDAs from sponsor to the acting agent. |
| Leaf | The last MDA in a chain; identifies the agent performing the action. |
| PEP | Policy Enforcement Point; verifies the chain and calls the PDP. |
| PDP | Policy Decision Point; an AuthZEN-conformant authorization service. |
| Attenuation | Narrowing of a capability set from parent to child. |

## 5. Delegation Assertion format

An MDA is a JWS in compact serialization (RFC 7515) whose payload is a JWT claims set (RFC 7519). Registered claims carry their normal meaning. All Mandatum-specific claims live under a single `mdt` claim to avoid collisions.

```json
{
  "iss": "spiffe://example.org/ns/agents/planner",
  "sub": "spiffe://example.org/ns/agents/retriever",
  "aud": "https://mcp.example.org",
  "iat": 1789200000,
  "exp": 1789203600,
  "jti": "01JB2X9K7P4Q8R3N6M0V5T2Y7C",
  "mdt": {
    "v": 1,
    "root": {
      "iss": "https://idp.example.org",
      "sub": "u-8f31c02e",
      "amr": ["pwd", "hwk"],
      "auth_time": 1789199400
    },
    "parent": "sha-256:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw",
    "depth": 1,
    "max_depth": 2,
    "cap": [
      {
        "resource": { "type": "mcp_tool", "id": "search.query" },
        "action": { "name": "invoke" },
        "conditions": { "args.index": { "in": ["public", "docs"] } }
      }
    ],
    "seq": {
      "max_invocations": 200,
      "constraints": [
        { "id": "no-write-after-external-read",
          "forbid": { "action": "invoke", "resource.type": "mcp_tool",
                      "resource.tags": ["mutating"] },
          "after": { "resource.tags": ["external-content"] } }
      ]
    }
  }
}
```

### 5.1 Digest encoding

Every digest in this specification is written `sha-256:<value>`, where `<value>` is the base64url encoding of the raw 32-byte SHA-256 output **without padding**, as defined by RFC 7515 §2 (`BASE64URL`). This is the encoding JOSE already uses, so an implementation handling JWS has it available.

Stating this is not pedantry. `mdt.parent` is the commitment that makes chain splicing detectable, and two implementations that encode the same hash differently reject every chain the other produces.

Test vectors, so an implementer can check an encoder against this document rather than against prose:

| Input | Digest |
| --- | --- |
| `the empty string` | `sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU` |
| `example` | `sha-256:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw` |
| `mandatum` | `sha-256:jUMrViVq7f3wcuQ44n0wJz5BNoNwIcxeu0MS7PGfEZI` |

Every digest appearing in the examples in this document is a real value computed this way, not a placeholder.

A verifier MUST compare digests as exact strings after checking the `sha-256:` prefix. It MUST NOT decode and re-encode before comparing, and MUST NOT accept a different encoding of the same hash: accepting several spellings of one value reintroduces the ambiguity this section exists to remove.

Only `sha-256` is defined. A verifier MUST reject any other prefix rather than attempt it, so that a future algorithm is a deliberate version bump rather than something an old verifier silently tolerates.

### 5.2 Claim semantics

| Claim | Required | Meaning |
| --- | --- | --- |
| `iss` | yes | The delegator. For depth 0 this is the sponsor's issuing authority. |
| `sub` | yes | The delegatee. A SPIFFE ID or other stable agent identifier. |
| `iat` | yes | Issued-at. Rule V4 compares it to the verifier's clock, so an assertion without one is treated as issued in 1970. |
| `aud` | yes | The resource server this assertion may be presented to. It is fixed for the whole chain by §6 rule 7 and compared to the verifier by V9, so a chain whose leaf omits it is refused everywhere and a link that changes it is refused as widening. |
| `exp` | yes | Expiry. Must not exceed the parent's `exp`. |
| `jti` | yes | Unique identifier. The unit of revocation. |
| `mdt.v` | yes | Format version. `1` for this document. |
| `mdt.root` | yes | The human sponsor. Byte-identical across every link in a chain. |
| `mdt.parent` | yes below depth 0 | Digest of the parent MDA. At depth 0 there is no parent: the member is **absent**. A verifier MUST treat an absent member and a `null` value identically, and MUST reject any other value at depth 0. Serializing it as the empty string is not conformant, and is a mistake this implementation made. |
| `mdt.depth` | yes | Zero-based index of this link. It orders the chain; it does not bound it. |
| `mdt.max_depth` | yes | How many further delegations are permitted below this assertion. Zero means the holder may act but may not sub-delegate. Falls by at least one per hop, so the sponsor's value bounds the whole chain. Never negative. |
| `mdt.cap` | yes | Capability set. May be empty, meaning no authority. |
| `mdt.seq` | no | Sequence-scoped constraints. Absent means no sequence limits. |

### 5.3 Why depth and max_depth are separate

`depth` says where a link sits; `max_depth` says how much further delegation may go. Tying the two together - for instance requiring `max_depth` to exceed `depth` - looks tidier and is wrong: combined with the per-hop decrease in §6 it halves the usable budget, because the limit falls as the position rises and they meet in the middle.

Keeping them independent means a sponsor granting `max_depth` of *n* gets exactly *n* sub-delegations, which is what an operator writing that number expects.

### 5.4 Why the sponsor is copied, not referenced

`mdt.root` is duplicated into every link rather than resolved by following the chain. A verifier that receives a partial chain, or that wants to index audit records by sponsor without a full verification pass, can then still attribute the action. The duplication is checked for consistency during verification (rule V6), so it cannot be used to forge attribution.

## 6. Attenuation rules

For every link *i* > 0, all of the following MUST hold. Together these make the chain monotonically non-widening.

1. `cap(i)` ⊆ `cap(i-1)` - every capability in the child is entailed by some capability in the parent. Entailment is defined in §6.1.
2. `exp(i)` ≤ `exp(i-1)`
3. `max_depth(i)` ≤ `max_depth(i-1) − 1`, and `max_depth(i)` ≥ 0. Together these make the budget strictly decreasing and finite, which is what bounds chain length.
4. `depth(i)` = `depth(i-1) + 1`
5. `seq(i)` is at least as restrictive as `seq(i-1)`: numeric budgets do not increase, and the constraint set is a superset. `max_invocations` is never negative, and zero means unlimited - so a child may only be zero where its parent was. A verifier MUST treat any non-positive child budget under a positive parent as widening, because a comparison that reads a negative as "smaller" is an escape rather than an attenuation.
6. `root(i)` is byte-identical to `root(i-1)`.
7. `aud(i)` = `aud(i-1)`. A chain is issued for one resource server and is evidence at that one only.

Rule 7 is what stops a re-target, and it is not redundant with V9. An agent holding a valid chain can sign a further link naming a *different* resource server: it delegates only what it holds, to a subject of its choosing, with the capabilities unchanged, so rules 1 to 6 all hold. Presented at that other server, V9 compares the leaf's audience to the verifier and passes, because the leaf names it. Every link is valid, every other rule is satisfied, and the sponsor authorized none of it - a confused deputy assembled entirely out of well-formed parts. Without rule 7 the audience binds only whoever issued the leaf, which is the agent under attacker control.

A child that violates any rule is not a valid delegation. There is no "escalation with approval" path in the format; raising authority requires a new chain issued from the sponsor.

### 6.1 Capability entailment

Capability `c` is entailed by parent capability `p` when the resource pattern of `c` is a subset of `p`'s, the action set of `c` is a subset of `p`'s, and `c`'s conditions are at least as restrictive as `p`'s. Condition comparison is performed on a decidable fragment only: set membership, string equality, prefix match, and numeric ranges. Conditions outside that fragment are rejected at issuance rather than approximated at verification, so that entailment is never decided by an incomplete check.

This is a deliberate limitation. An undecidable condition language would force verifiers to fail open or fail closed on inputs the issuer believed were valid.

Two edge cases, stated because implementations otherwise guess at them:

- An `in` condition with an empty list matches nothing. It is therefore the narrowest restriction expressible, and any parent condition entails it. Such a capability can never apply, which is useless but not unsafe; rejecting it would mean a delegator could not explicitly grant nothing on a key.
- A condition with no comparison set, or with more than one, is invalid and MUST be rejected at issuance. A condition with none set would restrict nothing, and one with several would require a combination rule this fragment deliberately does not define.

## 7. Chain verification

Input: an ordered chain `[MDA₀ … MDAₙ]`, a trust bundle, a revocation oracle, and the current time.

- **V1 Structure.** `MDA₀.mdt.parent` is absent or `null`, and `MDA₀.mdt.depth` is 0. For every *i* > 0, `MDA(i).mdt.parent` equals `sha-256` over the compact serialization of `MDA(i-1)`.
- **V2 Custody.** For every *i* > 0, `MDA(i).iss` equals `MDA(i-1).sub`. A delegator may only delegate authority it holds.
- **V3 Signatures.** Every MDA verifies against a key resolved for its `iss` through the SPIFFE trust bundle or the issuer's JWKS. Algorithm is taken from a fixed allowlist; `none` and symmetric algorithms are rejected. Which document belongs to which issuer is configuration held by the verifier. A verifier MUST NOT discover it from the assertion, and MUST NOT dereference the issuer identifier to find it: an assertion that names where its own key comes from verifies against a key its holder generated.
- **V4 Time.** For every link, `iat` ≤ now < `exp`, with a bounded skew.
- **V5 Attenuation.** Every rule in §6 holds.
- **V6 Root consistency.** `mdt.root` is byte-identical across all links.
- **V7 Depth.** `n` ≤ `MDA₀.mdt.max_depth`, where `n` is the number of delegation hops, one fewer than the number of links.
- **V8 Revocation.** No `jti` in the chain appears in the revocation set.
- **V9 Audience.** The leaf's `aud` matches the verifying resource server.

Verification is offline except for V3 key resolution and V8, both of which are cacheable. A verifier MUST NOT accept a chain on partial verification.

V7 is redundant in the current rule set: V5 forces `max_depth` to fall by at least one per hop and §5.2 forbids it going negative, so any chain that would violate V7 is already rejected by V5. It is retained as defence in depth against a later relaxation of V5. Implementations should test it directly rather than leave it as an unreachable branch.

### 7.1 Revocation semantics

Revoking any `jti` invalidates that link **and every chain that descends from it**, because descendants commit to it through `mdt.parent`. This is the property that answers credential piggybacking: a sponsor can kill one agent's authority, including everything it sub-delegated, without touching sibling chains or any other principal.

Revocation state is distributed as a compact set so that a PEP can evaluate V8 locally rather than calling a service on the path of every authorized action. The set is a Bloom filter with a published false-positive rate, and a false positive denies unless the verifier has an exact lookup to resolve it against.

The encoding is normative, because two implementations that index bits differently produce sets neither can read, and the way that fails is that one of them stops honouring revocations rather than that it errors.

```json
{
  "v": 1,
  "sequence": 42,
  "generated_at": 1789200000,
  "hashes": 7,
  "bits": "3q2-7w"
}
```

| Member | Meaning |
| --- | --- |
| `v` | Format version. A verifier MUST reject a version it does not implement rather than guess. |
| `sequence` | Monotonic publication counter. A verifier MUST refuse a set whose sequence is below the one it holds: accepting one reinstates every identifier revoked in between. |
| `generated_at` | Seconds since the epoch. A verifier MUST treat a set older than its configured maximum age as an error, not as an empty set. |
| `hashes` | *k*, the number of bit positions each identifier maps to. MUST be between 1 and 64 inclusive; a verifier MUST refuse a set outside that range. |
| `bits` | The filter, base64url without padding as in §5.1. Its length in bits is *m*. |

For an identifier *jti*, let *h* = SHA-256(*jti*), let *h₁* and *h₂* be the first and second eight bytes of *h* read big-endian, and let the *i*-th bit position, for *i* from 0 to *k*−1, be (*h₁* + *i*·*h₂*) mod *m*. The publisher sets every position for every revoked identifier; a verifier reports "may be revoked" only if every position is set.

Sizing is the publisher's choice, and the standard relations *m* = −*n*·ln *p* / (ln 2)² and *k* = (*m*/*n*)·ln 2 give a set whose false-positive rate is *p* at *n* revocations. The rate is a property of the published set, so a verifier does not need to be told it.

The bound on *k* is the one place the publisher's choice is not free, and it is a denial-of-service bound rather than a correctness one. A lookup costs *k* hash positions and runs before every authorized action, so an unbounded *k* makes the cost of enforcement a number the publisher writes down: a set of eighty bytes declaring *k* in the billions takes seconds per lookup and asks for tens of gigabytes to answer it. The document that says which agents are revoked would double as a way to stop the enforcement point evaluating anything. Sixty-four is past any operational need rather than a tuned figure - at optimal sizing *k* = −log₂ *p*, so *k* = 64 is a rate around 10⁻¹⁹, and a set wanting one in a billion uses *k* = 30. A publisher that cannot express its intended rate within the bound is asking for a rate no deployment needs.

A false negative is impossible by construction, which is the property that makes the fast path safe: an identifier the filter rejects was not in the set the publisher built, so no lookup is needed and none is made.

## 8. AuthZEN binding

A verified chain becomes the subject context of an OpenID AuthZEN Authorization API 1.0 evaluation request. Mandatum does not extend the API; it populates it.

```json
{
  "subject": {
    "type": "identity",
    "id": "u-8f31c02e",
    "properties": { "iss": "https://idp.example.org" }
  },
  "action": { "name": "tools/call" },
  "resource": {
    "type": "tool",
    "id": "search.query",
    "properties": {
      "server": "https://mcp.example.org",
      "arguments": { "index": "public" }
    }
  },
  "context": {
    "agent": "spiffe://example.org/ns/agents/retriever",
    "mandatum.delegation": {
      "sponsor": {
        "iss": "https://idp.example.org",
        "sub": "u-8f31c02e",
        "amr": ["pwd", "hwk"],
        "auth_time": 1789199400
      },
      "chain": "sha-256:LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
      "actors": [
        "spiffe://example.org/ns/agents/planner",
        "spiffe://example.org/ns/agents/retriever"
      ],
      "depth": 1,
      "leaf": "01JB2XA4M0RN5S8Q2K7T3W1Y9D"
    }
  }
}
```

The shape of `subject`, `action`, `resource` and `context.agent` is the COAZ-MCP default mapping for `tools/call`, unchanged. Under that binding `subject` is the principal on whose behalf access is requested and `context.agent` is the acting client, which is exactly the split a sponsor-rooted chain already has: the human goes in `subject`, the leaf agent in `context.agent`.

`context.agent` carries the acting client. The binding defines no place for the hops above it - it does not rule a chain out there, it does not address the question - so Mandatum puts them under a vendor-prefixed key rather than taking a name inside the binding's namespace. The question is open in [openid/authzen#612](https://github.com/openid/authzen/issues/612); see `docs/spec/coaz-mcp-conformance.md`. Its presence is itself a claim: a PEP populates it only from a chain that passed every rule in §7, so a PDP may rely on it for the same reason it may rely on `subject.id`.

`actors` answers "who was upstream". `chain` is what makes it more than a list - it commits to the exact links, so a sequence of actors cannot be reassembled from pieces of other chains. Whether the commitment is necessary, or a verified list is enough, is genuinely open; see §12.

The chain is verified **before** the PDP is called. The PDP receives a statement of fact ("this agent holds a valid chain rooted in this human") and applies organizational policy on top. Separating the two means an operator can change policy without changing credential handling.

Verification alone does not stop a PDP granting more than the sponsor did. Nothing in an evaluation response is bounded by the chain, so a PEP that asks the PDP and enforces the answer has handed the PDP the sponsor's authority. The bound comes from a third step, and only if the PEP takes it:

1. verify the chain;
2. check the chain's capability set covers the request;
3. ask the PDP;
4. admit the action against the chain's history (§9);
5. allow only if all four agree.

A PEP MUST perform step 2 and MUST refuse on its failure whatever the PDP said. This is what "a compromised PDP cannot manufacture authority that no sponsor granted" means, and it is a property of the enforcement point's ordering rather than of the format. An implementation that skips it has the confused deputy this specification exists to prevent, wearing a valid chain.

Step 4 is last, after the PDP has allowed, because admitting an action is also recording it: the check and the write are one atomic operation (§9.1), and they have to be, or two agents acting at once under one chain each read a budget of one before either writes. A call the PDP refused did not happen, so counting it would let anything able to provoke a policy denial spend a sponsor's invocation budget without ever invoking a tool. The ordering costs an evaluation on a call a constraint will refuse, which is the cheaper of the two mistakes.

Where the OIDF COAZ-MCP binding (WG draft, June 2026) specifies a mapping from MCP tool calls to AuthZEN requests, Mandatum follows it rather than defining a parallel one. What is implemented, what is not, and the one place the output goes beyond the binding are set out in [coaz-mcp-conformance.md](https://github.com/kanywst/mandatum/blob/v0.2.0/docs/spec/coaz-mcp-conformance.md).

### 8.1 Carrying a chain in an MCP request

The binding above says what a PDP is told. It does not say how the chain reaches the enforcement point in the first place, and a chain that travels differently in two deployments is a chain neither one's middleware can read.

A chain is carried in the `_meta` object of the `tools/call` request parameters, under the key:

```text
io.github.kanywst.mandatum/chain
```

Its value is a JSON array of the chain's compact serializations as strings, ordered from the sponsor's grant to the acting agent's assertion - the same order §5 gives the chain and the order verification requires. An absent key, a value that is not an array of strings, or an empty array is a refusal; none of them is an unauthenticated call that may proceed.

MCP reserves `_meta` for exactly this purpose and constrains what may be put there: a key's optional prefix is a series of dot-separated labels followed by a slash, implementations SHOULD use reverse DNS notation, and any prefix whose second label is `modelcontextprotocol` or `mcp` is reserved for the protocol itself. This key is reverse DNS for the project's own domain and its second label is `github`, so it is a third-party key by that rule and cannot be mistaken for one the protocol defines ([MCP, revision 2026-07-28, "General fields: `_meta`"](https://modelcontextprotocol.io/specification/2026-07-28/basic/index)).

Nothing about the transport authenticates the chain. `_meta` is caller-supplied, and every link in it is signed, which is the only reason it can be carried somewhere a caller controls: the verifier re-derives claims from the signed bytes (§7, V3) rather than reading what the request asserts about them. A PEP MUST NOT treat the presence of a chain as evidence of anything before §7 has run over it.

This binds a chain to the HTTP-based transports and to `tools/call`. The other methods the COAZ-MCP binding maps are not mapped here, and a chain says nothing about `tools/list` or `initialize`; an enforcement point implementing this is a per-call layer above MCP's own authorization, not a replacement for it.

## 9. Sequence-level evaluation

This is the part with no existing implementation, so it is specified carefully.

A **sequence** is the ordered history of actions performed under one chain root. The PEP maintains, per chain root, an append-only history and a derived state:

```text
  state = fold(evaluate_constraint, initial, history)
```

Each constraint in `mdt.seq.constraints` is a predicate over the history that must hold *after* appending the candidate action. If appending would falsify any constraint, the action is denied with a reason naming the constraint `id`.

The worked example in §5 encodes the lethal pattern that per-call authorization structurally cannot catch: an agent reads untrusted external content, then performs a mutating action. Each step is individually authorized. The pair is the exfiltration.

Two properties are required and shape the implementation:

- **Bounded state.** History cannot grow without limit. Constraints are compiled to a finite automaton over action *tags*, so per-chain state is a fixed-size vector regardless of history length. Constraints that do not compile are rejected at issuance.
- **Fail-closed on state loss.** If a PEP cannot read the sequence state for a chain that declares `mdt.seq`, it denies. Sequence constraints that silently degrade to per-call checks are worse than no constraints, because operators would believe they are protected.

Sequence state is per chain root and is therefore shared across every enforcement point that honours the same chain. Two PEPs with separate stores give an agent two histories to spend, which defeats the constraint rather than weakening it.

The reference implementation ships a single-process store only. It is correct for one enforcement point and wrong for more than one, and it says so. A replicated store is not written yet; until it is, a multi-PEP deployment does not have sequence constraints, whatever the assertions say. The store interface is small - an atomic read-modify-write per chain root - and is defined by `sequence.Store`.

### 9.1 What the state is keyed by

Sequence state is kept per **chain root** - the `jti` of the depth-0 assertion - not per agent. A constraint an agent inherits therefore cannot be escaped by delegating to a freshly minted sub-agent, because the sub-agent's actions land in the same history.

This has a consequence worth stating rather than discovering: two sibling chains descending from one sponsor grant share a history, so they share an invocation budget. A budget of 100 is 100 actions across everything that grant produced, not 100 each. That is the conservative reading - the budget is the sponsor's to spend - but it is a choice, and §12 records it as open.

A store MUST make read-modify-write atomic per root. Two agents acting at once under one chain that each read the state before either writes will each see room in a budget of one.

### 9.2 Triggers fire after the check

A constraint reads "once an action matching `after` has happened, an action matching `forbid` is denied". The trigger is evaluated **after** the current action has been admitted, so an action that matches both `forbid` and `after` is permitted once and refused thereafter. Evaluating it before would make such a constraint deny its own trigger, which no operator writing one intends.

### 9.3 An empty trigger is not permitted

A constraint whose `after` matches everything is refused by structural validation, so it fails at issuance and again at chain verification, and the evaluator refuses it a third time because it must not depend on someone else having checked.

It looks like a way to write "never allow this", and it is not: because a trigger needs something to have happened, an empty one takes effect from the chain's *second* action rather than its first. The gap is silent and the deployment believes it has a prohibition it does not have.

An unconditional prohibition belongs in the capability set, where it applies from the first action and attenuates down the chain like everything else. An empty `forbid` is a different matter and remains valid: "after reading untrusted content, do nothing else at all" is a coherent and useful rule.

## 10. Audit trail

Every decision - allow and deny - appends one record to a tamper-evident log:

| Field | Purpose |
| --- | --- |
| `root` | The human sponsor. Enables the attribution query. |
| `chain` | Digest of the full verified chain. |
| `leaf_jti` | The acting agent's link. The revocation handle. |
| `action`, `resource` | What was attempted. |
| `decision` | Allow or deny. |
| `reason` | Structured reason code, including the constraint `id` on denial. |
| `policy_revision` | The PDP's policy or bundle version. |
| `seq_index` | Position in the chain's action sequence. |
| `ts` | Timestamp. |

`policy_revision` is mandatory because without it a decision cannot be replayed: re-evaluating against today's policy answers a different question than the one the log records. The absence of this field in existing decision logs is the reason "why was this denied?" is currently unanswerable in practice.

The log is an RFC 6962-style Merkle tree. Inclusion and consistency proofs let an auditor verify that no record was altered or removed.

The EU AI Act shapes this section, and both the date and the requirement are easy to get wrong. The Digital Omnibus (Regulation (EU) 2026/1744, in force 2026-07-27) moved the Annex III high-risk obligations to 2027-12-02 and the Annex I ones to 2028-08-02; only the Article 50 transparency duties kept the original 2026-08-02 date. What Article 12 requires of a high-risk system is automatic recording of events over its lifetime, at a level of traceability appropriate to the intended purpose. It does not say "immutable" and it does not mention delegation. A tamper-evident log of who delegated what is a reasonable way to meet a record-keeping obligation; it is not the obligation. None of this section is built yet, and a mapping from the Act's articles to what the implementation does is worth writing once there is an implementation to map.

## 11. Threat model

Summarized here; the full model is in `docs/security/threat-model.md`.

| Threat | Mitigation |
| --- | --- |
| Forged delegation | V3 signature verification against a trust bundle. |
| Chain splicing | V1 parent hash commitment; links are not interchangeable. |
| Privilege escalation via sub-delegation | §6 attenuation, enforced at verify time, not issue time. |
| Replay after revocation | V8 with fail-closed distribution. |
| Confused deputy | V2 custody rule, §6 rule 7 fixing the audience for the whole chain, and V9 comparing it at the verifier. |
| Attribution stripping | V6 root consistency; `root` cannot be dropped or rewritten. |
| Log tampering | Merkle inclusion and consistency proofs. |
| Sequence-state evasion | Fail-closed on state loss; state keyed by chain root, not by PEP. |
| PDP compromise | A PDP may deny anything. It can widen nothing, provided the enforcement point checks the request against the chain's capability set as well as asking the PDP; see §8. Skipping that check gives the PDP the sponsor's authority. |

The last row is a deliberate design property: verification precedes and constrains the policy decision, so the PDP is not fully trusted.

## 12. Open questions

Honest list. These are unresolved and feedback is wanted.

1. Should `mdt.root` carry an assurance level (`acr`) so policy can require step-up authentication for high-impact sequences?
2. Is the finite-automaton constraint language expressive enough for real operator needs, or does it need bounded counting beyond simple budgets?
3. Should Mandatum define its own revocation distribution, or adopt an existing status mechanism (OAuth Status Lists) unchanged?
4. How should chains behave across trust domains? SPIFFE federation gives a key resolution answer but not a policy answer for cross-domain sponsorship.
5. Sibling chains under one sponsor grant share an invocation budget (§9.1). Is that the reading operators expect, or should a budget be per leaf, or per delegation subtree?
6. Is a delegation chain the right shape for multi-sponsor scenarios - an agent acting for two people at once - or does that need a different structure?

## 13. References

- OpenID AuthZEN Authorization API 1.0 (Final Specification, 2026-01-11)
- OpenID AuthZEN COAZ-MCP Binding 1.0 (Working Group Draft, 2026-06)
- Model Context Protocol specification 2026-07-28, Authorization
- MCP Enterprise-Managed Authorization (stable, 2026-06-18)
- RFC 6962 - Certificate Transparency (Experimental; obsoleted by RFC 9162)
- RFC 7515 - JSON Web Signature
- RFC 7519 - JSON Web Token
- RFC 8693 - OAuth 2.0 Token Exchange
- RFC 9728 - OAuth 2.0 Protected Resource Metadata
- SPIFFE ID and SVID specifications
- draft-ietf-wimse-arch, draft-ietf-wimse-s2s-protocol
- draft-klrc-aiagent-auth-03 - AI Agent Authentication and Authorization
- Birgisson et al., *Macaroons: Cookies with Contextual Caveats* (2014)
- Cloud Security Alliance and Strata Identity, *Securing Autonomous AI Agents* (2026-02)
- Cloud Security Alliance and Aembit, *Identity and Access Gaps in the Age of Autonomous AI* (2026-03)
- Regulation (EU) 2024/1689 (AI Act) Article 12, as amended by Regulation (EU) 2026/1744; Annex III high-risk obligations apply from 2027-12-02
