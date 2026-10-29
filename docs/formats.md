# Formats

What whosent reads in each format, and what it can and cannot vouch for. The rules tables are in the [README](../README.md#formats).

## JWT token exchange

whosent reads the delegation a JWT carries in the `act` claim of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) (OAuth 2.0 Token Exchange), and the profiles built on it: ID-JAG (`typ: oauth-id-jag+jwt`, the grant behind MCP's enterprise-managed authorization), Txn-Tokens (`typ: txntoken+jwt`), and Microsoft Entra agent tokens.

### One token

A token names its subject (`sub`) and, in nested `act` claims, who acted for it. The outermost `act` is the current actor; the deepest one acted first. whosent draws the subject as the root and the actors oldest first.

RFC 8693 section 4.1 makes only the token's own claims and the current actor authoritative. Prior actors are the issuer's word, with no signature of theirs in the token. whosent draws them as asserted (amber, never ticked) and applies no rule to them except whether they are actors at all. A VALID single token says in its headline that the prior actors are not a verified chain.

Microsoft Entra has no `act` claim. It names one acting application (`azp` or `appid`) with agent facets (`xms_act_fct`, `xms_sub_fct`: 11 is AgentIdentity, 13 is AgentIDUser) and the application an agent identity was made from (`xms_par_app_azp`), which whosent shows as an asserted link.

### Several tokens

Given the tokens of successive exchanges, oldest first (a JSON array of compact JWS strings, or one per line), each token is checked on its own and each exchange against the token it replaced, so the chain can break at a specific hop.

Rules J7 to J10, and the exchange half of J6, are whosent's consistency checks derived from RFC 8693 and the drafts built on it. No specification defines them as a verification procedure, and a deployment may have reasons to differ.

### Actor proofs

[draft-mcguinness-oauth-actor-proofs](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-proofs/) (revision 01, an individual draft) adds `actor_proofs` to a token: one compact JWT per covered hop, newest first, each signed by the actor that hop added and linked to the one before it by `prh`, the hash of its exact bytes. It is the first thing in a single token that can verify a prior actor at all.

Rule J11 applies the draft's consumer processing (section 7): the proof's form and `typ: actor-proof+jwt`, an asymmetric `alg`, no `aud`, a single-hop `act` whose `iss` and `sub` match the actor at that hop, the signature against the actor's keys, `iat` and `exp`, one `prh_alg` for the whole chain (SHA-256, SHA-384 or SHA-512), `actor_proofs_complete`, the newest proof's `sub` against the token's, and the token's audience and `resource` within the newest proof's `target`. A token that has grown past its newest proof's target, or whose `jti` is not the proof's `origin_jti`, is rejected: whosent has no trusted reissuing issuers, so it is in the draft's strict mode. Within a bundle, a token's inherited proofs must be the previous token's byte for byte (section 6.2).

An actor's keys are looked up by (`act.iss`, `act.sub`) under `actors` in the trust file, never from the proof. A prior actor is drawn as the actor's own word only when every proof of the chain holds, its proof was signed for the same subject as the newest (section 7.1), and every rule of the token carrying it was checked and holds. Anything short of that, unchecked included, leaves it asserted. A rejected chain breaks the token's own link at J11: that is whosent's choice, since the draft only drops the evidence and leaves rejecting the token to local policy. A valid proof shows that the actor took part and consented to the target. It does not show an authorization server checked the hop, and the draft's receipts companion, which would, is not read.

`whosent demo jwt-actor-proofs` and `jwt-actor-proofs-forged` show both.

### Actor Chain

[draft-mw-oauth-actor-chain](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/) (revision 02, an individual draft) takes the other road: the authorization server keeps each actor's signed step proof and puts its own signed acceptance of the latest hop in the token. A profiled token names a profile (`actp`: Declared or Verified, crossed with Full, Subset or Actor-Only disclosure) and a workflow (`acti`). A Verified token carries `actc`, the acceptance, and may carry `acte`, evidence: the current step, the whole path from the root, or a disclosed subset.

Rule J12 applies the draft's validation (section 18). For every profiled token: a known profile, `acti`, the claims section 7 requires, ActorIDs of exactly `iss` and `sub`, no repeated JSON member, and the section 22 limits. A well-formed Declared token has nothing signed to check, so J12 does not apply to it and its chain stays the issuer's word; it fails if it carries `actc` or `acte`. For a Verified token, `actc` is held to its closed header (`alg`, `kid`, `typ: oauth-actc+jwt`, nothing else, and never the polymorphic `EdDSA`), its schema, the token's `acti` and `actp`, and the signature of the server it names, looked up among the configured issuers. With inline evidence, every step proof (`typ: oauth-act-step+jwt`) is signed by the actor at that place in `act`, every acceptance by its `accepting_issuer`, `step_hash` is the SHA-256 of the exact proof, the server accepted no earlier than the actor signed (later than the draft's recommended 60 seconds is a warning, since the window is the server's to configure), the proof is for the token's subject, and the last acceptance is the token's `actc` byte for byte. Path evidence must start at a root, link each step to the acceptance before it by `prev`, and open each `view_commitment` (RFC 8785) to the chain before it plus its own actor. The current step's `resource` must equal `--audience` exactly (without `--audience`, J12 is unchecked), and the token's scope must be within the step's. In a bundle, `acti` and `actp` stay the same for every profiled token, Declared included. In a bundle, each token's `actc` must extend the previous token's, in the same workflow.

A prior actor is drawn as the actor's own word only under path or disclosed evidence that holds, in a token whose every rule holds. Disclosed evidence is still the issuer's attestation of where each actor sits, and the link says so. Commitment-only and introspected evidence leave every prior actor asserted: whosent never calls an introspection endpoint, so `actc` is all it checks. whosent knows no cross-domain subject mapping, so a step for another subject fails. An artifact's key must match its `kid` and be bound to its `alg` in the key document; no match and several matches are both rejected. The trust file binds keys to an issuer or an actor, not to an artifact type, so `typ` separation rests on the closed header.

`whosent demo jwt-actor-chain` and `jwt-actor-chain-forged` show a path that holds and a step the planner never signed.

JWTs have no standard revocation identifier, so there is no revocation simulation. `a` asks whether the last token holds a scope at an audience.

### Getting tokens

- From your IdP: paste the compact form into a file or pipe it on stdin. A leading `Bearer` is accepted.
- From an exchange: capture each token in order into a JSON array.
- `whosent demo --emit DIR jwt-bundle-healthy` writes demo tokens, key documents and the `check` command for them.

## Biscuit

A Biscuit token is a chain of signed blocks: the authority block, signed by the root key, then attenuation blocks, each signed with the key the block before it named. A block cannot add rights, only checks. whosent draws one link per block, named by its `context` string.

Signatures (v0 and v1 payloads, Ed25519 and P-256, third-party blocks, open and sealed tokens) are verified by whosent's own code, and checks are evaluated by its own Datalog engine, ported from the Rust reference. Agreement rests on the specification's 38 sample tokens: every block prints byte for byte as the reference prints it, and every authorizer reaches the same policy, the same failed checks in the same order and the same facts. Where the samples do not reach (unusual regular expressions, Datalog that runs past the reference's default time limit), the two could differ.

Without `--root-key`, the authority block is not checked and nothing below it is shown as verified. Without `--fact` or `--authorizer`, only expiry checks are evaluated, against the evaluation time.

Making a token with the [biscuit CLI](https://github.com/eclipse-biscuit/biscuit-cli):

```bash
biscuit keypair --only-private-key > root.key
biscuit keypair --from-file root.key --only-public-key > root.pub
echo 'right("orders", "read");' | biscuit generate --private-key-file root.key - > token.b64
biscuit attenuate token.b64 --block 'check if operation("read");' > attenuated.b64
whosent attenuated.b64 --root-key root.pub
```

## UCAN

A UCAN 1.0 chain is a series of delegations, each signed by its issuer's `did:key` and addressed to the next, ending in an invocation whose `prf` lists them. whosent draws the subject as the root, one link per delegation and the invocation last. Input is a container, a JSON array of base64 tokens, or the tokens one per line.

Everything is checked by whosent's own code. go-ucan v1.2.0 reads only the release-candidate tags and departs from the specification's policy semantics, so agreement rests on the specification's 1.0.0 fixtures: all 20 invocation cases, the delegation and the policy fixtures.

A policy that holds only because `not` turned an unresolved selector true is left unchecked. A chain without an invocation applies no policy, and its headline says so.

## Macaroons

A macaroon is minted from a root key only its issuer holds, and every caveat appended narrows it. whosent draws one link per caveat, with a third-party caveat's discharge under the caveat it answers. It reads the libmacaroons formats (binary v1 and v2, base64 or raw, and their JSON) with a root and its discharges back to back, and Fly.io tokens (`FlyV1 fm2_...`).

The chain is one HMAC. Without `--root-key` every caveat reads but none is vouched for; with it, a tampered macaroon fails as a whole, since an HMAC cannot say which caveat changed. Verification is whosent's own code, compared on every run with [go-macaroon](https://github.com/go-macaroon/macaroon) or [superfly/macaroon](https://github.com/superfly/macaroon); a disagreement exits 70.

libmacaroons predicates belong to the application, so whosent judges only time caveats and the exact predicates given with `--fact`, as libmacaroons' `satisfy_exact` does. Fly.io caveats such as Organization and Apps restrict the request. Without one they are not checked and the token is INCOMPLETE; `--fact org=ID --fact app=ID --fact action=r` gives one, judged with Fly.io's own access check, and `ask` does the same.
