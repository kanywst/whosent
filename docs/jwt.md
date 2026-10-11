# JWT delegation

whosent reads the delegation a JWT carries in the `act` claim of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) (OAuth 2.0 Token Exchange), and the profiles built on it: ID-JAG (`typ: oauth-id-jag+jwt`, the grant behind MCP's enterprise-managed authorization), Txn-Tokens (`typ: txntoken+jwt`), and Microsoft Entra's agent identity claims.

## One token: the issuer's word

A single token names its subject (`sub`) and, in nested `act` claims, who acted for it. The outermost `act` is the current actor; the deepest one acted first.

RFC 8693 section 4.1 makes only the token's own claims and the current actor authoritative. Prior actors are informational: the issuer vouches for them, and no signature of theirs is in the token. whosent draws them as **asserted** (amber, dashed, never ticked) and applies no rule to them except whether they are actors at all. A VALID single token says so in its headline: the token verifies, and the prior actors are the issuer's word, not a verified chain.

Microsoft Entra has no `act` claim. It names one acting application (`azp` or `appid`) with agent facets (`xms_act_fct`, `xms_sub_fct`: 11 is AgentIdentity, 13 is AgentIDUser) and the application an agent identity was made from (`xms_par_app_azp`). whosent shows the parent application as an asserted link.

## Several tokens: a chain checked hop by hop

Given the tokens of successive exchanges, oldest first (a JSON array of compact JWS strings, or one token per line), each token is checked on its own and each exchange against the token it replaced. That turns a list of actors into a chain that can break at a specific hop.

**Rules J7 to J10, and the exchange half of J6, are whosent's consistency checks derived from RFC 8693 and the drafts built on it. No specification defines them as a verification procedure.** They encode what a well-behaved exchange does, and a deployment may have reasons to differ.

## Rules

| Rule | Title | Checks |
| --- | --- | --- |
| J1 | token | a compact JWS with JSON header and claims, signed with an accepted public-key algorithm (RS, PS, ES, EdDSA). `alg: none`, HMAC algorithms and unknown critical extensions are refused |
| J2 | signature | the signature verifies against the keys configured for the issuer the token names (`--jwks ISSUER=PATH\|URL` or `--trust`); never against keys the token points to |
| J3 | time | `iat`, `nbf` and `exp`, within the skew. The last token must hold now; an earlier one must have held when the next was issued |
| J4 | audience | the last token is addressed to `--audience` |
| J5 | actor | the current actor is an object with a `sub`. Missing `iss` (required by the actor profile draft) is a warning, missing `sub_profile` a note |
| J6 | may_act | an exchanged token's actor is the party the previous token's `may_act` names (RFC 8693 section 4.4) |
| J7 | extends | an exchanged token's `act` chain is the previous token's plus exactly one new actor |
| J8 | scope | an exchanged token's scope (`scope` or `scp`) is a subset of the previous token's |
| J9 | subject | the subject does not change across an exchange |
| J10 | expiry | an exchanged token expires no later than the token it replaced |

JWTs have no standard revocation identifier, so the JWT format offers no revocation simulation. Time scrub and questions (`a`: does the last token hold this scope, at this audience) work as for every other format.

## Getting tokens to inspect

- A token from your own IdP: decode nothing, paste the compact form (a leading `Bearer` prefix is accepted) into a file or pipe it on stdin.
- An exchange: capture each token the exchanges return, in order, into a JSON array.
- The demos mint every shape with throwaway keys: `whosent demo jwt-okta-style`, `jwt-bundle-healthy`, `jwt-bundle-widened`, `jwt-entra-agent`, `jwt-id-jag` and more (`whosent demo --list`). `whosent demo --emit DIR jwt-bundle-healthy` writes the tokens, key documents and the `whosent check` command that checks them.
