# Security Policy

Everything whosent reads (a chain, a key document, a revocation set) can be hostile, and scripts gate on the exit code of `whosent check` and `whosent ask`.

## Supported versions

| Version | Supported |
| :--- | :--- |
| Latest release | Yes |
| Anything older | No, upgrade first |

Fixes ship as a new release. There are no backport branches.

## Reporting a vulnerability

**[Open a draft advisory](https://github.com/kanywst/whosent/security/advisories/new)** on GitHub. That is the only channel; do not open a public issue.

Include what you can of:

- The version (`whosent version`, which also names the embedded Mandatum version) and the OS
- The token or chain, key documents, root key, authorizer and revocation list that trigger it, or `whosent demo --emit` output modified to reproduce it
- The exact command line
- What you expected versus what happened

What to expect:

- Acknowledgement within 7 days
- An assessment of whether it is in scope within 14 days
- A fix in a patch release, published together with a GitHub Security Advisory crediting you unless you would rather stay anonymous

## Scope

In scope:

- whosent reporting a chain as VALID, or a request as PERMITTED, that the format's own rules deny: a JWT with a bad signature, an expired token or a wrong audience; a Biscuit token whose signatures, proof or checks fail, or that the reference implementation would refuse; a UCAN chain whose signatures, alignment, command, policy or time bounds fail, or that the specification's fixtures say must be refused; a Mandatum chain the embedded reference verifier would deny. Exit codes are a contract scripts depend on
- A prior JWT actor, which only the issuer asserts, being shown or exported as verified
- Key material being taken from a token (`jku`, `x5u`, `x5c`, `jwk`) instead of from your flags or trust file
- A bug in the embedded Mandatum reference verifier (`internal/mandatum`) that accepts what the specification forbids. mandatum is archived, so whosent is where it gets fixed
- A rule that was not checked being shown, printed or exported as passing
- An answer labelled AUTHORITATIVE when it was not
- A chain, key document or revocation set reaching the terminal unescaped: escape sequences, OSC 52, bidi overrides, anything that can change what the screen shows
- whosent making a network request that you did not configure, or fetching a key document over plaintext
- A panic, hang, or unbounded allocation reached through any input
- `demo --emit` writing outside the directory it was given, or through a link

Out of scope, because it is the documented design:

- Reporting a chain as INVALID or INCOMPLETE. That is the tool working
- A simulated revocation or a scrubbed clock in the interactive view changing the verdict on screen. Both are labelled, and neither reaches `check` or `ask`
- Bugs in Go or in dependencies. Report those upstream; if whosent needs a version bump, a normal issue or PR is fine
