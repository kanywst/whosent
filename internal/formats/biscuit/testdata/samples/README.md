# Biscuit specification samples

These are the sample tokens of the Biscuit specification, copied unchanged from [eclipse-biscuit/biscuit](https://github.com/eclipse-biscuit/biscuit) at commit `b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639` (`samples/current`). They are licensed under the Apache License 2.0; see [LICENSE](LICENSE).

`samples.json` records, for each `.bc` token, every block's source as the reference implementation prints it, the authorizer code each case runs, and the result the reference implementation produced. The tests in the parent package check whosent's decoder, verifier, printer and Datalog engine against all of it.

The tokens are signed with the fixed root key in `samples.json` and carry no expiry that matters at test time, which is why they can be committed where whosent's own demo tokens are minted on every run.
