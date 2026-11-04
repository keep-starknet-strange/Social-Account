# Security

This is a proof of concept. It has had one external review of the Cairo contracts
(issues #1 and #2) and is not audited for production use. Do not hold real funds in
accounts deployed from it.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository
and choose **Report a vulnerability**. You will get an acknowledgement within five working
days. Please include the affected commit, the steps to reproduce, and the impact you see.

There is no bug bounty.

## Scope

* `social_account/`: the `SocialAccount`, `JwkRegistry` and `ProverExecutor` contracts.
* `backend/`: the recover API, the relay and the JWK rotator.
* `client/`: the SDK and the demo app.

The vendored browser prover under `client/public/prover/` is upstream code; report problems
in it to [starknet-innovation/snip-36-prover-wasm](https://github.com/starknet-innovation/snip-36-prover-wasm).

## Known limitations

The README's *Trust assumptions* section and its *Open item* notes describe what the design
does not protect against, including that a dApp's OAuth client can recover the accounts under
its `aud` with no delay, that the registry roles are a trust root, and that deployed accounts
cannot be upgraded. Reports that restate those are welcome as design discussion, not as
vulnerabilities.
