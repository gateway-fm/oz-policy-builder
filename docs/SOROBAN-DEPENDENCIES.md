# Soroban dependency compatibility

Generated policies and the contracts test workspace pin **soroban-sdk 28.0.0** and
**stellar-accounts 0.8.0**. This is the SDK major required by the published OpenZeppelin
0.8.0 release. The execution runtime separately pins SDK/host 29.0.1 because its source
snapshots and admission checks target protocol 29. The root CLI/MCP graph has no Soroban host.

These are distinct compatibility boundaries:

| Component | Version | Meaning |
| --- | --- | --- |
| Newly generated policy source and Wasm | SDK 28.0.0, accounts policy library 0.8.0 | Policy `enforce`, `install`, `uninstall`, signer and context-rule wire types |
| Native contracts differential tests | SDK 28.0.0, accounts library 0.8.0 | Current native account-library implementation; delegated authentication is mocked in the generated-suite fixtures |
| Recognized deployed account and verifier Wasm | OpenZeppelin 0.7.2, existing exact code hashes | Existing storage reader, method inventory, wallet signing and authorization protocol |
| Isolated native execution | SDK/host 29.0.1 | Runs actual account and generated-policy Wasm under protocol 29 |

The policy interface is not the account signing protocol. OpenZeppelin 0.8.0 changes
account authentication: external signatures bind the account-address-bearing
`AuthDigestPreimage`, and delegated signers authorize that preimage struct. Existing
0.7.2 accounts use the prior digest encoding. This dependency update does **not** add
recognition or wallet signing support for a 0.8 account. Unknown account code remains refused.
Do not change the old account/verifier/spending-policy trust anchors or historical run evidence
to make a newly built library appear compatible.

The required cross-version proof is `scripts/test-pinned-account-authorization.sh`: newly
built policy Wasm must run through the exact recognized 0.7.2 account Wasm, including signed
delegate authorization, forged-signature refusal, persistent counters, rollback and the
state-invariant suite. The native 0.8 mock-account tests and shared XDR vectors supplement
that proof. They cannot replace it. A dependency change also requires reviewing changed
policy, helper and target fixture Wasm hashes, byte reproducibility, and fresh testnet evidence
at the delivered revision. Passing ordinary PR CI alone is insufficient for release.

## Security follow-up

This update does **not** resolve [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
As checked on 28 October 2026, the published Soroban hosts through 30.0.0 still require
elliptic-curve 0.13 / crypto-bigint 0.5.5. The advisory's fixed range begins at 0.7.6;
a direct update to that version cannot satisfy the old dependency requirement. No unsupported
cryptographic fork is introduced here.

The [temporary exception](SECURITY-EXCEPTIONS.md) retains its **10 November 2026** expiry.
[Issue #94](https://github.com/gateway-fm/oz-policy-builder/issues/94) remains open until all
affected native/test graphs use a compatible fixed chain, the audits pass without the ignore,
and the exception can be removed. A full account 0.8 migration additionally needs explicitly
versioned signing, registry, storage, wallet and testnet compatibility coverage.

Sources: [OpenZeppelin 0.8 release](https://github.com/OpenZeppelin/stellar-contracts/releases/tag/v0.8.0),
[account migration guide](https://github.com/OpenZeppelin/stellar-contracts/blob/v0.8.0/packages/accounts/README.md),
[Soroban host 30 manifest](https://github.com/stellar/rs-soroban-env/blob/v30.0.0/soroban-env-host/Cargo.toml).
