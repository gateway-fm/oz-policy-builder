# Temporary Soroban advisory acceptance

This is explicit risk acceptance for [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
not a fix to crypto-bigint or a claim of constant-time execution. It requires acceptance by
the maintainer approving the change. IvanBelyakoff owns reassessment and removal, tracked
in [issue #94](https://github.com/gateway-fm/oz-policy-builder/issues/94).

The exception expires at **2026-11-10 00:00 UTC**. The required supply-chain gate refuses an
expired exception and refuses changes to the reviewed affected packages or their direct
dependents in any of the three workspace lockfiles. Other advisory, source and license
failures remain failures. The root workspace's reviewed affected-package inventory is empty;
introducing this dependency there also causes refusal. All six cargo-deny audits use
`--locked`, so metadata resolution cannot silently replace a reviewed lockfile after
the inventory check.

## Reviewed scope

The application baseline is public revision `c25aa212e1413f44df9f81c3cbdd42f7e07f98b5`.
Independent source review covered:

| Workspace | Dependency path |
| --- | --- |
| Contracts, native tests | soroban-sdk 26.1.0 → soroban-env-host 26.1.3 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5 |
| Native execution | soroban-sdk / soroban-env-host 29.0.1 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5 |
| Root CLI/MCP | No crypto-bigint dependency in the locked graph |

The affected native arithmetic is reachable. Host production call sites in both versions
parse signatures, verify P256 signatures and recover secp256k1 public keys; no operation
receiving an ECDSA private key was identified. See the respective host crates'
`src/crypto/mod.rs:99–260` and `src/host.rs` verification/recovery entry points. ECDSA
0.16.9 `src/hazmat.rs:270–291` and `src/recovery.rs:281–315` derive verification/recovery
scalars from signatures and digests. Repository signing uses ed25519-dalek instead.

The native runtime dependency is **not test-only**. ECDSA signing features are enabled
transitively even though no project signing call site was found. Offline Wasm normal/build
graphs for the contract workspace and both generated policies contain no crypto-bigint;
that does not remove the native runtime dependency.

## Limits and removal

This review does not prove constant-time execution, exclude disclosure of confidential
offline inputs, or establish absence of every possible side channel. No timing study,
machine-code analysis or exhaustive dynamic reachability proof was performed. The risk
accepted is continued use of the vulnerable upstream package under the reviewed usage.

The advisory's published fixed range begins at 0.7.6; the pinned elliptic-curve 0.13.8
dependency requires crypto-bigint 0.5.x. A direct lockfile bump cannot satisfy it. An
unreviewed cryptographic backport or a changed Soroban host would require a separate
compatibility and security review.

Remove the exception as soon as a compatible fixed dependency chain is available. Reassess
before any new secret-scalar use, cryptographic signing/ECDH use, dependency change or
expiry extension. The lock inventory guard detects dependency changes; it does not inspect
source semantics or prove that future application changes preserve this review.

`scripts/advisory-exception.json` records the expiry, responsibility and normalized lock
inventories. `scripts/check-advisory-exception.py` enforces those bounds before the required
gate runs cargo-deny. Removing this advisory from `deny.toml` restores its normal failure
behavior; remove the associated metadata when retiring the exception.
