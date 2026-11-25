# Soroban dependency compatibility

Generated policies and the contracts test workspace pin **soroban-sdk 28.0.0** and
**stellar-accounts 0.8.0**. This is the SDK major required by the published OpenZeppelin
0.8.0 release. The execution runtime separately pins SDK 30.0.0-rc.1 and stable host 30.0.0 because its source
snapshots and admission checks target protocol 30. The root CLI/MCP graph has no Soroban host.

These are distinct compatibility boundaries:

| Component | Version | Meaning |
| --- | --- | --- |
| Newly generated policy source and Wasm | SDK 28.0.0, accounts policy library 0.8.0 | Policy `enforce`, `install`, `uninstall`, signer and context-rule wire types |
| Native contracts differential tests | SDK 28.0.0, accounts library 0.8.0 | Current native account-library implementation; delegated authentication is mocked in the generated-suite fixtures |
| Recognized deployed account Wasm | OpenZeppelin 0.7.3 example account, exact code hash | Storage reader, method inventory, wallet signing and authorization protocol (all unchanged from 0.7.2) |
| Recognized verifier and spending-limit policy Wasm | OpenZeppelin 0.7.2, existing exact code hashes | Owner key schemes and the prediction model's policy |
| Isolated native execution | SDK 30.0.0-rc.1 / host 30.0.0 | Runs actual account and generated-policy Wasm under protocol 30 |

The policy interface is not the account signing protocol. OpenZeppelin 0.8.0 changes
account authentication: external signatures bind the account-address-bearing
`AuthDigestPreimage`, and delegated signers authorize that preimage struct. The recognized
0.7.3 account uses the prior digest encoding, as 0.7.2 did. This dependency update does **not**
add recognition or wallet signing support for a 0.8 account. Unknown account code remains refused.
Do not change the old account/verifier/spending-policy trust anchors or historical run evidence
to make a newly built library appear compatible.

Newly generated artifacts have new dependency metadata, source manifests and Wasm hashes.
Current verification regenerates with the current pins: an SDK 26 artifact must not be
relabeled or accepted as an SDK 28 reproduction. Use its original recorded repository
revision to reproduce historical artifacts; regenerate and review proposals intended for
new installation. Existing installed Wasm is not upgraded by changing these dependencies.

The 0.8 spending-limit helper also changes behavior: it caps history at 815 entries and
permits zero transfers before checking an already exceeded budget. The production prediction
model continues to describe the exact recognized 0.7.2 policy. Its boundary/capacity parity
tests therefore execute that hash-checked Wasm in the pinned-account gate, rather than treating
the new native library as a substitute. Separate native tests pin these intentional differences.

The required cross-version proof is `scripts/test-pinned-account-authorization.sh`: newly
built policy Wasm must run through the exact recognized 0.7.3 account Wasm, including signed
delegate authorization, forged-signature refusal, persistent counters, rollback and the
state-invariant suite. The native 0.8 mock-account tests and shared XDR vectors supplement
that proof. They cannot replace it. The `nightly-live.yml` workflow also runs this gate
on pull requests changing the spending evaluator, policy generator/specification, contract
source/tests, native execution runtime, dependency locks/manifests or recorded gate inputs. The two parity tests must actually run and pass;
scheduled/dispatch checks remain a backstop, not their only execution opportunity. A dependency change also requires reviewing changed
policy, helper and target fixture Wasm hashes, byte reproducibility, and fresh testnet evidence
at the delivered revision. Passing ordinary PR CI alone is insufficient for release.

## Account 0.7.3 (GHSA-jpg9-m7w4-c7wc)

[GHSA-jpg9-m7w4-c7wc](https://github.com/OpenZeppelin/stellar-contracts/security/advisories/GHSA-jpg9-m7w4-c7wc)
(published 20 October 2026, medium): in `stellar-accounts` before 0.7.3, the host approves a
`Delegated` signer without any signature when the delegated address is the direct invoker of
the account's `__check_auth`. That is the case when the delegate is the contract requesting the
account's authorization, and when delegation loops back (self, mutual, or a chain into a mutual
pair). Whatever such a rule covers is then callable by anyone. The fix is in 0.7.3 and 0.8.0, and
OpenZeppelin's guidance is to upgrade and redeploy.

The recognized account is therefore OpenZeppelin's `examples/multisig-smart-account/account`
built at tag v0.7.3 (`252b35fe1a39fc524499e97d43cfe4598247a4cd`), with the same rustc 1.91.1,
stellar-cli 27.0.0 and Apple Silicon build host as before (`ozpb_domain::pinned_upstream`,
`scripts/verify-pinned-upstream.sh`). 0.7.3 rather than 0.8.0, because 0.8.0 changes the signed
digest (above) and 0.7.3 does not. The v0.7.2→v0.7.3 diff changes only
`packages/accounts/src/smart_account/{mod,storage}.rs`, tests, documentation and package
versions:

- `do_check_auth` refuses a `Delegated` signer whose address is the contract of any context
  being authorized (`DelegatedSignerIsContextContract`, 3017), before authenticating it;
- `add_context_rule` (and so the constructor), `add_signer` and `batch_add_signer` refuse a
  signer `Delegated` to the account itself (`SelfDelegatedSigner`, 3018);
- the digest (`sha256(signature_payload ‖ context_rule_ids.to_xdr())`), the storage keys and
  types, the wrapper contract and its 17 exports are unchanged, so wallet signing, the storage
  reader and the [method inventory](ACCOUNT-METHOD-INVENTORY.md) carry over. The method table's
  digest is the same; it is now bound to the 0.7.3 hash only.

Development registry version 6 recognizes the 0.7.3 account and revokes the 0.7.2 entry with the
advisory as its reason; versions 1 to 5 are unchanged and still recognize the 0.7.2 build. A
caller can supply its own signed snapshot, so the revocation binds only under a floor of 6
(`OZPB_REGISTRY_MIN_VERSION`, `--registry-min-version`, the wallet's `registryMinimumVersion`)
or a persisted version-6 checkpoint; the shipped configurations and documented commands use 6. The atomic live helper compiles in the
account hash, so its Wasm hash moved with it and the wallet's helper pin moved too. The
spending-limit policy and both verifiers keep their 0.7.2 builds: their sources are identical
at both tags.

On 19 November 2026 the 0.7.3 account code was already on testnet: its code entry read back
with exactly these bytes, live until ledger 8766158 at ledger 5805327, so nothing was uploaded.
The helper was redeployed on the new pin ([receipt](ATOMIC-LIVE-HELPER.md#current-helper-deployment-account-073)),
and the recorded protocol-30 target capture was re-recorded from that run's 0.7.3 account; the
earlier capture came from a 0.7.2 account, which execution now refuses.

The fix runs in the account that authorizes back, so it protects an account only when the
accounts it delegates to are also 0.7.3. OpenZeppelin documents two delegation-back cases the
check cannot see: a delegate that reaches this account through CAP-71 `delegate_auth`, and one
that calls `require_auth` on it from its own `__check_auth`. Both need a contract as the
`Delegated` signer. The authority check already refuses any contract signer, by name
(`UnsupportedReason::ContractSigner`), on the new grant rule and on every rule that reaches the
account's management surface, a bound policy or the grant's target. Rules outside that scope
are not read. The harness, the demo and the wallet name a classic `G…` account as the grant's
`Delegated` signer.

An account already deployed with the 0.7.2 code is not upgraded by any of this. The registry
resolves it as revoked, and execution and the wallet accept only the pinned code; recreate it
from the 0.7.3 code.

## Protocol 30 compatibility

The CLI/MCP decoder uses stable stellar-xdr 30.0.0. It accepts acquisition protocols through
30 and refuses future protocols; the acquisition protocol is the endpoint's current protocol,
not an assertion of a historical transaction's execution protocol. The execution/capture worker
accepts only source protocol 30. Protocol-29 captures and jobs remain historical evidence and
are not relabelled for host 30; record fresh captures for current execution.

CAP-88 headers carry millisecond extensions. Both Rust and wallet SDKs decode them while
preserving whole-second close-time semantics; advancing ledgers need not advance whole seconds.
Muxed contract addresses (`W…`, CAP-84) remain unsupported: recording refuses them and exact
plain-address constraints do not normalize them into an allowed address.

The worker's release-candidate SDK is off-chain only. The generated policy/helper SDK 28.0.0,
OpenZeppelin pins, CLI 27.0.0 build pin and recognized account/verifier Wasm are unchanged.
The stable SDK 30.0.0 requires host 30.0.1, outside the inventory reviewed for the
[advisory exception](SECURITY-EXCEPTIONS.md). Moving the worker to it needs that exception
reassessed for the new host and its compatibility gates repeated; until then it stays on the
release candidate. Current
contracts continue to run on protocol 30; the host migration does not upgrade installed code.
The wallet backend/harness use JavaScript SDK 17.4.0; the applied Pollywallet root is pinned
with its lockfile to SDK 16.4.1, which also decodes protocol-30 headers.

Recording decoder identity is checked. Older RPC recordings made by the XDR-28 build require
fresh acquisition while RPC retains the transaction, or an explicit self-supplied raw-XDR
import. Do not change decoder metadata to make an old acquisition appear current. Reacquisition
can change recording/spec hashes; it does not by itself change generated Wasm permissions.

[Protocol 30 validation](PROTOCOL-30-VALIDATION.md) records the automated gates and fresh
testnet observations separately from the historical Protocol-29 evidence.

Sources: [SDF Bell upgrade guide](https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide),
[SDK 30 release candidate](https://github.com/stellar/rs-soroban-sdk/releases/tag/v30.0.0-rc.1),
[CAP-88](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0088.md).

## Live-helper rollout

The SDK update also changes the helper's built Wasm hash. The wallet's reviewed helper pin
and the native execution test pin move together. Existing historical testnet receipts retain
their original hash; they are not evidence for the new helper build. Deploy the new source-built
helper with `testnet-harness/scripts/deploy-live-helper.mjs`, verify its readback receipt, and
configure the wallet server with that new address before repeating live-layer checks.
The manually dispatched `nightly-live.yml` workflow accepts `helper_probe=true` to run this
probe after the pinned-account gates; its public receipt is retained in the job log. It uses
throwaway automation keys, not wallet consent or human approval. A server
still configured with an old helper address is refused by the new hash check. No installed
account or policy is automatically upgraded by this rollout.

## Security follow-up

This update does **not** resolve [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
As checked through 30.0.0 on 28 October and 11 November, and through 30.0.1 on 25 November 2026, the published Soroban hosts still require
elliptic-curve 0.13 / crypto-bigint 0.5.5. The advisory's fixed range begins at 0.7.6;
a direct update to that version cannot satisfy the old dependency requirement. No unsupported
cryptographic fork is introduced here.

The [temporary exception](SECURITY-EXCEPTIONS.md) stays bounded by the expiry recorded there.
[Issue #94](https://github.com/gateway-fm/oz-policy-builder/issues/94) remains open until all
affected native/test graphs use a compatible fixed chain, the audits pass without the ignore,
and the exception can be removed. A full account 0.8 migration additionally needs explicitly
versioned signing, registry, storage, wallet and testnet compatibility coverage.

Sources: [OpenZeppelin 0.8 release](https://github.com/OpenZeppelin/stellar-contracts/releases/tag/v0.8.0),
[account migration guide](https://github.com/OpenZeppelin/stellar-contracts/blob/v0.8.0/packages/accounts/README.md),
[Soroban host 30 manifest](https://github.com/stellar/rs-soroban-env/blob/v30.0.0/soroban-env-host/Cargo.toml).
