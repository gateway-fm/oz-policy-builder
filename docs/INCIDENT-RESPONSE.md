# Incident response and revocation

What to do when something a fielded grant relies on stops being trustworthy: a registry entry is
revoked, a delegate key may be compromised, a defect is found in the generator, or an upstream
component publishes an advisory. Reporting a vulnerability is [SECURITY.md](../SECURITY.md); the
registry procedure behind revocations is [Registry governance](REGISTRY-GOVERNANCE.md).

Two facts decide every case below:

- **Only the account owner can take authority back.** An installed grant is a context rule on the
  user's smart account. Removing it is `remove_context_rule`, authorized by the account's owner
  rule (in the wallet integration, the owner's passkey). Nothing in this project can remove it
  for the user, and nothing here needs Gateway to do so.
- **A registry revocation does not disable an on-chain grant.** It makes synthesis, the authority
  check, installed-rule prediction and recognition refuse the capability with
  `E_REGISTRY_REVOKED`. A grant already installed keeps working until its owner removes it, its
  expiry ledger passes or its call cap is spent.

The project's part — fixing, revoking, publishing advisories — is bounded to the grant period
(through Tranche 3, [architecture §10](architecture.md#10-delivery-plan)). What users and
operators do is the same during the grant and after it; [After the grant period](#after-the-grant-period)
says what changes.

## How to revoke a grant

- **Wallet integration.** `Prepare revocation`, then approve with the owner passkey
  ([Revocation](POLLYWALLET-INTEGRATION.md#revocation)). The wallet reports the rule `removed`
  only after the account's `context_rule_removed` event and a readback that the rule is gone;
  policy cleanup is reported separately. It is offered for installations made by the running
  backend session: a restarted backend cannot revoke a rule an earlier one installed
  ([After a restart](POLLYWALLET-INTEGRATION.md#after-a-restart)), and nothing else in this tree
  can have the wallet account's passkey sign a removal. Any tool that can have the owner sign
  `remove_context_rule` for the rule ID works; for a grant you may need to revoke in a hurry, keep
  the installing session running.
- **Testnet harness runs.** `node lifecycle.mjs --run-dir <run>` in `testnet-harness/scripts`: the
  owner signs the removal, so it needs the run's keys
  ([Running the parts](../testnet-harness/README.md#running-the-parts)).

Revoking a rule ends the grant; a replacement is a new review and a new installation with a fresh
call counter ([Revoke-first replacement](POLLYWALLET-INTEGRATION.md#revoke-first-replacement)).

## (a) A hash you rely on is revoked in the registry

**Detect it.** Watch every hash a grant relies on: the account's Wasm, each owner verifier's, each
reviewed policy's, and the target's code hash where a target adapter is bound to it.
`ozpb registry monitor` matches a watched hash against revoked `policy/`, `account/`, `verifier/`
and `target_adapter/` entries. A generated policy has no entry to match (it is recognized by its
reproduced build), and a template-family revocation (`template/<family>`) is not matched by hash:
it shows in the report's `head.revocations` and in the project's advisory.

The monitor compares the published registry with your checkpoint: the one in your roots file, or
the one `ozpb registry verify` printed when you accepted the snapshot. The development roots file
carries none, so for the development registry on testnet:

```bash
N="Test SDF Network ; September 2015"
# once, when you accept the snapshot:
ozpb registry verify --signed docs/examples/registry.signed.json \
  --registry-roots docs/examples/registry-roots.json --network "$N" > checkpoint.json
# then on a schedule, against the newest published copy:
ozpb registry monitor --published docs/examples/registry.signed.json --checkpoint checkpoint.json \
  --registry-roots docs/examples/registry-roots.json --network "$N" \
  --wasm-hash <account wasm hash> --wasm-hash <owner verifier wasm hash> \
  --wasm-hash <reviewed policy wasm hash> --wasm-hash <adapter-bound target wasm hash>
```

A governed registry is monitored the same way with `--published registry/<network>` (its log) and
your pinned roots. Exit `6` means a watched hash is revoked; the report names each with the
custodians' reason. Exit `1` means the published log cannot be verified against your checkpoint —
a fork, an equivocation, a rollback, or roots you have not pinned, each an incident in itself — and
also any other error, such as a missing checkpoint or an unreadable file, so read its message. The
other codes are in [Monitoring](REGISTRY-GOVERNANCE.md#monitoring).

**Act on it.**

| Revoked | What to do |
| --- | --- |
| A reviewed **policy** in an installed grant | Revoke the grant before the delegate uses it again. |
| An owner **verifier** | Revoking the grant does not help: the verifier authenticates the owner rule, which controls the account. Replace the owner signer with one on a recognized verifier, or move the funds to an account whose owner uses one. This tree's wallet integration offers neither, so use the account's own management. |
| The **account** build | Removing rules does not change the account's code. Move the funds to an account created on a recognized build, then stop using the old one. |
| A **target adapter** your grant's bounds came from | Revoke the grant; synthesize again (exact by default) if you still need it. |
| A **template family** | Revoke grants generated from it and install regenerated ones; see [(c)](#c-a-vulnerability-in-the-generator-or-its-templates). |

Then advance your checkpoint and floor to the version that carries the revocation
([Consumers](REGISTRY-GOVERNANCE.md#consumers-pinning-roots-and-persisting-checkpoints)); a
consumer whose floor is below it still accepts the older, unrevoked snapshot.

**Target code that changed without a revocation.** A rule binds an address, not code; the
generated policy does not inspect target code on-chain
([architecture §6.1](architecture.md#61-what-is-actually-guaranteed-authorization-minimal-vs-effect-minimal)).
If a grant's target contract is upgraded, the permitted calls may now do something else. The
spec records the target code hash observed at recording, when there was one. The wallet's
`Check installed grant now` compares the target's identity for the one grant shape it supports,
the native asset contract
([monitoring](POLLYWALLET-INTEGRATION.md#on-demand-installed-grant-monitoring)); for any other
target, compare its current code hash with the spec's yourself. On a change, revoke the grant.

## (b) An agent or delegate key may be compromised

The delegate key signs calls under the grant; the owner rule is the authority over the account.

1. **Revoke the grant** with the owner's signature ([above](#how-to-revoke-a-grant)). Do not wait
   to confirm misuse first.
2. **Check what else the key can do.** Before installation the authority check refused a grant
   whose delegate key could alone change the account or reset its policies
   (`E_DELEGATE_HAS_AUTHORITY`), but only as of the ledger it read. Run `Check installed grant
   now` in the wallet (or `ozpb check-installed-grant`) for rules added since; remove any you do
   not expect.
3. **Do not reuse the key.** Install any replacement grant for a new delegate.

Until the rule is removed, the generated policy still limits the key to the exact recorded calls
and approved widenings, the call cap per installation and the expiry ledger.

Where the key lives decides the exposure: in the wallet integration the automation key exists only
in the backend's memory and disappears when the backend stops; `ozpb dry-run` reads a delegate key
from a 0600 file and signs only offline-domain requests, but the key stays a live credential on its
own network ([SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim)). The agent
holds no key: a compromised agent session can at most deliver a draft the wallet regenerates and
the owner must approve. **Disconnect Claude** ends draft delivery; it does not revoke an installed
grant.

A compromised **owner** credential is outside this toolkit: the owner rule can change everything,
and recovery is the account's and the wallet's own. A compromised **registry custodian** key is
[Rotation, lost and compromised keys](REGISTRY-GOVERNANCE.md#rotation-lost-and-compromised-keys).

## (c) A vulnerability in the generator or its templates

During the grant period the project handles a report as [SECURITY.md](../SECURITY.md#after-a-report)
describes, on a best-effort basis with no promised response times: private advisory, assessment, a
fix with a failing test first, revocation where a registry entry exists, and a published advisory
with a release note.

What is specific to generated code:

- **Fielded policies are not patched.** Generated policies have no setter or upgrade entry point
  ([ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §8). A fix that changes what codegen emits
  changes every affected source and Wasm hash, so a grant built before it is replaced, not
  updated: revoke it, regenerate from the same recording and decisions, review, and install.
- **The advisory names what is affected**: the template family, the toolkit releases and the grant
  shapes (constraint kinds, compositions) that reach the defect. The spec and BuildManifest record
  the template family and the constraints, but not the generator's source revision
  ([SCOPE.md item 2](SCOPE.md#implementation-boundaries)), so keep a note of which release
  generated each grant you install.
- **A template family that is unsound is revoked** (`template/<family>`); a corrected template is a
  new family version, because a revocation is permanent.

## (d) An upstream advisory

Worked example: [GHSA-jpg9-m7w4-c7wc](https://github.com/OpenZeppelin/stellar-contracts/security/advisories/GHSA-jpg9-m7w4-c7wc),
published by OpenZeppelin on 20 October 2026. In `stellar-accounts` before 0.7.3 a `Delegated`
signer is approved without a signature when it is the direct invoker of the account's
`__check_auth`. The account this toolkit recognized, OpenZeppelin's 0.7.2 example, was in range,
and generated grants authorize through delegated signers.

What the project did, each recorded in the tree:

1. Moved the recognized account to OpenZeppelin's example built at v0.7.3, rather than 0.8.0,
   whose signed digest differs ([SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)).
2. Published development registry version 6: it recognizes the 0.7.3 account and revokes the 0.7.2
   entry with the advisory as its reason. The shipped configurations and documented commands use 6
   as the floor.
3. Redeployed what compiles in the account hash — the atomic live helper
   ([receipt](ATOMIC-LIVE-HELPER.md#current-helper-deployment-account-073)) — and re-recorded the
   protocol-30 target capture, which had come from a 0.7.2 account.
4. Recorded the change and the user action in [SECURITY.md](../SECURITY.md#upstream-advisories) and
   the [release notes](release-notes/v0.2.0.md#security), marked breaking.

What users had to do — raise the registry floor to 6 or persist a version-6 checkpoint, and
recreate accounts from the 0.7.3 code — is in [SECURITY.md](../SECURITY.md#upstream-advisories).

When an upstream fix cannot be adopted yet, the exposure is accepted explicitly with a scope and
an expiry instead, as for RUSTSEC-2026-0387 ([SECURITY-EXCEPTIONS.md](SECURITY-EXCEPTIONS.md)).

## After the grant period

After Tranche 3 there is no committed maintenance: no fixes, advisories or registry versions are
promised. Nothing a user needs to protect a grant depends on them:

- Revoking a grant is always the owner's own transaction.
- A governed registry's last published version expires on its own date; after that, synthesis
  and the checks refuse it
  ([Validity](REGISTRY-GOVERNANCE.md#validity-expiry-and-the-end-of-the-grant-period)). The
  development registry's snapshots carry no expiry.
- Any operator can pin its own root policy and run the same governance, monitoring and
  revocation procedure with its own custodians, from a genesis of its own.
- Upstream advisories are published by their own projects — OpenZeppelin, Stellar, RustSec.

Operators running this toolkit in an organisation map the procedures above to their own incident
process, for example ISO/IEC 27001:2022 Annex A 5.24–5.26 (incident management planning,
assessment of events, response). That mapping, and whether it is in an audit's scope, is the
operating organisation's decision; see
[Key custody and incident handling in an ISMS](REGISTRY-GOVERNANCE.md#key-custody-and-incident-handling-in-an-isms).
