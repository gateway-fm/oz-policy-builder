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

- **Wallet integration.** For a grant the running backend session installed, `Prepare
  revocation`, then approve with the owner passkey
  ([Revocation](POLLYWALLET-INTEGRATION.md#revocation)). After a restart, attach the account and
  use **Remove a grant an earlier session installed**: the wallet lists the account's rules as
  stored now and removes the one you choose, bound to its exact current bytes and approved with
  the same passkey ([Removing an earlier session's grant](POLLYWALLET-INTEGRATION.md#removing-an-earlier-sessions-grant)).
  Either way the wallet reports the rule `removed` only after the account's
  `context_rule_removed` event and a readback that the rule is gone; policy cleanup is reported
  separately. It removes only grant-shaped rules (one contract's calls, limited by at least one
  policy): the owner rule, a rule naming the owner's passkey and a `Default`-context or
  policy-less rule are refused. On mainnet the session spend cap never stops a removal; the
  per-transaction cap still applies. A send whose result is uncertain blocks every later write in
  that session, a removal included: look the transaction up, then start a new session. Any other
  tool that can have the owner sign `remove_context_rule` for the rule ID works too.
- **Testnet harness runs.** `node lifecycle.mjs --run-dir <run>` in `testnet-harness/scripts`: the
  owner signs the removal, so it needs the run's keys
  ([Running the parts](../testnet-harness/README.md#running-the-parts)).

Revoking a rule ends the grant; a replacement is a new review and a new installation with a fresh
call counter ([Revoke-first replacement](POLLYWALLET-INTEGRATION.md#revoke-first-replacement)).

## Watching an installed grant

A rule added to the account after installation can reach the grant's policy or the account
itself. `ozpb check-installed-grant` reads the account and compares it with what was installed:
the exact recorded rule, no rule allocated after it, and the modeled authority without the rule
against the `authority_commitment` the installation was approved against. Given that commitment
and a ledger floor, its exit status is the alert, so run it on a schedule like the
[registry monitor](REGISTRY-GOVERNANCE.md#scheduling-the-monitor):

```bash
ozpb check-installed-grant --request installed-grant.json --rpc-sources rpc-sources.json \
  --registry-roots grant-monitor-roots.json \
  --registry-min-version <the installation's registry version> \
  --recorded-authority-commitment <the installation's authority_commitment> \
  --min-ledger <installation ledger, then the last run's observed_ledger + 1>
```

The request is `{"candidate": …, "installed_rule": …}`: the `check-policy-call-surface` request
the installation was checked with, and the rule as the account stored it (`id`, `name`,
`context_contract`, `valid_until`, `signer_ids`, `policy_ids`). The commitment is the
`verdict.authority_commitment` of the install intent the installation was built from; the wallet
keeps it with its installation record. The JSON observation is printed either way.

**The ledger floor.** An endpoint that stopped ingesting keeps serving an old, consistent ledger,
which would read as unchanged on every run. `--min-ledger` refuses an observation of an older
ledger (exit 4): pass the installation's ledger on the first run, then one more than the
`observed_ledger` of the last run's JSON, so a ledger that does not advance is no answer. At a
ledger every five or six seconds, an hourly run may pass a floor several hundred higher.

**The registry version is the installation's.** The request's spec pins the exact registry
snapshot the installation was checked under, and the commitment covers its root. Under the
operator's shared roots file, once its checkpoint and floor advance (the registry monitor's
exit 3 asks for that), the check refuses that older snapshot as a rollback and every run exits 1.
So keep a separate roots file for monitoring, `grant-monitor-roots.json`: the keys that signed
the installation's snapshot, no checkpoint or one at that version, and `--registry-min-version`
at that version. It is used only by this read-only check; revocations in later versions are the
[registry monitor](#a-a-hash-you-rely-on-is-revoked-in-the-registry)'s to report. When that
snapshot expires, the check refuses it and exits 1 on every run: the watch has ended, and
watching again needs a new review and installation against a current snapshot.

| Exit | Meaning | Action |
|---|---|---|
| 0 | unchanged: the recorded rule, nothing allocated after it, and the recorded commitment | record `observed_ledger` for the next floor |
| 5 | inactive: the rule has expired and is otherwise unchanged | it authorizes nothing; remove it when convenient |
| 3 | changed: the rule, its signers or policies, a later rule, or the modeled authority (a new refusal or unresolved item included) | page; unless the change is the owner's own, [revoke the grant](#how-to-revoke-a-grant) and treat it as [(b)](#b-an-agent-or-delegate-key-may-be-compromised) |
| 4 | no answer: the read or the check refused, for an incomplete or archived state, code at the account, a policy or the target other than the recognized code, or an endpoint failure; or the observation is older than `--min-ledger` | read the error; an endpoint failure or a lagging endpoint can be run again (or another endpoint used), anything else is treated as 3 |
| 1 | an error before any read: configuration, request, registry trust (an expired or superseded snapshot included) or build | fix it; until then the grant is not watched |
| 2 | a usage error: a malformed commitment, or one of the two flags without the other | fix the command |

Any other non-zero status (a crash is 101) is an alert too. These codes are not the registry
monitor's: 3, 4 and 5 mean different things there, so each command needs its own handler.

Each run sees one ledger from one endpoint (`rpc_reported`): an entry archived and restored
between runs, or a change made and undone, is not observed. Unlike the wallet's
[on-demand check](POLLYWALLET-INTEGRATION.md#on-demand-installed-grant-monitoring), it does not
read the policy's installation marker. A legitimate later rule counts as changed, as it does in
the wallet. Without the commitment and the floor any observation exits 0, which is what the
wallet expects; never schedule it that way.

## (a) A hash you rely on is revoked in the registry

**Detect it.** Watch everything a grant relies on: with `--wasm-hash`, the account's Wasm, each
owner verifier's, each reviewed policy's, and the target's code hash where a target adapter is
bound to it; with `--template`, the template family of each generated policy (its spec's
`template_family`). `ozpb registry monitor` matches a watched hash against revoked `policy/`,
`account/`, `verifier/` and `target_adapter/` entries, and a watched family against revoked
`template/<family>` entries. A generated policy has no entry of its own: it is recognized through
its family and by rebuilding it, so the family's revocation reaches every build of it. A
revocation of one build's hash (`policy/<hash>`) is refused by recognition too, but that hash
cannot be watched in advance: the head registers nothing under it until a revocation names it, so
watch the family. A watch item the head neither registers nor revokes, a typo above all, is
refused with exit `1` and named.

The monitor compares the published registry with your checkpoint: the one in your roots file, or
the one `ozpb registry verify` printed when you accepted the snapshot. The development roots file
carries none, so for the development registry on testnet (the commands call `ozpb` from your
`PATH`; in a checkout built with the [tester quickstart](TESTER-QUICKSTART.md), use
`target/debug/ozpb`):

```bash
N="Test SDF Network ; September 2015"
# once, when you accept the snapshot:
ozpb registry verify --signed docs/examples/registry.signed.json \
  --registry-roots docs/examples/registry-roots.json --network "$N" > checkpoint.json
# then on a schedule, against the newest published copy:
ozpb registry monitor --published docs/examples/registry.signed.json --checkpoint checkpoint.json \
  --registry-roots docs/examples/registry-roots.json --network "$N" \
  --wasm-hash <account wasm hash> --wasm-hash <owner verifier wasm hash> \
  --wasm-hash <reviewed policy wasm hash> --wasm-hash <adapter-bound target wasm hash> \
  --template policy-templates/scope@1
```

A governed registry is monitored the same way with `--published registry/<network>` (its log) and
your pinned roots. Exit `6` means a watched hash or template family is revoked; the report names
each with the custodians' reason. Exit `1` means the published log cannot be verified against
your checkpoint — a fork, an equivocation, a rollback, or roots you have not pinned, each an
incident in itself — and also any other error, such as a missing checkpoint or an unreadable file,
so read its message. The other codes are in [Monitoring](REGISTRY-GOVERNANCE.md#monitoring).

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

Where the key lives decides the exposure. On testnet the wallet's automation key exists only in the
backend's memory and disappears when the backend stops. On mainnet the delegate is the agent's own
key: the wallet backend reads it from the operator's 0600 file (`delegateKeyPath`) and holds it in
memory, and that file, like every other copy the agent keeps, stays a live credential after the
backend stops. `ozpb dry-run` reads a delegate key from a 0600 file and signs only offline-domain
requests, but the key stays a live credential on its own network
([SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim)). The Claude session
and the MCP server hold no key: a compromised agent session can at most deliver a draft the wallet
regenerates and the owner must approve. **Disconnect Claude** ends draft delivery; it does not
revoke an installed grant.

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
   the [release notes](release-notes/v1.0.0.md#security), marked breaking.

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
