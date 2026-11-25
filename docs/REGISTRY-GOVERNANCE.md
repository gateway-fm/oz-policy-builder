# Registry governance

The capability registry is a security root ([architecture §4.10](architecture.md#410-capability-registries-and-recognition-paths)):
synthesis, the live authority checks, installed-rule prediction and dry-run preparation all
recognize code only through a signed snapshot that verifies under roots the operator pinned. This
document is the procedure around those roots — who holds them, how a version is made, signed,
published and checked, how consumers pin and monitor it, what a revocation does, and what happens
when a snapshot's validity ends. The commands are `ozpb registry …`; the logic behind them is
`ozpb_registry::governance`, which applies exactly the checks a consumer's load applies.

What the code enforces, independent of this procedure:

- A **root policy** is a threshold and a map of key ids to Ed25519 public keys. A snapshot loads
  only with at least the threshold of valid signatures, every signature from a pinned key.
  Malformed or weak keys and unmeetable thresholds are refused as `E_REGISTRY_ROOT_POLICY`.
- The public **development root** (`docs/examples/registry-roots.json`) is refused for every
  network but testnet, by every consumer, with `E_REGISTRY_ROOT_POLICY`: anyone can sign with it.
- **Versions chain**: a consumer accepts a successor only with a higher `version`, the next
  `log_index` (exactly one more) and its parent's root in `previous_root`. A consumer's persisted
  floor or checkpoint refuses an older snapshot (`E_REGISTRY_ROLLBACK`), and a checkpoint refuses
  a different snapshot for the same version or one that does not directly extend it
  (`E_REGISTRY_TRANSPARENCY`). The tooling is stricter than a consumer: `successor` always
  produces exactly the next version, and `verify --replay` requires a published log to start at
  version 1, log index 1 with no parent and to count up by one.
- **Revocations are append-only**: a successor cannot remove or rewrite one.
- Every snapshot has a signed **validity interval**; outside it, it is refused
  (`E_REGISTRY_EXPIRED`).

## Roles

- **Custodians** each hold one Ed25519 key, pinned under a key id. The policy is m-of-n: at least
  2-of-3, held by different people on different devices, so that no one person can sign and the
  loss of one key does not stop the registry. A custodian key is used for registry roots and
  nothing else — never a key that also controls a Stellar account, because the signature is over
  32 raw bytes.
- A **release coordinator** prepares change sets, builds successors, collects signatures, combines
  them, verifies and publishes. The coordinator holds no key and needs no trust: the signatures
  are what a consumer checks.
- **Consumers** — operators of the CLI or an MCP server, wallet integrators — pin the root policy
  out of band, persist a checkpoint, and monitor the published log.

## Key ceremony

1. Each custodian, on their own machine, creates a key:

   ```bash
   ozpb registry keygen --out custodian-a.key --key-id custodian-a
   # {"public_key": "<64 hex>", "key_id": "custodian-a"}
   ```

   The file is new (an existing one is never replaced), mode 0600, and holds a Stellar secret
   seed (`S…`); the secret is never printed. A custodian who keeps the key on a hardware device
   instead exports only its Ed25519 public key, as 64 hex characters.
2. Each custodian sends their key id and public key to the coordinator, and confirms the hex over
   a second channel (voice or in person). A public key that arrives by one channel only is not
   pinned.
3. The coordinator writes the root policy:

   ```json
   {"threshold": 2, "keys": {"custodian-a": "<hex>", "custodian-b": "<hex>", "custodian-c": "<hex>"}}
   ```

   and publishes it as `registry/<network>/roots.json` and as a release asset.
4. The ceremony is recorded: who holds which key id, on what kind of device, where backups are,
   and the date. The record is the operating organisation's, not this repository's.

## Making and signing a version

**Genesis.** Version 1 starts from an unsigned `RegistrySnapshot` (`version` 1, `log_index` 1,
`previous_root` null), reviewed entry by entry. Its `valid_from_unix` and `expires_at_unix` are set
by the custodians before anyone signs: the interval is part of what they sign
([how long](#validity-expiry-and-the-end-of-the-grant-period)). So is every review reference: one
still beginning `PENDING, replace before signing:` is replaced with the completed review's
reference first, because `sign` refuses a snapshot that holds one, as `combine` and `verify` do.
The mainnet draft's template pack carries one, which names OpenZeppelin's documented review of
the generated code ([review record](OZ-REVIEW-PACKAGE.md#review-record)), so the mainnet ceremony
signs once that sign-off and the owner's acceptance are recorded, without waiting for the audit.
After the audit, and before or with 1.0.0, the custodians sign a successor whose template-pack
reference adds the audit report, whether or not the remediation changed the template pack
([the order for 1.0.0](VERSIONING.md#the-order-for-100)).

**Successor.** Every later version is built from the published parent and a declared change set:

```json
{
  "schema": "registry-change/v1",
  "valid_from_unix": 1800000000,
  "expires_at_unix": 1815552000,
  "accounts": {"<64-hex wasm hash>": {"release": "…", "rule_enumeration": "bounded_next_id", "…": "…"}},
  "revocations": {"policy/<64-hex wasm hash>": "why, in one sentence a user can act on"}
}
```

`policies`, `accounts`, `verifiers`, `target_adapters` and `templates` add or replace whole entries;
`revocations` adds new ones, effective at the successor's version. The validity interval is always
declared.

```bash
ozpb registry successor --parent registry/mainnet/v0001.signed.json --changes changes.json \
  --registry-roots registry/mainnet/roots.json \
  --network "Public Global Stellar Network ; September 2015" --out v0002.unsigned.json
```

It load-verifies the parent under the pinned roots and network, then puts the successor through
every check a consumer's load applies except the signatures that do not exist yet. A successor a
consumer would refuse — an interval that is inverted or already over, a malformed key, a hash
under two roles, an empty revocation reason, a rewritten revocation — is never written.

**Review.** Each custodian checks what they are about to sign:

```bash
ozpb registry sign --snapshot v0002.unsigned.json --print-root
# {"root": "…", "network_id": "…", "version": "2", "log_index": "2", "previous_root": "…",
#  "valid_from_unix": "…", "expires_at_unix": "…", "revocations": […], "pending_review": []}
```

and diffs the unsigned file against the parent. The root is the canonical hash of the whole
snapshot; signing it signs every entry, the network, the chain position and the interval.
`pending_review` must be empty: it lists every entry whose review reference still begins
`PENDING, replace before signing:`, and while it does not, a warning on stderr says the root is
for review only.

**Sign.** With a local key file (mode 0600, refused otherwise):

```bash
ozpb registry sign --snapshot v0002.unsigned.json --key-id custodian-a \
  --key-file custodian-a.key --out v0002.custodian-a.sig.json
```

With a key that never leaves a device: sign the 32 bytes the printed `root` hex decodes to — the
raw bytes, not the hex text — with Ed25519 on the device, and hand the result in:

```bash
ozpb registry sign --snapshot v0002.unsigned.json --key-id custodian-c \
  --public-key <64 hex> --signature <128 hex> --out v0002.custodian-c.sig.json
```

A signature that does not verify over that root under that public key is refused here. Both
forms refuse a snapshot that still carries a pending review reference (`E_REGISTRY_PARSE`, naming
the entry), so a draft is corrected before any custodian's signature is spent on it rather than
at combine. A device signs whatever root it is given before the hand-in can refuse, so a device
custodian checks `pending_review` first. The refusal belongs to these commands: a consumer's load
checks signatures, not review references, so signatures over a pending root assembled some other
way would load.

**Combine.**

```bash
ozpb registry combine --snapshot v0002.unsigned.json \
  --signature v0002.custodian-a.sig.json --signature v0002.custodian-c.sig.json \
  --registry-roots registry/mainnet/roots.json \
  --network "Public Global Stellar Network ; September 2015" \
  --out registry/mainnet/v0002.signed.json
```

Every signature must be over this snapshot's root, verify, and come from the key pinned under its
id; together they must meet the threshold, and no review reference may still begin
`PENDING, replace before signing:` (`sign` and `verify` refuse one too). The result is then
loaded as a consumer would load it — pinned roots, network, an interval not already over — and
only then written, so the log directory never receives a file `verify` would refuse. Its place in
the chain is the replay's to check.

**Verify before distributing.** The gate is a replay of the whole published log:

```bash
ozpb registry verify --replay registry/mainnet --registry-roots registry/mainnet/roots.json \
  --network "Public Global Stellar Network ; September 2015"
# prints the head checkpoint: {"version", "log_index", "root", "revocations"}
```

Every `vNNNN.signed.json` must load as the direct successor of the one before it, from a genesis,
and the head must be valid now (`--at <unix seconds>` checks a scheduled one). One snapshot can
be checked against a consumer's checkpoint with `verify --signed <file> --checkpoint <file>`
(without `--checkpoint`, the roots file's own). Add `--min-version <floor>` to check it under the
consumer's floor as well: a checkpoint older than the floor is refused with `E_REGISTRY_ROLLBACK`,
as a consumer configured that way refuses every request. Unlike `--registry-min-version`, it has
no environment fallback, and no `ozpb registry` command reads its roots from
`OZPB_REGISTRY_ROOTS_FILE` either: a floor belongs to one roots file and network, these commands
take theirs on the command line — two different roots files across a
[rotation](#rotation-lost-and-compromised-keys) — and the environment holds whichever deployment
the shell is configured for. Pass the floor that goes with the roots file you name.

## Publishing

- **Repository.** `registry/<network>/` holds `roots.json` and one `vNNNN.signed.json` per
  version, four or more digits, each file's number equal to the version inside it. A published
  file is never edited: a correction is a new version. Drafts, unsigned successors and detached
  signatures are working files, not log entries; `verify --replay` and `monitor` read only
  `v*.signed.json`.
- **Release assets.** Each release that changes the registry attaches the new head
  `vNNNN.signed.json`, `roots.json` and the head checkpoint `verify --replay` printed.

In this repository, [`registry/mainnet/`](../registry/mainnet/README.md) holds the draft,
unsigned mainnet genesis and a placeholder root policy with no keys, which every command refuses
until the key ceremony fills it. Nothing for mainnet is signed yet.

The repository history is the transparency log: append-only, and anyone can replay it. There is
no separate equivocation detector. A consumer's checkpoint already refuses a different snapshot
for a version it has accepted, so a published log that disagrees with what a consumer accepted
fails that consumer's monitor loudly.

## Rehearsing on testnet

The whole procedure runs on testnet with throwaway keys before any mainnet ceremony: generate
three keys with `keygen`, write a 2-of-3 `roots.json`, take `registry/mainnet/v0001.draft.json`,
change its `network_id` to testnet's, set a current interval and replace its pending review
reference (with one that claims no review: a rehearsal is not one), then sign, combine, replay,
build and sign a successor, and monitor exactly as above with
`--network "Test SDF Network ; September 2015"`. Synthesis then accepts the replayed head under
those roots and stamps its root into the spec, as every command that pins registry trust would,
and as they would the mainnet log under the custodians' roots. The CLI test
`crates/cli/tests/registry_governance_cli.rs` runs this rehearsal end to end, one signature made
outside the CLI as a hardware key would.

## Consumers: pinning roots and persisting checkpoints

Roots are configuration, never request data: `--registry-roots` for the CLI,
`OZPB_REGISTRY_ROOTS_JSON` for the MCP server ([developer guide](DEVELOPERS.md#build-configuration-operator-side)).
Take them from the release and check them against the custodians' published key ids. The roots
file may carry the durable checkpoint:

```json
{"threshold": 2, "keys": {"…": "…"}, "checkpoint": {"version": "2", "log_index": "2", "root": "…", "revocations": {}}}
```

with the floor (`--registry-min-version`, `OZPB_REGISTRY_MIN_VERSION`) at the same version. To
move to a new version: monitor (below) or `verify --signed <new> --checkpoint <current>`, then
write the printed checkpoint into the roots file and raise the floor. Without a persisted
checkpoint or floor, a restarted consumer would accept an older, correctly signed snapshot.

### Where trust is checked

Registry trust is enforced where a registry decides something: synthesis, the live authority
check, the install intent and unsigned assembly, installed-rule prediction and dry-run
preparation all load the snapshot under the pinned roots. `generate` and `verify` take no registry
trust, by design: they carry the root the spec names into the BuildManifest without checking it.
A manifest's `registry_snapshot` therefore says which snapshot the spec claims, not that anyone
verified it under your roots; a spec synthesized under your pinned roots is the path to a root
the toolkit has checked, and the install-time checks load it again.

## Monitoring

```bash
ozpb registry monitor --published registry/mainnet --registry-roots roots.json \
  --network "Public Global Stellar Network ; September 2015" \
  --wasm-hash <account wasm hash> --wasm-hash <owner verifier wasm hash> \
  --wasm-hash <reviewed policy wasm hash> --template policy-templates/scope@1 \
  --expiry-window-days 14
```

The checkpoint is the one in the roots file, or `--checkpoint <file>`. The published log (a
directory, or one head file that directly extends the checkpoint) is checked against it: the
copy of the checkpoint's own version must be exactly what was accepted — its signatures are not
checked again, so a consumer that re-pinned after a rotation keeps working — and every later
version must verify under the pinned roots as the chain extending it. A JSON report is printed
with the head, whether it is newer, its validity, and every watched hash or template family it
revokes. The exit
status is for cron; when several apply, the most urgent wins, in the order revoked, expired,
expiring, not yet valid, newer:

| Exit | Meaning | Action |
|---|---|---|
| 0 | current, not expiring within the window | none |
| 3 | a newer version is published | review it, then advance the checkpoint |
| 7 | the head's interval has not started | nothing loads it yet; keep the current version until it starts, and check the start date was intended |
| 4 | the head expires within the window | ask the custodians for a successor |
| 5 | the head has expired | synthesis and checks now refuse it; same |
| 6 | a watched hash or template family is revoked | the emergency-removal path below |
| 1 | the published log cannot be verified against the checkpoint — or the command is misconfigured, including a watched hash or template family the head neither registers nor revokes | read the message: a log that cannot be verified is an incident (a fork, an equivocation, a rollback, or a new version signed under roots you have not pinned); a watch item it names is mistyped or no longer in the registry, and must be fixed, since it could never report |
| 2 | a usage error: a flag missing, unknown or malformed, rejected before anything is read | nothing was checked and no report is printed; fix the invocation |

Any other non-zero status (a crash) means the run reached no verdict; treat it as an alert too.

Monitoring compares your checkpoint with one published source. It detects a log that contradicts
what you accepted, but it cannot detect newer versions that source withholds: a frozen or
selectively served log looks current. The backstop is each version's validity interval — a head
nobody replaces reaches exit 4 within the window and exit 5 when it ends, after which nothing
loads it — so keep intervals short enough that a freeze surfaces in time, and where it matters,
monitor more than one copy of the log (the repository and the release assets).

Watch what your installed grants rely on: the account's Wasm hash, each owner verifier's and
each reviewed policy's with `--wasm-hash`, and with `--template` the template family of each
generated policy (its spec names it, `template_family`). A generated policy has no registry entry
of its own: it is recognized through its family and by rebuilding it. Revoking the family reaches
every build of it; custodians can also revoke one build by its Wasm hash (`policy/<hash>`), and
recognition refuses that build too. Watch the family: a build's hash cannot be watched in advance,
because the head registers nothing under it until a revocation names it. Every watch item must be
something the head registers or revokes, and a family must be a valid family name: anything else —
a typo above all — is refused with exit 1 and the item named, because a watch that can never match
would otherwise read "current" forever.

## Scheduling the monitor

`monitor` detects; running it is the operator's. Run it on a schedule shorter than the expiry
window and than the time you can afford to learn of a revocation late — hourly is a reasonable
start — against every copy of the log you can reach. With cron:

```cron
# m h dom mon dow
17 * * * * cd /srv/ozpb && ./registry-monitor.sh >> /var/log/ozpb-registry-monitor.log 2>&1
47 * * * * cd /srv/ozpb && ./grant-monitor.sh >> /var/log/ozpb-grant-monitor.log 2>&1
```

where `registry-monitor.sh` updates the published log (a `git pull` of the repository, or the
latest release assets), runs the `monitor` command above, and acts on its status. The registry
monitor reports revoked code, not a changed rule on an account: `grant-monitor.sh` runs
`ozpb check-installed-grant --recorded-authority-commitment --min-ledger` for each installed grant,
keeps the `observed_ledger` of a run that exited 0 for the next floor (never a stale run's) and
acts on the exit status ([watching an installed grant](INCIDENT-RESPONSE.md#watching-an-installed-grant)). The two
commands' exit codes differ (3, 4 and 5 mean different things), so each script has its own
handler.
With systemd, a oneshot service running each script and a timer:

```ini
# ozpb-registry-monitor.timer
[Timer]
OnCalendar=hourly
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
```

What each status should set off:

- **0** — nothing; keep the report.
- **3** — a person reviews the new version (diff it against the one you hold) before the checkpoint
  and floor advance. Never advance them automatically: that is what makes a checkpoint worth
  keeping.
- **7** — nothing yet; alert if the start date is not the one the custodians announced.
- **4** — notify the custodians (or your own operators, if you pin your own roots) that a
  successor is due before the end date.
- **5** — page whoever runs the service: synthesis, the live checks and install intent now refuse
  every request until a successor is loaded.
- **6** — page, and start the [emergency-removal path](#revocation-and-emergency-removal) for every
  grant using the revoked capability; the report names each revoked capability and its reason.
- **1** — page. If the message names a watch item, fix the watch list (or, if a registered item was
  dropped without a revocation, ask the custodians why). Otherwise treat it as a security incident:
  the published log contradicts what you accepted, or a new version is signed under roots you have
  not pinned. Do not advance anything until it is explained.
- **2** — fix the script: the monitor never ran, so until it does nothing is being watched.

## Revocation and emergency removal

A revocation is a successor whose change set names the capability (`account/<hash>`,
`policy/<hash>`, `verifier/<hash>`, `target_adapter/<hash>`, `template/<family>`) and a reason a
user can act on. In an incident, the custodians sign it as soon as the threshold can meet; the
validity interval can stay the parent's.

Once a consumer accepts it, synthesis, the authority check, installed-rule prediction and
recognition refuse the capability with `E_REGISTRY_REVOKED` and the reason. Recognition refuses a
policy binding whose observed code hash is revoked under any of the four hash kinds, as
`--wasm-hash` reports it: this is what reaches a generated build revoked by its hash, which has no
entry of its own. Synthesis never sees a build's hash, so there only a family revocation applies.
**A revocation cannot disable an on-chain grant by itself.** What a user does when a hash they installed is revoked:

- A revoked **policy or template family** in an installed grant: revoke the grant with
  the wallet — in the reference integration,
  [`Prepare revocation`](POLLYWALLET-INTEGRATION.md#revocation), which removes the context rule
  with the owner's passkey — before the delegate can use it again. Synthesis and the live checks
  refuse a revoked family for every new generated policy, but one already installed keeps running
  until its rule is removed.
- A revoked owner **verifier**: revoking the grant does not help, because the verifier
  authenticates the owner rule itself. Replace the owner signer with one on a recognized
  verifier, or move the funds to an account whose owner uses one.
- A revoked **account** build: removing rules does not change the account's code. Two paths:
  - *Upgrade in place.* The pinned wrapper exports `upgrade`, which the
    [method inventory](ACCOUNT-METHOD-INVENTORY.md) records as guarded by the account's own
    authorization (`require_auth` on the account, so a rule that covers calls to the account
    itself — ordinarily the owner's) with a code effect. Calling it with the hash of a
    recognized build keeps the address, rules, signers and policies and changes the code. It needs
    that exact Wasm already uploaded to the network, the account's owner to sign, and a storage
    layout the new build reads: for 0.7.2 to 0.7.3, the reviewed diff leaves storage and the
    signed digest unchanged. Rules added under the old build stay, including any signer the new
    build would refuse to add, so re-run the authority check afterwards and remove what it
    refuses. The toolkit and the reference wallet build no upgrade transaction, and this path has
    not been exercised here; until it lands, the old code's flaw is live.
  - *Recreate and move.* Create an account on a recognized build and move the funds — the path
    the GHSA-jpg9-m7w4-c7wc revocation of the 0.7.2 account documents
    ([Soroban dependencies](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)) and the one
    to take when the owner cannot sign an upgrade or the flaw lets someone else act first.

A revocation is permanent. A capability revoked in error stays revoked; a corrected build is a
new hash and a new entry.

## Validity, expiry and the end of the grant period

How long a version is trusted is the custodians' decision at signing, and nothing extends it
afterwards: when it ends, synthesis and the checks refuse the snapshot until a successor is
loaded. The monitor's expiry window is there so that a successor is signed in time.

Choose an interval that ends no later than the custodians' commitment to watch the registered
code and revoke what turns out to be faulty. Until it ends, consumers trust every entry in the
head and `monitor` reports nothing amiss short of the expiry window, whether or not anyone is
still there to revoke one; expiry is the fail-safe for when nobody is.

Gateway's stewardship of a registry it publishes — reviewing new hashes, revoking, signing
successors — is for the grant period only, which ends when the Stellar Community Fund accepts the
third milestone ([versioning](VERSIONING.md#what-10-promises-and-for-how-long)), with no
open-ended commitment ([architecture §10, Maintenance](architecture.md#10-delivery-plan)). After
that, the last published version expires on its own date, which is why its interval should not
outlast that stewardship. The mainnet draft's six-month interval is a placeholder the custodians
replace at signing ([`registry/mainnet/`](../registry/mainnet/README.md)). Any operator can
continue: pin their own root policy (`--registry-roots`, `OZPB_REGISTRY_ROOTS_JSON` — any policy
the code accepts) and run this same procedure with their own custodians, from a genesis of their
own.

## Rotation, lost and compromised keys

Snapshots do not carry the root policy, so there is no in-band rotation: rotation is an
out-of-band re-pin, and that is the design for this milestone. The cutover is one step for
consumers, in this order:

1. New keys are made in a [ceremony](#key-ceremony) and the new `roots.json` is written.
2. The coordinator builds version N+1 on version N with `successor --registry-roots` naming the
   **current** roots, which signed version N.
3. The new custodians sign it, and `combine --registry-roots` names the **new** roots.
4. Version N+1 and the new `roots.json` are published together, in one commit and one release.
   Neither is published without the other: new roots with no version signed under them verify
   nothing new, and a version signed under roots nobody has pinned fails every consumer's monitor.
5. Each consumer replaces its pinned roots and loads version N+1 in the same change, keeping its
   checkpoint at N: `verify --signed vN+1 --checkpoint <N>` under the new roots, then the printed
   checkpoint and floor go into the new roots file. `monitor` under the new roots matches the
   published version N against the checkpoint without re-checking its signatures, so it follows
   the log across the rotation.

The roots themselves are announced out of band, like the first ones: the chain does not prove
that the old custodians handed over. `verify --replay` checks a log under one policy, so across a
rotation, replay the versions before it under the old roots and check the later ones with
`verify --signed <file> --checkpoint <file>` under the new.

- A **lost** key: while the remaining custodians still meet the threshold, rotate it out. Below
  the threshold the chain cannot continue; consumers must pin a new policy and accept a new
  genesis, announced out of band.
- A **compromised** key: rotate it out at once, and treat any version signed after the suspected
  compromise as suspect until the other custodians have re-reviewed it.

## Key custody and incident handling in an ISMS

For the organisation that operates a registry, custodian key generation, storage, use, rotation
and destruction fall under ISO/IEC 27001:2022 Annex A 8.24 (Use of cryptography), and the
revocation and compromised-key procedures above under A 5.24 (Information security incident
management planning and preparation), A 5.25 (Assessment and decision on information security
events) and A 5.26 (Response to information security incidents). This is a pointer for that
organisation's own controls and records, not a claim of certification; how they are documented,
and whether they are in an audit's scope, is the operating organisation's decision.
