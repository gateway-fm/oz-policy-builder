# Stellar / Soroban ecosystem conformance

**Why this exists.** The project was written first as a correct system and second as a system
built the way Soroban is built. This document records the platform's principles with links to
their sources, our current state against each, a verdict, and an action. It is what a design
decision is checked against, and what answers the question of whether we are reinventing
something the ecosystem already supplies.

Compiled 13 August 2026; last reconciled 18 August 2026 against the release-readiness hardening
pass. Verified against `stellar-cli` 27.0.0, `stellar-xdr` 26.0.1/27.0.0, `soroban-sdk` 26.1.0,
`stellar-accounts` 0.7.2, and the repository as of that pass. Sections 9–14 record the
subsystems that pass hardened; the disallowed-type gate that was pending at first compilation
has since landed (§4).

**Verdict legend:** ✅ conforms · 🗓 contracted for a later milestone · ⚠️ diverges · ❌ gap · ℹ️ open decision

The distinction between the first two and the rest is the one worth reading carefully. 🗓 is
not a softer ⚠️: it marks work this project has scoped, sequenced and committed to deliver in a
later milestone, so the section states a boundary of *this* milestone rather than a departure
from anything the ecosystem asks. Nothing in this document currently sits at ⚠️ or ❌; both stay
in the legend because the categories exist and a later reading may need them.

## Summary

| § | Subject | Verdict | In one line |
|---|---|---|---|
| 1 | Serialization and hashing | ✅ | Canonical form is XDR throughout, with a versioned preimage an outside implementation can reproduce from `docs/CANONICAL-HASHING.md`. |
| 2 | Artifact identity and verification | ℹ️ / 🗓 | Artifacts are readable by standard tooling but carry no provenance of ours. Both verification SEPs are Draft and unimplemented by released tooling; one question in them is genuinely open for generated contracts. Separately, our reproducibility holds across comparable hosts, not across any host. |
| 3 | State archival and TTL | ✅ | Bounded, threshold-conditional extension that never reaches past the rule's own window; restoration semantics verified against the environment rather than assumed. |
| 4 | Value system and numeric types | ✅ | No type without a faithful `ScVal` form, and the ban is enforced by lint rather than declared. |
| 5 | Authorization model | ✅ / 🗓 | No authorization primitive of our own, and OpenZeppelin's `spending_limit` is used by hash. External-verifier signers are refused outright rather than half-supported. |
| 6 | Errors and observability | ✅ / ℹ️ | Stable machine-readable error codes throughout; whether to emit an event on a successful `enforce` is undecided. |
| 7 | External security tooling | ℹ️ | Scout and the Veridise checklist are customary, not required. We check the generator thoroughly; running them over what it generates is a decision, not a shortfall. |
| 8 | Upgradeability and immutability | ✅ | No setters, no upgrade entry point. For an artifact whose value is "the reader sees exactly what executes", immutability is the requirement. |
| 9 | Evidence provenance and RPC binding | ✅ | Requested and returned transaction identity is bound and re-derived under the verified network passphrase. It remains RPC evidence, not a ledger-inclusion proof. |
| 10 | Capability registry governance | ✅ / 🗓 | The mechanism conforms; the committed root is a deterministic development key, suitable for reproducible examples and not for production governance. |
| 11 | Evaluator and differential evidence | ✅ / 🗓 | An independent evaluator agrees with the real compiled contract on verdict and denial reason. It does not exercise a full smart account's `__check_auth` — later-milestone evidence. |
| 12 | MCP surface and machine-readable failures | ✅ | Closed request schemas, generated JSON schemas, stable `E_*` codes, structured tool errors. |
| 13 | Build containment | 🗓 | The local builder bounds environment, inputs, outputs, concurrency and time. It is not a multi-tenant sandbox and this milestone does not offer it as one. |
| 14 | Defaults and limits | — | Every default and bound, with the reasoning for each value. |

Read the section for the reasoning; nothing above is a claim the section does not support.

Every claim here is meant to be checkable against the source it names — a SEP, a documentation
page, a line of this repository, or a line of the platform's own implementation. Where something
is unresolved, the section says what would resolve it.

---

## 1. Serialization and hashing ✅

**Platform principle.** Stellar's canonical format is **XDR**: field order is fixed by the
schema, integers are fixed-width, padding is defined. Rust structures map onto values by a
documented convention: a named struct → `ScVal::Map` with `Symbol` keys, a tuple → `ScVal::Vec`.

**An important qualification, without which the statement would be wrong.** XDR gives one
encoding per *particular value*, but it does not remove canonicalization altogether: the value
is still ours to choose. `ScMap` is a `VecM<ScMapEntry>`, so entry order is part of the value,
and semantically equivalent maps in different orders produce **different bytes**. The host type
`soroban_sdk::Map` is documented as ordered by key and normalizes the order itself.

**Outside a contract the ordering rule is also supplied, and we would use it rather than
restate it.** `stellar_xdr::ScMap`'s bare constructor keeps whatever order it is handed, but the
crate ships the sorting constructors `ScMap::sorted_from_entries`, `sorted_from_pairs` and
`sorted_from` (`stellar-xdr-27.0.0/src/scmap.rs:8-39`), which sort by key and then validate; and
`impl Validate for ScMap` (`src/scval_validations.rs:58-75`) rejects any map that is not strictly
ascending by key, which also rejects duplicate keys. So key ordering is an ecosystem rule with an
ecosystem enforcer, not something we need to define. What remains genuinely ours to fix is the
mapping of each type onto `ScVal` and the representation of `Option` and of enumerations.
Checked against `stellar-xdr` 27.0.0 and `soroban-sdk` 26.1.0.

**The template for hashing a structure** is `HashIdPreimage`: an XDR union whose discriminant
(`EnvelopeType`: `OpId = 6`, `ContractId = 8`, `SorobanAuthorization = 9`) provides domain
separation, followed by SHA-256 over the XDR bytes.

**What is to be adopted is the template, not the union itself.** Reusing `HashIdPreimage` or the
values of the system `EnvelopeType` for application hashes is not an option: it is exactly the
domain collision that separation prevents — our hash would become indistinguishable from a
protocol one. What is needed is a **versioned XDR envelope of our own** with our own domain
identifiers.

**What we have.** Hash identity is canonical XDR, version 2 (`CANONICALIZATION_VERSION = 2`):
every artifact type carries its own application domain identifier and schema version in a
versioned preimage of our own; maps are built through `ScMap::sorted_from_entries`, so the
ordering rule and its validator come from `stellar-xdr` rather than from a rule of ours;
integer widths and the `Option`/enumeration encodings are fixed explicitly; and SHA-256 is
applied to the resulting bounded XDR bytes (`canonical_hash`, `crates/domain/src/canonical.rs:158`).
The normative mapping and its fixtures are `docs/CANONICAL-HASHING.md`, so an external
implementation reproduces a hash from the specification instead of mirroring Rust declaration
order. The signer set — previously the sharpest divergence, a hand-written
`"external:" + strkey + ":" + hex` string encoding — now hashes the `ScVal` representation the
account itself stores (`SignerSpec::to_stored_scval`, `crates/policy-spec/src/lib.rs:197`; the
sort over encodings in `signer_set_hash`, `:247`). Call arguments inside the generated contract
compare as XDR, as they always did (`v.to_xdr(e)`, emitted by `emit_lib`,
`crates/codegen/src/lib.rs:538`).

Since the hardening pass the preimages are also **bounded before hashing**: encoded evidence is
capped below the 4 MiB canonical-hash preimage ceiling (per-value and total caps in §14), so a
recording the recorder accepts cannot fail only when it is hashed.

**Verdict.** Conforms. The earlier "diverges" — three inconsistent mechanisms: JSON bytes in
Rust declaration order, the hand-written signer encoding, and XDR only inside the contract —
was resolved by unifying on XDR, taken together with the schema-breaking rename in §3 so the
format broke once rather than twice.

**Honestly about the status of this requirement.** Soroban does **not** oblige off-chain
artifacts to be XDR; a JSON artifact would not have been a violation. The move was a strong
decision taken for interoperability and to keep the road to on-chain verification open, not a
conformance item we were breaching. The earlier "diverges" verdict referred to the internal
inconsistency of the three schemes and to the interoperability we chose to aim for, not to an
obligation imposed by the platform.

**Why not RFC 8785 (JCS).** Checked: JCS canonicalizes numbers through a double, so it loses
precision above 2⁵³ — the author of the maintained crate recommends outright that such numbers
be stored as strings. Our `i128` values are already strings, so this is not a blocker, but JSON
is not the ecosystem's format, implementations of JCS diverge from one another in exactly the
place that matters — `serde_jcs` carries a known open deviation in number encoding, and was
dormant from 2020 until it shipped 0.2.0 in March 2026; it is neither yanked nor deprecated, and
the "abandoned" characterisation circulating in a competing crate's README is not accurate — and
a Soroban contract cannot parse JSON at all, which closes the road to on-chain verification.

---

## 2. Artifact identity and its verification ℹ️ / 🗓 (verification SEPs are Draft)

**What the platform has and ships.** The wasm section `contractmetav0` with serialized
`SCMetaEntry` — the standardized way for an artifact to describe itself, specified by
**SEP-46 — Contract Meta** (status Active). It is written by the `contractmeta!` macro from
`soroban-sdk` or by the flag `stellar contract build --meta KEY=VALUE`. This is standard,
released functionality.

Some of the keys the toolchain writes **itself**. Checked on our own artifact:

```
$ stellar contract info meta --wasm <our wasm>
 • rsver: 1.91.1                                                    (Rust version)
 • rssdkver: 26.1.0#175aa41306f383057a8cdfc84b68d931664fc34e        (SDK + commit)
 • rssdk_spec_shaking: 2
 • cliver: 27.0.0#5a7c5fe76530bf4248477ac812fc757146b98cc4          (CLI + commit)
```

**Verification on top of that metadata: two Draft SEPs, and no released tooling.** Two
complementary approaches are specified.

**SEP-58 — Contract Build Reproducibility for Verification** (status **Draft**, version 0.6.0,
updated 2026-07-15) defines the vocabulary for rebuild-based verification. The vocabulary is
storage-independent: these are fields, not `contractmetav0` keys, and SEP-46's section is one of
the three venues SEP-58 allows for carrying them.

| Field | Meaning |
|---|---|
| `bldimg` | the container image the build ran in, **pinned by digest**, with an explicit registry host and a reference to a single-architecture manifest |
| `bldarg` | one shell-style argument injected ahead of the flags; repeatable, **order significant**; defaults to `contract` then `build` when absent |
| `bldopt` | one shell-style flag passed verbatim; repeatable, order not significant |
| `source_sha256` | **required**: the SHA-256 of the source archive's bytes |
| `source_uri` | optional: a URI the archive can be downloaded from |

The reasoning behind `bldimg` is the part worth carrying over: a registry tag is mutable and a
content digest is not, and the image bundles the Rust toolchain along with every other
build-time dependency — so pinning the image by digest transitively pins the toolchain, and one
field captures the whole build-time stack.

**SEP-55 — Contract Build Verification** (status **Draft**) takes the attestation route
instead: the build CI signs an attestation and a verifier checks that attestation rather than
rebuilding. SEP-58 states that the two are complementary and can coexist on the same contract.

Maturity has to be stated exactly, because it is easy to overstate in either direction. Both
SEPs are Draft, and **no released `stellar-cli` implements SEP-58 support**. The command
`stellar contract build` carries no subcommands at any tag from v20.0.0 through the current
release v27.1.0 (2026-07-31), so `stellar contract build verify` does not exist — that spelling comes
from `stellar/stellar-cli` PR #2525, which was closed without merging, and must not be written
down as if it were shipped. Two PRs are open and unmerged: #2585 adds a `--verifiable` flag to
`stellar contract build`, and #2586 adds `stellar contract verify` as a **sibling** of `build`
rather than a subcommand of it. Implementations are in flight as well — the public repository
`stellar-experimental/contract-verifications` **calls itself an experiment** — while explorers
already surface a status of their own: Stellar Lab shows a "Build Verified" badge, citing
SEP-55, and StellarExpert's page is headed "Contract Code Validation", carrying a `Source code:`
field with a `verified`/`unverified` enum in its API. So: a specified direction with a named
vocabulary to stay compatible with, not a finalized standard we are in breach of.

**What we have.** `contractmeta!` is absent from the generator's template entirely, so a
generated artifact carries no meta we wrote — no reference to the spec it came from — and we
publish the SEP-58 fields nowhere at all, in that section or in any other venue the SEP allows:
no `bldimg`, `bldarg`, `bldopt`, `source_sha256` or `source_uri`. What stands in its place is
`BuildManifest`, an out-of-band record whose `ToolchainIdentity.rustc_version` restates
`rsver`, `stellar_cli_version` restates `cliver`, and `soroban_sdk_version` restates
`rssdkver` — and the platform's variants are more precise than ours, since they include commits.
In shape it is a **parallel invention of SEP-55**: an assertion by the builder about how the
artifact was produced. The difference is that SEP-55's attestation is signed by the CI that
performed the build and checkable against it, whereas `BuildManifest` is checkable only with our
CLI — which the build runner already says out loud, stamping every real build
`builder: BUILDER_LOCAL`, whose value is `local-unattested` (stamped in `build_local`,
`crates/build-runner/src/lib.rs:841`), with the reason in that function's doc comment (`:771-774`):
"trust requires local reproduction or a separately trusted build attestation".

Those three restatements are no longer taken on the builder's word, which is the one thing about
them that was cheap to fix. `manifest_for` reads the built wasm's own `contractmetav0` and refuses
the build when it contradicts the claim, naming the manifest field, the metadata key and both
values (`reconcile_declared_toolchain`, same file). It compares the version for all three, and for
`cliver` the git revision as well — that half is precisely what the platform's spelling has and
ours does not, and a CLI built from a fork or a dirty tree reports the same version with a
different revision and produces a different wasm. Absent metadata is a refusal too: a claim with
nothing behind it is the case the check exists for, so finding nothing must not read as agreement.
A key the wasm states twice is refused on the same principle from the other side — reading the
entries into a map would resolve it by last-wins, and which occurrence is last is a fact about the
reader's walk order, so a verifier walking the two sections differently would reconcile the other
value and reach the opposite verdict about identical bytes. The stub builder is the single
exemption, because its placeholder wasm is not a module and carries no metadata at all.

What this does **not** do is make the manifest verifiable by a third party — that still needs
SEP-55's signature or SEP-58's rebuild. It makes our own statement about the toolchain a checked
one instead of an asserted one.

**Verdict on the provenance half: a deliberate divergence, and an open question we did not
invent.** Our artifacts are **readable** by standard tooling already — `stellar contract info
meta` shows the SEP-46 keys the toolchain writes itself (`rsver`/`cliver`/`rssdkver`) and anyone
can compute the wasm hash. What they do not carry is any trace of provenance: neither a reference
to the spec the policy was derived from, nor the fields either verification SEP needs. So the
link "artifact ↔ specification" can today be checked only with our `BuildManifest` and our CLI.

Nothing requires otherwise. No SEP obliges a contract to write meta of its own; both
verification SEPs are Draft and no released `stellar-cli` implements either; neither the RFP this
work answers nor the proposal that answered it asks for artifact verification. This section
records a direction we intend to stay compatible with, not a rule we are failing. Adopting the
vocabulary early would mean guessing at one specific unresolved point — SEP-58 keys on the
SHA-256 of a *source archive*, and a contract generated on demand has no archive — and a guess
the standard later contradicts is worse than the absence. The question is written up and raised
where the SEP is being discussed; when it resolves, the answer is to adopt the standard's
spelling rather than to keep our own.

**Verdict on the reproducibility half: our own guarantee is narrower than it sounds, and this
one is not waiting on anybody.** It is worth separating from the paragraph above, because that
one is a standard in progress and this one is a limit of what we can currently promise. We pin
rustc through `rust-toolchain.toml`, pin
dependency versions, and build `--locked` (in `BUILD_ARGS`,
`crates/build-runner/src/lib.rs:457-463`). SEP-58 pins the
container image by digest, which covers the operating system, the system libraries, the linker
and the toolchain in a single field. We pin neither the OS nor a container, so an identical wasm
hash reproduces on a sufficiently similar host and is not guaranteed off it. Containerised builds
need no finished SEP — the reason this is still open is cost and sequencing, not the standard, and
a digest-pinned builder is recorded as later-milestone work. Until then, "byte-identical across
two cold runs" means on comparable hosts, which is what CI measures and all this repository
claims.

**A side consequence worth recording.** Because `cliver` and `rsver` land **inside** the wasm,
they are part of its bytes and therefore of its `wasm_hash`. A change of CLI version thus
changes the artifact hash mechanically, even with identical generator output. This confirms the
need to pin `stellar-cli` and not only rustc: the platform records the version in the artifact,
which is what makes the dependency visible, but reproducibility still requires the pin.

**Action.**
1. Emit `contractmeta!` into the generated crate with a reference to provenance: `spec_hash`,
   `normalized_input_hash`, `template_family`, `registry_snapshot`. The artifact then describes
   what it was derived from self-sufficiently, in the SEP-46 section, read by standard
   `stellar contract info meta` — without our `BuildManifest`.
2. ~~Stop duplicating what the toolchain writes itself; in `BuildManifest`, either reference the
   wasm metadata or reconcile against it and fail on divergence.~~ **Done** for the reconciling
   half: the three restated versions are now checked against the wasm's `contractmetav0` and a
   divergence refuses the build. The rest stands — where `BuildManifest` asserts what SEP-55
   attests, follow SEP-55's shape rather than a private one, once there is a released
   implementation to follow.
3. Decide whether to build inside a digest-pinned container image and record it as SEP-58
   `bldimg` (with `bldarg`/`bldopt` for the invocation). This is the ecosystem's answer to
   reproducibility, and it is strictly stronger than pinning rustc and dependency versions.
4. Settle an open design question (ℹ️): a generated contract **has no source in the
   repository** — it is created on demand. This is a smaller obstacle than it first appears,
   because SEP-58 keys verification to `source_sha256` over the bytes of a source archive and
   makes `source_uri` optional, rather than to a repository and revision; a generator can
   produce that archive and record its hash. What remains open is where the archive is
   published and by whom, and whether pointing at the generator plus `spec_hash` — so a
   verifier reproduces the source by re-running generation — is worth specifying alongside it.
   **Unresolved.** It is settled by choosing a publication point for the archive and writing it
   down, or by establishing with the SEP's authors that a generator-plus-spec pointer satisfies
   a verifier; neither has been done.

---

## 3. State archival and TTL ✅ (security and, since the hardening pass, operations)

**Platform principle.** `persistent` entries have a TTL. When it expires the entry is
**archived**, not deleted, and, verbatim: "Archived persistent entries can never be re-created.
They must instead be restored."

**Protocol 23 changed the restoration path, and that matters.** Archived `Persistent` and
`Instance` entries are restored **automatically, before the host function executes** — but only
if they made it into the transaction's `restore list`, which simulation populates: "if the
simulation detects an access to an archived entry, it adds that entry to the restore list".
`RestoreFootprintOp` remains for rare cases (a transaction too large, fee management by the
developer), but it stopped being the only and primary path.

A transaction whose footprint contains an archived `Persistent` key that did **not** make it into
the restore list still fails at the apply stage, before the contract executes.

**The guidance on extension is conditional, and one line of it cuts against us.** It lives on
the *Persisting data* page, not on the state-archival page, and it is phrased throughout as
"should": global state that cannot be `Temporary` should be in `Instance` storage so that its
TTL is aligned, and an autonomous contract "should extend the TTL of any shared state touched by
an invocation via the `extend_ttl()` host function". The same page then says, verbatim: **"TTL
extensions should never be relied on for functionality or safety."** The reasoning it gives is
that anyone may extend any entry's TTL without authorization, so an extension is not a
control — which is a caution against building a guarantee on top of extension, and equally a
caution against over-engineering extension itself. Both belong here: the guidance is worth
following for predictable cost and behaviour, and it is not a requirement we are in breach of.

**What we have.** The generated policy keeps its per-installation state in `persistent()` —
since the hardening pass that is an installation marker for **every** policy, scoped by
(smart account, context-rule id), plus the call counter where the rule has one — and it
**extends TTL deliberately and boundedly**. A successful `enforce` and a successful `install`
extend the instance entry and the policy's own persistent entries toward `ttl_target(e)`: the
network's rolling `e.storage().max_ttl()` (the SDK exposes the maximum on `Storage`, not on
`Ledger`), clamped so the target never outlives `VALID_UNTIL_LEDGER` — past expiry every entry
point denies, so extending further would pay rent for an artifact that can no longer permit
anything. A denied call extends nothing, `uninstall` extends nothing, and the extension is
threshold-conditional rather than unconditional, so routine authorizations do not each buy
rent. The policy does not separately extend the **wasm code** entry (see action 2 below).

**Security verdict — conforms, along two different paths.** The architecture requires
(`docs/architecture.md:565`): "a call cap never resets **within an installation** due to
inactivity, TTL expiry, or archival". The requirement is satisfied by **the platform's semantics
rather than by our code**, and in both modes:

- *the ordinary flow* (simulate → assemble): the entry is restored automatically before
  execution, the counter comes back, and `install` runs into `has(&key)` → `AlreadyInstalled`.
  There is no reset;
- *a manually assembled transaction without a restore list*: it is rejected at the apply stage,
  before the contract is invoked. Neither `enforce` nor `install` runs, so this is fail-closed
  by platform rejection, not by policy denial — the distinction matters, because the policy
  contributes nothing to the outcome here.

**A load-bearing question, and its evidence.** Whether automatic restoration preserves the
entry's previous value is what the security verdict rests on: if restoration zeroed the value,
the cap would be reset by archival and the architecture's requirement would be violated. It
**does** preserve the value, and since the prose documentation only says that a restored entry
receives a minimal TTL extension — leaving preservation to be inferred from "cannot be
re-created, only restored" — the evidence is the implementation and the protocol change itself:

- `soroban-env-host` 26.1.3, `src/e2e_invoke.rs:733-756`: for a footprint key whose entry has
  expired, the host fetches the entry from the ledger snapshot, checks it is persistent, and
  records it as auto-restored. It measures the encoded entry and marks the key; it never
  rewrites `le.data`.
- `soroban-env-host` 26.1.3, `src/e2e_invoke.rs:1007-1043`: the decoded entry is inserted into
  the storage map as `(le, live_until_ledger)` — the value the contract then reads. The only
  entries dropped for expiry are **temporary** ones, which are skipped explicitly.
- [CAP-66](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md) states the
  outcome at protocol level: a restore emits a `LEDGER_ENTRY_RESTORE` change that "will include
  the complete LedgerEntry of the restored entry."

Two things about the shape of that evidence, so the next reader does not repeat the search. It
is **not** in `src/storage.rs`, which is where a checker looks first and where it is not. And
the Rust host covers simulation and the restore-list path; the on-ledger restore itself is
implemented in stellar-core, so this is evidence about the path our flow takes rather than a
reading of every implementation of the rule.

The scope of "never resets" is one installation, and that limit is real: `uninstall` removes the
entry, after which `install` is possible and the counter starts from zero. Both require
`smart_account.require_auth()`, so only the account's owner can reach it, and the result is a new
grant rather than the erosion of an existing one. The architecture now states the cap that way —
`docs/architecture.md:565` says "within an installation" rather than "lifetime", and the
reinstall invariant at `:553` is scoped to the installer flow instead of being asserted of the
policy contract, which cannot enforce it. The generated contract enforces its half of that
scoping since the hardening pass: `install` refuses a second installation (`AlreadyInstalled`),
`uninstall` of something never installed refuses (`NotInstalled`), `uninstall` removes the
policy-owned state, and `enforce` fails closed (`MissingState`) when the installation marker is
absent — so "a new grant" is a new marker, never a resumed one.

**The code has followed.** The rename reached the generated artifact's header, the reference
evaluator's message, the spec type (`StateSpec::CallCountPerInstallation`) and — the expensive
one — the wire field, which is now `call_count_per_installation` in the committed example spec.
That last one changes a signed artifact and every consumer that parses a spec, which is why it
was taken together with the canonicalization change rather than paid for separately: both break
the schema, and one break is cheaper than two.

The signed registry snapshot briefly carried the same name in its list of permitted *constraint*
kinds. That was a filing error rather than part of the rename — a call cap is a `StateSpec`, not
an argument constraint — and that list is now exactly `Constraint`'s vocabulary, derived from the
enum. State capabilities are consequently not declared by a template entry at all:
`TemplateCapability` has no `state_kinds`, and adding one changes the snapshot's shape. Nothing
read the entry while it was there, so this removed a declaration and no control.

**Operational verdict — conforms since the hardening pass.** The earlier divergence was that
the policy extended nothing, leaving rent, restoration fees, and the moment of archival
unpredictable for the user. Extension is now emitted, bounded twice (the rolling `max_ttl()`
and the rule's own validity window), conditional on a threshold, and withheld on denial and on
`uninstall`. It remains what the platform says it may be — a predictability measure, never a
safety mechanism: the security verdict above rests on restore semantics and fail-closed reads,
not on who paid for an extension.

**Action.**

1. ~~Extend the counter's TTL on read and write in `enforce`, bounding **each** extension by the
   current `e.storage().max_ttl()` and going no further than `VALID_UNTIL_LEDGER`.~~ **Done.**
   `ttl_target(e)` clamps the extension to the rolling `max_ttl()` and saturates at
   `VALID_UNTIL_LEDGER`, so the entries live no longer than the policy can permit and are
   archived naturally after it expires.
2. Extend the TTL of the **contract instance and of the wasm code** — their own entries with
   their own deadlines. **Done for the instance entry**, extended alongside the persistent
   entries in `install` and permitting `enforce`. The **wasm code** entry is deliberately left
   to the operator/installer: anyone may extend it, an archived entry is restored rather than
   lost, and the code entry is shared with every other deployment of the same wasm, so its rent
   is not obviously this policy's to pay. Keep both extensions proportionate: since extensions
   may not be relied on for functionality or safety, they buy predictability, and any design
   that would need them to hold a guarantee is the wrong design.
3. Do **not** reject, at generation time, a policy whose `valid_until` exceeds `max_ttl()`.
   `max_ttl()` is a sliding network bound counted from the current ledger, so an entry is carried
   to a distant future deadline by **successive** extensions. Rejection would cut off precisely
   the long-lived scenario the tool exists for. (Still holds; `ttl_target` is exactly that
   successive-extension mechanism.)
4. ~~Cover this with tests in the soroban test environment, advancing the ledger number.~~
   **Done.** `contracts/differential/tests/ttl.rs` advances the test ledger and covers: install
   and enforce extending the counter and instance entries, the no-op above the threshold, a
   denied call extending nothing, `uninstall` extending nothing, the target never outliving the
   validity window, the last permitted call not buying rent, and install-after-expiry refusing
   without writing state.

---

## 4. The value system and numeric types ✅

**Platform principle.** The complete value system is `ScVal`, and in the pinned `stellar-xdr`
27.0.0 that is **22 variants** (recounted from `src/generated/sc_val.rs`), **not one of them
fractional**: `Bool, Void, Error, U32, I32, U64, I64, Timepoint, Duration, U128, I128, U256,
I256, Bytes, String, Symbol, Vec, Map, Address, ContractInstance, LedgerKeyContractInstance,
LedgerKeyNonce`. The XDR format can encode a float (`impl ReadXdr for f32` is present), but no
Stellar type uses it. Amounts are integers in stroops (`i128`), ledger numbers are `u32`.

`Symbol` constraints: the character set `[a-zA-Z0-9_]`, length up to 32 bytes. Addresses are
strkeys (base32, the set `A-Z2-7`, with a checksum).

**What we have.** No floats anywhere. Amounts are `i128`, serialized as a decimal **string** with
a canonicality check (`is_canonical_i128`). Every map is a `BTreeMap`.

**Verdict.** Conforms, and the ban is **checked** rather than declared: the workspace-wide
`clippy.toml` forbids `HashMap`/`HashSet`/`f32`/`f64` (per-process iteration order and values
with no faithful JSON or `ScVal` form), and the registry snapshot hash has a cross-process
determinism test. Since the hardening pass the values are also **bounded**, not merely typed:
exact `ScVal` constraints are size-capped per value and per rule, validation and codegen share
the builder's input ceiling so a spec that validates cannot generate a crate the next stage
refuses, and a maximum-shaped rule is generated in a non-vacuous boundary test (the caps are
tabulated in §14).

**A note on the move to XDR (§1), now carried out.** Field names became `Symbol`s, so both
constraints applied: length ≤ 32 bytes and the character set. The `$schema` field was the known
problem — `$` is not permitted in a `Symbol` — and it appeared in four structures, not one. All
four are now `schema`; the value was always a plain identifier rather than a JSON-Schema URI, so
the `$` carried no meaning worth an encoding exception.

---

## 5. Authorization model ✅ / 🗓 (external verifiers deferred)

**Platform principle.** A smart account is a contract implementing the custom account interface;
`__check_auth` validates the proofs presented. OpenZeppelin's `stellar-accounts` formalizes this
as signers, context rules, and policies; a policy is a separate contract with
`enforce`/`install`/`uninstall`, and denial is expressed by a panic.

**What we have.** The generated policy implements exactly the `Policy` trait from
`stellar-accounts` 0.7.2, reads
`soroban_sdk::auth::Context::Contract(ContractContext { contract, fn_name, args })`, and denies
by panicking. The order of checks is fixed and documented in the artifact's header: account
authorization and installation state first, then the signer predicate (the account defers
signer validation to policies), then the strict signer set, then target/function/argument
tuple, then stateful invariants. Named signer predicates are strict by default, so adding a
signer to a live account rule cannot silently widen the generated grant, and zero
authenticated signers always deny.

**External verifier signers are deliberately unsupported in this milestone (🗓).** An off-chain
spec can name a verifier address and a verifier wasm hash, but the runtime OpenZeppelin signer
value carries only the verifier address and key — nothing at authorization time binds that
address to the recognized code. Registry recognition of a caller-supplied hash does not prove
the address runs that code, so validation rejects the shape (`E_SPEC_EXTERNAL_SIGNER_UNSUPPORTED`)
until a later acquisition/install layer can bind address to observed executable and survive
upgrades.

**The reviewed spending-limit composition is validated, not assumed.** Composition is accepted
only for a recognized SEP-41 `transfer` shape with the `i128` amount at argument index 2, a
positive limit and period, decisions that can replay the representative evidence, and never on
mixed transfer/non-transfer rules. Its stateful runtime behaviour is deliberately not
reimplemented by the Phase 1 evaluator — see §11.

**Verdict.** Conforms where it claims to; defers loudly where it cannot check. We invent no
authorization primitives of our own, and OpenZeppelin's `spending_limit` policy is **used by
hash** rather than replaced.

---

## 6. Errors and observability ✅ / ℹ️

**Platform principle.** Errors are declared with `#[contracterror]` and numeric codes; denial is
`panic_with_error!`. Events (`events().publish`) are the standard way to make a contract's
behaviour observable outside the transaction.

**What we have.** `#[contracterror]` with eleven distinguishable codes, every denial path named
(`RuleExpired`, `TargetMismatch`, `CallCountExceeded`, `NoTupleMatched`, …), including the
lifecycle refusals the hardening pass added (`AlreadyInstalled`, `NotInstalled`, and
`MissingState` for an enforce without an installation marker). This is not cosmetic:
distinguishable codes are what let the differential test compare not only "yes/no" but the
reason for a denial. On the toolkit's wire, error codes are likewise stable machine-readable
identifiers, standardized as `SCREAMING_SNAKE_CASE` with an exhaustive round-trip test (§12).

**Verdict on errors — conforms.**

**Open decision (ℹ️): observability.** The policy publishes no events, so no on-chain trace
remains of what it permitted or denied.

The first idea — "publish an event at least on denial" — is **technically unrealizable**, and
that is worth recording so it is not revisited: `panic_with_error!` reverts the invocation, so an
event published before the panic is reverted with it and never becomes an ordinary on-chain
event. Events are possible **only on a successful** `enforce`.

So the actual choice is: (a) publish an event on permit — which costs a fee in the authorization
path itself and enlarges the artifact; (b) take denial reasons from the result and from RPC
diagnostics, where they are already available off-chain; (c) if a durable on-chain trace of
denials is genuinely required, it has to be designed separately and deliberately rather than
bolted onto `enforce`. Whether (a) is wanted is to be discussed, given that (b) already works.

---

## 7. External security tooling ℹ️ (customary tools, not protocol requirements)

**What the ecosystem has.**
- **Scout** (CoinFabrik) — a static analyzer specifically for Soroban contracts, with a catalog
  of known vulnerability classes. The analyzer is `CoinFabrik/scout-soroban`, installed as the
  cargo subcommand `cargo-scout-audit`; `CoinFabrik/scout-soroban-examples` is the companion
  repository of reviewed examples, not the tool. (`CoinFabrik/scout` is the ink! analyzer and
  does not apply here.)
- **The Soroban security checklist** from Veridise.
- **The Soroban Security Audit Bank** — an SDF programme funding audits: SDF has conducted over
  40 audits, deploying over $3 million. STRIDE appears there as the audit-readiness support SDF
  offers to participating projects, not as preparation those projects are required to bring.

**What we have.** Whatever we test, all of it is about **our Rust code**. Not one
Soroban-specific analyzer runs on the **generated contracts**.

**Verdict.** A qualification about the frame: Scout and the Veridise checklist are **not protocol
requirements** and not "conformance" in the sense discussed in the other sections. They are
third-party tools that the ecosystem customarily applies. Our gap is not that we breach a norm,
but that we check the generator thoroughly and do not check what it generates.

**Action.**
1. Run Scout over the reference generated policies and look at the result. **Before** making a
   gate of it, three things are needed: pin the version (a tool's version changes the verdict,
   and that is part of the point of a gate);
   establish that the analyzer applies to our kind of input at all — generated source or wasm;
   and define the false-positive policy. A gate without those three will be either noise that
   people start routing around, or theatre.
2. Work through the Veridise checklist against the generated template and record the result line
   by line.
3. **Apply to the Soroban Security Audit Bank.** An external audit is the control this section
   cannot substitute for, and the programme is a funded route to obtaining one.

---

## 8. Upgradeability and immutability ✅

**Platform principle.** Contracts may be upgraded via `update_current_contract_wasm`;
`stellar-accounts` ships an `Upgradeable` extension. Upgradeability is a choice, not an
obligation.

**What we have.** The generated policy **deliberately** has neither an upgrade entry point nor
setters — this is written in the artifact's header: "No setters, no upgrade entry point." The
constraints are fixed as constants in the source, so a limit cannot be changed without changing
the code, and changing the code changes the hash. Whether the *account* a policy is installed
into is upgradeable is upstream's choice, and independent of the policy's immutability: the
policy cannot be altered whichever way that choice goes. The on-chain install run that
exercises the pairing is contracted in a later milestone, and is recorded with that milestone's
evidence.

**Verdict.** Conforms, and the choice is deliberate: for an artifact whose value is "the user
read exactly what executes", immutability is a requirement rather than an omission. The header
is the thing a user reads, which is why the cap wording there was renamed to
"within an installation" when §3 settled what the platform actually guarantees — a name that
overstates a guarantee costs more in that header than the same name would anywhere else.

---

## 9. Evidence provenance and RPC binding ✅ (RPC evidence, not ledger inclusion)

**Platform principle.** Soroban RPC is a query interface, not a trust anchor: `getTransaction`
returns what the configured endpoint says, `getLedgerEntries` reads current state, and nothing
in the protocol makes a JSON response self-authenticating. Whatever trust a recording carries
has to be assigned by the party that fetched it, and downgraded the moment it leaves their
hands.

**What we have.** For an executed transaction, the RPC adapter (hardened in this pass): rejects
any requested hash that is not exactly 32 bytes of hexadecimal; verifies the configured network
passphrase through `getNetwork`; compares the response `txHash` against the canonical requested
hash; decodes `envelopeXdr` and independently recomputes the transaction hash under that
network, so a response body cannot smuggle a different transaction under the right label;
bounds the HTTP stream before allocating or parsing JSON; and decodes authorization/meta XDR
under depth and size limits.

`rpc_reported` means exactly "returned by the configured RPC endpoint" — it is not an inclusion
proof. More importantly, serialized JSON is caller-controlled: the toolkit downgrades every
bundle crossing the synthesize JSON boundary to `self_supplied`, so changing a `trust` field
cannot mint RPC or indexer assurance (🗓 — a future hosted service can preserve stronger
provenance only with an authenticated receipt or a server-side recording ID).

`getLedgerEntries` observes contract executables at its reported latest ledger, which may be
later than the transaction's ledger. The observation ledger is stored with the observation; for
historical transactions the toolkit does not claim the current executable was the one at
execution time.

---

## 10. Capability registry governance ✅ / 🗓 (production governance is hosted-service work)

**What we have.** Registry snapshots are content-addressed, threshold-signed, network-bound,
versioned, chained by previous root, time-bounded, and checked against a persisted minimum
version or checkpoint, so a replayed older snapshot or a same-version fork is refused rather
than accepted. Capabilities are keyed by canonical lower-case wasm hashes (or a validated
template family), and unknown or revoked capabilities fail closed. Since the hardening pass,
accepted revocations are also **append-only across succession**: a signed successor snapshot
cannot remove a prior revocation or rewrite its reason or effective version, and revocations
survive registry restarts. Tests cover rollback, same-version equivocation with checkpoints,
transparency-chain forks, invalid key encodings, and revocation removal/mutation.

**Verdict.** Conforms as a mechanism; 🗓 as governance. The committed registry key is a
deterministic development root — suitable for reproducible examples, not production governance,
which needs independently controlled roots, durable checkpoints, rotation and revocation
operations, monitoring, and an incident process. (Also recorded in PROGRESS.md as a residual.)

---

## 11. Evaluator and differential evidence ✅ / 🗓

**What we have.** The reference evaluator interprets validated spec structures directly; it
consumes no generated Rust and cannot depend on codegen — the missing edge is enforced in the
cargo dependency graph by `scripts/check-dep-rules.sh`. Structural independence reduces common
implementation coupling; it does not make either side correct by definition, which is why
property tests, canonical fixtures, and the compiled-contract comparison all still run.
Mutation testing is not among them: it was used during the hardening pass to find what those
leave uncovered — two comments in `crates/evaluator/src/lib.rs` record what it caught — but its
harness is not part of this tree, so it is history here rather than a gate a reader can re-run.

Since the hardening pass the full-spec evaluator is **honest about composition**: it returns
`deny` when the generated conjunct conclusively denies, `permit` only when every relevant
component is modelled, and `indeterminate` when an attached reviewed policy could still deny
and its state is not modelled — a whole-spec permit is never manufactured from a partial model.
The differential suite is correspondingly **scoped**: it invokes the generated policy contract
directly in a Soroban test environment and compares verdict plus denial reason against the
explicitly scoped `evaluate_generated_rule` model.

**Verdict.** Conforms for what it claims. 🗓 for what it does not: the suite does not exercise
a full OpenZeppelin smart account's `__check_auth`, reviewed-policy composition, wallet
installation, or live account state — later-milestone evidence, not implied by the phrase
"compiled contract".

---

## 12. MCP surface and machine-readable failures ✅

**What we have.** Request DTOs are closed schemas and reject unknown fields. The enum, the
published `ErrorCode::ALL` vocabulary and the wire spelling are generated from one list, so
every declared error code is necessarily in the vocabulary and in the serialization
round-trip table that walks it — exhaustive by construction rather than by diligence, which
is the fix for two codes that had been added to the enum and to `as_str` (a match the
compiler checks) while missing from `ALL` (an array nothing tied to the variants), silently
narrowing that table. Codes are standardized as `SCREAMING_SNAKE_CASE`, and public DTOs
generate JSON Schema. Tool execution and validation
failures return as MCP `CallToolResult` values with `isError: true` and structured
`{code, message, details}` data rather than being misclassified as JSON-RPC protocol failures,
so an agent can distinguish transaction-not-found, network mismatch, import parse, build
timeout/resource, and registry failures by stable wire codes.

The server never deploys, signs, or holds user keys. HTTP mode is loopback-only,
bearer-protected, request-bounded, rate- and concurrency-limited, and RPC-allowlisted. MCP
annotations remain hints, not authorization controls.

---

## 13. Build containment 🗓 (a local safeguard; hosted isolation is later-milestone work)

**What we have.** The local builder uses fixed commands and arguments, an offline `--locked`
Cargo build, bounded source/wasm/log sizes, a bounded timeout with bounded version probes,
process-group termination, a protected per-user cache, and — since the hardening pass — a
sanitized allowlisted child environment that excludes service and cloud credentials and proxy
variables, plus a combined CPU budget so HTTP request concurrency multiplied by Cargo jobs
cannot exceed the detected budget.

**Verdict.** Diverges from what hosting would need, and says so. These controls provide no
cgroup memory/CPU/disk/PID quotas, namespaces, seccomp, per-job filesystem isolation, egress
isolation, or cancellation on client disconnect. Tranche 1 therefore does not describe loopback
HTTP or the local compiler as a safe multi-tenant hosted service; before hosting, this needs a
secret-free worker identity, a digest-pinned image (§2 action 3), hard OS quotas, per-job
workspace and cache strategy, bounded egress, cancellation, durable rate limits, and
operational monitoring.

---

## 14. Defaults and limits

The knobs and caps the release ships with, and what each one does and does not promise:

| Setting | Interpretation |
|---|---|
| Rust 1.91.1 / CLI 27.0.0 / SDK 26.1.0 / OZ 0.7.2 | Intentional reproducibility set; upgrades change artifact hashes and require review. |
| Build timeout 600 s | Reasonable for a cold local build; hosted infrastructure still needs an outer deadline and hard quotas (§13). |
| Build jobs CPU−1, minimum 1 | Appropriate for one local build; HTTP defaults to one concurrent request and enforces a combined CPU budget. |
| HTTP request body 1 MiB / RPC response 24 MiB | Transport ceilings; nested domain and per-XDR limits still apply before evidence is accepted. |
| RPC timeout 30 s and bounded response stream | Prevents unbounded read/allocation; endpoint correctness is still part of `rpc_reported` trust (§9). |
| XDR 512 KiB per value / 1 MiB total encoded evidence | Deliberately below the 4 MiB canonical-hash preimage ceiling, so a recording accepted by the recorder does not fail only when hashed (§1). |
| Import document 1 MiB + 4 KiB | The total-evidence ceiling above plus the format's own JSON syntax — an import carries no simulated authorizations or state changes, so a longer document cannot describe admissible evidence. Refused on length before parsing, which is also the only bound on the supplied network passphrase. The syntax that allowance covers measures ~200 bytes, so the 4 KiB is headroom, not a fit. Over HTTP the 1 MiB request-body limit binds first, so the last 4 KiB of this range is reachable only over stdio and in-process. |
| 5 policies / 15 signers / 20-byte name | Equal to the pinned OpenZeppelin account constants and contract-tested. |
| 32 rules / 32 calls per rule / 32 args per call / 256 recordings | Defensive off-chain caps; text, evidence-reference and exact-ScVal limits prevent these counts from hiding unbounded payloads. |
| 64 KiB exact ScVal / 256 KiB exact-ScVal XDR per rule / 2 MiB generated crate | Validation and codegen share the builder's input ceiling; a maximum-shaped rule is generated in a non-vacuous boundary test (§4). |
| Example period 120,960 ledgers | Roughly seven days at an assumed five-second cadence; it is a ledger count, not seconds. |
| Example max calls 12 | Explicit demo decision, not inferred protocol truth; synthesis verifies it can cover representative calls. |
| No expiry | Allowed only with explicit high-blast-radius acknowledgement. |

---

## One thing we deliberately do not do

Reject a policy at generation time because `valid_until` exceeds `max_ttl()`. That bound is
sliding, measured from the current ledger, so a distant expiry is legitimate and is reached by
successive extensions; refusing it would cut off the long-lived grant the tool exists to produce
(§3, action 3).

---

## Sources

- [State archival — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival)
- [Persisting data — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/persisting-data) (the conditional extension guidance, and "TTL extensions should never be relied on for functionality or safety")
- [Choosing the right storage type — Stellar Docs](https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage)
- [Authorization — Stellar Docs](https://developers.stellar.org/docs/learn/fundamentals/contract-development/authorization)
- [`contractmeta!` — soroban-sdk docs](https://docs.rs/soroban-sdk/latest/soroban_sdk/macro.contractmeta.html)
- [SEP-46 — Contract Meta (Active)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0046.md)
- [SEP-55 — Contract Build Verification (Draft)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0055.md)
- [SEP-58 — Contract Build Reproducibility for Verification (Draft, 0.6.0)](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0058.md)
- SEP-58 support in `stellar-cli`, open and unmerged: [#2585 `--verifiable`](https://github.com/stellar/stellar-cli/pull/2585) · [#2586 `stellar contract verify`](https://github.com/stellar/stellar-cli/pull/2586); the unshipped `build verify` spelling comes from [#2525, closed](https://github.com/stellar/stellar-cli/pull/2525)
- [stellar-experimental/contract-verifications](https://github.com/stellar-experimental/contract-verifications)
- [Contract code validation — StellarExpert](https://stellar.expert/explorer/public/contract/validation)
- [Contract Source Validation SEP — stellar/discussions#1573](https://github.com/orgs/stellar/discussions/1573)
- [Contract Explorer — Stellar Docs](https://developers.stellar.org/docs/tools/lab/smart-contracts/contract-explorer)
- [OpenZeppelin stellar-contracts / accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts)
- [smart-account-kit](https://github.com/kalepail/smart-account-kit) · [passkey-kit](https://github.com/kalepail/passkey-kit)
- [Scout for Soroban — CoinFabrik (the analyzer, `cargo-scout-audit`)](https://github.com/CoinFabrik/scout-soroban) · [reviewed examples](https://github.com/CoinFabrik/scout-soroban-examples)
- [Soroban security checklist — Veridise](https://veridise.com/blog/audit-insights/building-on-stellar-soroban-grab-this-security-checklist-to-avoid-vulnerabilities/)
- [Soroban Security Audit Bank — Stellar](https://stellar.org/blog/developers/soroban-security-audit-bank-raising-the-standard-for-smart-contract-security)
- [serde_json_canonicalizer (JCS, for comparison)](https://docs.rs/serde_json_canonicalizer/latest/serde_json_canonicalizer/) · [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)
