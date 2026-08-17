# Stellar / Soroban ecosystem conformance

**Why this exists.** The project was written first as a correct system and second as a system
built the way Soroban is built. This document records the platform's principles with links to
their sources, our current state against each, a verdict, and an action. It is what a design
decision is checked against, and what answers the question of whether we are reinventing
something the ecosystem already supplies.

Compiled 13 August 2026. Verified against `stellar-cli` 27.0.0, `stellar-xdr` 26.0.1/27.0.0,
`soroban-sdk` 26.1.0, `stellar-accounts` 0.7.2, and the repository at `main` plus the pending
change that adds the workspace-wide disallowed-type gate (§4).

**Verdict legend:** ✅ conforms · ⚠️ diverges · ❌ gap · ℹ️ open decision

Every claim here is meant to be checkable against the source it names — a SEP, a documentation
page, a line of this repository, or a line of the platform's own implementation. Where something
is unresolved, the section says what would resolve it.

---

## 1. Serialization and hashing ⚠️

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

**What we have.** Three inconsistent mechanisms:

| What | Mechanism | Where |
|---|---|---|
| `PolicySpec`, `BuildManifest`, `RegistrySnapshot`, `RecordingBundle`, `NormalizedInput` | `serde_json::to_vec`, field order = declaration order in Rust | `canonical_json_bytes`, `crates/domain/src/lib.rs:279` |
| the signer set | a hand-written binary encoding: the per-signer strings `"external:" + strkey + ":" + hex`, then a sort over those encodings and a 4-byte length prefix per entry | `SignerSpec::canonical_bytes`, `crates/policy-spec/src/lib.rs:171`; the sort and prefixes in `signer_set_hash`, `:193-202` |
| call arguments inside the contract | **XDR** (`v.to_xdr(e)`) | emitted by `emit_lib`, `crates/codegen/src/lib.rs:396` |

Domain separation is present, but as string prefixes over JSON (`ozpb:v1:policy-spec`) — the
idea is right, the carrier is a format that requires canonicalization.

**Verdict.** Diverges. The intent matches the platform's; the implementation does not. The
consequence: an external implementation is obliged to mirror the field order of our structures
by hand, and moving a field in Rust silently breaks an external verifier. The signer set is the
sharpest case — it is the one hashed structure carried by a hand-written binary encoding where
XDR is the obvious carrier (`ScVal` for the signer, `to_xdr()` for the bytes), and that has not
been done.

**Action.** Unify on XDR: represent hashable structures as `ScVal`, building every map through
`ScMap::sorted_from_*` so the ordering rule and its validator come from the crate rather than
from a rule of ours, fix the remaining choices explicitly (type mapping, `Option`, enumerations),
hash `to_xdr()`, and do domain separation with a versioned union **of our own** carrying our own
domain IDs. Raise `CANONICALIZATION_VERSION` to 2 (the constant exists for precisely this). The
window in which this is cheap is while we are the only implementation.

**Honestly about the status of this requirement.** Soroban does **not** oblige off-chain
artifacts to be XDR; a JSON artifact is not a violation. This is a strong decision taken for
interoperability and to keep the road to on-chain verification open, not a conformance item we
are breaching. The "diverges" verdict above refers to the internal inconsistency of the three
schemes and to the interoperability we chose to aim for, not to an obligation imposed by the
platform.

**Why not RFC 8785 (JCS).** Checked: JCS canonicalizes numbers through a double, so it loses
precision above 2⁵³ — the author of the maintained crate recommends outright that such numbers
be stored as strings. Our `i128` values are already strings, so this is not a blocker, but JSON
is not the ecosystem's format, implementations of JCS diverge from one another in exactly the
place that matters — `serde_jcs` carries a known open deviation in number encoding, and was
dormant from 2020 until it shipped 0.2.0 in March 2026; it is neither yanked nor deprecated, and
the "abandoned" characterisation circulating in a competing crate's README is not accurate — and
a Soroban contract cannot parse JSON at all, which closes the road to on-chain verification.

---

## 2. Artifact identity and its verification ❌

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
`BuildManifest`, an out-of-band record whose `ToolchainIdentity.rustc_version` duplicates
`rsver`, `stellar_cli_version` duplicates `cliver`, and `soroban_sdk_version` duplicates
`rssdkver` — and the platform's variants are more precise than ours, since they include commits.
In shape it is a **parallel invention of SEP-55**: an assertion by the builder about how the
artifact was produced, which a consumer takes on the builder's word. The difference is that
SEP-55's attestation is signed by the CI that performed the build and checkable against it,
whereas `BuildManifest` is checkable only with our CLI — which the build runner already says out
loud, stamping every real build `builder: "local-unattested"` (in `build_local`,
`crates/build-runner/src/lib.rs:514`), with the reason in that function's doc comment
(`:450-453`): "trust requires local reproduction or a separately trusted build attestation".

**Verdict.** A gap, but more precisely: our artifacts are **readable** by standard tooling
already (`stellar contract info meta` shows the SEP-46 keys the toolchain writes itself —
`rsver`/`cliver`/`rssdkver` — and anyone can compute the wasm hash) — what they do not carry is
any trace of provenance. Neither a reference to the spec the policy was derived from, nor the
fields either verification SEP needs. Which is why the link "artifact ↔ specification" can today
only be checked with our `BuildManifest` and our CLI.

**Our reproducibility guarantee is weaker than the one SEP-58 assumes, and that is a gap rather
than a different spelling of the same thing.** We pin rustc through `rust-toolchain.toml`, pin
dependency versions, and build `--locked` (in `BUILD_ARGS`,
`crates/build-runner/src/lib.rs:401-407`). SEP-58 pins the
container image by digest, which covers the operating system, the system libraries, the linker
and the toolchain in a single field. We pin neither the OS nor a container, so an identical wasm
hash reproduces on a sufficiently similar host and is not guaranteed off it.

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
2. Stop duplicating what the toolchain writes itself; in `BuildManifest`, either reference the
   wasm metadata or reconcile against it and fail on divergence. Where `BuildManifest` asserts
   what SEP-55 attests, follow SEP-55's shape rather than a private one.
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

## 3. State archival and TTL ⚠️ (operations) / ✅ (security)

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

**What we have.** The generated policy keeps its call counter in `persistent()` and **extends no
TTL anywhere** — `extend_ttl` occurs neither in the template nor in the generator. The constant
`VALID_UNTIL_LEDGER` lives on its own, unconnected to the network's maximum
(`e.storage().max_ttl()` — the SDK exposes the maximum TTL on `Storage`, not on `Ledger`, which
carries `max_live_until_ledger()`).

**Security verdict — conforms, along two different paths.** The architecture requires
(`docs/architecture.md:567`): "a call cap never resets **within an installation** due to
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
`docs/architecture.md:567` says "within an installation" rather than "lifetime", and the
reinstall invariant at `:555` is scoped to the installer flow instead of being asserted of the
policy contract, which cannot enforce it.

**The code has followed.** The rename reached the generated artifact's header, the reference
evaluator's message, the spec type (`StateSpec::CallCountPerInstallation`) and — the expensive
one — the wire field, which is now `call_count_per_installation` in the committed example spec
and in the signed registry snapshot's list of permitted constraint kinds. That last one changes a
signed artifact and every consumer that parses a spec, which is why it was taken together with
the canonicalization change rather than paid for separately: both break the schema, and one break
is cheaper than two.

**Operational verdict — diverges, but more mildly than it first appeared.** "Breaks silently"
would be an overstatement: under the normal flow through simulation the policy will usually be
restored automatically. The real cost is different and has three parts: the user pays a fee for
rent and restoration; clients that assemble a transaction **manually or without simulation** will
still fail before execution; and the moment at which that happens is unpredictable. Proactive TTL
extension remains justified — for predictability of cost and behaviour, not as a rescue from
inevitable breakage.

**Action.**

1. Extend the counter's TTL on read and write in `enforce`, bounding **each** extension by the
   current `e.storage().max_ttl()` and going no further than `VALID_UNTIL_LEDGER`. This ties the two
   lifetimes together: the entry lives no longer than the policy is valid, and after the policy
   expires the state is archived naturally instead of paying rent forever.
2. Separately extend the TTL of the **contract instance and of the wasm code** — these are their
   own entries with their own deadlines, and the guidance is to extend the state an invocation
   touches. Keep both extensions proportionate: since extensions may not be relied on for
   functionality or safety, they buy predictability, and any design that would need them to hold
   a guarantee is the wrong design.
3. Do **not** reject, at generation time, a policy whose `valid_until` exceeds `max_ttl()`.
   `max_ttl()` is a sliding network bound counted from the current ledger, so an entry is carried
   to a distant future deadline by **successive** extensions. Rejection would cut off precisely
   the long-lived scenario the tool exists for.
4. Cover this with tests in the soroban test environment, advancing the ledger number —
   otherwise it becomes one more rule that is written down and not checked.

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

**Verdict.** Conforms. The ban becomes **checked** rather than declared with the change that
adds a workspace-wide `clippy.toml` forbidding `HashMap`/`HashSet`/`f32`/`f64`, together with a
cross-process determinism test of the registry snapshot hash; that gate is pending and is not on
this branch, so until it lands the conformance rests on review rather than on a gate.

**A note on the move to XDR (§1), now carried out.** Field names became `Symbol`s, so both
constraints applied: length ≤ 32 bytes and the character set. The `$schema` field was the known
problem — `$` is not permitted in a `Symbol` — and it appeared in four structures, not one. All
four are now `schema`; the value was always a plain identifier rather than a JSON-Schema URI, so
the `$` carried no meaning worth an encoding exception.

---

## 5. Authorization model ✅

**Platform principle.** A smart account is a contract implementing the custom account interface;
`__check_auth` validates the proofs presented. OpenZeppelin's `stellar-accounts` formalizes this
as signers, context rules, and policies; a policy is a separate contract with
`enforce`/`install`/`uninstall`, and denial is expressed by a panic.

**What we have.** The generated policy implements exactly the `Policy` trait from
`stellar-accounts` 0.7.2, reads
`soroban_sdk::auth::Context::Contract(ContractContext { contract, fn_name, args })`, and denies
by panicking. The order of checks is fixed and documented in the artifact's header: signer
predicate → signer set → target/function/argument tuple → state invariants.

**Verdict.** Conforms. We invent no authorization primitives of our own, and OpenZeppelin's
`spending_limit` policy is **used by hash** rather than replaced.

---

## 6. Errors and observability ✅ / ℹ️

**Platform principle.** Errors are declared with `#[contracterror]` and numeric codes; denial is
`panic_with_error!`. Events (`events().publish`) are the standard way to make a contract's
behaviour observable outside the transaction.

**What we have.** `#[contracterror]` with ten distinguishable codes, every denial path named
(`RuleExpired`, `TargetMismatch`, `CallCountExceeded`, `NoTupleMatched`, …). This is not
cosmetic: distinguishable codes are what let the differential test compare not only "yes/no" but
the reason for a denial.

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

## 7. External security tooling ⚠️

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
read exactly what executes", immutability is a requirement rather than an omission. That value
is exactly what the unfixed "lifetime cap" wording in the artifact's header currently spends
(§3): the header is the thing a user reads, so a name there that overstates the guarantee costs
more than the same name would anywhere else.

---

## Actions, by priority

| # | Action | Section | Type |
|---|---|---|---|
| 1 | ~~Unify canonicalization on XDR~~ — **done.** `ScVal` built through `ScMap::sorted_from_entries` for ordering, explicit per-type rules, and a versioned preimage tagged with our own domains rather than the protocol's `HashIdPreimage`. Specified in `docs/CANONICAL-HASHING.md`, so an external implementation can reproduce a hash | 1 | breaking, done |
| 2 | Extend the counter's TTL on read/write, each extension ≤ the current `max_ttl()` and no further than `valid_until` | 3 | operational |
| 3 | Extend the TTL of the **contract instance and wasm code** separately, at the start of public functions | 3 | operational |
| 4 | Emit `contractmeta!` with the artifact's provenance (`spec_hash` and the rest) into the SEP-46 section; stop duplicating `rsver`/`cliver`/`rssdkver`, and follow SEP-55's shape where `BuildManifest` asserts what SEP-55 attests | 2 | compatibility |
| 5 | Run Scout and the Veridise checklist over the generated policies; a gate only after pinning the version, checking applicability, and defining a false-positive policy | 7 | security |
| 6 | Apply to the Soroban Security Audit Bank | 7 | process |
| 7 | TTL tests in the soroban environment, advancing the ledger number | 3 | tests |
| 8 | Settle where a generated contract's source archive is published, and by whom — SEP-58 requires `source_sha256` over its bytes and leaves `source_uri` optional | 2 | unresolved |
| 9 | Decide whether to publish an event on a **successful** `enforce`; denials come from RPC diagnostics | 6 | unresolved |
| 10 | Decide whether to build inside a digest-pinned container image and record it as SEP-58 `bldimg`; pinning rustc and dependency versions pins neither the OS nor the container | 2 | compatibility |
| 11 | ~~Rename the cap from "lifetime" to per-installation~~ — **done**, including the wire field, now `call_count_per_installation` in the committed example and in the signed registry snapshot. Taken together with row 1 because both break the schema, and one break is cheaper than two | 3 | done |

Not on the list, and deliberately so: rejecting a policy at generation time because
`valid_until` exceeds `max_ttl()`. That bound is sliding, measured from the current ledger, so a
distant expiry is legitimate and is reached by successive extensions; refusing it would cut off
the long-lived grant the tool exists to produce (§3, action 3).

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
