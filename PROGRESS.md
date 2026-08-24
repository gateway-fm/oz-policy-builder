# Progress

Two phases delivered, plus two hardening passes. **345 tests** (319 host + 26 contract), all
green; 16 crates + contracts workspace. `scripts/verify-phase1.sh` is the strict release gate
(dependency/publication/build-input/quoted-hash invariants, fmt + clippy + tests over both
workspaces and both generated crates, golden/determinism checks, wasm reproducibility, the
`#[ignore]`d real-toolchain suite, cargo-deny, cargo-machete, cargo-mutants);
`scripts/verify-phase1.sh --offline` is the explicitly reduced local mode, and its success
message names the release-only gates it did not run. `scripts/verify-phase2.sh` gates the
second milestone. Two `#[ignore]`d tests need the real toolchain (`stellar-cli` + a warm
contract cache), both in `ozpb-build-runner`: the golden end-to-end build, and the
boundary-shape compile check. CI runs them in the `nightly live` workflow.
`scripts/mutation-test.sh` is wired into CI and passes: all mutants caught in both
security-critical cores.

---

# Release-readiness hardening (2026-08-18)

An adversarial release review of the Tranche-1 surface before publication: every claim the
milestone makes was re-read the way an attacker or a release auditor would read it, and each
finding became either a fail-closed check or an explicit non-claim. Nothing here widens what
Phase 1 promises; most of it narrows a promise to exactly what the code can keep.

**Trust boundaries, made structural rather than asserted.**

- [x] **`install_safe` is gone from `SmartAccountRecord`.** It was a caller-supplied boolean
      standing where evidence should be. Account compatibility is now established solely from
      the code hash observed via RPC and resolved through the signed registry; a falsified
      hash refuses with `E_INCOMPATIBLE_ACCOUNT`. The demo's refusal step (step 8) now
      demonstrates exactly that: one field of one input changed to a syntactically valid lie,
      the same command as the permit path, and a required refusal.
- [x] **External-verifier signers are rejected at validation**
      (`E_SPEC_EXTERNAL_SIGNER_UNSUPPORTED`). The runtime OpenZeppelin signer value carries only the
      verifier address and key, so nothing at authorization time binds that address to the
      recognized verifier code; registry recognition of a caller-supplied hash proves nothing
      about the address. Until an acquisition/install layer can bind address to observed
      executable, the shape is refused rather than half-supported.
- [x] **Serialized recordings cannot mint trust.** Any bundle crossing the synthesize JSON
      boundary is downgraded to `self_supplied` — a `trust` field in caller JSON is not
      `rpc_reported`. The RPC adapter itself now verifies the network passphrase via
      `getNetwork`, compares the response `txHash` against the canonical requested hash, and
      independently recomputes the transaction hash from `envelopeXdr`, under bounded HTTP
      streams and bounded XDR decoding.

**The generated policy got a real lifecycle.** Every generated policy — stateless ones
included — now writes an installation marker scoped by (smart account, context-rule id):
`install` refuses a duplicate (`AlreadyInstalled`) and refuses after expiry, `uninstall` of
something never installed refuses (`NotInstalled`) and removes policy-owned state, and
`enforce` fails closed (`MissingState`) when the marker is absent. The artifact header's check
order is now: account authorization and installation state first, then the signer predicate,
then the rest. TTL extension covers the marker alongside the counter and instance entries, and
`contracts/differential/tests/ttl.rs` + `differential.rs` grew the lifecycle, isolation and
TTL-target cases. This moved the golden crates, so both derived identities moved with them —
the current values are the ones under "Verifiable artifacts" below, which is the single place
this document quotes them, precisely so that a later emission change cannot leave a figure
behind in a sentence about an earlier one. The normalized codegen-input hash `662ad7a9…` did
not move, because the inputs did not — only the emission.

**Validation owns its bounds.** User-controlled strings, evidence references and exact `ScVal`
values are size-capped per value and per rule; the caps sit deliberately below the 4 MiB
canonical-hash preimage ceiling, so a recording the recorder accepts cannot fail only when
hashed; and validation and codegen share the builder's 2 MiB input ceiling, so a spec that
validates cannot generate a crate the next stage refuses (`E_CODEGEN_RESOURCE_LIMIT` guards
the seam, and a maximum-shaped rule is generated in a non-vacuous boundary test).
Template-family hostility checks moved from codegen into the validation typestate
(`E_SPEC_TEMPLATE_FAMILY`), where the rest of the grammar checks live. Spending-limit
composition is validated semantically: a recognized SEP-41 `transfer` shape with the `i128`
amount at argument index 2, positive limit and period, decisions that can replay the
representative evidence — and never on mixed transfer/non-transfer rules.

**Evaluation stopped rounding up.** A rule that attaches a reviewed policy no longer yields a
whole-spec `permit` from the reference evaluator: the verdict is `indeterminate` while the
reviewed policy's state is unmodelled, and the layer-2 differential model is explicitly scoped
to the generated policy. On the registry side, accepted revocations persist across restarts
and are append-only across successor snapshots — a signed successor cannot un-revoke, rewrite
a reason, or move an effective version.

**Wire and MCP errors are a contract.** Every declared error code serializes as
`SCREAMING_SNAKE_CASE` and round-trips through an exhaustive `ErrorCode::ALL` table — closing
the two-spellings problem where `EBuildTimeout` shipped verbatim beside `E_BUILD_TIMEOUT`
prose. MCP tool failures return structured `{code, message, details}` with `isError: true`
instead of surfacing as JSON-RPC protocol errors, and request DTOs are closed schemas that
reject unknown fields.

**The build runner's environment is allowlisted.** The child build sees a sanitized
environment — service and cloud credentials and proxy variables excluded — and HTTP request
concurrency × cargo jobs is held to the detected CPU budget. The golden-build fixture also
gained the `rust-toolchain.toml` its real crate ships: its absence was R-01, the omission that
kept the `nightly live` workflow red for five days, because the fixture built with whatever
toolchain the runner had instead of the pinned one the manifest claims.

**Gates fail closed and say what they did not run.** `verify-phase1.sh` became the strict
release gate described in the header; `--offline` is the explicitly reduced mode whose success
message names the skipped release-only gates, so an offline pass can never read as a release
pass. `check-licenses.sh` fails when the advisory tooling cannot run instead of passing
vacuously. The live demo derives its policy expiry from `getLatestLedger` plus a
120,960-ledger horizon instead of a committed absolute ledger that necessarily expires.

**Docs follow the narrowed claims.** README and `docs/DEVELOPERS.md` state the Phase-1
assurance boundary (account recognition is generation compatibility, not installation safety;
`verify` and the install path are second-milestone), and `docs/ECOSYSTEM-CONFORMANCE.md` was
reconciled section by section — §9–§14 now cover the subsystems this pass hardened, and every
file:line reference in it was re-read against the tree.

Verified on this pass: fmt, `clippy -D warnings` and tests for both workspaces (319 host +
26 contract) and fmt for both generated crates; all gate scripts through
`verify-phase1.sh` in release mode (including cargo-deny, cargo-machete and the mutation
suite); the previously red `#[ignore]`d build-runner suite against the pinned stellar-cli
27.0.0, both tests green; and the live-testnet demo end to end, including the new dynamic
expiry and the step-8 refusal.

---

# The milestone boundary made a file boundary (2026-08-14)

The four post-MVP operations sat inline among the MVP ones in `toolkit`, their DTOs among the
MVP DTOs in `api-types`, their tool registrations among the MVP tools in `mcp-server`, and
their subcommands among the MVP subcommands in `cli`. Producing a first-milestone tree
therefore meant editing four shared files — the kind of edit that goes wrong quietly and
cannot be repeated reliably at the next milestone. Each crate now has a `tranche2` module, so
the extraction is a list of paths instead. No behaviour and no public surface changed; the
one visible difference is that `ozpb --help` lists `dev-registry` before the post-MVP
commands rather than among them, because a `#[command(flatten)]` group is contiguous.

Two assumptions about where the boundary ran turned out to be wrong, which is why this was
done rather than assumed. `cli` — a first-milestone crate — called four post-MVP operations
directly, so removing them left it as the one thing in the workspace that did not compile.
And the differential suite's dependency on the harness read as the whole suite depending on
it; `differential.rs` and `ttl.rs` mention it nowhere, so the strongest evidence for
code-generation quality stays where its claim is and only `generated_suite.rs` travels.

`verify` moves with the post-MVP operations although it is not one of the four. Three of the
fields it reports and its overall `matches` verdict come from the dry-run harness, so a
`verify` split along the milestone line would be a different tool wearing the same name.

**What leaves at the boundary.** Verified by deleting exactly this list: both workspaces then
build and their whole suites pass.

- `crates/api-types/src/tranche2.rs`, `crates/toolkit/src/tranche2.rs`,
  `crates/mcp-server/src/tranche2.rs`, `crates/cli/src/tranche2.rs`
- `crates/mcp-server/tests/mcp_stdio_tranche2.rs`
- `crates/harness/`, `crates/call-surface-core/`
- `contracts/differential/tests/generated_suite.rs`
- `scripts/verify-phase2.sh`, `scripts/check-unmodeled-acknowledged.py`,
  `scripts/layer1-unmodeled-acknowledged.txt` — all three are post-MVP: the first runs
  `ozpb dry-run`, the second parses its output, the third is that gate's data. **No CI
  workflow runs any of them**, so nothing would report their absence or their presence, and
  they are the entries most likely to travel into a first-milestone tree by inertia.

**What the extraction needs beyond deleting those paths.** Each is one or two lines, and the
list is the whole of it:

- the `mod` / `pub use` lines in the four parent modules, and in `cli` the flattened variant
  and its dispatch arm;
- in `mcp-server`, the router sum collapses back to the single MVP router, and
  `POST_MVP_TOOLS` in `tests/common/mod.rs` empties — the tool-count assertion is written
  against the sum of the two lists so that it stays exact either way;
- `ozpb-harness` and `ozpb-call-surface-core` leave `crates/toolkit/Cargo.toml`, the root
  `[workspace.dependencies]` and `workspace.members`; `ozpb-harness` leaves
  `contracts/differential/Cargo.toml`;
- both crate names leave `scripts/check-dep-rules.sh`. That step announces itself: a rule
  naming an absent crate now stops the gate instead of passing silently.

**Where the boundary is a convention rather than a mechanism**, stated so its cleanliness is
not read as more than it is. Cargo rejects an optional dev-dependency, which is the only
construction that could gate `ozpb-harness` behind the `required-features` of a single
`[[test]]` target, so that edge is package-wide however few files use it. And nothing
mechanical marks the three scripts above — only this list.

---

# Hardening pass — build containment, rendering safety, evidence honesty (2026-08-10)

An audit of two properties RFP requirement #3 depends on: that a generated policy always
compiles, and that it cannot claim one restriction while enforcing another. Both held — the
compile gate is unskippable (`crates/toolkit/src/lib.rs` `?`-propagates a build failure before
source is ever returned) and all eight value-interpolation sites were validator-gated. The
audit surfaced five other defects, now closed:

- [x] **1. The build timeout bounded nothing.** `run_bounded` killed only the `stellar` child,
      while `cargo` and its `rustc` workers survived, and the timeout path returned before
      joining its reader threads, leaking them and their pipe descriptors. Now the child is a
      process-group leader (`process_group(0)`) and the group is SIGKILLed via `nix::killpg`;
      readers join on **every** exit path; the toolchain version probes are bounded too. Both
      behaviours were verified to *fail* against the previous code before the fix landed.
      Unix-only; Windows keeps child-only kill (job objects are container-era work).
- [x] **2. Every production build was cold.** `target_dir: None` meant a fresh temp dir per
      build, so each request recompiled the whole dependency tree single-threaded inside 120s
      — while the only test of that path passed a *warm* shared `contracts/target`. The cache
      is now shared and persistent by default, jobs are configurable, and the default timeout
      is 600s now that it is a real bound.
- [x] **3. Build settings were unconfigurable.** All seven call sites hardcoded
      `BuildConfig::default()`. Now exposed **operator-side only** (four CLI flags with
      matching env vars the MCP server reads before the transport branch, so stdio and HTTP
      agree) — never on the wire, since a caller-chosen timeout is resource exhaustion and a
      caller-chosen builder path arbitrary execution. `Builder::Stub` is unreachable from
      configuration (tested), and operator faults now map to `EBuildUnavailable` instead of
      reading to an agent as "your spec does not compile".
- [x] **4. Rendering safety was convention, not structure** (§4.4). A future `Constraint`
      variant carrying a `String` would have slipped past the `_ => {}` arm unvalidated. Now
      `crates/codegen/src/render.rs` holds validator-only-constructible literal types, the
      emitter takes a `RenderRule` and never sees a `RuleSpec`, and the conversion is
      exhaustive over `Constraint`. **Output is byte-identical** — the golden gates pass
      without `UPDATE_GOLDEN`, so no published artifact hash moved.
- [x] **5. Coverage and composed-policy gaps could pass green.** `all_agree` is silent about
      breadth, the harness computed a `coverage` map it never read, and `verify-phase2.sh`
      grepped only `"all_agree": true` — so a regression that stopped emitting a whole
      boundary class, or a newly composed reviewed policy, would still report success. Added
      `expected_classes` (derived from the spec's own shape, not a fixed list) plus
      `EvidenceReport::missing_classes()`, surfaced `coverage`/`missing_classes` on
      `DryRunOutput` and `models_all_policies`/`unmodeled_reviewed_policies` on `VerifyOutput`
      as its own dimension (deliberately *not* folded into `matches`), and gated both. The
      composed-policy gate reads `scripts/layer1-unmodeled-acknowledged.txt` and fails on an
      unacknowledged gap **and** on a stale entry, so it cannot become a blanket exemption.

Also added: the RFP's "always compilable" claim is now a property test
(`any_validated_spec_generates_parseable_rust` over every constraint variant, predicate kind,
state shape and arity, parsed with `syn`), with the real-compiler counterpart
(`boundary_specs_compile_to_wasm`, `#[ignore]`d) covering `i128::MIN`/`MAX`, zero-arg tuples,
the longest legal symbol, and the `max_calls` boundaries. `MAX_SIGNERS_PER_RULE` /
`MAX_POLICIES_PER_RULE` are now asserted against `stellar_accounts::smart_account::MAX_SIGNERS`
/ `MAX_POLICIES` from the contracts workspace (the host workspace cannot depend on that crate).

**Independent security review of this pass — findings and what changed.** Two reviewers were
run against the diff with instructions to attack each claim. Nine survived refutation; all are
now fixed, each with a regression test:

- **The rendering-safety claim was false in one place (high).** `template_family` still reached
  the emitted header as a bare `&str`. It arrives on the *spec*, and `generate_code`/`verify`
  accept a caller-supplied spec — the registry check that resolves a family runs only on the
  *synthesize* path. A newline let it open new `//!` lines (forging the limits a reviewer
  reads, above a duplicated hash line) or inject a crate-root attribute:
  `#![doc = include_str!("…")]` reads an arbitrary file inside the operator's build and returns
  the failure verbatim to the caller, and `#![cfg(any())]` strips the whole policy. Fixed with a
  fifth render type, `TemplateFamily`, whose charset excludes newline, backtick, quote, `#` and
  `[`; `emit_lib` now takes no bare `&str` at all.
- **The timeout could still fail to bound the request (medium) — a regression this pass
  introduced.** Joining the reader threads unconditionally meant a descendant that left the
  process group (its own `setsid`, or a wrapper run under job control) kept a pipe open and the
  join waited for *its* lifetime. Measured at **60s for a 1s timeout**; the old code returned at
  once and merely leaked two threads. Now the collection is bounded (5s grace, then the thread
  is abandoned) — verified by reverting the bound and watching the same test fail at 60.2s.
- **The kill was not on every path (low–medium).** It was gated on `Ok(None)`, so a
  `wait_timeout` I/O error left the build running with nothing bounding the caller; and
  `terminate_process_group(&child)?` returned before the joins, so a kill failure (e.g. `EPERM`)
  reproduced the very leak being fixed. Both paths now terminate, collect, then propagate.
- **The new shared build cache was attackable (medium; high on a shared Linux host).**
  `std::env::temp_dir().join("ozpb-build-cache")` is a fixed name with no uid, and
  `create_dir_all` follows symlinks. Pre-creating it as a symlink gave an arbitrary write with
  the worker's privileges; pre-creating it as attacker-owned allowed planting dependency
  artifacts that link into the policy wasm — and since `verify` reproduces through the *same*
  cache, the reproduction would agree, i.e. `matches: true` on wasm that does not correspond to
  the reviewed source. Now per-uid, created `0700`, and refused if it is a symlink, not a
  directory, owned by another uid, or group/world-accessible.
- **The coverage floor over-demanded, and could be masked (medium ×2).** It required
  `TupleCrossProduct` whenever two tuples shared `(fn, arity)`, but the generator skips mixes
  that reproduce an observed tuple — so two tuples differing in exactly one position emit
  nothing and a *correct* spec failed the gate (the shape the synthesizer produces from the same
  payment recorded at two amounts). And because both the floor and coverage were unioned across
  rules, rule 0's cases could vouch for rule 1's gap. The floor is now per rule, and demands
  cross-products only when two tuples differ in ≥2 positions.
- **A class could be "covered" by permit-only cases (low).** With an expiry at `u32::MAX` the
  only expiry-*denial* case is unreachable, so `TimeBoundary` was reported covered having never
  shown a denial. Deliberately **reported, not gated** — it is a degenerate bound (a cap of
  `i128::MAX` cannot be exceeded), so failing would reject correct specs; the new
  `permit_only_classes` says the grant is effectively unbounded on that axis.
- **The acknowledgement file could pre-silence an unchecked spec (medium).** Staleness was only
  detectable for specs the gate loop covers, so an entry naming `soroswap` sat unnoticed and
  would arrive pre-acknowledged the day that spec joined the loop. A `--known-specs` mode now
  fails on any entry outside the checked set.
- **`Strkey` proved "decodable", not "is an Address" (low).** Muxed (`M…`) and pre-auth (`T…`)
  strkeys decoded fine and would be emitted into `Address::from_str`, where the SDK panics at
  *runtime* — a policy that deploys and then denies everything, invisible to every offline gate.
  Restricted to contract and ed25519-account strkeys.
- **Smaller items:** the version probe silently truncated 64 KiB of attacker-influenced bytes
  into the BuildManifest (now first line, ≤256 bytes, hard failure otherwise); a hanging probe
  reported `EBuildTimeout`, telling an agent its spec was too big when the fault was the
  operator's (now `EBuildUnavailable`); operator paths leaked into wire error messages (§6.5);
  `OZPB_BUILD_TIMEOUT_SECS`/`_JOBS` had no ceiling, so a typo failed *open*; the four
  default-config toolkit wrappers had zero callers and silently bypassed operator config
  (removed); and several pre-existing `cmd && echo ✔` lines in `verify-phase2.sh` did not abort
  under `set -e` (a failing `cargo test -p ozpb-harness` printed nothing and the gate still
  said PASSED).

**Deliberately out of scope, scheduled rather than dropped:**

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7:
   `prepare_install_intent` requires a `Safe` authority-surface verdict, and the pure core is
   complete and tested but fed a caller-supplied snapshot. Excluded from this pass because it
   is only verifiable against a live network, so most of it cannot be test-driven offline.
   **This is the next pass.**
2. **Containerized build + the missing BuildManifest provenance fields** (§4.4, §6.3 — container
   image digest, source commit + dirty-tree status, template-pack hash, canonicalization version,
   build target). The builder is still honestly labelled `local-unattested`. Adding manifest
   fields rehashes every manifest, so both land together at a release gate. Memory / disk / cgroup
   limits from §4.6 remain part of that work and are **not** claimed today. §6.3 now carries a
   scope note listing the fields the manifest holds against the ones it does not, so the document
   states the gap instead of leaving a reader to diff it against the struct.
3. **Real reviewed policy wasm at layer 2** (F5d). The blocker is not a dependency bump:
   `stellar-accounts` 0.7.2 ships `src/policies/*.rs` as *library helpers* and its `#[contract]`
   wrappers exist only under `src/*/test/`, so **OpenZeppelin publishes no policy wasm**.
   Pinning one requires building a policy contract from OZ source and deciding its review
   status. Related: `simple_threshold` and `weighted_threshold` appear only in the docs, never
   in code.
4. **Encoded-literal rendering** — template-pack v2, one deliberate artifact-hash break.
5. ~~**`api-types` schema-stability tests.**~~ **Closed by the release-readiness pass.**
   `error_codes_round_trip` now iterates `ErrorCode::ALL` exhaustively and asserts each code's
   single `SCREAMING_SNAKE_CASE` spelling, which was the deliberate breaking wire change this
   item said should be decided rather than drifted into; request DTOs are closed schemas that
   reject unknown fields, and `dtos_have_schemas` covers the MCP-exposed inputs and outputs.
6. **Layer-2 deny-code agreement.** `generated_suite.rs` asserts only the permit/deny boolean,
   while the hand-written `differential.rs` agrees on verdict *and* deny reason.
7. ~~**`scripts/mutation-test.sh` does not currently pass.**~~ **Closed.** The run exposed
   **8 surviving mutants** — 3 in `crates/evaluator` and 5 in `crates/synthesizer` — all
   pre-existing (the survivor set was byte-identical between a clean-HEAD worktree and the
   hardening pass). They mattered because of where they sat: two comparisons in the reference
   evaluator that the differential suite treats as the independent second opinion, and the
   target-code-hash drift guard. Each now has a test, and the script is wired into CI as its
   own job so it cannot drift again. Two were subtler than they looked: `evaluate_rule` had no
   coverage in its own crate (every test went through `evaluate`), and the predicate
   comparisons share a deny reason with a later check, so the first attempt at those tests
   passed while the mutants still survived — the tests had to be built so only the comparison
   under test could decide the outcome.

---

# Post-audit hardening (self-audit against the RFP)

A find-the-gaps pass over the RFP surfaced four items the earlier phases had asserted but
not *proven*; all four are now closed and verified.

- [x] **State changes as evidence** — the recorder now extracts `LedgerEntryChanges`
      (`tx_changes_before` / per-op `state` / `tx_changes_after`, meta v3 **and** v4) into
      typed `StateChange` evidence on the bundle, so contract-storage effects are captured
      alongside auth calls and token movements — not silently dropped. (`recorder-core`, +2 tests.)
- [x] **Automated MCP protocol test** — `crates/mcp-server/tests/mcp_stdio.rs` spawns the
      *built* server binary and drives the real JSON-RPC handshake over stdio: `initialize`
      + `tools/list` (all 11 tools carry output schemas, exact count asserted), a `dry_run` `tools/call` returning
      structured all-agree evidence, an `evaluate_spec` permit derived from the committed
      example spec (never drifts), and a malformed-input call yielding a machine-readable
      error. Closes the "MCP wiring only manually exercised" gap. (+4 tests.)
- [x] **Mutation testing** (architecture §8) — `scripts/mutation-test.sh` + `.cargo/mutants.toml`
      run `cargo-mutants` on the two security-critical cores, and a survivor is treated as a
      missing deny-test. Killed at the time by targeted tests (threshold boundary,
      permission-bundle fan-out, tuple dedup, spending-limit param validation, widening
      apply/reject reasons, scval encoding). Deterministic test-support fixtures are scoped out
      with a documented rationale (their correctness is enforced by the downstream
      golden/differential suites). Per-crate counts are deliberately not quoted here — they
      move with the code and with the pinned `cargo-mutants` version; the header states the
      current result, and it is now enforced by CI rather than by a manual run.
- [x] **Developer docs** — `docs/DEVELOPERS.md`: CLI + MCP usage, the synthesizer's scoping
      decisions (exact-by-default, widening-only-via-explicit-decision, permission-bundle),
      and a step-by-step guide to extending the toolkit with a new template primitive.

---

# Independent implementation review — findings addressed

A source/security review (`tmp/architecture-implementation-review-2026-07-22.md`) raised two
critical and six high-severity findings. Status:

- [x] **1. Duplicate-signer threshold bypass (critical).** Signers now canonicalize to a
      logical identity (external keys hex-decoded, so casing aliases collapse); duplicates
      fail validation, and synthesis validates before returning. The generated `matched_count`
      iterates *expected* signers, matching the evaluator's unique-count semantics.
- [x] **2. Numeric-string source injection (critical).** `EqI128`/`LeI128`/`GeI128` are
      validated as canonical decimal i128 before codegen (hostile tokens can't cross the
      `ValidatedSpec` typestate), and codegen emits `i128::MIN` as the named constant so a
      validated spec always compiles.
- [x] **3. Recognition/verification as caller assertions.** The `recognized` boolean is gone;
      `check_against_policy`/`check_policy_call_surface` verify wasm hash + registry + storage
      against a signed snapshot. A real `BuildManifest` (`crates/build-runner`) reproduces wasm
      via a sandboxed `stellar contract build`; `verify.matches` requires byte-identical
      reproduction. Build tests are hermetic via an injectable `Builder` (real vs. `Stub`).
- [x] **4. Registry not in the synthesis path.** Synthesis resolves every capability
      (account/verifier/template/policy) through `ozpb-registry` fail-closed; target code
      hashes come from recorder evidence; reviewed **adapters** are wired in and produce
      `AdapterDerived` provenance with `AdapterRequired`/`Refuse` drift. The three wasm hashes
      are now **real** — built from OpenZeppelin's own example contracts at tag `v0.7.2` (see
      `ozpb_domain::pinned_upstream` for provenance), replacing hashes-of-text-labels that
      recognized nothing. *Residual:* the signing **root** is still a development key derived
      from a fixed string, so a production deployment must supply its own governance root; and
      reviewed-adapter resolution from the registry snapshot is the last mile (the synthesizer
      supports adapters; the toolkit passes none yet).
- [x] **5. Dry-run false confidence.** The harness covers *every* rule; synthesis refuses
      spending-limit composition on mixed transfer/non-transfer rules; and dry-run/verify now
      **flag composed reviewed policies as outside layer-1 coverage** (`unmodeled_policies`) so
      `all_agree` is never read as covering an unmodeled on-chain cap. *Residual (5d):*
      exercising the **real** reviewed spending-limit wasm in the layer-2 differential
      (cap/window/ordering/rollback) needs that audited wasm pinned in the contracts workspace.
- [x] **6. Recorder provenance.** `getNetwork` verifies the passphrase; missing
      ledger/timestamp and malformed simulation auth fail closed; empty sim-auth never falls
      back to envelope auth; simulation `stateChanges` are preserved; `approve` events are
      decoded; XDR decoding uses bounded limits. (All with tests.)
- [~] **7. Call-surface / install path.** `check_policy_call_surface` is exposed (11 MCP
      tools) and `prepare_install_intent` requires a validated `Safe` verdict; the admin-rule
      skip is guarded (a weak/empty Default-as-admin now fails closed); dominance is
      conservatively fail-closed. *Residual:* a **live acquisition adapter** (getLedgerEntries
      → `AccountState` with `NextId`/`Count` reconciliation and transitive closure) is not yet
      built, so the end-to-end live→verdict path is not operational — the pure core is
      complete and tested but is fed a caller-supplied snapshot. `assemble_install_transaction`
      is deliberately wallet-owned (needs live sequence/fees); method-level capability-algebra
      dominance is future work.
- [~] **8. HTTP server hardening.** `--http` is loopback-only and refuses to start without a
      ≥32-byte bearer token and an RPC allowlist; it applies bearer auth (constant-time),
      a global rate limit, a request-size bound, an SSRF allowlist on the record tools, and
      runs blocking work off the async executor. **All now have tests** (loopback guard, SSRF
      allowlist, constant-time compare). *Residual:* per-tool quotas, OS-level compile
      isolation, and a no-secrets worker role before genuine multi-tenant public hosting.

Also fixed from the review's tests/code-quality section: untracked 919 build-output files
and gitignored them + the testnet secrets; the advisory gate now covers **both** workspaces
(the contracts `paste` unmaintained advisory is ignored with justification).

**Honest status:** findings 1, 2, 3, 5(a–c), 6 are fully resolved with tests; 4, 7, 8 are
resolved except for the residuals above, which are live-integration / dependency-pinning work
that cannot be completed or truthfully tested offline. Do not read this as "Phase 2 fully
delivered end-to-end" — the live call-surface scan and the real passkey wallet install/revoke
flow remain the operational Phase-2/3 work.

---

# Phase 2 — Testnet (prove & integrate)

Target (architecture.md §10, Phase 2): four-layer harness with constraint-derived deny
generation + differential testing · the two-surface `check_policy_call_surface` with
`PolicyBindingSet` ordering · `dry_run` / `verify` / `check_against_policy` /
`prepare_install_intent` / `import_recording` tools · Claude skill with clarification +
confirm-before-deploy · all three walkthroughs · pollywallet integration · hosted testnet
endpoint.

## Delivered (offline, deterministic, tested)

- [x] `harness` — constraint-derived deny-suite generator + labeled permit/deny evidence
      report (layer 1); the suite is exposed so layer 2 drives identical mutations.
- [x] `call-surface-core` — the **two-surface account authority check** (§4.8 / D4 / D6):
      bounded_next_id enumeration, Count reconciliation failing closed on archival deficit,
      transitive closure, conservative dominance, both the direct-policy and
      account-management surfaces (the management-surface bypass), no override.
- [x] Layer-2 differential: the harness-generated deny suite run through the **real
      compiled contract** in a committed-state soroban env (W2), agreeing on verdict + code.
- [x] Walkthroughs: W1 (Blend claim), W2 (SEP-41 subscription), W3 (bounded Soroswap) —
      synthesized, validated, harness layer-1 all-agree; W3 compiles to wasm (the richest
      shape: LeI128/GeI128 bounds, exact scval path, AnyValue deadline).
- [x] `AnyValue` constraint (maximal widening) + code-hash-bound `adapters` (Soroswap
      router arg roles: MaxInput/MinOutput/CallerChosen/ExactOnly).
- [x] New tools wired through toolkit + MCP (now **11 tools**, all with output schemas) +
      CLI: `dry_run`, `verify` (dimensions reported separately), `check_against_policy`
      (recognition-scoped), `import_recording`, `prepare_install_intent` (pure intent only).
- [x] Claude skill (`skills/policy-builder/SKILL.md`) + `.mcp.json` + plugin manifest:
      clarification + confirm-before-deploy; the skill never decides bytes, signs, or
      offers an "install anyway" path.
- [x] `verify-phase2.sh` — all six offline gates pass.

## Live testnet / runtime evidence (done — see docs/TESTNET-EVIDENCE.md)

This sandbox *does* have network egress, Node 24, and the Stellar CLI, so several items
first parked as "blocked" were actually done against **live Protocol-27 testnet**:

- [x] **Recorder against live Gateway public RPC** — a real on-chain `transfer` recorded
      via `rpc.testnet.stellar.gateway.fm`; decoded auth call + token movement match chain.
- [x] **Generated policy deployed on testnet** — real contract instance
      `CCFRJAPI5DUYR2FPOH5NCZGU3QYH3QFZMB7FMR67EJEJ32LA4YTD4G6L` (compiles → deploys).
- [x] **MCP full `tools/call` round-trip (stdio)** — `dry_run` returns structured content.
- [x] **MCP streamable-HTTP endpoint** (`--http`) — real `initialize` over HTTP with a
      session id; the transport a hosted endpoint uses (only the public URL/TLS/auth is ops).
- [x] **Full OZ smart-account `__check_auth` install + on-chain permit/deny** — deployed an
      OZ smart account (External ed25519 admin) + verifier, generated a native-SAC policy
      with the toolkit, installed it via `add_context_rule` authorized by a hand-built
      `AuthPayload` (ed25519 over the rule-ID-bound `auth_digest` — the signing
      smart-account-kit wraps), then on-chain: a permit (exact transfer SUCCEEDED, real XLM
      moved) and denies (over-amount and wrong-recipient reverted). Reproducible harness in
      `testnet-harness/`; addresses + tx hashes in `docs/TESTNET-EVIDENCE-TRANCHE-2.md`. This is the
      Phase-2 verifiable outcome (minus the passkey UX + video).

- [x] **pollywallet UI + headless passkey (Playwright)** — cloned the real repo (unit suite
      53/54; 1 expired live fixture), booted its dev server locally, and drove its actual
      "Create Smart Wallet" button headless with a CDP **virtual WebAuthn authenticator**:
      pollywallet's own `@simplewebauthn/browser` passkey registration completed (resident
      secp256r1 credential; screenshot in `docs/media/`). Also a self-contained headless
      passkey create+sign proof with recorded video. Harness: `testnet-harness/browser/`.
      The only gap to a full pollywallet install run is its server-side relayer (Channels)
      config — a backend dep, not a browser/passkey limit; and pollywallet's AI-codegen +
      Docker compile-sandbox deps are what this toolkit replaces.

## Still requires a human / external party

- [ ] **Hosted public endpoint** — the server runs (stdio + streamable HTTP); a public URL
      + TLS + auth is ops/deployment.
- [ ] **OpenZeppelin technical-reviewer sign-off** — external human review. (A narrated
      demo video is a human artifact; the Playwright harness already records `.webm` runs.)
- [ ] **Hosted public endpoint** — the server runs; a public URL + TLS + auth layers are ops.
- [ ] **Demo video; OpenZeppelin reviewer sign-off** — external/human.

---

# Phase 1 progress

Target (architecture.md §10, Phase 1): recorder (executed + simulated, meta v3/v4, all
credential arms, authorizer selection, trust levels, dual hashing) · PolicySpec v1
(mandatory signer predicate, exact tuples, provenance) · acyclic artifact chain · initial
capability registries · reference evaluator · synthesizer v1 (exact-by-default,
fail-closed) · codegen (signer predicate + tuple scope, immutable config) + spending_limit
composition · reproducible builds · MCP server v0 (6 tools, stdio).

**Verifiable outcome (met):** a recorded testnet-shaped transfer becomes a compilable Rust
policy, byte-identical across two cold runs, agreeing with the reference evaluator on a
constraint-derived suite — including zero-signer denial and strict-mode signer-mutation
denial.

## Status — COMPLETE

- [x] Repo scaffold (workspace, toolchain pin, dep-rule check script)
- [x] `domain` — hashes, newtypes, trust levels, canonical encoding (13 tests)
- [x] `policy-spec` — schema, validation typestate, canonical spec hash (16 tests)
- [x] `evaluator` — independent reference evaluator (20 tests)
- [x] `synthesizer` — exact-by-default, fail-closed (11 tests)
- [x] `recorder-core` + `source-bundle` — XDR fixtures, dual hashing (13 tests)
- [x] `registry` — signed snapshots, rollback rejection, fail-closed queries (7 tests)
- [x] `codegen` — deterministic template assembly, golden output (7 tests)
- [x] `contracts/` — golden policy compiles + 14-case differential suite (evaluator vs
      real compiled contract in a committed-state soroban env)
- [x] `api-types` + `toolkit` + `source-rpc` + `mcp-server` (6 tools, stdio) + `cli`
- [x] Phase 1 verification: `scripts/verify-phase1.sh` — all 6 gates pass

**Totals:** 112 tests (98 host + 14 differential) · 13 crates + contracts workspace.

## The pipeline (all deterministic, all fail-closed)

```
EvidenceSnapshot ─(recorder-core)→ RecordingBundle ─(synthesizer)→ PolicySpec
   ↑ acquisition adapters            (auth tree, dual hashes)        (exact tuples,
   (source-rpc / source-bundle,       evidence, trust levels)         signer predicate,
    trust derived by path)                                            provenance)
                                                                          │
                                              reference evaluator ◄───────┤ (validate → ValidatedSpec)
                                              (independent; CI-enforced    │
                                               no codegen dep)             ▼
                                                                      codegen → immutable
                                                                      Soroban policy crate
                                                                      (compiles; byte-identical
                                                                       wasm; differential-verified)
```

## Verifiable artifacts

- **Codegen determinism:** two cold runs of `ozpb generate` produce byte-identical
  `src/lib.rs` (sha256 `fefcd81f…`); normalized codegen-input hash `662ad7a9…`.
- **Wasm reproducibility:** `stellar contract build` → byte-identical wasm across a full
  `cargo clean` rebuild (sha256 `5c54d021…`). The claim holds; the gate that asserted it did
  not until 2026-08-13. It hashed `contracts/target/…`, which the rebuild never writes: the
  golden crate is excluded from the contracts workspace (it carries its own
  `[profile.release]`), so `stellar contract build` writes to *its* target dir. The old gate
  compared one untouched file with itself and passed unconditionally — and locally that file
  existed at all only because the differential suite builds the crate as a dev-dependency, a
  different build with a different hash. Found by the first scheduled nightly run, which failed
  with `No such file or directory` on a fresh checkout. The gate now cleans, asserts the
  artifact is gone before rebuilding, and compares.
- **Differential agreement:** the reference evaluator and the real compiled policy agree
  on verdict AND deny code across 14 adversarial cases.
- **MCP:** `initialize` + `tools/list` over stdio expose 6 tools, each with an output
  schema generated from the shared `api-types` DTOs.
- **Offline demo:** `docs/examples/` holds runnable pipeline inputs; the CLI runs
  record → synthesize → generate → evaluate with no network.

## Architecture invariants enforced (not just asserted)

- `evaluator ↛ codegen` and cores are transport-free — `scripts/check-dep-rules.sh`
  (CI job) fails on any forbidden edge in the cargo graph.
- Codegen output must equal the committed golden crate — `golden_crate_matches_committed_output`.
- Generated code passes the same `rustfmt`/`clippy -D warnings` gates as handwritten code.
- Confidential material must not enter the public tree —
  `scripts/check-publication-allowlist.sh` (negative sentinel test).

## Notes / follow-ups

- **Dependency skew:** `contracts/Cargo.lock` pins `ed25519-dalek` to 2.1.1 — `soroban-env-host`
  declares an open-ended `>=2.0.0` and the 3.x line breaks its testutils.
- **Registry:** the `registry::dev` snapshot now pins real upstream wasm hashes (OZ example
  contracts at `v0.7.2`, built with this repo's pinned rustc — provenance in
  `ozpb_domain::pinned_upstream`). Its signing root remains a development key.
- **Not in Phase 1 (by design, per §10):** dry-run harness layers 3–4, verify/check_against_policy/
  prepare_install_intent/assemble_install_transaction tools, wallet integration, hosted
  endpoint, the call-surface check — these are Phase 2/3.
