# Progress

The first phase, plus two hardening passes. `scripts/verify-phase1.sh` is the strict
release gate (dependency/publication/build-input/quoted-hash invariants, fmt + clippy +
tests over both workspaces and the generated crate, golden/determinism checks, wasm
reproducibility, the `#[ignore]`d real-toolchain suite, cargo-deny, cargo-machete);
`scripts/verify-phase1.sh --offline` is the explicitly reduced local mode, and its success
message names the release-only gates it did not run. Two `#[ignore]`d tests need the real
toolchain (`stellar-cli` + a warm contract cache), both in `ozpb-build-runner`: the golden
end-to-end build, and the boundary-shape compile check. CI runs them in the `nightly live`
workflow, and the release gate runs them too.

---

# Release-readiness hardening (2026-08-18)

An adversarial release review of the Tranche-1 surface: every claim the milestone makes was
re-read the way an attacker or a release auditor would read it, and each finding became
either a fail-closed check or an explicit non-claim. Nothing here widens what Phase 1
promises; most of it narrows a promise to exactly what the code can keep.

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
TTL-target cases. This moved the golden crate, so both derived identities moved with it:
emitted `src/lib.rs` is now sha256 `f0a84503…` and the clean-rebuild wasm `5b9374d8…`; the
normalized codegen-input hash `662ad7a9…` did not move, because the inputs did not — only the
emission.

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
reviewed policy's state is unmodelled, and the differential model is explicitly scoped to the
generated policy. On the registry side, accepted revocations persist across restarts and are
append-only across successor snapshots — a signed successor cannot un-revoke, rewrite a
reason, or move an effective version.

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

---

# Hardening pass — build containment, rendering safety, evidence honesty (2026-08-10)

An audit of two properties RFP requirement #3 depends on: that a generated policy always
compiles, and that it cannot claim one restriction while enforcing another. Both held — the
compile gate is unskippable (`crates/toolkit/src/lib.rs` `?`-propagates a build failure before
source is ever returned) and all eight value-interpolation sites were validator-gated.

The audit ran over the whole toolkit, so some of what it found belongs to a component the
first milestone does not contract: the dry-run harness and the reproduce-and-verify surface
are second-milestone deliverables (§4.5, §10), and the findings that landed on them —
evidence-breadth reporting and composed reviewed policies being read as covered — are
recorded with that milestone rather than claimed here. The four defects it found in what this
milestone delivers, all now closed:

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
Also added: the RFP's "always compilable" claim is now a property test
(`any_validated_spec_generates_parseable_rust` over every constraint variant, predicate kind,
state shape and arity, parsed with `syn`), with the real-compiler counterpart
(`boundary_specs_compile_to_wasm`, `#[ignore]`d) covering `i128::MIN`/`MAX`, zero-arg tuples,
the longest legal symbol, and the `max_calls` boundaries. `MAX_SIGNERS_PER_RULE` /
`MAX_POLICIES_PER_RULE` are now asserted against `stellar_accounts::smart_account::MAX_SIGNERS`
/ `MAX_POLICIES` from the contracts workspace (the host workspace cannot depend on that crate).

**Independent security review of this pass — findings and what changed.** Two reviewers were
run against the diff with instructions to attack each claim. Nine survived refutation. Three
of them landed on the dry-run harness and the composed-policy gate — second-milestone
deliverables, so they are recorded with that milestone. The rest are fixed here, each with a
regression test:

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
- **`Strkey` proved "decodable", not "is an Address" (low).** Muxed (`M…`) and pre-auth (`T…`)
  strkeys decoded fine and would be emitted into `Address::from_str`, where the SDK panics at
  *runtime* — a policy that deploys and then denies everything, invisible to every offline gate.
  Restricted to contract and ed25519-account strkeys.
- **Smaller items:** the version probe silently truncated 64 KiB of attacker-influenced bytes
  into the BuildManifest (now first line, ≤256 bytes, hard failure otherwise); a hanging probe
  reported `EBuildTimeout`, telling an agent its spec was too big when the fault was the
  operator's (now `EBuildUnavailable`); operator paths leaked into wire error messages (§6.5);
  `OZPB_BUILD_TIMEOUT_SECS`/`_JOBS` had no ceiling, so a typo failed *open*; and the four
  default-config toolkit wrappers had zero callers and silently bypassed operator config
  (removed).

**Deliberately out of scope, scheduled rather than dropped:**

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7: the install
   path a later milestone contracts cannot proceed without a `Safe` authority-surface verdict,
   and that verdict is derived from an account snapshot no adapter here acquires. Excluded from
   this pass because it is only verifiable against a live network, so most of it cannot be
   test-driven offline. **This is the next pass.**
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
6. **Layer-2 deny-code agreement.** The hand-written `differential.rs` here agrees with the
   reference evaluator on verdict *and* deny reason. The generated layer-2 suite, which asserts
   only the permit/deny boolean, is part of the dry-run harness — a second-milestone
   deliverable — so bringing it up to deny-code agreement belongs to that milestone.

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
      + `tools/list` (every served tool carries an output schema, and the served set is
      asserted against the list of names the milestone contracts), an `evaluate_spec`
      `tools/call` returning a permit derived from the committed example spec (so it never
      drifts from the fixture), and a malformed-input call yielding a machine-readable
      error. Closes the "MCP wiring only manually exercised" gap. (+3 tests.)
- [x] **Developer docs** — `docs/DEVELOPERS.md`: CLI + MCP usage, the synthesizer's scoping
      decisions (exact-by-default, widening-only-via-explicit-decision, permission-bundle),
      and a step-by-step guide to extending the toolkit with a new template primitive.

---

# Independent implementation review — findings addressed

An independent source-and-security review of the implementation, run on 2026-07-22, raised two
critical and six high-severity findings. Status:

- [x] **1. Duplicate-signer threshold bypass (critical).** Signers now canonicalize to a
      logical identity (external keys hex-decoded, so casing aliases collapse); duplicates
      fail validation, and synthesis validates before returning. The generated `matched_count`
      iterates *expected* signers, matching the evaluator's unique-count semantics.
- [x] **2. Numeric-string source injection (critical).** `EqI128`/`LeI128`/`GeI128` are
      validated as canonical decimal i128 before codegen (hostile tokens can't cross the
      `ValidatedSpec` typestate), and codegen emits `i128::MIN` as the named constant so a
      validated spec always compiles.
- [x] **3. Recognition/verification as caller assertions.** The `recognized` boolean a caller
      could simply set is gone: recognition is derived, by matching an observed code hash
      against a signed registry snapshot, and an unmatched hash is an error rather than a
      guess. A real `BuildManifest` (`crates/build-runner`) reproduces wasm via a sandboxed
      `stellar contract build`, and build tests are hermetic via an injectable `Builder` (real
      vs. `Stub`). The tools that consume a reproduction to answer "does this *deployed* policy
      correspond to this source" are second-milestone deliverables, so that question is not
      answered in this milestone.
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
- [~] **5. Dry-run false confidence.** The part of this finding that lands on synthesis is
      closed: synthesis refuses spending-limit composition on mixed transfer/non-transfer rules,
      so a spec cannot describe a cap that would not apply to every rule it covers. Everything
      else in the finding concerns the dry-run harness and the evidence report it emits — a
      second-milestone deliverable (§4.5) — and so is the residual (5d): exercising the **real**
      reviewed spending-limit wasm in the layer-2 differential (cap/window/ordering/rollback)
      needs that audited wasm pinned in the contracts workspace.
- [x] **6. Recorder provenance.** `getNetwork` verifies the passphrase; missing
      ledger/timestamp and malformed simulation auth fail closed; empty sim-auth never falls
      back to envelope auth; simulation `stateChanges` are preserved; `approve` events are
      decoded; XDR decoding uses bounded limits. (All with tests.)
- [ ] **7. Call-surface / install path.** The authority-surface check and the install intent are
      second-milestone deliverables (§4.8, §10), so nothing in this milestone answers whether an
      account's installation surface is safe to touch. What this milestone does carry is the
      *precondition*: `install_safe` on the account record, which synthesis treats as a
      fail-closed input — a false verdict yields no spec at any level of permission, and
      `scripts/demo-tranche1.sh` evidences that refusal against live testnet. A **live
      acquisition adapter** (getLedgerEntries → `AccountState` with `NextId`/`Count`
      reconciliation and transitive closure) is the missing piece that would let the verdict be
      derived rather than supplied. `assemble_install_transaction` is deliberately wallet-owned
      in every milestone (it needs live sequence/fees); method-level capability-algebra
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

**Honest status:** findings 1, 2, 3 and 6 are fully resolved with tests; 4 and 8 are resolved
except for the residuals above, which are live-integration / dependency-pinning work that cannot
be completed or truthfully tested offline. Findings 5 and 7 land largely on components a later
milestone contracts — the dry-run harness, the authority-surface check, the install path — and
are marked accordingly rather than counted as closed here. The live call-surface scan and the
real passkey wallet install/revoke flow are operational work for a later milestone.

---

# Phase 1 progress

Target (architecture.md §10, Phase 1): recorder (executed + simulated, meta v3/v4, all
credential arms, authorizer selection, trust levels, dual hashing) · PolicySpec v1
(mandatory signer predicate, exact tuples, provenance) · acyclic artifact chain · initial
capability registries · reference evaluator · synthesizer v1 (exact-by-default,
fail-closed) · codegen (signer predicate + tuple scope, immutable config) + spending_limit
composition · reproducible builds · MCP server v0 over stdio, exposing the five tools §10
names (`record_transaction`, `record_simulation`, `synthesize_policy`, `evaluate_spec`,
`generate_code`).

**Verifiable outcome (met):** a recorded testnet-shaped transfer becomes a compilable Rust
policy, byte-identical across two cold runs, agreeing with the reference evaluator on a
constraint-derived suite — including zero-signer denial and strict-mode signer-mutation
denial.

## Status — COMPLETE

- [x] Repo scaffold (workspace, toolchain pin, dep-rule check script)
- [x] `domain` — hashes, newtypes, trust levels, canonical encoding (22 tests)
- [x] `policy-spec` — schema, validation typestate, canonical spec hash (22 tests)
- [x] `evaluator` — independent reference evaluator (27 tests)
- [x] `synthesizer` — exact-by-default, fail-closed (39 tests)
- [x] `recorder-core` + `source-bundle` — XDR fixtures, dual hashing (20 tests)
- [x] `registry` — signed snapshots, rollback rejection, fail-closed queries (17 tests)
- [x] `codegen` — deterministic template assembly, golden output (21 tests)
- [x] `build-runner` — bounded local builds, `BuildManifest` attestation (22 tests, 2 of them
      `#[ignore]`d because they need the real Stellar toolchain)
- [x] `contracts/` — golden policy compiles, and the differential suite agrees with the
      reference evaluator on verdict and deny code (17 cases) plus a storage-rent suite over
      the generated policy's TTL behaviour (8 cases), both against the real compiled contract
      in a committed-state soroban env
- [x] `api-types` + `toolkit` + `source-rpc` + `mcp-server` (stdio; the five tools §10 names
      for this phase, plus `import_recording`, so six served) + `cli`
- [x] Phase 1 verification: `scripts/verify-phase1.sh` — the strict release gate passes end
      to end (and `--offline` names what it skipped)

**Totals:** 298 tests (273 host + 25 in the contracts workspace) · 14 crates + contracts
workspace. Counted by running the two suites `scripts/verify-phase1.sh` runs —
`cargo test --workspace` and, in `contracts/`, `cargo test -p ozpb-differential` — which is
also how to re-count them; the number here is what those commands reported on 2026-08-19 and
moves whenever a test is added.

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
  `src/lib.rs` (sha256 `f0a84503…`); normalized codegen-input hash `662ad7a9…`.
- **Wasm reproducibility:** `stellar contract build` → byte-identical wasm across a full
  `cargo clean` rebuild (sha256 `5b9374d8…`). The claim holds; the gate that asserted it did
  not until 2026-08-13. It hashed `contracts/target/…`, which the rebuild never writes: the
  golden crate is excluded from the contracts workspace (it carries its own
  `[profile.release]`), so `stellar contract build` writes to *its* target dir. The old gate
  compared one untouched file with itself and passed unconditionally — and locally that file
  existed at all only because the differential suite builds the crate as a dev-dependency, a
  different build with a different hash. Found by the first scheduled nightly run, which failed
  with `No such file or directory` on a fresh checkout. The gate now cleans, asserts the
  artifact is gone before rebuilding, and compares.
- **Differential agreement:** the reference evaluator and the real compiled policy agree
  on verdict AND deny code across 17 adversarial cases.
- **MCP:** `initialize` + `tools/list` over stdio expose `record_transaction`,
  `record_simulation`, `import_recording`, `synthesize_policy`, `evaluate_spec` and
  `generate_code` — each with an output schema generated from the shared `api-types` DTOs.
  `mcp_stdio.rs` asserts the served set against that list of names, not against a bare
  count, so a tool that appears or disappears is named by the failure.
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
- **Not in Phase 1 (by design, per §10):** the dry-run harness and its evidence report, the
  `verify` / `check_against_policy` / `prepare_install_intent` / `assemble_install_transaction`
  tools, the agent skill, the three end-to-end walkthroughs, wallet integration, a hosted
  endpoint, and the call-surface check — these are Phase 2/3, and this milestone is not reviewed
  against them.
