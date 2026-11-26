# OpenZeppelin review package

For OpenZeppelin's technical review of the code this project generates
([architecture §11](architecture.md#11-ecosystem-engagement)): a generated policy is an ordinary
Soroban contract implementing the `stellar-accounts` `Policy` trait, and a `stellar-contracts`
maintainer is its natural reviewer. This package says what to read, how the generated contract
uses the library, which versions it is paired with, and where each of the five review gates
stands. Security scope, threat model and known limits are in [AUDIT-SCOPE.md](AUDIT-SCOPE.md).

## What to read, in order

1. [Architecture §4.4](architecture.md#44-code-generation-cratescodegen) and
   [§5](architecture.md#5-why-generated-policies-stay-small-and-auditable): templates rather than
   free-form generation, immutable per-grant specialization, the generated-code contract, and
   the three rings that keep the reviewed surface small.
2. `contracts/golden-transfer-policy/src/lib.rs` and `src/contract.rs`: a generated policy exactly
   as emitted. The crate header states its guarantees and its check order; the crate root's three
   `contractmeta!` entries state its provenance.
3. `contracts/soroswap-swap-policy/src/contract.rs`: a second shape, with bounds derived by a
   reviewed target adapter. `contracts/two-payment-policy/src/contract.rs`: a third, one rule
   with two exact tuples of one function.
4. [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §15, the generated crate measured against
   your `code-quality.md`: what it satisfies, nine argued divergences, and three upstream defects.
   §6 (events) and §3 (TTL) give the reasoning those rows cite. §2 says what the contract meta
   and the BuildManifest ([architecture §6.3](architecture.md#63-reproducibility-and-artifact-provenance))
   state, and that only reproduction establishes an artifact's origin.
5. `crates/codegen/src/lib.rs` (`emit_lib` and the helpers it calls) and
   `crates/codegen/src/render.rs`: the snippet library, and the render-safe literal types
   (`MetaValue` among them) that are the only way a recorded value reaches the source.
6. `crates/policy-spec/src/lib.rs` (`Constraint`, `PredicateKind`, `StateSpec`, validation) with
   `docs/examples/subscription-spec.json`: the vocabulary a grant can express.
7. The compiled policy under test: `contracts/differential/tests/differential.rs` (verdict and
   deny reason against the independent reference evaluator), `generated_suite.rs`,
   `two_payment_generated_suite.rs` (both mixes of the two tuples refused), `events.rs`, `ttl.rs`,
   and `account_wasm_invariants.rs`, which runs the generated Wasm inside the pinned account Wasm
   ([map of what it shows](SCOPE.md#state-invariants-and-direct-calls)).
8. The capability entries for your prebuilt contracts: the `dev` module of
   `crates/registry/src/lib.rs` (each entry's `review_reference`), the exact hashes in
   `ozpb_domain::pinned_upstream` (`crates/domain/src/lib.rs`), and how they are rebuilt from your
   source ([DEVELOPERS.md](DEVELOPERS.md#verifying-the-pinned-upstream-trust-anchors)).
9. [SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md): the version boundaries summarized below.
10. [TARGET-ADAPTERS.md](TARGET-ADAPTERS.md) with `crates/synthesizer/src/adapters.rs`: adapter
    design.
11. [MAINNET-GATES.md](MAINNET-GATES.md): each acceptance gate before mainnet use with the tests
    CI runs for it by name; [G4](MAINNET-GATES.md#g4-tuple-correlation) and
    [G14](MAINNET-GATES.md#g14-security-review) bear on this review. `scripts/mutation-test.sh`
    is the mutation gate over eight pure cores, codegen, policy-spec and the evaluator among them
    ([DEVELOPERS.md](DEVELOPERS.md#invariants-ci-enforces-dont-break-these)).

## How a generated policy uses `stellar-accounts`

- **Imports.** `policies::Policy` and `smart_account::{ContextRule, Signer}`, nothing else. No
  library policy module is linked or delegated to: the Wasm has to be a function of the spec
  alone (§15, divergence 3).
- **The trait.** `impl Policy for GeneratedPolicy` with `type AccountParams = u32`, a placeholder
  because every limit is compiled in. `enforce`, `install` and `uninstall` each begin with
  `smart_account.require_auth()`, and refuse only through `panic_with_error!`.
- **Check order in `enforce`.** Installation marker, expiry, signer predicate (an empty
  `authenticated_signers` first, because the account defers signer validation to its policies),
  the strict signer set against `context_rule.signers` for named identities, context kind,
  target, function, argument tuple, call count where the rule has a cap; then TTL extension and
  the event. The first failed condition names the refusal.
- **Storage.** Persistent `#[contracttype]` keys `PolicyStorageKey::Installed(Address, u32)`
  and, where the rule has a cap, `PolicyStorageKey::CallCount(Address, u32)`, keyed by the
  runtime `smart_account` and `context_rule.id`. Constraints are constants, and the account's own address (`SELF`) is
  compared against the `smart_account` argument at runtime, so one deployment serves any
  number of accounts and equal grants share one Wasm.
- **TTL.** Extension only on a permit or an install, bounded by `max_ttl()` and, where the rule
  has one, by the compiled expiry, and withheld once a cap is spent; the getters extend nothing, under the caller-managed
  state exception of your checklist (§3; §15, divergence 2).
- **Events.** `GeneratedPolicyInstalled`, `GeneratedPolicyEnforced` and
  `GeneratedPolicyUninstalled`, each a `#[contractevent]` with `smart_account` as its single topic
  and `context_rule_id` in the data, following your policies' shape. The enforce event carries
  `context_hash: BytesN<32>` where yours carry the `Context`, and `remaining_calls` where
  `spending_limit` carries `total_spent_in_period` (§6; §15, divergence 9). Its serialized size is
  asserted by `an_event_costs_what_the_conformance_record_says_it_costs` in `events.rs`.
- **Errors.** One `#[contracterror] PolicyError`, codes 1–11, declared identically in every
  generated policy and asserted against the evaluator's deny reasons. They do not take the next
  ten-wide block after your policies' 3200–3227, which your next policy module would need (§15,
  divergence 1).
- **Getters.** `is_installed` and, where a cap exists, `remaining_calls`, in an inherent
  `#[contractimpl]`.
- **Contract meta.** `soroban_sdk::contractmeta!` entries `ozpb_generator`, `ozpb_template_family`
  and `ozpb_codegen_input` (the normalized codegen-input hash,
  [CANONICAL-HASHING.md](CANONICAL-HASHING.md#the-normalized-codegen-input)), readable with
  `stellar contract info meta`. No enforcement logic; the spec hash and registry root stay in the
  BuildManifest, so equal grants still share one Wasm (§2).
- **No setters and no upgrade entry point.** Reconfiguration is remove and reinstall (§8; §15,
  divergence 4).

## Version pairing

| Component | Versions | Where pinned |
| --- | --- | --- |
| Generated policies | `soroban-sdk =28.0.0`, `stellar-accounts =0.8.0`, rustc 1.91.1 | `Cargo.toml` of `contracts/golden-transfer-policy`, `contracts/soroswap-swap-policy`, `contracts/range-transfer-policy` and `contracts/two-payment-policy`; `Pins::default` in `crates/codegen/src/lib.rs` |
| Recognized account | Your `examples/multisig-smart-account/account` at v0.7.3 (`stellar-accounts` 0.7.3, `soroban-sdk` 26.1.0), built here from source | Exact hash in `ozpb_domain::pinned_upstream` |
| ed25519 and WebAuthn verifiers, reviewed spending-limit policy | Your `examples/multisig-smart-account` at v0.7.2 (`stellar-accounts` 0.7.2, `soroban-sdk` 26.1.0), built here from source | Exact hashes in `ozpb_domain::pinned_upstream` |

**Why they differ.** Commit 3207b6ae (28 October 2026) moved generated policies, fixtures and the
native contract tests to your 0.8.0 release and the SDK major it requires, and kept the deployed
account's signing protocol and every trust anchor on 0.7.2. The account has since moved to your
v0.7.3 build for GHSA-jpg9-m7w4-c7wc, which leaves its signed digest, storage and exports
unchanged ([SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)).
A policy depends on the policy interface — `enforce`, `install`, `uninstall`, `Signer`,
`ContextRule` — while 0.8.0 also changed how the account authenticates: external and delegated
signers authorize the account-address-bearing `AuthDigestPreimage`. Recognizing a 0.8 account
therefore needs versioned wallet signing, registry and storage-reader support, so until that
exists the 0.8 account code is unknown to the toolkit and refused ([SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md)).

**What exercises the pairing.** `scripts/test-pinned-account-authorization.sh` builds the 0.7.3
account from its pinned source, generates and builds a policy with the current pins, and runs it
through the account's complete `__check_auth`: `pinned_account_wasm_full_authorization` in
`contracts/differential/tests/account_wasm_auth.rs` (signed delegated authorization, forged
signatures refused, counters committed across ledgers, an N+1 call and its rollback), the 18 tests
of `account_wasm_invariants.rs`, and the parity tests in `policy_prediction.rs` against the 0.7.2
spending-limit Wasm. `.github/workflows/nightly-live.yml` runs it nightly and on pull requests that
touch codegen, the contracts or the pins, on macOS arm64, the only host on which the account
reproduces byte-for-byte. The native suites in `contracts/differential` run against the 0.8.0
library's account with delegated authentication mocked; they supplement this gate and cannot
replace it.

## The five review gates

None of the five has an OpenZeppelin review recorded in this repository; the table says what
exists for each.

| Gate ([§11](architecture.md#11-ecosystem-engagement)) | What exists in this tree | State |
| --- | --- | --- |
| PolicySpec and constraint vocabulary, with the signer-predicate and tuple model | `crates/policy-spec`: constraints `EqAddress`, `EqScval`, `EqI128`, `LeI128`, `GeI128`, `RangeI128` (both bounds, inclusive; declared from development registry version 7), `AnyValue`; predicates `AnyOf`, `AllOf`, `Threshold`, `AnyOfCurrentRuleSigners`; `CallCountPerInstallation`; a validation typestate; reference semantics in `crates/evaluator`; [CANONICAL-HASHING.md](CANONICAL-HASHING.md); the tuple model's cross products refused through a compiled policy (`two_payment_generated_suite.rs`) | In use since Tranche 1; exact synthesis ([G3](MAINNET-GATES.md#g3-exact-synthesis)) and tuple correlation ([G4](MAINNET-GATES.md#g4-tuple-correlation)) are closed in the gate map; policy-spec and the evaluator are mutation-gated |
| Capability-registry entries for your prebuilt contracts and verifier hashes | Entries in `registry::dev` for your 0.7.2 spending-limit policy and both verifiers and your 0.7.3 account, each keyed by exact hash with a source-review reference, and the revoked 0.7.2 account entry; the account's method inventory in `crates/registry/src/account_methods.rs`; `scripts/verify-pinned-upstream.sh`; governance tooling, `ozpb registry` ([REGISTRY-GOVERNANCE.md](REGISTRY-GOVERNANCE.md)) | Development registry, signed with a public development key that every network but testnet refuses; the entries describe our builds of your source, not artifacts you publish. The mainnet log (`registry/mainnet/`) is an unsigned draft until its key ceremony |
| Template snippet library | `crates/codegen` (`emit_lib`, `render.rs`), one template family, `policy-templates/scope@1`; mutation-gated | Covers signer predicate with strict set, target, function and tuple checks, exact and bounded `i128`, address and exact `ScVal`, call count and expiry. Embedding addresses as encoded bytes is deferred to template-pack v2 ([SCOPE.md item 4](SCOPE.md#implementation-boundaries)) |
| Generated-code final form | `contracts/golden-transfer-policy`, `contracts/soroswap-swap-policy`, `contracts/range-transfer-policy`, `contracts/two-payment-policy`; [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §15; provenance in contract meta and in BuildManifest v2 (§2; [architecture §6.3](architecture.md#63-reproducibility-and-artifact-provenance)) | Self-assessed against your checklist. All four pass `cargo clippy -D warnings` in CI. Provenance is self-asserted; `ozpb verify` reproduces the artifact |
| Adapter design | [TARGET-ADAPTERS.md](TARGET-ADAPTERS.md), `crates/synthesizer/src/adapters.rs`, `crates/domain/src/target_adapters.rs` | One adapter, `soroswap-router@2`; its router binding is a development-registry assertion whose Wasm was not reproduced from source; no Blend adapter |

## Upstream items

- **Unbounded enforce events.** In `stellar-accounts` 0.8.0 your three policies embed the whole
  `Context` in their enforce event, so a permitted call with a large enough argument fails on the
  network's event-size limit ([ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §15,
  divergence 9 and "Three upstream defects"). Reported as
  [OpenZeppelin/stellar-contracts#852](https://github.com/OpenZeppelin/stellar-contracts/issues/852)
  and fixed by
  [OpenZeppelin/stellar-contracts#896](https://github.com/OpenZeppelin/stellar-contracts/pull/896),
  merged on 20 November 2026, which replaces the `Context` with a bounded `EnforcedContext`
  projection. No release carries it yet; v0.8.0 is the latest. Generated policies keep
  `context_hash` until a release ships the type. Moving to it would change every generated Wasm
  and the asserted event size.
- **Your checklist's `cargo build --target wasm32v1-none --release`** cannot succeed inside your
  own workspace, whose root enables soroban-sdk's `experimental_spec_shaking_v2`; `stellar
  contract build` sets what that feature's build script requires (§15, "Three upstream defects").

## What will still change before the audited revision

No change to generated code is planned for this milestone beyond the upstream items above.
Encoded-literal rendering, which would embed addresses as encoded bytes and change every
generated source and Wasm hash, stays deferred to template-pack v2
([SCOPE.md item 4](SCOPE.md#implementation-boundaries)). The audited revision is the freeze commit
[AUDIT-SCOPE.md](AUDIT-SCOPE.md) names; this review and the external audit both start on it. A
change to generated code this review asks for before its sign-off goes to the auditor too, and
is within the scope of the audit's remediation.

Already in this tree: the `contractmeta!` provenance above, which changed every generated source
and Wasm hash ([ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §2, action 1); BuildManifest
schema `build-manifest/v2`, which adds the canonicalization version, the build target and a
`producer` record, and so rehashed every manifest
([SCOPE.md item 2](SCOPE.md#implementation-boundaries)); the recognized account's move from
the 0.7.2 example to the 0.7.3 build for GHSA-jpg9-m7w4-c7wc, with development registry version 6
revoking the 0.7.2 entry
([SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)); and several
accepted tuples of one function checked under that function's guard once,
`fn_0_ok && (check_call_0(..) || check_call_1(..))`, where the emitter used to repeat the guard
per tuple, which `clippy::nonminimal_bool` refuses. The verdicts are the same; the source and Wasm
of such a rule changed, and of the committed crates only the two-payment fixture has one
([G4](MAINNET-GATES.md#g4-tuple-correlation)).

Recognizing your 0.8.0 account may follow; it needs the versioned signing, registry, storage and
wallet support described in [SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md).

## Review record

Records OpenZeppelin's documented sign-off on generated-code quality when it is given, one row
per review, with a link to where the review itself can be read. An empty table means no review
has been recorded. The sign-off row comes before the mainnet installation: the mainnet registry's
template pack cites it as its review reference, and the release candidate the installation is
made from carries it, without waiting for the audit's report
([the order for 1.0.0](VERSIONING.md#the-order-for-100)).

| Date | Reviewer | Scope | Outcome | Link |
| --- | --- | --- | --- | --- |
