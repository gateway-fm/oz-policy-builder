# Mainnet acceptance gates

[Architecture §10](architecture.md#10-delivery-plan) lists the acceptance gates before any mainnet
use, "checked in CI/review, not aspirational". This document maps each gate to the tests that
establish it, says how far they reach, and states every deviation. It is also the list CI runs:
`scripts/check-mainnet-gates.sh` reads the evidence blocks below, refuses the document if a
named test is not in the file it cites, and runs each named test once by its full name, failing
unless it passes exactly once.

## The grant shape this tranche ships

One context rule on the native asset's Stellar Asset Contract, permitting exactly one recorded
`transfer(SELF, G recipient, amount)` with an exact amount of at most 1,000,000 stroops (the
bound the live check needs for its one-stroop-more denial) and a call cap, for one Ed25519
delegate, enforced by a generated `policy-templates/scope@1` policy with no reviewed policy
composed beside it. It is installed into OpenZeppelin's 0.7.3 example smart account,
recognized by its exact code hash
([Soroban dependencies](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)), whose owner
is a passkey through OpenZeppelin's WebAuthn verifier. This is the shape the
[Pollywallet integration](POLLYWALLET-INTEGRATION.md) generates, checks in all four layers
(its live layer is two named cases, the exact transfer and one stroop more), installs and
revokes, in a testnet or a [mainnet session](POLLYWALLET-INTEGRATION.md#mainnet-sessions). On
mainnet the delegate is the agent's own key, and a session needs protocol 30 on the network and a
signed production registry ([mainnet installation](MAINNET-INSTALL.md)); this tree records no
mainnet installation.

## Statuses

- **closed**: the named tests establish the gate as worded for every grant the toolkit
  generates. What it cannot handle it refuses, and the row says where a refusal stands in for
  something the gate names.
- **narrowed**: the named tests establish the gate for the shape above and its path to
  installation; the row states what lies outside that shape or path.
- **open**: part of the gate is not established even for the shape above; the row says which
  part and what would close it.
- **review**: a review or process gate; the row names the evidence that closes it.

A gate is only as strong as what it rests on: G1, G8 and G11 hold at installation because the
authority check of G2 refuses or lists every other rule that could change the grant, and that
check reads an `rpc_reported` observation, so their rows say so.

A narrowed or open gate is not accepted by being listed. The owner's acceptance of a stated
deviation is recorded in [TRANCHE-3-VERIFICATION.md](TRANCHE-3-VERIFICATION.md), not here.

## Summary

| Gate | Requirement (abridged from architecture §10) | Status | Evidence | Deviation, or what would close it |
| --- | --- | --- | --- | --- |
| G1 | No policy-bearing grant authorizes without its declared signer predicate; strict signer sets for named identities; a dynamic predicate only explicitly labeled | **closed** | [G1](#g1-signer-predicate) | Rests on G2's install-time check, an `rpc_reported` observation, refusing a weak management rule that could strip the policy |
| G2 | The authority-surface check passes at install and preflight over both surfaces, archive-safe, transitive, snapshot-coherent and bounded, over the exact binding set; identities matched by the wallet; one-ledger observation; post-install changes and restorations alert; adversarial suites pass | **open** | [G2](#g2-authority-surface) | Open: restorations are not observed. Post-install changes alert through `ozpb check-installed-grant`'s exit status when the operator schedules it, but each run sees one ledger, not what happened between runs, and the watch ends when the installation's registry snapshot expires. Also: the observation is `rpc_reported`, not an authenticated ledger snapshot; the through-account suites cover the pinned account and the pure check, not the live check end to end |
| G3 | Synthesis is exact by default and never infers numeric direction from XDR type alone | **closed** | [G3](#g3-exact-synthesis) | — |
| G4 | Accepted calls keep complete tuple correlations, each mapped to its recorded invocation | **closed** | [G4](#g4-tuple-correlation) | — |
| G5 | Workflow claims are state-enforced or described as independent permissions | **closed** | [G5](#g5-workflow-claims) | — |
| G6 | Reports separate offline conformance, committed-state integration and live preflight, with acquisition-derived labels; serialized input is downgraded | **narrowed** | [G6](#g6-reports-and-evidence-labels) | All four layers exist only for the native-SAC transfer; other shapes report their missing layers |
| G7 | Stateful limits satisfy the executable invariants (missing state, install-only initialization, archival and restoration, max TTL, reinstall, inactivity, expiration changes, failed transactions) | **narrowed** | [G7](#g7-stateful-limits) | One generated fixture through one account code hash, with SDK test TTLs; a reviewed policy is not executed in composition |
| G8 | Installed code is recognized by a reviewed registry entry or a verified generated-artifact attestation; external verifiers recognized; unknown is unverified; custom source labeled | **closed** | [G8](#g8-recognition) | Custom source is refused rather than labeled: no path accepts it. The code at each address is recognized from G2's `rpc_reported` observation |
| G9 | The artifact chain is acyclic; each build carries a complete, immutable BuildManifest with a pinned registry snapshot | **open** | [G9](#g9-artifact-chain-and-buildmanifest) | Open: the default builder, which the shipped path uses, compiles without a container, so its manifests name no image, and every field is the producer's unattested statement. By design, `generate` and `verify` do not check the registry root they record |
| G10 | Registry governance resists rollback, freeze and equivocation; revocation triggers alerts and the emergency-removal path | **open** | [G10](#g10-registry-governance) | Open: a revoked account build or owner verifier has documented owner procedures but no tooled or exercised path. Also: the mainnet log is an unsigned draft until its key ceremony; the operator schedules the monitor |
| G11 | Reconfiguration is fail-closed; stateful grants never overlap; no unbacked atomicity claims | **narrowed** | [G11](#g11-reconfiguration) | Revoke-first replacement has no live run; the through-account test makes the management calls itself. No overlap is seen through G2's `rpc_reported` observation |
| G12 | Hosted processing passes privacy, SSRF, resource-isolation and log-redaction tests | **open** | [G12](#g12-hosted-processing) | Open for the release's endpoint, the self-hosted HTTP server: a static check holds the package's log settings, but no test drives the endpoint and reads what it retains. Also: builds are isolated from the API only in worker mode, accepted on the operator's host |
| G13 | The public/private split exists and the publication allowlist's negative test passes in CI | **closed** | [G13](#g13-publication-split) | — |
| G14 | Security review covers the full authorization-to-install path | **review** | [G14](#g14-security-review) | No audit report is in this tree |

## How the evidence blocks are read

Each gate's section except a review gate's ends with one evidence block, a fence reading
exactly ```` ```gate-evidence G<n> ````, one check per line: `<run> <path> <name>`. A closed gate
names at least one check that runs in CI.

- `ci` runs in CI. A Rust test is named by its full path as `cargo test -- --list` prints it,
  in the file that defines it; the binary follows from the path (a crate's `src/` is its unit
  tests, `tests/<name>.rs` is that test binary). A wallet test is named by its exact title in
  its `wallet/tests/*.test.mjs` file.
- `release` is one of the pinned-account suites in `contracts/differential/tests` that need
  source-built Wasm. `scripts/test-pinned-account-authorization.sh` builds it, on an Apple
  Silicon host, and requires each of these tests by name; it runs in the
  `pinned-account-authorization` job of `.github/workflows/nightly-live.yml`. The checker
  lists them as not run, and verifies that the workflow still runs the script and that the
  script requires each test by name, in a `for test in` list whose body checks
  `grep -qx "test $test ... ok"` or in a `grep -qx 'test NAME ... ok'` check, after running that
  test's binary. The loop or check must sit at the top level of the script, unindented, and stop
  it with a non-zero status when the test is missing: under `set -e`, or through `|| exit` or a
  `|| { ... }` block ending in `exit N`, N from 1 to 255. A loop body holds only that check. A
  check used as an `if` or `!` condition, or followed by `|| true`, `|| :`, `&&` or a pipe,
  requires nothing.
- `ci-step` is a command a workflow runs; the checker verifies that a line of the workflow, not
  a comment, still runs it. Which job, trigger or condition runs it is not checked.

```bash
bash scripts/check-mainnet-gates.sh               # every ci test
bash scripts/check-mainnet-gates.sh --part host   # one CI job's part: host, contracts or wallet
python3 scripts/test-check-mainnet-gates.py       # the checker's own regression tests
```

A test listed under two gates runs once. Passing establishes what each gate's status says, no
more.

## G1. Signer predicate

The generated policy refuses an authorization whose authenticated signers do not satisfy its
predicate, the empty set included, and for named identities refuses a live signer set that
differs from the compiled one; validation requires strict mode for named identities. The
registry declares which predicates a template supports and that the reviewed spending limit
enforces none, and the toolkit refuses a rule outside those declarations. A dynamic predicate
cannot carry the strict flag and compiles in no signer. Through the pinned account, adding a key
to the grant's rule is refused by the policy, and the account's own authentication refuses a
signature over another payload.

The same pinned-account test shows a weak account-management rule removing the grant's policy,
which leaves an unlimited rule on the target. The predicate holds against that only because the
authority check ([G2](#g2-authority-surface)) refuses such a rule the agent can use alone and
lists one held by anyone else.

```gate-evidence G1
ci  contracts/differential/tests/differential.rs  zero_signers_denies_in_both
ci  contracts/differential/tests/differential.rs  unrecognized_signer_denies_in_both
ci  contracts/differential/tests/differential.rs  strict_mode_denies_grown_and_swapped_signer_sets_in_both
ci  crates/policy-spec/src/lib.rs  tests::named_identities_require_strict_signer_set
ci  crates/policy-spec/src/lib.rs  tests::dynamic_predicate_rejects_strict_flag
ci  crates/codegen/src/lib.rs  tests::compilability::a_dynamic_predicate_compiles_in_no_signer_even_when_the_rule_carries_one
ci  crates/evaluator/src/lib.rs  tests::dynamic_predicate_uses_live_set_and_still_denies_zero_signers
ci  crates/registry/src/lib.rs  tests::sign_load_resolve_round_trip
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::signed_template_must_declare_the_generated_rules_capabilities
release  contracts/differential/tests/account_wasm_invariants.rs  weak_account_rule_cannot_widen_the_grant_signers_but_can_strip_its_policy
release  contracts/differential/tests/account_wasm_auth.rs  pinned_account_wasm_full_authorization
```

## G2. Authority surface

The scan reads every rule slot through `NextId`, follows the signer and policy closure, and
fails closed on missing, archived or undecodable entries, a `Count` mismatch, and an exceeded
bound, taking its bounds from the signed account capability. A snapshot that changes between
reads is retried as a whole. The check covers the account's management surface and the new
rule's target, refuses the agent's key where it can act alone, refuses another usable rule
beside a stateful grant, and refuses a new rule aimed at the account or a bound policy. Bound
policies must run exactly the recognized code. An incomplete scan yields no list, an unread
owner is unresolved, the install intent carries arguments only for an answer with no refusal,
and the result never says "safe". The wallet matches the listed owner against its own passkey
and refuses a foreign key, a refusal or anything unresolved before asking for a signature. Its
on-demand monitor compares the installed rule and modeled authority with the installation's;
`ozpb check-installed-grant`, given the installation's recorded commitment, makes the same
comparison and says what it found by its exit status, for cron.
The adversarial suites run direct calls and management bypasses through the pinned account.

Open, and the other deviations:

- **Observation, not proof.** The result is `rpc_reported`: one endpoint's responses,
  reconciled at the ledger it reports, not an authenticated ledger snapshot. An endpoint that
  lies consistently is not detectable ([SCOPE item 1](SCOPE.md#implementation-boundaries),
  [audit limit 1](AUDIT-SCOPE.md#known-limits--not-findings)). Closing it needs an authenticated
  ledger-state source.
- **Changes alert per run; restorations are not observed (open).** Post-install drift is found
  by the wallet's [on-demand check](POLLYWALLET-INTEGRATION.md#on-demand-installed-grant-monitoring)
  while its page is open, and by `ozpb check-installed-grant --recorded-authority-commitment
  --min-ledger`, whose exit status (3 changed, 4 no answer or an observation older than the
  floor, 5 expired) is the alert when the operator runs it on a schedule
  ([watching an installed grant](INCIDENT-RESPONSE.md#watching-an-installed-grant)); nothing in
  this tree schedules it. Each run observes one ledger: TTL continuity, so an archival and
  restoration between runs, is not observed, nor a change made and undone between runs. The
  check pins the installation's registry snapshot, so it runs under a monitoring roots file
  held at that version and ends when the snapshot expires (every run then exits 1; a new review
  and installation follow). It does not read the policy's installation marker, which the
  wallet's check does. The wallet's check also runs the registry monitor, which reports revoked
  or expiring code, not a changed rule ([G10](#g10-registry-governance)). Closing it needs the
  account's entries observed continuously between runs, restorations included.
- **One account, pure check.** The direct-call and management-bypass suites run through the
  pinned 0.7.3 account Wasm only, and feed the scan, projection and pure check from a local
  ledger with recognition supplied by the test and the reader's default bounds: no registry,
  artifact rebuild or live endpoint. An archived signer or policy registry entry and the
  wallet's replacement flow are not exercised through the account
  ([SCOPE, not covered](SCOPE.md#state-invariants-and-direct-calls)).

```gate-evidence G2
ci  crates/source-rpc/src/account_state_scan.rs  account_state_scan::tests::complete_bounded_read_reconciles_rule_and_signer_closure
ci  crates/source-rpc/src/account_state_scan.rs  account_state_scan::tests::missing_and_archived_entries_fail_closed
ci  crates/source-rpc/src/account_state_scan.rs  account_state_scan::tests::a_count_that_disagrees_with_its_response_is_incomplete
ci  crates/source-rpc/src/account_state_scan.rs  account_state_scan::tests::a_changed_snapshot_retries_the_entire_scan
ci  crates/source-rpc/src/account_state_scan.rs  account_state_scan::tests::each_scan_bound_fails_before_reading_past_it
ci  crates/source-rpc/src/account_reconciliation.rs  account_reconciliation::tests::transitive_entries_and_reference_counts_are_exact
ci  crates/toolkit/src/call_surface_live.rs  call_surface_live::tests::the_plan_takes_its_bounds_from_the_signed_account_capability
ci  crates/call-surface-core/src/tests.rs  tests::count_deficit_fails_closed_without_guessing_why
ci  crates/call-surface-core/src/tests.rs  tests::missing_transitive_signer_fails_closed
ci  crates/call-surface-core/src/tests.rs  tests::case_6_restricted_key_that_can_manage_alone_is_refused
ci  crates/call-surface-core/src/tests.rs  tests::readable_target_rule_is_listed_for_its_signers_and_refused_for_the_agent
ci  crates/call-surface-core/src/tests.rs  tests::stateful_grant_beside_another_usable_rule_on_the_target_is_refused
ci  crates/call-surface-core/src/tests.rs  tests::new_rule_cannot_target_the_account_or_a_bound_policy
ci  crates/call-surface-core/src/tests.rs  tests::bound_policy_must_be_recognized
ci  crates/call-surface-core/src/tests.rs  tests::the_result_never_says_safe
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::observed_code_and_binding_evidence_must_match_exactly
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::incomplete_state_never_yields_a_list
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::unread_classic_owner_is_unresolved
ci  crates/toolkit/src/install_intent.rs  install_intent::tests::a_refusal_is_an_error_carrying_every_finding_with_a_fixed_code
ci  crates/toolkit/src/install_intent.rs  install_intent::tests::a_clear_answer_yields_the_exact_arguments_it_committed_to
ci  wallet/tests/approval.test.mjs  wallet chooses its exact passkey management rule and freezes displayed semantics
ci  wallet/tests/approval.test.mjs  wallet refuses foreign key before requesting a passkey signature
ci  wallet/tests/approval.test.mjs  wallet refuses refusal before requesting a passkey signature
ci  wallet/tests/approval.test.mjs  wallet refuses unresolved before requesting a passkey signature
ci  wallet/tests/approval.test.mjs  matching public key does not substitute for the exact stored credential or policy-free rule
ci  wallet/tests/monitor.test.mjs  monitor compares the exact retained rule and projected authority without signing or adopting a baseline
ci  wallet/tests/monitor.test.mjs  later allocations remain drift
ci  crates/toolkit/src/installed_grant/tests.rs  installed_grant::tests::a_scheduled_comparison_is_unchanged_only_at_the_recorded_commitment
ci  crates/toolkit/src/installed_grant/tests.rs  installed_grant::tests::a_scheduled_comparison_reports_expiry_as_inactive_unless_the_authority_drifted
ci  crates/toolkit/src/installed_grant/tests.rs  installed_grant::tests::a_scheduled_comparison_refuses_an_observation_older_than_the_floor
ci  crates/toolkit/src/installed_grant/tests.rs  installed_grant::tests::a_scheduled_comparison_reads_an_unknown_shape_as_changed
ci  crates/cli/src/authority.rs  authority::tests::a_scheduled_run_without_an_answer_or_with_a_changed_rule_alerts
ci  crates/cli/tests/authority_cli.rs  scheduled_installed_monitoring_exits_with_a_status_cron_can_alert_on
ci  contracts/differential/tests/generated_suite.rs  direct_mutating_calls_require_the_smart_account_authorization
release  contracts/differential/tests/account_wasm_invariants.rs  grant_rule_cannot_reach_its_policy_and_rule_zero_is_listed_authority
release  contracts/differential/tests/account_wasm_invariants.rs  policy_address_rule_can_uninstall_and_call_surface_refuses_it
release  contracts/differential/tests/account_wasm_invariants.rs  policy_address_rule_held_by_another_key_is_listed_with_its_signer
release  contracts/differential/tests/account_wasm_invariants.rs  alternate_contract_rule_cannot_reach_policy_methods
release  contracts/differential/tests/account_wasm_invariants.rs  weak_account_rule_can_create_a_policy_reset_rule
release  contracts/differential/tests/account_wasm_invariants.rs  weak_account_rule_can_take_over_a_protected_rule_by_adding_its_signer
release  contracts/differential/tests/account_wasm_invariants.rs  weak_account_rule_reaches_the_policy_and_the_code_through_wrapper_methods
release  contracts/differential/tests/account_wasm_invariants.rs  weak_management_can_revive_an_expired_rule_without_resetting_its_counter
release  contracts/differential/tests/account_wasm_invariants.rs  expired_weak_rules_are_noted_and_revived_only_through_live_management
release  contracts/differential/tests/account_wasm_invariants.rs  archived_management_rule_is_restored_and_used_in_one_transaction
```

## G3. Exact synthesis

Every observed argument becomes an exact constraint. A bound enters only through an explicit
decision on an amount argument, with canonical numerals and a declared blast radius, or through
a reviewed adapter bound to the observed code hash and whole argument shape. The adapter takes
direction from the argument's meaning: a maximum input admits an upper bound, and a minimum
output gets no invented floor. A user decision cannot loosen what an adapter's role requires:
a bound below a recorded minimum output, one leaving a maximum input with no finite cap, or any
widening of an argument the adapter keeps exact is refused. A widening that matches nothing, or
that contradicts observed-exact provenance, is refused, and an unverified registry never widens.
The adapter is selected by the recording's observed hash, which the caller supplies; the install
intent reads the target's code in the same capture as the authority check and refuses other code.

A bound must admit the recorded value, and an argument takes one widening. A cap on a signed
amount sets no floor, so synthesis asks for one: the answer is a range, `min <= x <= max`, which
the generated policy checks at both ends (development registry version 7 declares the kind;
earlier versions refuse it), or an explicit acknowledgement of the open floor; a range from
`i128::MIN` is a cap and asks the same. No floor is ever inferred from the type. The declared
blast radius has a floor of its own: a bound with no finite top must be rated high unless an
adapter declares the argument a minimum output, and validation holds a bound spanning the whole
`i128` range to high, as it does `any_value`. The ranged-transfer fixture's generated crate is committed exactly as
codegen emits it, and every case the harness derives from it is decided the same way by the
compiled policy and the reference evaluator.

```gate-evidence G3
ci  crates/synthesizer/src/lib.rs  tests::happy_path_synthesizes_a_validating_exact_spec
ci  crates/synthesizer/src/lib.rs  tests::widening_applies_only_with_explicit_decision_and_only_to_amounts
ci  crates/synthesizer/src/lib.rs  tests::hostile_numeric_widening_fails_during_synthesis
ci  crates/synthesizer/src/lib.rs  tests::widening_that_matches_nothing_fails_closed
ci  crates/synthesizer/src/lib.rs  tests::adapter_never_widens_a_call_with_the_wrong_whole_argument_shape
ci  crates/synthesizer/src/adapters.rs  adapters::tests::max_input_permits_upper_bound_min_output_does_not_invent_a_floor
ci  crates/policy-spec/src/lib.rs  tests::widening_with_observed_exact_provenance_fails
ci  crates/policy-spec/src/lib.rs  tests::any_value_demands_high_blast_radius_or_a_bound_adapter
ci  crates/toolkit/src/target_adapter_tests.rs  target_adapter_tests::absent_or_different_binding_stays_exact_and_unverified_registry_never_widens
ci  crates/toolkit/src/install_intent.rs  install_intent::tests::install_intent_refuses_adapter_required_target_with_other_code
ci  crates/synthesizer/src/lib.rs  tests::a_second_widening_of_the_same_argument_is_refused
ci  crates/synthesizer/src/lib.rs  tests::a_numeric_bound_must_admit_the_recorded_value
ci  crates/synthesizer/src/lib.rs  tests::a_cap_on_a_signed_amount_needs_its_open_floor_acknowledged
ci  crates/synthesizer/src/lib.rs  tests::a_range_on_a_signed_amount_asks_no_floor_question
ci  crates/policy-spec/src/lib.rs  tests::a_range_is_inclusive_and_an_empty_one_is_refused
ci  crates/evaluator/src/lib.rs  tests::range_i128_permits_both_ends_and_denies_either_side
ci  crates/toolkit/src/lib.rs  tests::a_range_synthesizes_under_a_registry_that_declares_it_and_is_refused_under_one_that_does_not
ci  crates/codegen/src/lib.rs  tests::range_crate_matches_committed_output
ci  crates/codegen/src/lib.rs  tests::a_bound_at_the_i128_limit_emits_no_vacuous_comparison
ci  contracts/differential/tests/range_generated_suite.rs  range_cases_agree_through_the_compiled_policy
ci  crates/synthesizer/src/lib.rs  tests::a_user_bound_against_an_adapter_role_is_refused
ci  crates/synthesizer/src/lib.rs  tests::a_user_widening_of_an_argument_an_adapter_keeps_exact_is_refused
ci  crates/toolkit/src/target_adapter_tests.rs  target_adapter_tests::explicit_user_widening_keeps_its_distinct_intent_and_provenance
ci  crates/synthesizer/src/lib.rs  tests::an_open_above_bound_requires_high_blast_radius
ci  crates/policy-spec/src/lib.rs  tests::a_bound_spanning_the_i128_domain_requires_high_blast_radius
ci  crates/synthesizer/src/lib.rs  tests::a_range_from_i128_min_asks_the_floor_question_a_cap_asks
```

## G4. Tuple correlation

An allowed call is one whole `(contract, function, arguments)` tuple. Validation refuses an
incomplete tuple and one without evidence and justification, and evidence references must name
a recording in range. Identical tuples merge and distinct ones stay distinct, never combined into
a product, and each recording of a distinct call becomes its own tuple. A widening names an
argument rather than a call, so one that would loosen several distinct tuples of a function is
refused: it cannot carry one recorded call's bound into another's. Changing any one position
of the recorded call is denied by both the reference evaluator and the compiled policy.

Cross products are checked through a compiled policy. The two-payment fixture's rule accepts
`transfer(SELF, first payee, 1,000)` and `transfer(SELF, second payee, 2,000)`, each from its own
recording; its generated crate is committed exactly as codegen emits it. The derived suite must
contain both mixes of the two, and each is refused with `NoTupleMatched` by the compiled policy
(run through the `stellar-accounts` 0.8 account library with mocked authorization, not the pinned
account Wasm — tuple matching is the policy's alone) and by the reference evaluator, while both
recorded payments permit. The evaluator's handling of a mix that another tuple does accept is
covered separately. The compiled condition reads each function's guard once, with that
function's tuples under it, so the crate is linted like every other generated crate.

```gate-evidence G4
ci  crates/synthesizer/src/lib.rs  tests::tuple_dedup_merges_identical_and_keeps_distinct
ci  crates/synthesizer/src/lib.rs  tests::a_widening_on_a_multi_tuple_function_is_refused_unless_scoped
ci  crates/policy-spec/src/lib.rs  tests::incomplete_tuples_fail
ci  crates/policy-spec/src/lib.rs  tests::missing_evidence_and_justification_fail
ci  crates/policy-spec/src/lib.rs  tests::evidence_references_are_structural_and_in_range
ci  crates/harness/src/lib.rs  tests::cross_products_never_mix_different_functions
ci  crates/harness/src/lib.rs  tests::a_mutation_accepted_by_another_tuple_is_labeled_permit
ci  crates/harness/src/lib.rs  tests::a_mixed_tuple_accepted_by_a_range_is_labeled_permit
ci  crates/synthesizer/src/walkthroughs.rs  walkthroughs::tests::two_payments_are_one_rule_with_two_exact_tuples_differing_in_two_positions
ci  crates/codegen/src/lib.rs  tests::two_payment_crate_matches_committed_output
ci  crates/codegen/src/lib.rs  tests::tuples_of_one_function_are_checked_under_one_function_guard
ci  contracts/differential/tests/two_payment_generated_suite.rs  cross_products_of_two_accepted_tuples_are_refused_by_the_compiled_policy_and_the_evaluator
ci  contracts/differential/tests/differential.rs  amount_mutations_deny_in_both
ci  contracts/differential/tests/differential.rs  recipient_and_sender_mutations_deny_in_both
ci  contracts/differential/tests/differential.rs  function_and_target_mutations_deny_in_both
ci  contracts/differential/tests/generated_suite.rs  generated_deny_suite_agrees_with_the_real_contract
```

## G5. Workflow claims

No ordered workflow is implemented or claimed. A recording of several contracts becomes a
permission bundle, one independent rule per contract, and synthesis says that ordering and
dependency between them are not enforced; the derived suite covers each rule. The policy-builder
skill tells the user the same ([`SKILL.md`](../skills/policy-builder/SKILL.md)). The wallet
refuses installation consent for a spec with two rules, so it never presents a bundle.

```gate-evidence G5
ci  crates/synthesizer/src/lib.rs  tests::multiple_contracts_yield_a_permission_bundle
ci  crates/harness/src/lib.rs  tests::suite_covers_every_rule_in_a_permission_bundle
ci  wallet/tests/live-consent.test.mjs  the shape is one exact native transfer of at most 1,000,000 stroops, with a call cap, installing exactly the reviewed grant
ci  wallet/tests/install-gate.test.mjs  the installation consent is derived only for the reviewed grant, rule and fee bound
```

## G6. Reports and evidence labels

A reproduced reference run cannot become a complete four-layer report, a captured layer cannot
meet the bar alone, and denials from different layers do not add up. Verification reports
reproduction without claiming live preflight. Preflight labels its success as state-dependent
and keeps restoration apart from success. Evidence labels come from how a recording was
acquired: imported evidence is `self_supplied` at most, and a caller can only lower a label at
the synthesis boundary, including for the same mainnet evidence imported instead of fetched.
The wallet keeps the first three layers apart from the live layer and opens installation only
when all four passed for this review.

Deviation: all four layers (reference, account Wasm, captured target, live enforcement) run
together only for the one-rule native-SAC transfer. The W1 and W3 account-Wasm checks do not
execute their targets offline, W2's reviewed-policy composition is not supported on that path,
and other shapes' reports name the layers they lack
([deviations](TRANCHE-2-VERIFICATION.md#deviations-and-open-gaps-against-the-phase-2-design)).
Closing it needs general captured-target execution and a policy-bound live check per shape.

```gate-evidence G6
ci  crates/toolkit/src/dry_run_tests.rs  dry_run_tests::reproduced_reference_cannot_become_a_complete_four_layer_run
ci  crates/toolkit/src/dry_run_report_tests.rs  dry_run_report::tests::captured_layer_counts_its_two_denials_and_never_meets_the_bar_alone
ci  crates/toolkit/src/verification.rs  verification::tests::verification_reports_reproduction_without_claiming_live_preflight
ci  crates/source-rpc/src/preflight.rs  preflight::tests::requests_auth_enforcement_and_labels_exact_state_dependent_success
ci  crates/source-rpc/src/preflight.rs  preflight::tests::restoration_is_a_separate_non_success_outcome
ci  crates/toolkit/src/lib.rs  tests::caller_supplied_provenance_labels_are_downgraded_before_synthesis
ci  crates/toolkit/src/lib.rs  tests::a_wire_bundle_may_only_have_its_trust_lowered_at_the_synthesis_boundary
ci  crates/recorder-core/src/lib.rs  tests::imported_snapshots_are_self_supplied_at_most
ci  crates/domain/src/lib.rs  tests::downgrading_to_self_supplied_never_raises_a_level
ci  crates/source-rpc/tests/mainnet_corpus.rs  the_same_mainnet_evidence_imported_is_labelled_by_its_acquisition
ci  crates/harness/src/lib.rs  tests::report_serializes_with_disclaimer
ci  wallet/tests/verification-gate.test.mjs  first three layers remain distinct from unavailable live enforcement
ci  wallet/tests/verification-gate.test.mjs  only the exact four passed bound layers enable final acceptance
ci  wallet/tests/dry-run.test.mjs  denials from different layers do not add up to the per-layer minimum
ci  wallet/tests/install-actions.test.mjs  status keeps install false when one of the four layers did not pass
```

## G7. Stateful limits

Missing state denies; `install` is the only initializer and a second install fails; the call cap
exhausts with committed state; installations are isolated by account and rule; reinstalling
starts a new grant. A decayed TTL is extended to the policy's validity clamped to the network
maximum, extension never outlives the validity, a denied call extends nothing, and installing
after expiry writes nothing. A later denial rolls back an earlier permit's counter. Through the
pinned account: archived state denies until restored, an idle
grant survives until its shortest TTL, extending a rule's validity does not outlive the compiled
expiry, stale state for the next rule ID is refused rather than adopted, a failed composition
rolls back, and the cap holds across ledgers with an N+1 rollback.

Deviation: the account-path suite runs one generated fixture against one account code hash,
with the SDK's test TTLs rather than a network's. A reviewed policy (the spending limit) is not
executed in composition through the account Wasm
([SCOPE item 3](SCOPE.md#implementation-boundaries)); the shipped shape composes none.

```gate-evidence G7
ci  contracts/differential/tests/differential.rs  missing_state_denies_in_both
ci  contracts/differential/tests/differential.rs  install_is_the_only_initializer_and_double_install_fails
ci  contracts/differential/tests/differential.rs  lifetime_call_cap_exhausts_in_both_with_committed_state
ci  contracts/differential/tests/differential.rs  uninstall_obeys_upstream_lifecycle_and_reinstall_resets_state
ci  contracts/differential/tests/differential.rs  installation_markers_are_isolated_by_account_and_rule
ci  contracts/differential/tests/differential.rs  expiry_boundary_agrees_in_both
ci  contracts/differential/tests/ttl.rs  enforce_extends_the_counter_when_the_ttl_is_below_the_threshold
ci  contracts/differential/tests/ttl.rs  the_ttl_target_never_outlives_the_policy_validity_window
ci  contracts/differential/tests/ttl.rs  a_denied_call_extends_nothing
ci  contracts/differential/tests/ttl.rs  installing_after_expiry_is_rejected_without_writing_state
ci  contracts/differential/tests/ttl.rs  remaining_calls_refuses_an_installation_whose_marker_is_gone
ci  contracts/differential/tests/generated_suite.rs  generated_suite_commits_permits_and_rolls_back_a_later_denial
ci  contracts/differential/tests/generated_suite.rs  later_policy_denial_rolls_back_an_earlier_policy_counter
release  contracts/differential/tests/account_wasm_invariants.rs  archived_counter_denies_until_restored
release  contracts/differential/tests/account_wasm_invariants.rs  grant_survives_inactivity_until_its_shortest_ttl
release  contracts/differential/tests/account_wasm_invariants.rs  extended_rule_validity_does_not_outlive_the_compiled_expiry
release  contracts/differential/tests/account_wasm_invariants.rs  stale_policy_state_is_refused_not_adopted
release  contracts/differential/tests/account_wasm_invariants.rs  failed_composition_rolls_back_the_permitting_policy
release  contracts/differential/tests/account_wasm_auth.rs  pinned_account_wasm_full_authorization
```

## G8. Recognition

Account, policy and verifier code is recognized only by an exact hash in a loaded, verified
snapshot; anything else, or any query before a snapshot loads, fails closed. The committed
example recognizes the 0.7.3 account and revokes the 0.7.2 build, whose method inventory is
empty, and the wallet pins the same hashes the toolkit does. A passkey owner is recognized
through its reviewed verifier code. A generated policy is recognized by rebuilding it from its
spec and comparing every non-lock file and the manifest; a bound policy whose code was upgraded
fails. The mainnet draft registry, once signed, recognizes the reviewed code.

Refusal in place of a label: no path accepts custom source, so there is none to label. `verify`
reports any edited or added file as a source mismatch, and the wallet installs only what it
regenerates ([generated source support](POLLYWALLET-INTEGRATION.md#generated-source-support)).
A custom-source flow would need its own label and gate before it could be offered.

Recognition at installation reads the code at each address from G2's scan, so it is as good as
that `rpc_reported` observation ([G2](#g2-authority-surface)).

```gate-evidence G8
ci  crates/registry/src/lib.rs  tests::unknown_hashes_fail_closed
ci  crates/registry/src/lib.rs  tests::queries_before_load_fail_closed
ci  crates/registry/src/lib.rs  tests::the_committed_example_recognizes_the_fixed_account_and_revokes_the_vulnerable_one
ci  crates/registry/src/lib.rs  tests::revoked_capabilities_fail_resolution_with_the_recorded_reason
ci  crates/registry/src/lib.rs  tests::a_revoked_signature_verifier_is_refused
ci  crates/registry/src/account_methods.rs  account_methods::tests::the_vulnerable_build_has_no_reviewed_methods
ci  crates/registry/tests/mainnet_draft.rs  the_draft_loads_for_mainnet_once_signed_and_recognizes_the_reviewed_code
ci  crates/call-surface-core/src/tests.rs  tests::unrecognized_account_fails_closed
ci  crates/call-surface-core/src/tests.rs  tests::external_owners_need_recognized_observed_verifiers_and_well_formed_keys
ci  crates/call-surface-core/src/tests.rs  tests::upgraded_bound_policy_fails_even_when_its_address_is_recognized
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::exact_checked_bindings_produce_the_authority_list
ci  crates/toolkit/src/call_surface.rs  call_surface::tests::a_passkey_owner_is_listed_through_the_registry
ci  crates/toolkit/src/verification.rs  verification::tests::verification_checks_every_non_lock_file_and_requires_the_manifest
ci  crates/cli/src/verification.rs  verification::tests::binary_extra_file_is_recorded_as_a_source_mismatch
ci  wallet/tests/approval.test.mjs  the wallet pins the account and verifier hashes crates/domain pins
```

## G9. Artifact chain and BuildManifest

The PolicySpec schema is closed, so it cannot carry a build output, and the BuildManifest
references the spec by hash
([architecture §4.2](architecture.md#42-policyspec-and-the-artifact-chain)). The manifest
(`build-manifest/v2`) records the canonicalization version, the build target the crate declares
(a build compiled for another target is refused), and a producer record: the toolkit's source
commit and dirty flag, the template-pack hash, and the image when a disposable worker built it.
Its hash binds every field, the producer record included; a manifest that misstates the compiler
the Wasm records is refused; `verify` reproduces every field but the producer record, which it
reports, and says when another producer made the artifact.

Open, and the other deviation:

- **No container, no attestation (open).** The default builder, which the CLI and so the wallet
  use, compiles in its own environment: its manifests name no image and builds are not isolated
  from one another. Every field is the producer's own statement, labelled `local-unattested`;
  nothing lets a third party check a manifest without rerunning `ozpb verify`
  ([SCOPE item 2](SCOPE.md#implementation-boundaries)). A [published build](PUBLISHING.md) gives
  that rerun its inputs under the Wasm hash, and `ozpb verify-published` refuses one whose files
  the manifest does not describe, its lockfile included, before reproducing it; that is still a
  rerun, not an attestation. Closing it needs a containerized default builder that records its
  image, and output someone else can check.
- **Registry root, by design.** `generate` and `verify` record the root the spec names without
  checking it; trust is enforced at synthesis, the install intent and the live checks, which load
  the snapshot under the pinned roots ([SCOPE item 7](SCOPE.md#implementation-boundaries)). The
  wallet synthesizes under its pinned roots before it generates, so on the shipped path the
  recorded root is one that was checked; a manifest from `generate` alone carries no such
  assurance.

```gate-evidence G9
ci  crates/policy-spec/src/lib.rs  tests::spec_round_trips_through_json_with_closed_schema
ci  crates/build-runner/src/lib.rs  tests::manifest_hash_binds_source_wasm_lockfile_and_pipeline_inputs
ci  crates/build-runner/src/lib.rs  tests::a_manifest_that_misstates_the_compiler_is_refused
ci  crates/build-runner/src/lib.rs  tests::a_manifest_records_canonicalization_target_and_its_producer
ci  crates/build-runner/src/lib.rs  tests::the_manifest_hash_binds_the_producer_record
ci  crates/build-runner/src/lib.rs  tests::a_reproduction_compares_every_field_but_the_producer_record
ci  crates/build-runner/src/lib.rs  tests::a_build_not_compiled_for_the_declared_target_is_refused
ci  crates/codegen/src/lib.rs  tests::the_template_pack_hash_is_the_emitter_source_without_its_tests
ci  crates/toolkit/src/verification.rs  verification::tests::verification_reproduces_a_manifest_from_another_producer_and_says_so
ci  crates/toolkit/src/lib.rs  tests::generated_artifact_includes_wasm_and_a_binding_manifest
ci  crates/toolkit/src/publication.rs  publication::tests::a_published_build_reproduces_through_verify
ci  crates/toolkit/src/publication.rs  publication::tests::a_changed_source_byte_is_refused_by_the_index_and_then_by_the_manifest
```

## G10. Registry governance

A consumer refuses an older snapshot than its floor or checkpoint, a different snapshot for the
same version after a restart, and a fork from an old root; revocations are append-only; every
snapshot has a validity interval outside which it is refused, which bounds a freeze; the
development root is refused off testnet. `ozpb registry monitor` reports a revoked watched code
hash or template family, expiry and a newer head, refuses a watch item the head does not know,
and fails loudly on a log that contradicts the checkpoint; its exit status is the alert, on a
schedule the operator sets up as [the governance
guide](REGISTRY-GOVERNANCE.md#scheduling-the-monitor) describes. The wallet's installed-grant
check runs the same monitor and reports the registry beside the grant. For a revoked policy or
template family, the emergency-removal path is the wallet's revocation of the grant, which
succeeds only with the removal event and an absent read-back, and also reaches a grant an
earlier session installed.

Open, and the other deviations:

- **A revoked account build or owner verifier (open).** Removing the grant does not help, and
  the responses are owner procedures this tree documents but neither tools nor has run:
  upgrading the account in place to a recognized build, or creating a new account and moving
  the funds; for a verifier, replacing the owner signer
  ([revocation and emergency removal](REGISTRY-GOVERNANCE.md#revocation-and-emergency-removal)).
  Closing it needs one of those paths exercised end to end.
- **Precondition.** The mainnet log is an unsigned draft until its key ceremony
  ([`registry/mainnet/`](../registry/mainnet/README.md)); the tests below keep it so and keep
  the draft from claiming an audit.
- **Scheduling and freeze.** Nothing in this tree runs the monitor on a schedule; that is the
  operator's. Monitoring cannot see newer versions a source withholds; each version's validity
  interval is the backstop.

```gate-evidence G10
ci  crates/registry/src/lib.rs  tests::rollback_and_freeze_are_rejected
ci  crates/registry/src/lib.rs  tests::a_persisted_checkpoint_rejects_same_version_equivocation_after_restart
ci  crates/registry/src/lib.rs  tests::transparency_chain_rejects_a_fork_from_an_old_root
ci  crates/registry/src/lib.rs  tests::accepted_revocations_are_append_only_and_immutable
ci  crates/registry/src/lib.rs  tests::network_and_snapshot_validity_are_pinned
ci  crates/registry/src/lib.rs  tests::the_development_root_is_refused_for_every_network_but_testnet
ci  crates/registry/src/governance/tests.rs  governance::tests::monitoring_reports_newer_versions_expiry_and_watched_revocations
ci  crates/registry/src/governance/tests.rs  governance::tests::monitoring_fails_loudly_on_a_log_that_contradicts_the_checkpoint
ci  crates/registry/src/governance/tests.rs  governance::tests::replay_accepts_exactly_an_unbroken_chain_from_genesis
ci  crates/registry/src/governance/tests.rs  governance::tests::monitoring_reports_a_revoked_watched_template_family
ci  crates/registry/src/governance/tests.rs  governance::tests::a_watch_item_the_head_does_not_know_is_an_error
ci  crates/registry/src/governance/tests.rs  governance::tests::a_watched_template_family_must_be_a_valid_family_name
ci  crates/cli/tests/registry_governance_cli.rs  a_production_shaped_testnet_registry_runs_end_to_end
ci  crates/cli/tests/registry_governance_cli.rs  the_committed_mainnet_log_awaits_its_key_ceremony
ci  crates/cli/tests/development_root_cli.rs  synthesize_refuses_the_development_root_for_mainnet
ci  crates/registry/tests/mainnet_draft.rs  the_draft_claims_no_audit_and_marks_what_custodians_must_fill_in
ci  wallet/tests/install-actions.test.mjs  revoke removes the installed rule only with the event, an absent readback and a separate cleanup report
ci  wallet/tests/earlier-revoke-actions.test.mjs  a rule an earlier session installed is listed, removed with the passkey and verified
ci  wallet/tests/registry-monitor.test.mjs  each exit status is read with its meaning, as the governance guide tabulates it
ci  wallet/tests/registry-monitor.test.mjs  the installed-grant monitor reports the registry alongside the grant
```

## G11. Reconfiguration

The check refuses a second stateful grant while another usable rule reaches the target, and
says whether policies or nothing would let the agent through; two counted rules on one policy
would multiply its authority, which is why. The wallet's only reconfiguration is revoke-first
replacement: it needs a verified removal, fresh owner and rule reads and an explicit
acknowledgement that authority already used is additional to the new cap; an installed grant
cannot overlap its replacement; an unverified removal never opens it. There is no
add-before-remove path, so no atomic replacement is claimed. Through the pinned account,
revoke-then-recreate never overlaps and bounds aggregate use to one cap.

Deviation: [revoke-first replacement](POLLYWALLET-INTEGRATION.md#revoke-first-replacement) has
no testnet run, and it is session-local. The through-account test makes the account's management
calls itself rather than through the wallet
([wallet integration](TRANCHE-2-VERIFICATION.md#contracted-outcome-and-milestone-boundary)).
Closing it needs a live replacement run through the wallet. That no other grant overlaps is
read from G2's `rpc_reported` observation ([G2](#g2-authority-surface)).

```gate-evidence G11
ci  crates/call-surface-core/src/tests.rs  tests::stateful_grant_beside_another_usable_rule_on_the_target_is_refused
ci  crates/call-surface-core/src/tests.rs  tests::an_overlap_says_whether_policies_or_nothing_lets_the_agent_through
ci  contracts/differential/tests/generated_suite.rs  overlapping_counted_rules_multiply_aggregate_authority
ci  wallet/tests/replacement-actions.test.mjs  replacement needs verified removal, fresh owner/rule reads and explicit budget acknowledgement
ci  wallet/tests/replacement-actions.test.mjs  an installed grant cannot overlap its replacement
ci  wallet/tests/replacement-actions.test.mjs  a confirmed but unverified removal never opens replacement
ci  wallet/tests/replacement.test.mjs  replacement acknowledgement names the removed grant and discloses additive historical authority
release  contracts/differential/tests/account_wasm_invariants.rs  revoke_then_recreate_never_overlaps_and_bounds_aggregate_use
release  contracts/differential/tests/account_wasm_invariants.rs  overlapping_real_account_grants_have_independent_caps
```

## G12. Hosted processing

The gate applies to the release's endpoint: `ozpb-mcp-server --http`, the streamable HTTP server
each release ships as a binary and an image for operators to run themselves
([production release](SELF-HOSTING.md#production-release)), against mainnet too
([mainnet configuration](SELF-HOSTING.md#mainnet-configuration)). Gateway operates no production
service. The shipped grant shape does not depend on it: the wallet backend runs the local CLI,
and an agent can use a local stdio server.

For that server, the tests below establish that it reads only allowlisted HTTPS RPC sources and
refuses SSRF vectors, and refuses to start with a configured source the allowlist does not
cover; reports a failed RPC read from any tool by its category only, withholding the endpoint's
text, the URL a transport error quotes included; refuses an envelope carrying signatures before
any request, in `preflight_transaction` and `record_simulation`; keeps one session's artifacts from another;
authenticates before spending quota, bounds request bodies and refuses requests over the quota;
refuses a spec whose reference suite would exceed its case or case-data limit before deriving it; returns a
failed build's exit status without the compiler's output and removes each built crate from the
shared cache; and frees a build slot when a request is cancelled. The self-hosted workflow checks the hosted
transport's bounds and the build-worker launcher, and runs the Compose package and rootless
worker containment.

The package keeps confidential input out of logs by retaining none
([data handling](SELF-HOSTING.md#data-handling-and-handover)), and `scripts/check-log-redaction.py`
reads the files it ships and fails on a setting that would retain a log or print a credential:
the proxy's loggers must discard, with no access log, debug mode, credential logging or admin
endpoint; both Compose services and the build-worker containers must use the `none` log driver,
and the systemd unit must send the API's output to `null`; the entrypoint must not trace or print
the bearer token or the trust inputs; and the workspace must link no log subscriber or telemetry
crate, so the log events of the server's dependencies go nowhere. Its self-test changes each
setting in turn and requires the refusal.

Open: log redaction is checked as configuration, not observed. What the server's own code writes
is read, not tested: on stderr, one line at startup naming the listen address, the error that
stops a failed startup, and the message of any panic. The shipped package drops all of it; a
deployment [behind an ingress](SELF-HOSTING.md#behind-your-own-ingress-instead-of-the-proxy)
whose orchestrator keeps container output retains it. Closing it needs a test that drives the packaged endpoint with
confidential input and finds none of it in any log or retained output.

Also: builds are isolated from the API and from each other only in disposable-worker mode,
whose containment is accepted on the operator's chosen host
([isolated builds](ISOLATED-BUILDS.md#acceptance-on-the-chosen-host)); the Compose package
compiles in the API's own trust domain, bounded but not isolated
([self-hosting](SELF-HOSTING.md)); the server refuses to start that way unless the operator sets
`OZPB_HTTP_UNISOLATED_BUILDS=accept`, as that package does. The self-hosted workflow runs on changes to its paths, not on
every pull request.

```gate-evidence G12
ci  crates/mcp-server/src/main.rs  tests::rpc_allowlist_blocks_ssrf_vectors
ci  crates/mcp-server/src/main.rs  tests::every_configured_rpc_source_must_be_allowlisted_on_a_hosted_server
ci  crates/mcp-server/src/main.rs  tests::hosted_sessions_do_not_share_generated_artifacts
ci  crates/mcp-server/src/authority.rs  authority::tests::endpoint_controlled_errors_are_redacted_before_mcp_serialization
ci  crates/mcp-server/src/main.rs  tests::hosted_rpc_errors_withhold_endpoint_controlled_text_from_every_read
ci  crates/mcp-server/src/preflight.rs  preflight::tests::hosted_preflight_refuses_signed_material_before_any_request
ci  crates/mcp-server/src/main.rs  tests::hosted_record_simulation_refuses_signed_material_before_any_request
ci  crates/mcp-server/src/http.rs  http::tests::unauthenticated_requests_are_refused_without_spending_the_quota
ci  crates/toolkit/src/verification.rs  verification::tests::a_spec_whose_reference_suite_is_too_large_is_refused_before_any_work
ci  crates/mcp-server/src/cancel.rs  cancel::tests::cancelled_generate_code_kills_worker_group_and_frees_build_slot
ci  crates/mcp-server/src/http.rs  http::tests::a_hosted_server_compiles_in_process_only_when_the_operator_accepts_it
ci  crates/mcp-server/tests/mcp_http.rs  hosted_mode_refuses_to_compile_in_process_unless_the_operator_accepts_it
ci  crates/build-runner/src/lib.rs  tests::a_shared_server_withholds_compiler_output_and_evicts_the_crate_it_built
ci  crates/mcp-server/tests/mcp_http.rs  the_served_endpoint_authenticates_bounds_bodies_and_refuses_requests_over_the_quota
ci  crates/mcp-server/tests/mcp_stdio_capture.rs  an_endpoint_echoing_the_envelope_never_reaches_the_response
ci-step  .github/workflows/ci.yml  python3 scripts/check-log-redaction.py
ci-step  .github/workflows/ci.yml  python3 scripts/test-check-log-redaction.py
ci-step  .github/workflows/self-hosted.yml  python3 scripts/test-hosted-mcp.py
ci-step  .github/workflows/self-hosted.yml  python3 scripts/test-worker-launcher.py
ci-step  .github/workflows/self-hosted.yml  bash scripts/test-hosted-container.sh
ci-step  .github/workflows/self-hosted.yml  python3 scripts/test-worker-containment.py --image "$worker_image"
```

## G13. Publication split

This repository is the public tree, kept apart from the confidential source; the allowlist gate
scans the committed tree for the shapes confidential material takes, and its negative test plants
sentinels and requires the gate to refuse each one. Both run on every pull request. The
byte-for-byte comparison with the private documents runs only where they are present, from the
pre-push hook, not in CI.

```gate-evidence G13
ci-step  .github/workflows/ci.yml  bash scripts/check-publication-allowlist.sh
ci-step  .github/workflows/ci.yml  bash scripts/test-check-publication-allowlist.sh
```

## G14. Security review

A review gate. [AUDIT-SCOPE.md](AUDIT-SCOPE.md) is the scope for an external audit of the
authorization-to-install path: components, trust boundaries, threat model, invariants and known
limits. What closes the gate is the audit report for a frozen revision, with every finding's
remediation or accepted risk, and OpenZeppelin's review of the generated code
([review package](OZ-REVIEW-PACKAGE.md)). No audit report is in this tree; the tests above are
evidence for an auditor, not a substitute.
