# Tranche 2 verification guide

This guide separates reproducible automated checks from the live integration evidence required
by [architecture §10, Phase 2](architecture.md#10-delivery-plan). A passing command below is
evidence for the checked revision and named fixtures. It does not establish completion of the
four-layer harness, wallet integration, hosted service, or three end-to-end walkthroughs.
Read [SCOPE.md](SCOPE.md) and the [change review plan](CHANGE-REVIEW-PLAN.md) alongside it.

## Run the automated checks

Use the revision being reviewed and record `git rev-parse HEAD` and `git status --short` with
the results. The full command extends the Phase 1 release gate. Install the prerequisites and
check the tool versions listed in the [Tranche 1 guide](TRANCHE-1-VERIFICATION.md#1-run-the-release-gate),
then run from the repository root:

```bash
bash scripts/verify-phase2.sh
```

It runs Phase 1's formatting, lint, test, deterministic-build, and dependency checks; the
focused evidence checks below; and a Stellar CLI build of the committed Soroswap policy.
Missing release tools, failed builds, missing Wasm output, and failed evidence checks stop
the command. Success ends with `AUTOMATED PHASE 2 CHECKS PASSED (release mode)` and a reminder
of the separate live evidence requirements.

For a reduced local check:

```bash
bash scripts/verify-phase2.sh --offline
```

This passes `--offline` to the Phase 1 gate and omits the additional Soroswap Wasm build.
It therefore excludes Phase 1's real-builder tests, CLI compilation, Wasm reproducibility,
license/advisory scan, and unused-dependency check. “Offline” means no live Stellar operations;
Cargo may still fetch dependencies. It is not the release check or a milestone acceptance run.

The focused checks are also available independently, without repeating the Phase 1 gate:

```bash
bash scripts/check-phase2-evidence.sh
# CI divides the same checks between its two workspace jobs:
bash scripts/check-phase2-evidence.sh --host-only
bash scripts/check-phase2-evidence.sh --contracts-only
```

These are a subset of verification. Each selected Rust test uses its full name and must pass
exactly once; Cargo succeeding with zero matching tests is a failure. Python regression tests
exercise the gates with removed tests, failed report producers, malformed reports, and omitted
build evidence. CI runs those regression tests as well as both focused modes. PR CI does not
run the complete release command or the additional Stellar CLI build.

## What the focused checks establish

| Check | Evidence and limits |
| --- | --- |
| Subscription CLI reference suite | Labeled layer-1 outcomes, an original permit and denial controls per declared rule, agreement, and no missing required boundary classes. Summary counts, coverage, and policy gaps must match detailed evidence. Exact acknowledgements preserve repeated policy instances. |
| W1 Blend, W2 subscription, W3 Soroswap harness fixtures | Reference-evaluator agreement on the committed Rust fixtures. W3 includes amount boundaries and a caller-chosen deadline. These tests are not live protocol walkthroughs. |
| Golden generated suite | Partial layer 2: generated mutations through a test account and natively registered Rust policy, plus exact reasons for selected unambiguous denials. |
| Golden stateful cases | Permits commit counters; a later denial rolls back state, including an earlier policy's counter. An overlapping-rule test demonstrates aggregate authority across independent counters, not safe reconfiguration. |
| Soroswap generated suite | Partial layer 2: test-account/native-policy permit and denial behavior for bounds, route, recipient, and deadline mutations. |
| MCP stdio verification tests | Named verification tools have schemas, the reference operation returns evidence, and malformed specs retain structured errors. This does not test a hosted endpoint or successful real-builder verification over MCP. |

The partial layer-2 tests register natively compiled Rust in the local Soroban test host with
test accounts (`HarnessAccount` and `SwapAccount`). They do not execute the generated Wasm
artifact. Management setup and delegated-signer authentication are mocked. These tests do not
demonstrate a delegate's digest-bound signature, execution of captured target contracts,
live preflight, or a complete four-layer dry-run. The separate Soroswap Wasm build establishes
compilation only; its artifact is not executed by these tests.

The subscription acknowledgement names `oz:spending_limit`: layer 1 does not model its
stateful cap or period. An acknowledgement never waives a disagreement or missing boundary
class and never establishes on-chain composition coverage. New gaps, stale entries, and
entries for unchecked specs fail the gate. The focused gate uses one `--run` invocation with
`label=spec-path` pairs, so every declared example must actually run and pass. Repeated policy
kinds require one acknowledgement per instance. Permit-only classes are printed as limitations.
See [scope item 3](SCOPE.md) for the reviewed-policy Wasm boundary.

To retain the complete subscription report, use this inspection helper. It checks report
consistency and acknowledgements but skips the input-spec checks. Run the focused checks
above for the complete gate:

```bash
set -o pipefail
cargo run --locked -q -p ozpb-cli -- reference-suite --spec docs/examples/subscription-spec.json \
  | tee subscription-reference.json \
  | python3 scripts/check-unmodeled-acknowledged.py subscription scripts/layer1-unmodeled-acknowledged.txt
```

Review the outcomes and coverage, not only `all_agree`. The checker validates a locally
generated report's consistency; it does not authenticate a report obtained from another party.

## Evidence still required for milestone acceptance

The [Phase 2 outcome](architecture.md#10-delivery-plan) includes a public demo and video of
recording a testnet transaction, generating a policy, reviewing labeled permit/deny evidence
and the authority check, signing an install with a passkey, and revoking it. Review those
operations at the actual delivered revision; this guide does not assert that they are all
available in the current CLI or MCP surface.

The table highlights review areas; architecture §10 is the authoritative, complete acceptance
scope. Passing the automated subset above does not waive any of its requirements.

| Area | Separate evidence to review |
| --- | --- |
| Full harness | Each executed layer and its omissions; generated Wasm through complete account authentication; state-invariant tests and the adversarial direct-call suite; target execution using captured Wasm and state; current live preflight, with state and ledger anchors. |
| Authority and installation | Complete, fresh account and policy observations; intended wallet owner binding; proposed bindings and intent identities; successful and refused paths. A fixture or caller-supplied verdict cannot establish live authority. |
| Tool deliverables | The `dry_run`, `verify`, `check_against_policy`, `prepare_install_intent`, `assemble_install_transaction`, and `import_recording` operations, with their required evidence and refusal behavior through the supported shells. |
| Wallet | Consent and signature authorization, deploy/install separation, confirmed installation records, reconfiguration and overlap handling, revocation, and post-install monitoring. |
| W1/W2/W3 walkthroughs | The actual Blend, SEP-41, and Soroswap paths with code-hash-bound adapters; positive cases and relevant denials. Local reference fixtures alone do not satisfy this requirement. |
| Agent workflow | Clarification of ambiguous constraints, exact permission review, and the confirmation step before deployment. The installed skill's text alone is not an executed workflow. |
| Hosted endpoint | Versioned deployment, published self-hostable image, authentication and quotas, isolated builds, RPC restrictions, and privacy controls exercised against the deployed service. |

For each live run retain the reviewed revision, tool versions, network, transaction identifiers,
account/policy/target identities and code hashes, observation ledgers, spec, generated sources,
build manifest, labeled evidence reports, wallet decisions, confirmed results, and refusals.
Distinguish mocked, captured, and live state; identify which writes committed. Preserve a full
run log and an artifact inventory with the walkthrough or video. Exclude signing secrets and
access tokens from shared artifacts. A successful historical run is evidence for that revision
and observation, not a guarantee about current network state.
