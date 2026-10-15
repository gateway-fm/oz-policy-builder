#!/usr/bin/env bash
# Focused, local evidence checks shared by CI and the Phase 2 verification command.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=all
case "${1:-}" in
    "") ;;
    --host-only) MODE=host ;;
    --contracts-only) MODE=contracts ;;
    *) echo "usage: bash scripts/check-phase2-evidence.sh [--host-only|--contracts-only]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "usage: bash scripts/check-phase2-evidence.sh [--host-only|--contracts-only]" >&2
    exit 2
fi

# Cargo succeeds when a filter matches no tests. Require one pass from each full name,
# in a single named test binary, so a renamed or removed check cannot turn the gate green.
check_test() {
    local name="$1" output
    shift
    if ! output="$(cargo test --locked -q "$@" "$name" -- --exact 2>&1)"; then
        echo "  EVIDENCE CHECK FAILED: $name" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    if [[ ! "$output" =~ test\ result:\ ok\.\ 1\ passed\; ]]; then
        echo "  EVIDENCE CHECK ASSERTED NOTHING: $name did not pass exactly once" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    echo "  $name: one passing test"
}

if [ "$MODE" != contracts ]; then
    echo "== layer 1: reference agreement, coverage, and acknowledged modeling gaps =="
    python3 scripts/test-check-unmodeled-acknowledged.py
    python3 scripts/check-unmodeled-acknowledged.py --run \
        scripts/layer1-unmodeled-acknowledged.txt subscription=docs/examples/subscription-spec.json
    # W1 and W3 are Rust fixtures; only W2 has a runnable example JSON spec in this tree.
    for name in w1_blend_claim_evidence_all_agrees \
                subscription_evidence_report_all_agrees \
                w3_soroswap_evidence_all_agrees_including_bounds_and_any_deadline; do
        check_test "tests::$name" -p ozpb-harness --lib
    done

    echo "== MCP stdio: verification schemas, reference response, and structured refusals =="
    for name in verification_tools_are_listed_with_schemas \
                reference_suite_returns_labeled_layer_one_evidence \
                both_verification_tools_preserve_structured_spec_errors; do
        check_test "$name" -p ozpb-mcp-server --test mcp_stdio_verification
    done
fi

if [ "$MODE" != host ]; then
    echo "== partial layer 2: natively compiled Rust registered with test accounts =="
    echo "   Generated Wasm is not executed; management setup and delegated authentication are mocked."
    for name in generated_deny_suite_agrees_with_the_real_contract \
                generated_golden_denials_preserve_the_expected_reason \
                generated_suite_commits_permits_and_rolls_back_a_later_denial \
                later_policy_denial_rolls_back_an_earlier_policy_counter \
                overlapping_counted_rules_multiply_aggregate_authority; do
        check_test "$name" --manifest-path contracts/Cargo.toml -p ozpb-differential --test generated_suite
    done
    check_test swap_mutations_agree_through_the_smart_account \
        --manifest-path contracts/Cargo.toml -p ozpb-differential --test swap_generated_suite
fi

echo "FOCUSED PHASE 2 CHECKS PASSED ($MODE); see docs/TRANCHE-2-VERIFICATION.md for evidence limits"
