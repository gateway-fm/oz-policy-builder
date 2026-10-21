#!/usr/bin/env bash
# Actual pinned-account/generated-policy execution. No RPC write or signing key
# is needed: the fixed delegate seed is confined to the Rust test process.
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
python3 scripts/native-execution-fixture.py spec "$work"
( cd contracts/golden-transfer-policy && cargo fetch --locked )
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/spec.json" --rule 0 --out "$work/generated"
python3 scripts/native-execution-fixture.py job "$work"
export OZPB_NATIVE_TEST_JOB="$work/job.json"
cargo test --manifest-path execution-runtime/Cargo.toml --locked -- \
    --include-ignored | tee "$work/result.log"
for test in \
    worker_rejects_protocol_identity_and_expansion_mismatches_before_signing \
    real_candidate_account_path_cannot_substitute_a_missing_delegate \
    real_candidate_account_path_runs_the_derived_suite_and_commits_state \
    process_runs_the_complete_interactive_protocol; do
    grep -qx "test $test ... ok" "$work/result.log" || {
        echo "required native execution test did not run and pass: $test" >&2
        exit 1
    }
done
