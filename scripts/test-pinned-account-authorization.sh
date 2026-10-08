#!/usr/bin/env bash
# Build the exact recognized account and a signable generated policy, then run
# the full delegated-auth and committed-state test. Artifacts stay in a temp dir.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
account_wasm="$work/pinned-account.wasm"

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    # A local artifact may save a cold source build. The test still asserts the
    # exact pinned hash; the scheduled gate leaves this override unset.
    cp "$OZPB_ACCOUNT_WASM" "$account_wasm"
else
    # This reproduces the recorded public tag/commit, compiler and CLI pins,
    # hash, and account export set before releasing the artifact to the test.
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$account_wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi

python3 - docs/examples/subscription-spec.json "$work/signable-spec.json" <<'PY'
import json
import sys

source, dest = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    spec = json.load(file)
signers = spec["rules"][0]["authorization"]["signers"]
assert len(signers) == 1
assert signers[0]["delegated"]["address"] == "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI"
# Public key for the fixed test seed [42; 32]. The matching private key exists
# only in the test process and never becomes part of a generated artifact.
signers[0]["delegated"]["address"] = "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W"
with open(dest, "w", encoding="utf-8") as file:
    json.dump(spec, file, separators=(",", ":"))
PY

cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/signable-spec.json" --rule 0 --out "$work/generated-policy"

# The Rust test checks this generated Wasm against its reviewed hash, derived
# with rustc 1.91.1, stellar-cli 27.0.0#5a7c5fe and the pinned locks.

export OZPB_ACCOUNT_WASM="$account_wasm"
export OZPB_POLICY_WASM="$work/generated-policy/generated_sub_transfer_r0.wasm"
( cd contracts && cargo test --locked -p ozpb-differential \
    --test account_wasm_auth -- --ignored --exact pinned_account_wasm_full_authorization ) \
    | tee "$work/test.log"
grep -qx 'test pinned_account_wasm_full_authorization ... ok' "$work/test.log" || {
    echo "the required full-authorization test did not run and pass" >&2
    exit 1
}

# Build the small target from reviewed source. Its hash is asserted in the
# joined test, and no Wasm artifact is checked into the repository.
bash scripts/check-build-input-pins.sh
target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
case "$target_dir" in
    /*) ;;
    *) target_dir="$PWD/$target_dir" ;;
esac
CARGO_TARGET_DIR="$target_dir" cargo build --locked --release --target wasm32v1-none \
    --manifest-path contracts/authorized-target-fixture/Cargo.toml
export OZPB_TARGET_WASM="$target_dir/wasm32v1-none/release/ozpb_authorized_target_fixture.wasm"

( cd contracts && cargo test --locked -p ozpb-differential \
    --test candidate_authorization -- --ignored --exact \
    signed_candidate_executes_captured_target_and_denies_adjacent_amount ) \
    | tee "$work/candidate.log"
grep -qx 'test signed_candidate_executes_captured_target_and_denies_adjacent_amount ... ok' \
    "$work/candidate.log" || {
    echo "the required signed candidate target test did not run and pass" >&2
    exit 1
}
