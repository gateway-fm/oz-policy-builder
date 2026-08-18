#!/usr/bin/env bash
# Phase 1 acceptance gate (architecture §10 Phase 1 verifiable outcome):
# a recorded transfer becomes a compilable Rust policy, byte-identical across two cold
# runs, agreeing with the reference evaluator including zero-signer + strict-set denial.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. dependency rules (evaluator ↛ codegen; cores transport-free) =="
bash scripts/check-dep-rules.sh

# clippy also carries the hash-determinism gate: `clippy.toml` disallows `HashMap`/`HashSet`
# (per-process iteration order) and floats (no faithful JSON form, absent from `ScVal`) so the
# rule that keeps serialized bytes stable is checked rather than stated in a comment.
#
# Both workspaces, because the root `Cargo.toml` excludes `contracts` and `--workspace` therefore
# never reaches it. `clippy.toml` does apply there — clippy walks up to the repository root to
# find it — so a single invocation would leave this gate reporting a pass while the contracts
# workspace held a banned type. That is the shape of defect this gate exists to prevent, and CI
# lints the two workspaces separately for the same reason.
#
# fmt needs four invocations, for a stronger version of the same reason, and had only one until
# 30 differences had piled up behind it. `--all` means "the members of this workspace", and
# neither generated policy crate is a member of one: `contracts` excludes both, each carrying its
# own `[profile.release]` so it builds standalone. Running fmt in `contracts` happens to reach
# golden-transfer-policy through the differential suite's dev-dependency on it — an edge that
# exists for testing, not for coverage — and does not reach soroswap-swap-policy at all, because
# nothing depends on that crate. Both are generated artifacts a reviewer reads, and four of the
# 30 differences were in one of them: unformatted text there is a defect in the code generator,
# not in a checked-in file.
echo "== 2. fmt + clippy (fmt/clippy gates are part of the contract, §4.11) =="
cargo fmt --all --check
( cd contracts && cargo fmt --all --check )
( cd contracts/golden-transfer-policy && cargo fmt --all --check )
( cd contracts/soroswap-swap-policy && cargo fmt --all --check )
cargo clippy --workspace --all-targets -- -D warnings
( cd contracts && cargo clippy --all-targets -- -D warnings )

echo "== 3. host workspace test suite (TDD) =="
cargo test --workspace

echo "== 4. contracts: differential suite (evaluator vs real compiled policy) =="
( cd contracts && cargo test -p ozpb-differential )

echo "== 5. determinism: codegen is byte-identical and the golden crate is in step =="
# Asserted without a toolchain, so this gate is meaningful on a machine without stellar-cli.
#
# Each name is required to have MATCHED at least one passing test rather than merely to have
# exited 0, because `cargo test <filter>` exits 0 when the filter matches nothing: a gate
# naming a test that was renamed, moved, or never existed here keeps reporting a pass while
# asserting nothing whatsoever. That is not hypothetical — this gate carried a third name that
# matched no test in this tree, and its green said so about a property nobody was checking.
# Matched with bash's own regex rather than through a pipe to `grep -q`: under `pipefail`, grep
# exiting the moment it matches leaves the test binary killed by SIGPIPE, and the pipeline
# reports that death — so the check failed on a test that had just passed.
ran_at_least_one='test result: ok\. [1-9][0-9]* passed'
for t in generation_is_byte_deterministic golden_crate_matches_committed_output; do
    if ! out="$(cargo test -q -p ozpb-codegen "$t" 2>&1)"; then
        echo "  DETERMINISM GATE FAILED: $t"
        printf '%s\n' "$out" | tail -20
        exit 1
    fi
    if [[ ! "$out" =~ $ran_at_least_one ]]; then
        echo "  DETERMINISM GATE ASSERTED NOTHING: no passing test matched '$t'"
        printf '%s\n' "$out" | tail -20
        exit 1
    fi
done
echo "  codegen deterministic; golden crate matches codegen output"
# The end-to-end shell path additionally proves the CLI emits those same bytes, but it
# compiles the policy, so it needs the toolchain.
if command -v stellar >/dev/null 2>&1; then
    rm -rf target/det-a target/det-b
    cargo run -q -p ozpb-cli -- generate --spec docs/examples/subscription-spec.json --rule 0 --out target/det-a
    cargo run -q -p ozpb-cli -- generate --spec docs/examples/subscription-spec.json --rule 0 --out target/det-b
    A=$(shasum -a 256 target/det-a/src/lib.rs | cut -d' ' -f1)
    B=$(shasum -a 256 target/det-b/src/lib.rs | cut -d' ' -f1)
    [ "$A" = "$B" ] || { echo "  CLI CODEGEN NON-DETERMINISTIC"; exit 1; }
    echo "  CLI end-to-end byte-identical: $A"
else
    echo "  (stellar-cli not installed — skipping the end-to-end CLI check)"
fi

echo "== 6. wasm reproducibility (requires stellar-cli) =="
if command -v stellar >/dev/null 2>&1; then
    # A note, not a gate: this compares two builds made with whatever CLI is installed, so its
    # verdict holds at any version. But `stellar contract build` stamps its own version into the
    # wasm (`cliver` in contractmetav0), so the hash printed below is only *this* CLI's — it will
    # not equal the recorded hashes, or CI's, on a different one. Gates whose verdict does depend
    # on the version (scripts/verify-pinned-upstream.sh) fail instead of noting.
    #
    # Advisory means advisory: `set -euo pipefail` is in force, so both probes are allowed to fail
    # and are read afterwards. Otherwise a reformatted documentation table would abort this gate —
    # and verify-phase2.sh with it — after clippy and the whole test suite had already passed, for
    # a line that is only ever informational.
    EXPECTED_CLI="$(bash scripts/recorded-build-inputs.sh stellar-cli 2>/dev/null || true)"
    HAVE_CLI="$(stellar --version 2>/dev/null | awk 'NR==1 {print $2}' || true)"
    if [ -z "$EXPECTED_CLI" ]; then
        echo "  note: could not read the recorded stellar-cli version, so whether this CLI matches"
        echo "        the one the recorded hashes were built with is undetermined"
    elif [ "$HAVE_CLI" != "$EXPECTED_CLI" ]; then
        echo "  note: stellar-cli ${HAVE_CLI:-unknown} (this repo pins $EXPECTED_CLI);" \
             "the hash below is this CLI's alone"
    fi
    # The golden crate is EXCLUDED from the contracts workspace (it carries its own
    # [profile.release], which a workspace member would not get), so it is its own workspace
    # root and `stellar contract build` writes to ITS target dir — not contracts/target.
    #
    # This gate used to hash contracts/target/..., which the rebuild never touches: that copy
    # comes from the differential suite building the crate as a dev-dependency. It compared one
    # untouched file with itself and passed unconditionally. The two copies do not even have the
    # same hash, because they are built in different contexts.
    G=contracts/golden-transfer-policy
    W="$G/target/wasm32v1-none/release/generated_sub_transfer_r0.wasm"
    ( cd "$G" && stellar contract build >/dev/null 2>&1 )
    H1=$(shasum -a 256 "$W" | cut -d' ' -f1)
    ( cd "$G" && cargo clean >/dev/null 2>&1 )
    # Non-vacuity: if the artifact survives the clean, the rebuild below proves nothing.
    [ -f "$W" ] && { echo "  cargo clean did not remove the wasm — this gate would be vacuous"; exit 1; }
    ( cd "$G" && stellar contract build >/dev/null 2>&1 )
    H2=$(shasum -a 256 "$W" | cut -d' ' -f1)
    [ "$H1" = "$H2" ] && echo "  wasm byte-identical across a full clean rebuild: $H1" \
        || { echo "  WASM DIFFERS: $H1 vs $H2"; exit 1; }
else
    echo "  (stellar-cli not installed — skipping wasm reproducibility)"
fi

echo "== 7. license & supply-chain gate (permissive-license requirement, §4.11) =="
if command -v cargo-deny >/dev/null 2>&1; then
    bash scripts/check-licenses.sh
else
    echo "  (cargo-deny not installed — skipping; run: cargo install cargo-deny --locked)"
fi

echo "ALL PHASE 1 GATES PASSED"
