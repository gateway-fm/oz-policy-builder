#!/usr/bin/env bash
# Regression test for `mutation-test.sh`.
#
# The gate's value is that a green run means every mutant in the cores was killed. Three ways it
# could stop meaning that without anyone noticing: it runs a different cargo-mutants than the one
# its verdicts were taken with, it treats a timed-out mutant as killed, or it quietly narrows the
# packages it mutates. Each case below drives the real script with a stand-in `cargo` that
# records how it was called and answers as cargo-mutants would.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE="${GATE:-scripts/mutation-test.sh}"
fail=0
shim_dir="$(mktemp -d)"
trap 'rm -rf "$shim_dir"' EXIT

# `cargo mutants --version` prints $FAKE_VERSION; any other `cargo mutants …` call appends its
# arguments to $shim_dir/calls and exits $FAKE_STATUS.
cat >"$shim_dir/cargo" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = mutants ] && [ "${2:-}" = --version ]; then
    echo "cargo-mutants ${FAKE_VERSION}"
    exit 0
fi
printf '%s\n' "$*" >>"$(dirname "$0")/calls"
exit "${FAKE_STATUS:-0}"
EOF
printf '#!/bin/sh\nexit 0\n' >"$shim_dir/cargo-mutants"
chmod +x "$shim_dir/cargo" "$shim_dir/cargo-mutants"

# run VERSION STATUS ARGS… — echoes the gate's output; returns its exit code.
run() {
    local version="$1" status="$2"
    shift 2
    rm -f "$shim_dir/calls"
    PATH="$shim_dir:$PATH" FAKE_VERSION="$version" FAKE_STATUS="$status" bash "$GATE" "$@" 2>&1
}

expect() {
    local label="$1" want_code="$2" want_text="$3" got_code="$4" got_text="$5"
    if [ "$got_code" -ne "$want_code" ]; then
        echo "FAIL: $label — expected exit $want_code, got $got_code"
        printf '%s\n' "$got_text" | sed 's/^/    /'
        fail=1
    elif ! printf '%s' "$got_text" | grep -q -- "$want_text"; then
        echo "FAIL: $label — expected output matching '$want_text'"
        printf '%s\n' "$got_text" | sed 's/^/    /'
        fail=1
    else
        echo "ok: $label"
    fi
}

calls() { cat "$shim_dir/calls" 2>/dev/null; }

out="$(run 27.1.0 0)"; code=$?
expect "a clean run passes" 0 "every mutant" "$code" "$out"
for core in ozpb-recorder-core ozpb-evaluator ozpb-synthesizer ozpb-policy-spec ozpb-call-surface-core ozpb-registry ozpb-domain ozpb-codegen; do
    if ! calls | grep -q -- "--package $core"; then
        echo "FAIL: the default run does not mutate $core"
        fail=1
    fi
done

out="$(run 27.0.0 0)"; code=$?
expect "another cargo-mutants version is refused" 1 "pinned to 27.1.0" "$code" "$out"
if [ -n "$(calls)" ]; then
    echo "FAIL: mutants ran under an unpinned cargo-mutants"
    fail=1
fi

out="$(run 27.1.0 2)"; code=$?
expect "a surviving mutant fails the gate" 2 "FAILED" "$code" "$out"

out="$(run 27.1.0 3)"; code=$?
expect "a timed-out mutant fails the gate" 3 "FAILED" "$code" "$out"

out="$(run 27.1.0 4)"; code=$?
expect "a failing baseline fails the gate" 4 "could not run" "$code" "$out"

out="$(run 27.1.0 0 -p ozpb-toolkit)"; code=$?
expect "a package outside the cores is refused, not mutated" 2 "not one of the core packages" "$code" "$out"

out="$(run 27.1.0 0 --in-diff HEAD)"; code=$?
expect "a branch with no Rust change has nothing to mutate" 0 "no Rust change" "$code" "$out"
if [ -n "$(calls)" ]; then
    echo "FAIL: an empty diff still invoked cargo-mutants"
    fail=1
fi

[ "$fail" -eq 0 ] && echo "mutation-test.sh self-test OK" || exit 1
