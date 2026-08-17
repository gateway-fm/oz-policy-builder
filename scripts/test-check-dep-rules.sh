#!/usr/bin/env bash
# Regression test for `check-dep-rules.sh`.
#
# The gate looks each crate up in `cargo metadata` by name. A name that matches no package
# yields an empty dependency list, no forbidden edge is found, and the gate reports success —
# so a misspelled crate, or one that has left the workspace, silently stops being checked. A
# rule that can be disabled by a typo is not a rule, and this is a gate whose whole value is
# that its passing means something.
#
# The cases below drive the gate through a mutated copy of itself rather than through mocks, so
# what is under test is the real lookup path. The copy is made next to the original because the
# gate resolves the repository root relative to its own location.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/check-dep-rules.sh
fail=0

# Run a copy of the gate with `sed_expr` applied. Echoes its output; returns its exit code.
run_mutated() {
    local sed_expr="$1"
    local copy
    copy="$(mktemp scripts/.tmp-dep-rules-XXXXXX.sh)"
    # shellcheck disable=SC2064
    trap "rm -f '$copy'" RETURN
    sed "$sed_expr" "$GATE" > "$copy"
    bash "$copy" 2>&1
}

expect() {
    local label="$1" want_code="$2" want_text="$3" got_code="$4" got_text="$5"
    if [ "$got_code" -ne "$want_code" ]; then
        echo "FAIL: $label — expected exit $want_code, got $got_code"
        printf '%s\n' "$got_text" | sed 's/^/    /'
        fail=1
    elif ! printf '%s' "$got_text" | grep -q "$want_text"; then
        echo "FAIL: $label — expected output matching '$want_text'"
        printf '%s\n' "$got_text" | sed 's/^/    /'
        fail=1
    else
        echo "ok: $label"
    fi
}

# 1. A crate named in the rules but absent from the workspace must stop the gate, and must say
#    so in its own words: after an extraction, "missing" and "violated" need different answers.
out="$(run_mutated 's/ozpb-evaluator/ozpb-evaluato/g')"; code=$?
expect "a misspelled crate name is caught, not skipped" 1 "NOT IN THE WORKSPACE" "$code" "$out"

# 2. The same for a crate named only in the CORES list, so both call sites are covered.
out="$(run_mutated 's/ozpb-domain/ozpb-domai/g')"; code=$?
expect "a missing CORES crate is caught" 1 "NOT IN THE WORKSPACE" "$code" "$out"

# 3. A genuine forbidden edge must still be reported as a violation, and must not be confused
#    with an absent package — the two failures have opposite remedies.
out="$(run_mutated 's/^check_forbidden ozpb-evaluator ozpb-codegen$/check_forbidden ozpb-cli clap/')"; code=$?
expect "a real forbidden edge is reported as a violation" 1 "FORBIDDEN EDGE" "$code" "$out"

# 4. And the unmutated gate must still pass on this tree, or the cases above prove nothing.
out="$(bash "$GATE" 2>&1)"; code=$?
expect "the real gate passes on this workspace" 0 "dependency rules OK" "$code" "$out"

if [ "$fail" -ne 0 ]; then
    echo "check-dep-rules regression test FAILED"
    exit 1
fi
echo "check-dep-rules regression test OK"
