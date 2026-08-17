#!/usr/bin/env bash
# Architecture §4.11: dependency rules are enforced in CI, not by convention.
# - evaluator must NEVER depend on codegen (differential-testing independence)
# - core crates must be transport- and async-free
set -euo pipefail
cd "$(dirname "$0")/.."

META="$(cargo metadata --format-version 1 --no-deps)"

fail=0
# A rule that names a crate the workspace does not have is not a satisfied rule, it is an
# unasked question: the lookup returns nothing, no forbidden edge is found, and the gate
# reports success. That makes every rule here disableable by a typo, and makes a crate leaving
# the workspace silently take its rules with it. So an absent package stops the gate, and says
# something different from a violation — the two have opposite remedies. Removing a crate on
# purpose therefore means removing its name here too, which is the intended, visible step.
check_forbidden() {
    local crate="$1"; shift
    local deps
    if ! deps="$(printf '%s' "$META" | python3 -c "
import sys, json
m = json.load(sys.stdin)
for p in m['packages']:
    if p['name'] == '$crate':
        print('\n'.join(d['name'] for d in p['dependencies']))
        break
else:
    sys.exit(3)
")"; then
        echo "NOT IN THE WORKSPACE: $crate — the rule naming it is checking nothing"
        echo "  (renamed, removed, or misspelled; if removed on purpose, drop its name here)"
        fail=1
        return
    fi
    for forbidden in "$@"; do
        if printf '%s\n' "$deps" | grep -qx "$forbidden"; then
            echo "FORBIDDEN EDGE: $crate -> $forbidden"
            fail=1
        fi
    done
}

# Differential independence: the reference evaluator (and the harness that drives it)
# share nothing with codegen.
check_forbidden ozpb-evaluator ozpb-codegen

# Functional cores: no async runtimes, no transports, no RPC clients.
CORES="ozpb-domain ozpb-recorder-core ozpb-policy-spec ozpb-synthesizer ozpb-evaluator ozpb-codegen"
for c in $CORES; do
    check_forbidden "$c" tokio rmcp reqwest ureq stellar-rpc-client hyper axum
done

if [ "$fail" -ne 0 ]; then
    echo "dependency rules VIOLATED"
    exit 1
fi
echo "dependency rules OK"
