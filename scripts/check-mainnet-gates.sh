#!/usr/bin/env bash
# Architecture §10's acceptance gates before any mainnet use, checked from docs/MAINNET-GATES.md.
# The document is the list: scripts/mainnet-gates-plan.py reads it, refuses it if a row or a named
# test is missing, and prints each check. This script runs every named test once, by its full
# name, in the binary its file belongs to, and requires exactly one pass. A gate's status says
# what those tests establish; passing here does not move a gate from narrowed, open or review.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { echo "usage: bash scripts/check-mainnet-gates.sh [--part host|contracts|wallet]" >&2; exit 2; }
PART=all
case "$#:${1:-}" in
    0:) ;;
    2:--part) case "$2" in host|contracts|wallet) PART="$2" ;; *) usage ;; esac ;;
    *) usage ;;
esac

# Same contract as check-phase2-evidence.sh: Cargo succeeds when a filter matches no tests, so
# require one pass from each full name in one named binary, or a renamed test turns this green.
check_test() {
    local name="$1" output
    shift
    if ! output="$(cargo test --locked -q "$@" "$name" -- --exact 2>&1)"; then
        echo "  GATE CHECK FAILED: $name" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    if [[ ! "$output" =~ test\ result:\ ok\.\ 1\ passed\; ]]; then
        echo "  GATE CHECK ASSERTED NOTHING: $name did not pass exactly once" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    echo "  $name: one passing test"
}

# node --test reports the file itself as one passing test when the pattern matches nothing, so
# a pass count proves nothing. Require the title's own `ok` line, exactly once, and no failure.
check_node_test() {
    local file="$1" pattern="$2" title="$3" output matched
    if ! output="$(cd wallet && node --test --test-reporter=tap --test-name-pattern="$pattern" \
        "$file" 2>&1)"; then
        echo "  GATE CHECK FAILED: wallet/$file: $title" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    matched="$(printf '%s\n' "$output" | sed -nE 's/^ *ok [0-9]+ - //p' | grep -cxF -- "$title" || true)"
    if [ "$matched" != 1 ] || printf '%s\n' "$output" | grep -qE '^ *not ok '; then
        echo "  GATE CHECK ASSERTED NOTHING: wallet/$file: '$title' did not pass exactly once" >&2
        printf '%s\n' "$output" | tail -20 >&2
        return 1
    fi
    echo "  wallet/$file: $title: one passing test"
}

PLAN="$(python3 scripts/mainnet-gates-plan.py)"

failed=0
ran=0
other_parts=()
release=()
steps=()
# Plan lines arrive on fd 3, so a test that reads standard input cannot swallow the rest.
while IFS=$'\t' read -r -a field <&3; do
    kind="${field[0]}" gates="${field[1]}"
    case "$kind" in
        rust|node)
            part="${field[2]}"
            if [ "$PART" != all ] && [ "$PART" != "$part" ]; then
                other_parts+=("$part")
                continue
            fi
            echo "[$gates] $part"
            if [ "$kind" = rust ]; then
                check_test "${field[3]}" "${field[@]:4}" || failed=$((failed + 1))
            else
                check_node_test "${field[3]}" "${field[4]}" "${field[5]}" || failed=$((failed + 1))
            fi
            ran=$((ran + 1))
            ;;
        release) release+=("[$gates] ${field[2]} ${field[3]}") ;;
        step) steps+=("[$gates] ${field[2]}: ${field[3]}") ;;
    esac
done 3<<< "$PLAN"

echo "== not run here =="
if [ "${#other_parts[@]}" -gt 0 ]; then
    printf '%s\n' ${other_parts[@]+"${other_parts[@]}"} | sort | uniq -c \
        | awk '{print "  part " $2 ": " $1 " named test(s), run by --part " $2 " in CI"}'
fi
echo "  Release gate: scripts/test-pinned-account-authorization.sh builds the Wasm (Apple Silicon; the"
echo "  pinned-account-authorization job in .github/workflows/nightly-live.yml) and requires each by name:"
printf '    %s\n' ${release[@]+"${release[@]}"}
echo "  Named CI steps, run by their workflow:"
printf '    %s\n' ${steps[@]+"${steps[@]}"}

if [ "$failed" -gt 0 ]; then
    echo "MAINNET GATE CHECKS FAILED: $failed of $ran named test(s)" >&2
    exit 1
fi
if [ "$PART" = all ]; then label="all parts"; else label="part $PART"; fi
echo "MAINNET GATE CHECKS PASSED ($label): $ran named test(s), each exactly once."
echo "This checks the tests docs/MAINNET-GATES.md names; each gate's status there says what they"
echo "establish. Narrowed, open and review gates stay so until that document changes."
