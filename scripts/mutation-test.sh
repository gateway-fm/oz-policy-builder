#!/usr/bin/env bash
# Mutation testing over the trust-bearing cores (architecture §8).
#
# A mutant is a small deliberate defect: a flipped comparison, a function that returns a default,
# a deleted negation. If the crate's own tests still pass with it in place, nothing pins that
# behaviour — the same reasoning as a deny suite, applied to our own code. The gate fails on any
# surviving ("missed") mutant; the fix is a test, or, for a mutant no input can observe, an
# exclusion in `.cargo/mutants.toml` that says so.
#
#   bash scripts/mutation-test.sh                     # every core package (hours; scheduled CI)
#   bash scripts/mutation-test.sh -p ozpb-evaluator   # one package
#   bash scripts/mutation-test.sh --in-diff origin/main   # only code a branch changed (pull requests)
#
# Requires `cargo install cargo-mutants --locked --version 27.1.0`.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned because mutant generation is part of what the verdict means: another version can
# generate different mutants and so reach a different verdict on the same tree.
EXPECTED_MUTANTS_VERSION="27.1.0"

# The pure cores: no I/O, no async, and the logic every trust claim rests on — from the recorder
# that turns ledger evidence into a recording, through synthesis and validation, to the templates
# the generated contract is rendered from.
CORE_PACKAGES=(
    ozpb-recorder-core
    ozpb-evaluator
    ozpb-synthesizer
    ozpb-policy-spec
    ozpb-call-surface-core
    ozpb-registry
    ozpb-domain
    ozpb-codegen
)

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

packages=()
diff_base=""
while [ $# -gt 0 ]; do
    case "$1" in
        -p | --package)
            [ $# -ge 2 ] || usage
            packages+=("$2")
            shift 2
            ;;
        --in-diff)
            [ $# -ge 2 ] || usage
            diff_base="$2"
            shift 2
            ;;
        -h | --help) usage ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            ;;
    esac
done
[ ${#packages[@]} -gt 0 ] || packages=("${CORE_PACKAGES[@]}")

for p in "${packages[@]}"; do
    known=0
    for core in "${CORE_PACKAGES[@]}"; do [ "$p" = "$core" ] && known=1; done
    if [ "$known" -ne 1 ]; then
        echo "$p is not one of the core packages this gate covers: ${CORE_PACKAGES[*]}" >&2
        exit 2
    fi
done

if ! command -v cargo-mutants >/dev/null 2>&1; then
    echo "cargo-mutants is not installed:" >&2
    echo "  cargo install cargo-mutants --locked --version ${EXPECTED_MUTANTS_VERSION}" >&2
    exit 1
fi
have=$(cargo mutants --version | awk '{print $2}')
if [ "$have" != "$EXPECTED_MUTANTS_VERSION" ]; then
    echo "cargo-mutants $have is installed; this gate is pinned to ${EXPECTED_MUTANTS_VERSION}." >&2
    echo "  cargo install cargo-mutants --locked --version ${EXPECTED_MUTANTS_VERSION}" >&2
    exit 1
fi

# cargo-mutants writes `<dir>/mutants.out` but will not create `<dir>` itself.
mkdir -p target/mutants
args=(--no-shuffle --timeout 120 --output target/mutants)
for p in "${packages[@]}"; do args+=(--package "$p"); done
# Each job builds its own copy of the tree; two is what a CI runner's memory allows.
args+=(--jobs "${MUTANTS_JOBS:-2}")

if [ -n "$diff_base" ]; then
    diff_file=$(mktemp)
    trap 'rm -f "$diff_file"' EXIT
    git diff "$diff_base"...HEAD -- 'crates/*.rs' 'crates/**/*.rs' >"$diff_file"
    if [ ! -s "$diff_file" ]; then
        echo "mutation testing: no Rust change under crates/ since $diff_base"
        exit 0
    fi
    args+=(--in-diff "$diff_file")
fi

# cargo-mutants exits 2 when a mutant was missed and 3 when one timed out; a timeout is not a
# kill, so both fail the gate. Its own report names each mutant.
report=$(mktemp)
trap 'rm -f "$report" "${diff_file:-}"' EXIT
status=0
cargo mutants "${args[@]}" 2>&1 | tee "$report" || status=$?
case "$status" in
    0)
        if grep -Eq 'No mutants (to filter|found under the active filters|were generated|were viable)' "$report"; then
            echo "mutation testing: no viable mutants were exercised in ${packages[*]}"
            if [ -z "$diff_base" ]; then exit 1; fi
        else
            echo "mutation testing OK: every viable mutant in ${packages[*]} was caught"
        fi
        ;;
    2 | 3)
        echo "mutation testing FAILED: surviving or timed-out mutants, listed in" >&2
        echo "  target/mutants/mutants.out/missed.txt and timeout.txt" >&2
        ;;
    *) echo "mutation testing could not run (cargo-mutants exit $status)" >&2 ;;
esac
exit "$status"
