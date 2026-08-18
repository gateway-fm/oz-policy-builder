#!/usr/bin/env bash
# Print one recorded build input from the `pinned_upstream` provenance table.
#
#   bash scripts/recorded-build-inputs.sh rust                  # -> 1.91.1
#   bash scripts/recorded-build-inputs.sh stellar-cli           # -> 27.0.0
#   bash scripts/recorded-build-inputs.sh stellar-cli-revision  # -> 5a7c5fe7…
#
# Not executable on purpose: it is an internal helper that prints a value for other scripts, not
# an operator entry point, so every call site invokes it through `bash` — the same convention as
# scripts/check-unmodeled-acknowledged.py, which is invoked through `python3`.
#
# Why these two values are asserted rather than merely documented: both end up *inside* the wasm.
# The SDK macro writes `rsver`/`rssdkver` into a `contractmetav0` section at compile time, and
# `stellar contract build` appends a second `contractmetav0` section carrying
# `cliver = <version>#<git-revision>`. Measured on the golden policy — same source, same rustc,
# target dir warm so cargo recompiled nothing, only the CLI differing:
#
#   CLI 27.0.0 -> b8ea10a2d41a242db8450e18e432cd76cf477bd7061a79ca94a348e8cca6580b
#   CLI 27.1.0 -> 90792361630c2bc7d5cbaa5f3b217a59cf7fcef0caa396ef380b3313dd794386
#
# That pair predates the TTL codegen change and is kept as it was taken: it is a controlled
# comparison, and replacing half of it with a later measurement would leave two values that
# differ by the source as well as the CLI, demonstrating nothing. The golden policy's current
# hash under CLI 27.0.0 is `0291b543…` (2026-08-18, after emission was made rustfmt-clean); it is
# not comparable with the 27.1.0 value above, because the source changed in between.
#
# So a recorded wasm hash is reproducible only with the recorded compiler AND the recorded CLI.
# The provenance table on `ozpb_domain::pinned_upstream` is where those inputs are written down
# ("reproduce with these exact inputs or you will get a different hash"), which makes it the one
# home for the values; scripts/check-build-input-pins.sh asserts the pins in use still match it.
set -euo pipefail
cd "$(dirname "$0")/.."

PROVENANCE=crates/domain/src/lib.rs

usage() {
    echo "usage: bash scripts/recorded-build-inputs.sh <rust|stellar-cli|stellar-cli-revision>" >&2
    exit 2
}
[ "$#" -eq 1 ] || usage
case "$1" in
    rust)        ROW="Rust" ;;
    stellar-cli) ROW="Stellar CLI" ;;
    # The release's git revision, the other half of `cliver` and just as much a build input as
    # the version. It is not in the provenance table, which records versions; its home is the
    # workflow env beside the version and the checksum it belongs to, so the three values that
    # identify one release live together and are read from one place.
    stellar-cli-revision)
        WORKFLOW=.github/workflows/nightly-live.yml
        if [ ! -f "$WORKFLOW" ]; then
            echo "recorded-build-inputs: no workflow at $WORKFLOW" >&2
            echo "  it records the stellar-cli release revision; if it moved, update this helper" >&2
            exit 1
        fi
        REV="$(sed -n 's/^ *STELLAR_CLI_REVISION: *\([0-9a-f]*\) *$/\1/p' "$WORKFLOW" 2>/dev/null || true)"
        case "$REV" in
            # A git revision is exactly 40 lowercase hex characters; anything else — absent,
            # abbreviated, reformatted, or two matching lines whose combined output contains a
            # newline — must reach this message rather than flow on as an expected value.
            ????????????????????????????????????????) ;;
            *)
                echo "recorded-build-inputs: cannot read STELLAR_CLI_REVISION from $WORKFLOW" >&2
                echo "  expected exactly one line of the form:" >&2
                echo "    STELLAR_CLI_REVISION: <40 lowercase hex characters>" >&2
                exit 1
                ;;
        esac
        printf '%s\n' "$REV"
        exit 0
        ;;
    *)           usage ;;
esac

# A missing or renamed provenance file has to reach the message below instead of surfacing as a
# bare `sed: can't read ...` — under `set -e` that would abort before any explanation is printed.
if [ ! -f "$PROVENANCE" ]; then
    echo "recorded-build-inputs: no provenance file at $PROVENANCE" >&2
    echo "  it records the build inputs every shipped wasm hash was produced with;" >&2
    echo "  if it moved, this helper and its callers need the new path" >&2
    exit 1
fi

# The Rust row is bold and carries a trailing clause — `| Rust | **1.91.1** — this repo's ... |` —
# so tolerate surrounding `**` and anything after the version. `|| true` keeps any other sed
# failure from aborting before the diagnosis below.
VALUE="$(sed -n "s#^/// | $ROW | \**\([0-9][0-9.]*\)\**.*#\1#p" "$PROVENANCE" 2>/dev/null || true)"

# One test for every remaining failure mode: no row, a reformatted row, a non-numeric value, and
# more than one matching row — whose combined output contains a newline and so cannot be a version.
case "$VALUE" in
    '' | *[!0-9.]*)
        echo "recorded-build-inputs: cannot read the recorded '$ROW' version from $PROVENANCE" >&2
        echo "  expected exactly one provenance-table row: | $ROW | <x.y.z> |" >&2
        exit 1
        ;;
esac

printf '%s\n' "$VALUE"
