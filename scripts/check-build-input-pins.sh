#!/usr/bin/env bash
# Assert that the pins builds actually use still equal the build inputs recorded in the
# `pinned_upstream` provenance table: the rustc channel, and the stellar-cli version CI installs.
#
# Runs on the pull-request path (ci.yml) because that is the only path that can block a merge.
# The nightly wasm workflow is scheduled, so a disagreement introduced by a PR would first appear
# a day later, in a job whose own header lists three plausible *external* causes for a red — which
# is how the CLI pin came to say 27.1.0 while every shipped wasm hash was built with 27.0.0, with
# nothing objecting. A recorded build input that nothing compares against is a comment.
#
# Both inputs are inside the hashed bytes: the SDK macro writes `rsver` into a `contractmetav0`
# section at compile time, and `stellar contract build` appends a second one carrying `cliver`.
# Reproducing a recorded wasm hash therefore needs the recorded rustc *and* the recorded CLI.
#
# No toolchain, no network, about a second — it only reads checked-out files.
set -euo pipefail
cd "$(dirname "$0")/.."

WORKFLOW=.github/workflows/nightly-live.yml
fail=0

# rustc: rust-toolchain.toml is what every build in this repository actually resolves to, and
# verify-pinned-upstream.sh forces that same channel when reproducing the recorded hashes.
RECORDED_RUST="$(bash scripts/recorded-build-inputs.sh rust)"
CHANNEL="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [ -z "$CHANNEL" ]; then
    echo "cannot read the toolchain channel from rust-toolchain.toml"
    fail=1
elif [ "$CHANNEL" != "$RECORDED_RUST" ]; then
    echo "rustc pin disagrees with the recorded build provenance:"
    echo "  rust-toolchain.toml      channel     = $CHANNEL"
    echo "  crates/domain provenance Rust        = $RECORDED_RUST"
    echo "  the shipped wasm hashes were produced with $RECORDED_RUST, so a channel bump means"
    echo "  re-deriving those hashes and updating the table — not editing one of the two numbers"
    fail=1
else
    echo "rustc $CHANNEL matches the recorded build provenance"
fi

# stellar-cli: the nightly workflow is the only place it is installed, so its pin is the version
# every wasm gate in CI builds with.
RECORDED_CLI="$(bash scripts/recorded-build-inputs.sh stellar-cli)"
PINNED_CLI="$(sed -n 's/^ *STELLAR_CLI_VERSION: *\([0-9][0-9.]*\) *$/\1/p' "$WORKFLOW" 2>/dev/null || true)"
case "$PINNED_CLI" in
    '' | *[!0-9.]*)
        echo "cannot read STELLAR_CLI_VERSION from $WORKFLOW"
        echo "  expected exactly one line of the form: STELLAR_CLI_VERSION: <x.y.z>"
        fail=1
        ;;
    "$RECORDED_CLI")
        echo "stellar-cli $PINNED_CLI matches the recorded build provenance"
        ;;
    *)
        echo "stellar-cli pin disagrees with the recorded build provenance:"
        echo "  $WORKFLOW  STELLAR_CLI_VERSION = $PINNED_CLI"
        echo "  crates/domain provenance                Stellar CLI = $RECORDED_CLI"
        echo "  a CLI bump changes every wasm hash, because cliver is inside the hashed bytes, so"
        echo "  it means re-deriving the recorded hashes — and re-pinning STELLAR_CLI_SHA256 too"
        fail=1
        ;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "recorded build inputs and the pins in use agree"
