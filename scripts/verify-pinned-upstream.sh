#!/usr/bin/env bash
# Reproduce the pinned upstream wasm hashes in `ozpb_domain::pinned_upstream` and check them
# against the constants this repository ships.
#
# Why this exists. Those constants are trust anchors: the capability registry recognizes an
# on-chain contract by matching its code hash against them, and refuses anything else. A hash
# documented only in a comment is a claim a reviewer has to take on faith. This makes it
# checkable — clone the pinned tag, build with the pinned toolchain, compare.
#
# It is deliberately NOT part of verify-phase1/2: a cold build of upstream's workspace takes
# minutes and needs network access to clone. Run it when the pins change, when bumping the
# upstream tag, or when reviewing this repository's trust anchors.
#
# The hash depends on the compiler. Upstream's rust-toolchain.toml says `channel = "stable"`,
# which floats, so building with a different rustc yields a different hash from identical
# source. This script forces the toolchain this repository pins.
set -euo pipefail
cd "$(dirname "$0")/.."

UPSTREAM_REPO="https://github.com/OpenZeppelin/stellar-contracts.git"
UPSTREAM_TAG="v0.7.2"
UPSTREAM_COMMIT="a9c42169000638da937577f592ebf61a7a3c94ca"
TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
CLI_REPO="https://github.com/stellar/stellar-cli.git"
CLI_RELEASES="https://github.com/stellar/stellar-cli/releases"

for tool in git stellar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 1; }
done

# The pins these builds use must still equal the recorded provenance, or the comparison below is
# against a hash nobody can reproduce. Covers rustc (forced into every build here) and the CLI.
bash scripts/check-build-input-pins.sh

# The hash also depends on the CLI, so reproducing it with a different one is not a weaker check
# but a meaningless one: `stellar contract build` appends a `contractmetav0` section carrying
# `cliver = <version>#<git-revision>`, inside the bytes being hashed, so a different CLI reports
# MISMATCH on all three constants while saying nothing about the trust anchors themselves.
#
# BOTH halves of `cliver` matter. A CLI built from a source checkout, a fork or a dirty tree
# reports the pinned version from `stellar --version` yet stamps a different revision, so the
# version alone does not identify the compiler of record.
#
# The expected revision is READ FROM A RECORDED CONSTANT, never resolved from the tag. A tag is
# mutable: resolving `v$EXPECTED_CLI` at check time would mean that if the tag ever moved, this
# script would start rejecting the checksum-pinned historical release and accepting whatever the
# tag now names — with no change to this repository, and while claiming to have verified the
# supply chain. That is the same reasoning by which UPSTREAM_COMMIT above is a constant and a
# moved tag is treated as an event to investigate rather than a value to adopt.
#
# `git ls-remote` is still consulted, but as a second opinion about the tag rather than as the
# source of truth: a tag that no longer names the recorded revision is reported, not obeyed.
# Installing from crates.io is fine — the published crate carries `.cargo_vcs_info.json` with the
# release commit and yields an identical `cliver`.
#
# Checked before the clone, so a wrong CLI costs a second instead of three cold builds.
EXPECTED_CLI="$(bash scripts/recorded-build-inputs.sh stellar-cli)"
EXPECTED_CLI_REV="$(bash scripts/recorded-build-inputs.sh stellar-cli-revision)"
HAVE_CLI="$(stellar --version 2>/dev/null | awk 'NR==1 {print $2}')"
HAVE_CLI_REV="$(stellar --version 2>/dev/null | awk 'NR==1 {gsub(/[()]/, "", $3); print $3}')"
if [ "$HAVE_CLI" != "$EXPECTED_CLI" ]; then
    echo "stellar-cli $HAVE_CLI, but the pinned hashes were built with $EXPECTED_CLI"
    echo "  install the pinned release:"
    echo "    $CLI_RELEASES/tag/v$EXPECTED_CLI"
    echo "  or, if the bump is intended, re-derive the constants and update the provenance table"
    echo "  in crates/domain/src/lib.rs — a CLI bump changes every hash this script checks."
    exit 1
fi

# The tag as a second opinion, not as the answer. An annotated tag lists both the tag object and
# the commit it peels to; prefer the commit. Unreachable is not an error here — the assertion
# below rests on the recorded constant, which needs no network.
CLI_LS="$(git ls-remote --tags "$CLI_REPO" "v$EXPECTED_CLI" 2>/dev/null || true)"
TAG_CLI_REV="$(printf '%s\n' "$CLI_LS" | awk '/\^\{\}$/ {print $1; exit}')"
if [ -z "$TAG_CLI_REV" ]; then
    TAG_CLI_REV="$(printf '%s\n' "$CLI_LS" | awk 'NF {print $1; exit}')"
fi
if [ -n "$TAG_CLI_REV" ] && [ "$TAG_CLI_REV" != "$EXPECTED_CLI_REV" ]; then
    echo "v$EXPECTED_CLI now names $TAG_CLI_REV, but the recorded release revision is"
    echo "$EXPECTED_CLI_REV."
    echo "  a moved tag is a supply-chain event, not a build failure — investigate before"
    echo "  trusting either value, and do not simply adopt the new one."
    exit 1
fi

if [ "$HAVE_CLI_REV" != "$EXPECTED_CLI_REV" ]; then
    echo "stellar-cli $HAVE_CLI, but built from ${HAVE_CLI_REV:-an unknown revision}, not the"
    echo "v$EXPECTED_CLI release ($EXPECTED_CLI_REV)."
    echo "  cliver records <version>#<revision> and both halves are inside the hashed bytes, so"
    echo "  this build produces different wasm from the release the recorded hashes came from."
    echo "  Install the published release, or bump the pin deliberately and re-derive the hashes."
    exit 1
else
    CLI_DIAGNOSIS="* a different stellar-cli build — ruled out: cliver $HAVE_CLI#$HAVE_CLI_REV
    matches the recorded v$EXPECTED_CLI release exactly"
    echo "== stellar-cli $HAVE_CLI#$HAVE_CLI_REV (the recorded v$EXPECTED_CLI release), rustc $TOOLCHAIN =="
    if [ -z "$TAG_CLI_REV" ]; then
        echo "   (the tag was not reachable; the assertion used the recorded revision, which is"
        echo "    the authority in either case)"
    fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "== cloning $UPSTREAM_REPO at $UPSTREAM_TAG =="
if ! git -c advice.detachedHead=false clone -q --depth 1 --branch "$UPSTREAM_TAG" \
    "$UPSTREAM_REPO" "$WORK/src" 2>/dev/null; then
    echo "  clone failed — no network, or the tag no longer exists upstream"
    exit 1
fi

ACTUAL_COMMIT="$(git -C "$WORK/src" rev-parse HEAD)"
if [ "$ACTUAL_COMMIT" != "$UPSTREAM_COMMIT" ]; then
    echo "  tag $UPSTREAM_TAG now points at $ACTUAL_COMMIT, expected $UPSTREAM_COMMIT"
    echo "  a moved tag is a supply-chain event, not a build failure — investigate before trusting"
    exit 1
fi
echo "  commit $ACTUAL_COMMIT ✔"

echo "== building with rustc $TOOLCHAIN (upstream's own pin floats on 'stable') =="
declare -a NAMES=(
    "spending-limit-policy:multisig_spending_limit_policy_example:OZ_SPENDING_LIMIT_POLICY_WASM"
    "account:multisig_account_example:OZ_SMART_ACCOUNT_WASM"
    "ed25519-verifier:multisig_ed25519_verifier_example:OZ_ED25519_VERIFIER_WASM"
)

fail=0
for entry in "${NAMES[@]}"; do
    dir="${entry%%:*}"; rest="${entry#*:}"; artifact="${rest%%:*}"; const="${rest##*:}"
    ( cd "$WORK/src/examples/multisig-smart-account/$dir" \
        && RUSTUP_TOOLCHAIN="$TOOLCHAIN" stellar contract build >/dev/null 2>&1 )
    built="$(shasum -a 256 "$WORK/src/target/wasm32v1-none/release/$artifact.wasm" | cut -d' ' -f1)"

    # The shipped constant, read back out of the source as bytes.
    pinned="$(python3 - "$const" <<'PY'
import re, sys
src = open("crates/domain/src/lib.rs").read()
m = re.search(sys.argv[1] + r": Hash32 = Hash32\(\[(.*?)\]\)", src, re.S)
if not m:
    print("NOT-FOUND"); raise SystemExit
print("".join(f"{int(b, 16):02x}" for b in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))))
PY
)"
    if [ "$built" = "$pinned" ]; then
        printf "  %-28s %s ✔\n" "$dir" "$built"
    else
        printf "  %-28s MISMATCH\n     built:  %s\n     pinned: %s\n" "$dir" "$built" "$pinned"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo
    echo "A mismatch is not automatically a problem — check the cause before changing anything:"
    echo "  * different rustc than $TOOLCHAIN (the usual cause; the hash is compiler-dependent)"
    echo "  $CLI_DIAGNOSIS"
    echo "  * upstream source changed under the tag (see the commit check above)"
    exit 1
fi
echo "pinned upstream hashes reproduce from $UPSTREAM_TAG with rustc $TOOLCHAIN"
