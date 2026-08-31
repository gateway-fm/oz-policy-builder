#!/usr/bin/env bash
# Unused-dependency gate (architecture §4.11 engineering gate).
#
# scripts/check-dep-rules.sh asserts the ABSENCE of forbidden edges; nothing asserted that a
# declared edge is actually used, so a stale declaration survived every gate and had to be
# found by hand. This closes that hole.
#
# Coverage: cargo-machete walks directories rather than workspaces, so one run from the repo
# root analyses EVERY manifest in the tree — the toolkit workspace, the `contracts/` workspace,
# and the generated policy crates that both workspaces exclude. Those are included on
# purpose: a shipped policy
# crate should not carry a dependency it never uses, and the fix for one there is in codegen.
#
# --with-metadata resolves each manifest through `cargo metadata`, which is what makes
# [dev-dependencies] and [build-dependencies] visible; without it only [dependencies] is
# checked and a stale dev-dependency slips through. The cost is that a manifest cargo cannot
# resolve is SKIPPED with a message on stderr and no effect on the exit code — a silent hole,
# so it is treated as a failure below.
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned: which declarations a version considers "used" is the gate's meaning, so a different
# version can legitimately produce a different verdict. CI installs exactly this one.
EXPECTED_MACHETE_VERSION="0.9.2"
if ! command -v cargo-machete >/dev/null 2>&1; then
    echo "cargo-machete not installed:"
    echo "  cargo install cargo-machete --locked --version ${EXPECTED_MACHETE_VERSION}"
    exit 1
fi
HAVE=$(cargo machete --version 2>/dev/null | awk '{print $NF}')
if [ "$HAVE" != "$EXPECTED_MACHETE_VERSION" ]; then
    echo "  note: cargo-machete ${HAVE} (CI pins ${EXPECTED_MACHETE_VERSION}); verdicts may differ"
fi

# The walk honours .gitignore, so a manifest that is tracked yet ignored would be analysed by
# nobody while this gate still reported success. Assert the walk can see all of them.
hidden=$(git ls-files '*Cargo.toml' | git check-ignore --stdin --no-index || true)
if [ -n "$hidden" ]; then
    echo "manifests tracked by git but hidden from the walk by an ignore rule:"
    printf '%s\n' "$hidden" | while read -r m; do echo "  $m"; done
    echo "unused-dependency gate would not cover them — fix the ignore rule"
    exit 1
fi

echo "== unused dependencies: every manifest in the tree (both workspaces + excluded crates) =="
status=0
out=$(cargo machete --with-metadata --skip-target-dir 2>&1) || status=$?
echo "$out"

# A manifest cargo could not resolve was skipped, and machete does not fail for it.
if printf '%s\n' "$out" | grep -q '^error when handling '; then
    echo "at least one manifest was SKIPPED, so this gate proved less than it claims."
    echo "if this checkout is a git worktree nested inside the parent repository, cargo"
    echo "resolves the parent's workspace root instead — run the gate from a plain checkout."
    exit 1
fi

fail=0

# A [package.metadata.cargo-machete] suppression whose crate turns out to be used is stale
# config. Machete prints it without failing, and only for a crate that also has a real
# finding — so this catches it whenever it is reported at all, not in every case it exists.
if printf '%s\n' "$out" | grep -q 'marked as ignored, but is actually used'; then
    echo "a cargo-machete suppression is stale — drop it from the manifest"
    fail=1
fi

if [ "$status" -ne 0 ]; then
    echo "unused dependencies found — remove them, or justify one with"
    echo "  [package.metadata.cargo-machete]"
    echo "  ignored = [\"<crate>\"]  # why the analysis cannot see the use"
    fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "unused-dependency gate OK"
