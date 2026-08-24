#!/usr/bin/env bash
# The negative case for `check-publication-allowlist.sh`, and the one that runs anywhere.
#
# `docs/architecture.md` §6.5 states that CI verifies the negative case — "a planted sentinel
# file/fingerprint must fail publication". That promise had no implementation. In CI the private
# root does not exist, so the byte-for-byte half cannot run at all, and the only thing left was
# two money-shaped regexes over the tree: a gate reporting OK about a comparison it never made.
#
# This is that missing test. It plants sentinels into a scratch tree and asserts the gate refuses
# them, which needs no private root and so means the same thing on a developer machine and on a
# CI runner. It tests the real script against real git objects, not a mock of it.
set -uo pipefail
cd "$(dirname "$0")/.."

GATE="$PWD/scripts/check-publication-allowlist.sh"
fail=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A scratch repository with its own private root beside it, laid out the way the gate expects:
# the root is the parent of the checkout, and the gate finds it from `--git-common-dir`.
ROOT="$WORK/root"
REPO="$ROOT/repo"
mkdir -p "$REPO"
git -C "$REPO" init -q -b main
git -C "$REPO" config user.email test@example.invalid
git -C "$REPO" config user.name "Gate Test"
mkdir -p "$REPO/scripts"
cp "$GATE" "$REPO/scripts/check-publication-allowlist.sh"

# The private document the public tree must never carry, and a hidden one, since hidden files
# were once skipped when reading the root.
printf 'internal planning, do not publish\n' > "$ROOT/SENTINEL-PRIVATE.md"
printf 'SENTINEL_TOKEN=do-not-publish\n' > "$ROOT/.sentinel-env"

commit_and_run() {
    git -C "$REPO" add -A
    git -C "$REPO" commit -q -m "case" --no-verify
    ( cd "$REPO" && bash scripts/check-publication-allowlist.sh HEAD 2>&1 )
}

expect_refused() {
    local label="$1" needle="$2" output
    output="$(commit_and_run)"
    local status=$?
    if [ "$status" -eq 0 ]; then
        echo "FAIL: $label — the gate passed a tree it must refuse"
        printf '%s\n' "$output" | sed 's/^/    /'
        fail=1
    elif ! grep -qF -- "$needle" <<<"$output"; then
        echo "FAIL: $label — refused, but not for the stated reason (wanted /$needle/)"
        printf '%s\n' "$output" | sed 's/^/    /'
        fail=1
    else
        echo "ok: $label"
    fi
}

expect_clean() {
    local label="$1" output
    output="$(commit_and_run)"
    local status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAIL: $label — the gate refused a tree that carries nothing private"
        printf '%s\n' "$output" | sed 's/^/    /'
        fail=1
    else
        echo "ok: $label"
    fi
}

# The control comes first: without it, every case below could be passing because the gate
# refuses everything.
printf '# public readme\n' > "$REPO/README.md"
expect_clean "a tree with nothing planted is accepted"

# 1. The private document, under its own name.
cp "$ROOT/SENTINEL-PRIVATE.md" "$REPO/SENTINEL-PRIVATE.md"
expect_refused "a private document committed under its own name" "FORBIDDEN FILE committed to the public tree"
rm "$REPO/SENTINEL-PRIVATE.md"

# 2. The same bytes under an innocuous name — the case a filename list cannot catch.
cp "$ROOT/SENTINEL-PRIVATE.md" "$REPO/docs-release-notes.md"
expect_refused "the same bytes under another name" "byte-identical"
rm "$REPO/docs-release-notes.md"

# 3. Its name merely cited, without the bytes.
printf 'see SENTINEL-PRIVATE.md for the plan\n' > "$REPO/notes.md"
expect_refused "a private document cited by name" "PRIVATE DOCUMENT named in the public tree"
rm "$REPO/notes.md"

# 4. A hidden private file's bytes, under a visible name. Hidden files were once skipped when
#    reading the private root, which made this exact tree pass.
cp "$ROOT/.sentinel-env" "$REPO/config-sample.txt"
expect_refused "a hidden private file's bytes under a visible name" "byte-identical"
rm "$REPO/config-sample.txt"

# 5. The fingerprint, with no file involved at all — the half that runs where there is no
#    private root, so this is the case CI would otherwise be relying on alone.
# The figure is assembled at run time from parts that are not money-shaped on their own, so
# this file carries no such literal itself. Writing one here would put exactly the shape the
# gate exists to keep out into a tracked file — the mistake the gate's own header records.
printf 'the award was $%s,%s in total\n' 12 345 > "$REPO/pitch.md"
expect_refused "a money-shaped figure in the tree" "FORBIDDEN CONTENT fingerprint"
rm "$REPO/pitch.md"

# 6. A secret that is in the commit but not in the working copy. This is the shape the gate was
#    blind to while it hashed the filesystem: the read failed, the loop continued, OK was
#    printed. Built by writing the tree directly, so the path never exists on disk.
blob="$(git -C "$REPO" hash-object -w --no-filters -- "$ROOT/SENTINEL-PRIVATE.md")"
idx="$WORK/scratch.index"
GIT_INDEX_FILE="$idx" git -C "$REPO" read-tree HEAD
GIT_INDEX_FILE="$idx" git -C "$REPO" update-index --add --cacheinfo "100644,$blob,docs/notes.md"
tree="$(GIT_INDEX_FILE="$idx" git -C "$REPO" write-tree)"
commit="$(echo planted | git -C "$REPO" commit-tree "$tree" -p HEAD)"
if [ -e "$REPO/docs/notes.md" ]; then
    echo "FAIL: the planted path exists on disk, so this case would not prove anything"
    fail=1
elif output="$( cd "$REPO" && bash scripts/check-publication-allowlist.sh "$commit" 2>&1 )"; then
    echo "FAIL: a secret present in the commit and absent from the working copy was passed"
    printf '%s\n' "$output" | sed 's/^/    /'
    fail=1
else
    echo "ok: a secret in the commit but not in the working copy"
fi

# 7. A secret added in one commit and deleted in the next. The tip tree is clean, so scanning
#    only the tip passes it — while pushing the branch publishes the blob in history.
git -C "$REPO" checkout -q -b add-then-delete
cp "$ROOT/SENTINEL-PRIVATE.md" "$REPO/transient.md"
git -C "$REPO" add -A && git -C "$REPO" commit -q -m "adds it" --no-verify
added="$(git -C "$REPO" rev-parse HEAD)"
rm "$REPO/transient.md"
git -C "$REPO" add -A && git -C "$REPO" commit -q -m "deletes it" --no-verify
tip="$(git -C "$REPO" rev-parse HEAD)"
if ! ( cd "$REPO" && bash scripts/check-publication-allowlist.sh "$tip" >/dev/null 2>&1 ); then
    echo "FAIL: the tip tree should be clean, so this case is not testing what it claims"
    fail=1
elif ( cd "$REPO" && bash scripts/check-publication-allowlist.sh "$added" "$tip" >/dev/null 2>&1 ); then
    echo "FAIL: a blob added and then deleted in the same range was passed"
    fail=1
else
    echo "ok: a secret added in one commit and deleted in the next"
fi
git -C "$REPO" checkout -q main

# 8. A ref whose name contains a slash. `sed "s/^${REF}://"` made `/` the delimiter, sed failed,
#    `|| true` swallowed it and the fingerprint scan was skipped while the gate printed OK.
git -C "$REPO" checkout -q -b feature/slashed
printf 'the total was $%s,%s\n' 12 345 > "$REPO/pitch.md"
git -C "$REPO" add -A && git -C "$REPO" commit -q -m "planted" --no-verify
if ( cd "$REPO" && bash scripts/check-publication-allowlist.sh feature/slashed >/dev/null 2>&1 ); then
    echo "FAIL: a slash in the ref name skipped the fingerprint scan"
    fail=1
else
    echo "ok: a ref name containing a slash still scans"
fi
git -C "$REPO" checkout -q main
git -C "$REPO" branch -qD feature/slashed

# 9. A private document the script cannot read must fail closed: omitting it would drop it from
#    the comparison, and a copy of it committed under another name would then pass.
chmod 000 "$ROOT/SENTINEL-PRIVATE.md"
if ( cd "$REPO" && bash scripts/check-publication-allowlist.sh HEAD >/dev/null 2>&1 ); then
    echo "FAIL: an unreadable private document was skipped rather than failing closed"
    fail=1
else
    echo "ok: an unreadable private document fails closed"
fi
chmod 644 "$ROOT/SENTINEL-PRIVATE.md"

# 10. A private root that exists but holds nothing to compare must not report success: that is
#    indistinguishable from the strong half having run and found nothing.
EMPTY_ROOT="$WORK/empty"
EMPTY_REPO="$EMPTY_ROOT/repo"
mkdir -p "$EMPTY_REPO/scripts"
git -C "$EMPTY_REPO" init -q -b main
git -C "$EMPTY_REPO" config user.email test@example.invalid
git -C "$EMPTY_REPO" config user.name "Gate Test"
cp "$GATE" "$EMPTY_REPO/scripts/check-publication-allowlist.sh"
printf '# nothing to see\n' > "$EMPTY_REPO/README.md"
git -C "$EMPTY_REPO" add -A
git -C "$EMPTY_REPO" commit -q -m "empty root" --no-verify
if output="$( cd "$EMPTY_REPO" && bash scripts/check-publication-allowlist.sh --require-private-root HEAD 2>&1 )"; then
    echo "FAIL: an empty private root reported success where the comparison was demanded"
    printf '%s\n' "$output" | sed 's/^/    /'
    fail=1
else
    echo "ok: an empty private root is refused rather than passed"
fi

# 11. The mirror of case 10, and the one that matters most for CI: without the flag, a checkout
#     whose parent holds no private documents must pass. A runner's checkout sits under a
#     workspace directory that exists and is empty of them, and making that a failure broke
#     every clean build until this case existed to say so.
if output="$( cd "$EMPTY_REPO" && bash scripts/check-publication-allowlist.sh HEAD 2>&1 )"; then
    echo "ok: a checkout with no private root beside it passes when the comparison is not demanded"
else
    echo "FAIL: a runner-shaped checkout was refused — this breaks CI on every clean build"
    printf '%s\n' "$output" | sed 's/^/    /'
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "publication allowlist self-test FAILED"
    exit 1
fi
echo "publication allowlist self-test passed (the planted sentinel fails publication)"
