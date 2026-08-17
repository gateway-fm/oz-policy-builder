#!/usr/bin/env bash
# Architecture §6.5: the public repository is produced from an explicit allowlist, and CI
# runs the NEGATIVE test — confidential/program-internal material must never appear in the
# public tree. This is a backstop, not the primary control (the primary control is that
# the repo lives in its own directory, separate from the confidential source).
#
# Fails if any forbidden filename or content fingerprint is present in the tree.
#
# What this gate does NOT catch, stated so that its passing is not read as more than it is: it
# matches names and fixed strings, never meaning. Prose describing private material without
# naming it — a changelog referring to revisions of an unpublished document, or a sentence
# revealing that an internal discussion is planned — passes cleanly. Review is the control for
# that; this script only makes the mechanical cases impossible to miss.
#
# Scope is the **tracked** tree. What is not committed is not published, and scanning build
# output instead costs minutes and produces findings about files no reader will ever see.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
SELF="scripts/check-publication-allowlist.sh"

# Enumerated once, NUL-delimited, into a file rather than a variable. Two reasons, and both
# matter for a gate whose whole job is to notice one specific file:
#
#   * `git ls-files` without `-z` is line-oriented and C-quotes any path containing a control
#     character or a non-ASCII byte, so a private document with a legal but awkward filename
#     would not match its own tracked path and could be committed past this check;
#   * command substitution strips NULs, so the delimiter cannot survive `$(...)` at all.
#
# Enumerating once also matters: this repository carries several registered worktrees, and
# re-running the command per pattern turned a fast check into a two-and-a-half-minute one.
TRACKED_LIST="$(mktemp)"
trap 'rm -f "$TRACKED_LIST"' EXIT
git ls-files -z > "$TRACKED_LIST"

# Forbidden filenames (proposal / reviews / deal material must never be committed here).
# Kept explicit rather than derived alone, because CI checks out the repository without its
# private parent and a purely derived list would verify nothing there.
# Values removed before this repository was first published: the filenames and the exact
# deal-material strings this gate searched for were themselves confidential, and a
# published gate that names what it looks for discloses the set it protects. They live in
# the private root. The tip of this history replaces the mechanism entirely — see
# "gates: stop the publication gate carrying the material it guards".
FORBIDDEN_NAMES=()

# `architecture.md` exists in both roots on purpose: the public copy under docs/ is a
# deliverable and the private root holds its working copy. Deriving must not flag it.
SHARED_NAMES=("architecture.md")

# A static list goes stale the moment a new private document is written, and the gap is silent —
# which is how five of the names above came to be missing. Where the private root is present,
# that is locally, where authoring happens, derive the rest from it so a document created
# tomorrow is covered without anyone remembering to edit this file. In CI the parent holds no
# such files and this adds nothing.
for path in ../*.md ../*.txt; do
    [ -e "$path" ] || continue
    base="$(basename "$path")"
    case " ${SHARED_NAMES[*]} " in *" $base "*) continue ;; esac
    case " ${FORBIDDEN_NAMES[*]} " in *" $base "*) continue ;; esac
    FORBIDDEN_NAMES+=("$base")
done

for name in "${FORBIDDEN_NAMES[@]}"; do
    if grep -zqF -- "$name" "$TRACKED_LIST"; then
        echo "FORBIDDEN FILE committed to the public tree: $name"
        fail=1
    fi
done

# A private document need not be copied in to be disclosed: citing it by name tells a reader it
# exists and invites them to ask for it. Catch the mention as well as the file. One pass over
# the tracked tree, with this script excluded because it necessarily lists the names.
MENTIONS="$(xargs -0 grep -lIF \
    $(printf -- '-e %s ' "${FORBIDDEN_NAMES[@]}") -- < "$TRACKED_LIST" 2>/dev/null \
    | grep -v "^${SELF}$" || true)"
if [ -n "$MENTIONS" ]; then
    echo "FORBIDDEN FILE referenced by name in:"
    printf '  %s\n' $MENTIONS
    fail=1
fi

# Content fingerprints that would indicate confidential deal material leaked in.
# (Budget figures, tranche amounts, and the like belong only in the private root.)
FORBIDDEN_FINGERPRINTS=()
# Over the tracked tree for the same reason as above, and because the recursive form walked
# `target/` and any registered worktrees — tens of gigabytes of build output — once per
# fingerprint, which is what made this gate take minutes instead of seconds.
for fp in "${FORBIDDEN_FINGERPRINTS[@]}"; do
    if xargs -0 grep -lIF -- "$fp" < "$TRACKED_LIST" 2>/dev/null | grep -qv "^${SELF}$"; then
        echo "FORBIDDEN CONTENT fingerprint present: '$fp'"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "publication allowlist VIOLATED — confidential material must stay in the private root"
    exit 1
fi
echo "publication allowlist OK (no confidential material in the public tree)"
