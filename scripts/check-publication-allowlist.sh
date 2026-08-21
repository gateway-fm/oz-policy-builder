#!/usr/bin/env bash
# Architecture §6.5: the public repository is produced from an explicit allowlist, and this is
# the NEGATIVE test — confidential/program-internal material must never appear in the public
# tree. A backstop, not the primary control; the primary control is that this repository lives
# in its own directory, separate from the confidential source.
#
# Two checks, and which of them can run depends on where the script is:
#
#   * where the private root is present — a working machine — the tracked tree is compared
#     against what is *actually* in that root, by filename and by content hash. No list of
#     forbidden names is kept anywhere, so a private document written tomorrow is covered the
#     moment it exists, and a copy committed under a different name is caught by its bytes.
#   * everywhere, including CI, where `..` holds nothing: content patterns for the shapes
#     confidential deal material takes. Shapes, never values. An earlier version of this file
#     listed the award figure itself as the string to search for, in a tracked file, and passed
#     its own scan because the script excludes itself from it — green while carrying the one
#     number it exists to keep out.
#
# The consequence is deliberate: the strong check belongs on the machine where the accident
# happens, which is also the only place it is possible. `.githooks/pre-push` runs it there.
#
# What this gate does NOT catch, stated so that its passing is not read as more than it is: it
# matches bytes and shapes, never meaning. Prose describing private material without quoting it
# — a changelog referring to revisions of an unpublished document, or a sentence revealing that
# an internal discussion is planned — passes cleanly. Review is the control for that.
#
# Scope is the **tracked** tree. What is not committed is not published, and scanning build
# output instead costs minutes and produces findings about files no reader will ever see.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
SELF="scripts/check-publication-allowlist.sh"

# `architecture.md` exists in both roots on purpose: the public copy under docs/ is a
# deliverable and the private root holds its working copy. Comparison must not flag it.
SHARED_NAMES="architecture.md"

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

# ── The comparison, where there is something to compare against ──────────────────────────
#
# One `python3` rather than a `shasum`/`sha256sum` per file: the two spellings are not both
# present on macOS and on the CI image, and this reads whole documents rather than short
# strings. `python3` is already a dependency of the quoted-hash gate.
COMPARISON="$(SHARED_NAMES="$SHARED_NAMES" python3 - "$TRACKED_LIST" <<'PYEOF'
import hashlib, os, pathlib, sys

shared = set(os.environ["SHARED_NAMES"].split())
private_root = pathlib.Path("..")

# Top-level regular files only. The private root also holds sibling checkouts of this
# repository, and walking those means walking their build output.
private_by_name, private_by_digest = {}, {}
for entry in sorted(private_root.iterdir()) if private_root.is_dir() else []:
    if not entry.is_file() or entry.name.startswith(".") or entry.name in shared:
        continue
    private_by_name[entry.name] = entry.name
    try:
        private_by_digest[hashlib.sha256(entry.read_bytes()).hexdigest()] = entry.name
    except OSError:
        pass

if not private_by_name:
    print("NO_PRIVATE_ROOT")
    raise SystemExit(0)

with open(sys.argv[1], "rb") as handle:
    tracked = [p.decode("utf-8", "surrogateescape") for p in handle.read().split(b"\0") if p]

for path in tracked:
    name = os.path.basename(path)
    if name in private_by_name:
        print(f"FILE\t{path}\t{name}")
        continue
    try:
        digest = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError:
        continue
    if digest in private_by_digest:
        print(f"COPY\t{path}\t{private_by_digest[digest]}")

# A private document need not be copied in to be disclosed: citing it by name tells a reader
# it exists and invites them to ask for it. Free to check here, where the names are known.
for path in tracked:
    if path == "scripts/check-publication-allowlist.sh":
        continue
    try:
        text = pathlib.Path(path).read_text(errors="ignore")
    except OSError:
        continue
    for name in private_by_name:
        if name in text:
            print(f"MENTION\t{path}\t{name}")
PYEOF
)"

if [ "$COMPARISON" = "NO_PRIVATE_ROOT" ]; then
    echo "  (no private root beside this checkout: the byte-for-byte comparison cannot run here)"
elif [ -n "$COMPARISON" ]; then
    printf '%s\n' "$COMPARISON" | while IFS="$(printf '\t')" read -r kind path name; do
        case "$kind" in
            FILE)    echo "FORBIDDEN FILE committed to the public tree: $path" ;;
            COPY)    echo "FORBIDDEN FILE committed under another name: $path is byte-identical to ../$name" ;;
            MENTION) echo "PRIVATE DOCUMENT named in the public tree: $path cites $name" ;;
        esac
    done
    fail=1
fi

# ── The shapes, everywhere ───────────────────────────────────────────────────────────────
#
# Budget figures, tranche amounts and the like belong only in the private root. A pattern that
# matches any money-shaped figure catches the leak and states nothing, which is the difference
# between this list and the one it replaced.
FORBIDDEN_FINGERPRINT_PATTERNS=(
    '\$[0-9]{1,3},[0-9]{3}'          # an award/tranche figure in USD
    '[0-9]{1,3},[0-9]{3} in XLM'     # the same figure denominated in XLM
)
# Over the tracked tree for the same reason as above, and because the recursive form walked
# `target/` and any registered worktrees — tens of gigabytes of build output — once per
# pattern, which is what made this gate take minutes instead of seconds.
for fp in "${FORBIDDEN_FINGERPRINT_PATTERNS[@]}"; do
    if xargs -0 grep -lIE -- "$fp" < "$TRACKED_LIST" 2>/dev/null | grep -qv "^${SELF}$"; then
        echo "FORBIDDEN CONTENT fingerprint present, matching /$fp/"
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "publication allowlist VIOLATED — confidential material must stay in the private root"
    exit 1
fi
echo "publication allowlist OK (no confidential material in the public tree)"
