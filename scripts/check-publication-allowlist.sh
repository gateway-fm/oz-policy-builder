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

# What is about to be published, read as a **tree** rather than as the working copy. Reading the
# filesystem was a hole: a secret could sit in the commit while the path was deleted or edited
# locally, and this gate would hash the clean file and pass. `.githooks/pre-push` passes the
# commit it is about to push; CI and `verify-phase1.sh` default to what is committed here.
#
# `--require-private-root` says the caller knows the byte-for-byte half must run here, so a
# missing or empty private root is a failure rather than a skip. `.githooks/pre-push` passes it,
# because a developer machine is where a private document can be committed by accident and is
# also the only place the comparison is possible. CI does not: a runner checks out one
# repository, its parent is a workspace directory holding nothing, and demanding the comparison
# there would fail every clean build — which it did, before this flag existed.
# Several refs, because one is not enough. A push introducing a commit that adds a private file
# and a later one that deletes it leaves a clean tip tree while publishing the blob in history,
# so `.githooks/pre-push` passes every commit it is about to introduce and each is scanned.
REFS=()
REQUIRE_PRIVATE_ROOT=0
for arg in "$@"; do
    case "$arg" in
        --require-private-root) REQUIRE_PRIVATE_ROOT=1 ;;
        -*) echo "publication allowlist: unknown option $arg" >&2; exit 2 ;;
        *)  REFS+=("$arg") ;;
    esac
done
[ "${#REFS[@]}" -eq 0 ] && REFS=(HEAD)
for ref in "${REFS[@]}"; do
    if ! git rev-parse --verify --quiet "$ref^{tree}" >/dev/null; then
        echo "publication allowlist: '$ref' does not name a tree" >&2
        exit 1
    fi
done

# The private root is the directory the repository itself sits in — and "the repository" means
# its main checkout, not wherever this copy happens to be. Both repositories carry registered
# worktrees under `.claude/worktrees/`, so `..` there is a directory of sibling worktrees and
# the comparison below would find no private documents and quietly downgrade itself to the
# pattern-only half. `--git-common-dir` points at the one `.git` all worktrees share, so its
# parent is the main checkout and its grandparent is the root we mean, from anywhere.
# `OZPB_PRIVATE_ROOT` states the root outright. Set, it is authoritative and holding nothing is
# a fault; unset, the path below is a guess about the layout, and a guess that lands on a
# directory with no private documents means "not that layout here", not "misconfigured".
if [ -n "${OZPB_PRIVATE_ROOT:-}" ]; then
    PRIVATE_ROOT="$OZPB_PRIVATE_ROOT"
    REQUIRE_PRIVATE_ROOT=1
else
    PRIVATE_ROOT="$(dirname "$(dirname "$(cd "$(git rev-parse --git-common-dir)" && pwd)")")"
fi

# `architecture.md` exists in both roots on purpose: the public copy under docs/ is a
# deliverable and the private root holds its working copy. Comparison must not flag it.
SHARED_NAMES="architecture.md"

# Enumerated once, NUL-delimited, into a file rather than a variable. Two reasons, and both
# matter for a gate whose whole job is to notice one specific file:
#
#   * `git ls-tree` without `-z` is line-oriented and C-quotes any path containing a control
#     character or a non-ASCII byte, so a private document with a legal but awkward filename
#     would not match its own tracked path and could be committed past this check;
#   * command substitution strips NULs, so the delimiter cannot survive `$(...)` at all.
#
# Enumerating once also matters: this repository carries several registered worktrees, and
# re-running the command per pattern turned a fast check into a two-and-a-half-minute one.
#
# Each record is `<mode> SP blob SP <oid> TAB <path>`. The OID is what makes the copy check
# below cheap and honest at once: git's blob id is a hash of the content, so a private document
# committed here under any name carries the same id `git hash-object` gives for the original,
# and nothing has to be read out of the working tree to notice it.
TRACKED_LIST="$(mktemp)"
trap 'rm -f "$TRACKED_LIST"' EXIT
for ref in "${REFS[@]}"; do
    git ls-tree -r -z "$ref" >> "$TRACKED_LIST"
done

# ── The comparison, where there is something to compare against ──────────────────────────
#
# One `python3` rather than a `shasum`/`sha256sum` per file: the two spellings are not both
# present on macOS and on the CI image, and this reads whole documents rather than short
# strings. `python3` is already a dependency of the quoted-hash gate.
COMPARISON="$(SHARED_NAMES="$SHARED_NAMES" PRIVATE_ROOT="$PRIVATE_ROOT" SELF="$SELF" \
    REFS="$(printf '%s\n' "${REFS[@]}")" python3 - "$TRACKED_LIST" <<'PYEOF'
import os, pathlib, subprocess, sys

shared = set(os.environ["SHARED_NAMES"].split())
private_root = pathlib.Path(os.environ["PRIVATE_ROOT"])
refs = [r for r in os.environ["REFS"].splitlines() if r]
self_path = os.environ["SELF"]

# Absent and empty are different answers and get different verdicts. CI checks out one
# repository and has no private root at all, which is expected; a root that exists but yields
# nothing to compare means the path was miscomputed or the documents moved, and silently
# downgrading to the pattern-only half is how a gate reports success about nothing.
if not private_root.is_dir():
    print("NO_PRIVATE_ROOT")
    raise SystemExit(0)

# Top-level regular files only. The private root also holds sibling checkouts of this
# repository, and walking those means walking their build output. Hidden files are included:
# `is_file()` already excludes the `.git` and `.claude` directories, and a private `.env` is
# exactly the kind of thing this comparison exists to catch.
entries = [e for e in sorted(private_root.iterdir()) if e.is_file() and e.name not in shared]
if not entries:
    print("EMPTY_PRIVATE_ROOT")
    raise SystemExit(0)

private_by_name = {e.name: e.name for e in entries}
private_by_oid = {}
for entry in entries:
    # git's own hash of the bytes, so it compares directly against the blob ids in the tree.
    done = subprocess.run(
        ["git", "hash-object", "--no-filters", "--", str(entry)],
        capture_output=True, text=True,
    )
    if done.returncode != 0:
        # Skipping it would drop the document from the comparison silently, and a byte-identical
        # copy committed under another name would then pass the half that exists to catch it.
        # A private document this script cannot read is a reason to stop, not to continue.
        print(f"UNREADABLE\t{entry.name}\t{done.stderr.strip() or 'git hash-object failed'}")
        raise SystemExit(0)
    private_by_oid[done.stdout.strip()] = entry.name

# `<mode> SP blob SP <oid> TAB <path>`, NUL-terminated.
tracked = []
with open(sys.argv[1], "rb") as handle:
    for record in handle.read().split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        fields = meta.split(b" ")
        if len(fields) < 3:
            continue
        tracked.append((raw_path.decode("utf-8", "surrogateescape"), fields[2].decode()))

seen = set()
for path, oid in tracked:
    if (path, oid) in seen:
        continue
    seen.add((path, oid))
    name = os.path.basename(path)
    if name in private_by_name:
        print(f"FILE\t{path}\t{name}")
        continue
    if oid in private_by_oid:
        print(f"COPY\t{path}\t{private_by_oid[oid]}")

# A private document need not be copied in to be disclosed: citing it by name tells a reader it
# exists and invites them to ask for it. Free to check here, where the names are known, and
# searched with `git grep` over the tree for the same reason the hashes above are blob ids.
#
# Hidden files are deliberately out of this half. Their names are generic - `.env`,
# `.DS_Store`, `.gitignore` - and appear in ignore files and setup docs for reasons that
# disclose nothing, so a name match there is noise rather than signal. Their *bytes* stay
# covered: a hidden private file committed here, under its own name or another, is caught above.
reported = set()
for name in (n for n in private_by_name if not n.startswith(".")):
    for ref in refs:
        done = subprocess.run(
            ["git", "grep", "-l", "-I", "-F", "-e", name, ref, "--", "."],
            capture_output=True, text=True,
        )
        for line in done.stdout.splitlines():
            # `git grep <ref>` prefixes each hit with `<ref>:`. Stripped as a literal prefix,
            # not by splitting on the first colon, which a ref containing one would break.
            path = line[len(ref) + 1:] if line.startswith(ref + ":") else line
            if path == self_path or (path, name) in reported:
                continue
            reported.add((path, name))
            print(f"MENTION\t{path}\t{name}")
PYEOF
)"

if [ "$COMPARISON" = "NO_PRIVATE_ROOT" ] || [ "$COMPARISON" = "EMPTY_PRIVATE_ROOT" ]; then
    # Nothing to compare against. Whether that is a fact about the environment or a fault
    # depends on who is asking: a runner has no private root and never did, while a pre-push
    # hook asked for the comparison precisely because it can be made here.
    if [ "$REQUIRE_PRIVATE_ROOT" -eq 1 ]; then
        echo "publication allowlist: no private documents to compare at $PRIVATE_ROOT" >&2
        echo "  the byte-for-byte half cannot run, so this gate would only be the pattern scan," >&2
        echo "  and it was asked to run. Point OZPB_PRIVATE_ROOT at the private root, or run" >&2
        echo "  from a checkout whose parent is it." >&2
        exit 1
    fi
    echo "  (no private documents at $PRIVATE_ROOT: the byte-for-byte half cannot run here)"
elif [ "${COMPARISON%%$(printf '\t')*}" = "UNREADABLE" ]; then
    echo "publication allowlist: a private document could not be read, so the comparison" >&2
    printf '%s\n' "$COMPARISON" | while IFS="$(printf '\t')" read -r _kind name reason; do
        echo "  would have been incomplete: $PRIVATE_ROOT/$name — $reason" >&2
    done
    exit 1
elif [ -n "$COMPARISON" ]; then
    printf '%s\n' "$COMPARISON" | while IFS="$(printf '\t')" read -r kind path name; do
        case "$kind" in
            FILE)    echo "FORBIDDEN FILE committed to the public tree: $path" ;;
            COPY)    echo "FORBIDDEN FILE committed under another name: $path is byte-identical to $PRIVATE_ROOT/$name" ;;
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
# Over the tree being published, for the same reason the hashes above are blob ids: a figure can
# sit in the commit while the working copy is clean. `git grep <ref>` also fixes what made this
# gate slow — the recursive filesystem form walked `target/` and every registered worktree, tens
# of gigabytes of build output, once per pattern.
for fp in "${FORBIDDEN_FINGERPRINT_PATTERNS[@]}"; do
    # `git grep <ref>` prefixes each hit with `<ref>:`. Stripped by literal parameter expansion,
    # not by `sed "s/^${REF}://"`: a ref like `feature/x` made `/` the substitution delimiter,
    # sed failed, `|| true` swallowed it, `hits` came back empty and the scan was skipped while
    # the gate printed OK. A gate that reports success having checked nothing is the one outcome
    # worth more care than the check itself.
    hits=""
    for ref in "${REFS[@]}"; do
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            path="${line#"$ref":}"
            [ "$path" = "$SELF" ] && continue
            case "$hits" in *"$path"$'\n'*) continue ;; esac
            hits="$hits$path"$'\n'
        done < <(git grep -l -I -E -e "$fp" "$ref" -- . 2>/dev/null || true)
    done
    if [ -n "$hits" ]; then
        echo "FORBIDDEN CONTENT fingerprint present, matching /$fp/"
        printf '%s\n' "$hits" | sed 's/^/  /'
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "publication allowlist VIOLATED — confidential material must stay in the private root"
    exit 1
fi
echo "publication allowlist OK (no confidential material in the public tree)"
