#!/usr/bin/env python3
"""Fail when a tracked document quotes a hash the tree can no longer produce.

The attestation chain is only worth what a reader can re-run. A document that quotes a
hash nothing in the repository produces any more does not merely go out of date: the
reader follows it, cannot reproduce it, and concludes — correctly, on the evidence in
front of them — that the chain is broken. That happens most easily when the canonical
encoding changes, because every derived hash moves at once and prose does not.

So: every hash-shaped string quoted in a scanned document must still be present in some
code-backed artifact in the tree, or be listed in the exemption file with its class and
the reason it is not derivable here.

WHAT IS AUTHORITATIVE
---------------------
Only artifacts something else already keeps honest, because a gate whose reference is
itself unchecked proves that two files agree and nothing more:

  * docs/examples/*.json — the committed fixtures. `crates/toolkit/tests/
    examples_are_current.rs` asserts the trust pair still matches `registry::dev`, and
    the phase gates run the rest through the real CLI.
  * `pinned_upstream` in crates/domain/src/lib.rs — read from the `Hash32([...])` byte
    literals, NOT from any hex spelling of them. A gate that compared prose against
    prose could be satisfied by two documents copying the same stale value.
  * the `Normalized codegen input hash:` header of each committed generated policy crate,
    which that crate's golden test holds to codegen's output. Stated per crate rather than
    by naming the tests, because which crates a milestone commits is itself a milestone
    decision: any sentence that counted them, or that named a test only some trees have,
    is false wherever that set is different.
  * the SHA-256 of each Rust file of each generated crate, computed here. Those files are
    byte-for-byte what `ozpb generate` emits, so these are exactly the digests a reader
    gets by running it — and they move whenever the emission does, which is what makes them
    the values most likely to be left behind. Every `.rs` file, not the crate root alone:
    since the split into a root and a `contract.rs`, the root is a header and a `pub mod`
    declaration, and its digest no longer moves when the policy's behaviour does.
Deliberately NOT authoritative: a committed `build-manifest.json`. No gate regenerates or
validates one — re-derivation is operator-invoked where it exists at all — so a stale or
hand-edited manifest would make an equally stale document pass, which is the failure this
check exists to prevent rather than a source it can rely on. It would also admit
`wasm_hash`, contradicting the exclusion of wasm hashes stated below. None is committed
today; when one lands, make it authoritative only alongside a gate that regenerates it.

Authoritative means "some artifact in the tree carries this value right now". It does
NOT mean the artifact is itself current — the tests named above are the checks for that.
This gate answers one question: has a document been left behind by its own artifacts.

WHAT THIS DELIBERATELY DOES NOT COVER, so that a pass is not read as more than it is
------------------------------------------------------------------------------------
  * Attribution. A quoted hash that is present in the tree but labelled as something it
    is not passes cleanly. The gate checks presence, never what the sentence claims.
    Precision is the point: a check that fired on every 64-hex string would hit
    lockfile checksums, transaction hashes and commit SHAs, and would be routed around
    within a week.
  * Cargo.lock, wherever one lives — the workspace roots and each standalone generated
    crate. Those are crates.io registry checksums: a different kind of hash, thousands of
    them, and `--locked` builds are their check.
  * Rust sources and tests under crates/. Test vectors belong to their tests, and doc
    comments there quote counterfactual hashes on purpose — the `pinned_upstream`
    provenance table cites the value a *different* compiler produces, precisely to show
    that a pinned hash without a pinned compiler is not reproducible. Flagging that
    would be flagging the documentation of the hazard.
  * Captured network responses (crates/source-rpc/tests/captured-testnet/). They record
    what the RPC said, not what this repository computes.
  * JSON fixtures as subjects. They are the reference, not the thing being checked.
  * Wasm hashes. Reproducing one needs the pinned rustc AND the pinned stellar-cli, so
    only the nightly wasm workflow can adjudicate them; offline they can be recorded as
    exempt but never verified.
  * Hex runs shorter than 8 characters, and truncations not marked with an ellipsis.
    A bare 7-hex token is a git short SHA far more often than a hash.

Scanned: tracked *.md, scripts/*.sh, .github/workflows/*.yml — the files a reader reads
and follows. Scope is the tracked tree, as in scripts/check-publication-allowlist.sh:
what is not committed is not published.

Usage: python3 scripts/check-quoted-hashes.py
"""

import hashlib
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
EXEMPTIONS = "scripts/quoted-hash-exemptions.txt"

# A generated crate is recognised by its header marker, looked for near the top of the file rather
# than at byte zero. It was `startswith` until the generator began emitting an SPDX line above the
# doc comment: every generated crate stopped being recognised at once, and the gate exited saying
# it had found none — loudly, which is the only reason this was a five-minute problem. Anchoring on
# "the marker is in the header" instead survives another line landing above it, and the exit above
# still fires if a file has no marker at all, so the check cannot go quietly vacuous.
GENERATED_MARKER = "//! GENERATED POLICY"
GENERATED_MARKER_WINDOW = 512
PROVENANCE = "crates/domain/src/lib.rs"

# A full hash as the toolkit writes it (`hex::encode`, lowercase), bounded so a 128-hex
# signature is not read as its own first half. Case-insensitive: an uppercase 64-hex
# token is a hash in every case that matters, and the base32 strkeys in these files are
# 56 characters and contain letters outside the hex alphabet.
FULL = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
# A deliberately abbreviated hash: `e79269093c…`. The ellipsis is what makes this
# checkable — it is the author saying "this is the front of a longer value" — and what
# keeps it precise, since an unmarked 8-hex run is usually not a hash at all.
TRUNCATED = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{8,63})(?:…|\.\.\.)")

SCANNED = ("*.md", "scripts/*.sh", ".github/workflows/*.yml")


def tracked() -> list[str]:
    """Tracked paths, NUL-delimited: `git ls-files` without -z C-quotes any path holding
    a non-ASCII byte, and command substitution cannot carry a NUL, so the list is read
    from the process directly."""
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, check=True, capture_output=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def text(path: str) -> str:
    try:
        return (REPO / path).read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        # Tracked but not on disk. Fails closed either way, but a traceback reads as a broken
        # gate rather than as the broken checkout it actually is.
        sys.exit(f"{path}: tracked but unreadable ({error.strerror}); the tree is incomplete")


def scanned(paths: list[str]) -> list[str]:
    return [p for p in paths if any(pathlib.PurePath(p).match(g) for g in SCANNED)]


def pinned_upstream_hashes() -> set[str]:
    """The `Hash32([...])` byte literals inside `pub mod pinned_upstream`, as hex."""
    body = text(PROVENANCE).partition("pub mod pinned_upstream {")[2]
    if not body:
        sys.exit(
            f"{PROVENANCE}: no `pub mod pinned_upstream` — this gate reads the pinned wasm\n"
            "hashes from that module's byte literals. If it moved, point the gate at its new\n"
            "home; a harvest that silently finds nothing would bless every stale quote."
        )
    # Top-level module, so a brace in the first column closes it.
    body = re.split(r"(?m)^\}", body)[0]
    # Every declared constant must parse, not merely most of them. Skipping the ones that do
    # not read cleanly would quietly shrink the reference set, and the union with the fixtures
    # can hide the loss entirely — the same pinned hashes appear in the signed dev snapshot, so
    # dropping one here changed no totals at all when this was tried.
    #
    # Which is why the names are enumerated separately from the values. Deriving the roll from
    # the same pattern that reads the values makes the check circular: a constant whose
    # initializer stops matching disappears from both sides at once and nothing notices. The
    # names come from the declaration alone, and any name without a value is an error.
    declared = re.findall(r"pub const\s+(\w+)\s*:\s*Hash32\s*=", body)
    if not declared:
        sys.exit(
            f"{PROVENANCE}: `pinned_upstream` declares no `Hash32` constants. The gate cannot\n"
            "verify quotes of values it failed to read, so this is an error, not a pass."
        )
    parsed: dict[str, str] = {}
    for name, literal in re.findall(
        r"pub const\s+(\w+)\s*:\s*Hash32\s*=\s*Hash32\(\[(.*?)\]\)", body, re.S
    ):
        octets = re.findall(r"0x([0-9a-fA-F]{2})", literal)
        if len(octets) != 32:
            sys.exit(
                f"{PROVENANCE}: `pinned_upstream::{name}` did not read as 32 hex octets "
                f"({len(octets)} found).\nThe gate cannot verify quotes of a value it failed "
                "to read, so this is an error, not a pass."
            )
        parsed[name] = "".join(octets).lower()
    unread = [name for name in declared if name not in parsed]
    if unread:
        sys.exit(
            f"{PROVENANCE}: `pinned_upstream` declares {', '.join(unread)} but the gate could "
            "not read\nthe value from a `Hash32([0x.., ..])` literal. Either the initializer "
            "changed shape or the\nconstant moved; a reference the gate silently omits blesses "
            "every stale quote of it."
        )
    return set(parsed.values())


def generated_crate_hashes(paths: list[str]) -> set[str]:
    """Per generated policy crate: the codegen-input hash its crate root declares, and the
    SHA-256 of **every** Rust file of the crate — the digests a reader gets from
    `ozpb generate`."""
    # Selected by codegen's own banner rather than by path, so the hand-written test crate
    # alongside them is not mistaken for a generated one. The banner is in the crate root.
    roots = [
        p
        for p in paths
        if re.fullmatch(r"contracts/[^/]+/src/lib\.rs", p)
        and GENERATED_MARKER in text(p)[:GENERATED_MARKER_WINDOW]
    ]
    if not roots:
        sys.exit(
            "no generated policy crate found under contracts/*/src/lib.rs; they are a required\n"
            "reference for this gate and finding none would make it vacuous."
        )
    # Every `.rs` file of each recognised crate, not the root alone. Emission produces a crate
    # root and a contract module, and the root is now a header plus a `pub mod` declaration —
    # so a gate that digested it alone would hold documents to a figure that no longer moves
    # when the policy's behaviour does, which is the exact staleness this file exists to catch.
    sources = []
    for root in roots:
        crate = root[: -len("src/lib.rs")]
        sources.extend(
            p for p in paths if p.startswith(f"{crate}src/") and p.endswith(".rs")
        )
    found = set()
    for path in sources:
        raw = (REPO / path).read_bytes()
        found.add(hashlib.sha256(raw).hexdigest())
        # `\s*(?://!\s*)?` because the digest is on the line *after* its label. A 64-hex token
        # plus any label overshoots the comment width OpenZeppelin's `rustfmt.toml` enforces, so
        # the emitter wraps the header and the value lands on a continuation line with its own
        # `//!` marker. A pattern that required the two on one line found no header at all — which
        # this gate reports as a broken reference rather than passing, which is why the wrap was a
        # one-line fix here instead of a silently vacuous check.
        if path not in roots:
            continue
        declared = re.search(
            r"Normalized codegen input hash:\s*(?://!\s*)?([0-9a-fA-F]{64})",
            raw.decode("utf-8"),
        )
        if not declared:
            sys.exit(
                f"{path}: no `Normalized codegen input hash:` header. Every generated crate\n"
                "carries one and documents quote it, so a missing header is a broken reference."
            )
        found.add(declared.group(1).lower())
    return found


def authoritative(paths: list[str]) -> set[str]:
    found = pinned_upstream_hashes() | generated_crate_hashes(paths)
    fixtures = [
        p
        for p in paths
        if pathlib.PurePath(p).match("docs/examples/*.json")
    ]
    if not any(pathlib.PurePath(p).match("docs/examples/*.json") for p in fixtures):
        sys.exit("no docs/examples/*.json fixtures found; the gate's reference set is missing.")
    for path in fixtures:
        found |= {m.group(0).lower() for m in FULL.finditer(text(path))}
    return found


def exemptions() -> dict[str, tuple[int, str]]:
    """`<hex>|<class>|<why it is not derivable from this tree>`, one per line."""
    rows: dict[str, tuple[int, str]] = {}
    for number, line in enumerate(text(EXEMPTIONS).splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 3 or not all(f.strip() for f in fields):
            sys.exit(f"{EXEMPTIONS}:{number}: expected '<hex>|<class>|<reason>', got {line!r}")
        value, kind, _reason = (f.strip() for f in fields)
        if not re.fullmatch(r"[0-9a-fA-F]{8,64}", value):
            sys.exit(f"{EXEMPTIONS}:{number}: {value!r} is not an 8-64 character hex string")
        rows[value.lower()] = (number, kind)
    return rows


def main() -> int:
    paths = tracked()
    known = authoritative(paths)
    exempt = exemptions()
    allowed = known | set(exempt)

    unaccounted: list[tuple[str, int, str, str]] = []
    used: set[str] = set()

    for path in scanned(paths):
        for number, line in enumerate(text(path).splitlines(), start=1):
            for match in FULL.finditer(line):
                value = match.group(0).lower()
                if value in exempt:
                    used.add(value)
                elif value not in known:
                    unaccounted.append((path, number, value, "quoted hash"))
            for match in TRUNCATED.finditer(line):
                prefix = match.group(1).lower()
                hit = sorted(v for v in allowed if v.startswith(prefix))
                if not hit:
                    unaccounted.append((path, number, prefix + "…", "truncated hash"))
                used |= {v for v in hit if v in exempt}

    fail = 0

    # An exemption declares a value this tree cannot derive. When the tree *can* derive one, the
    # exemption is not an exception but a blindfold: the exempt branch above is taken first, so
    # the quote is marked used and never compared against the artifact at all — and on the day
    # that artifact moves, the stale document keeps the exemption alive and the gate passes
    # forever. Prefix rather than equality, because exemptions may be recorded truncated and a
    # short one shadows every derivable value it prefixes.
    shadowing = sorted(
        (value, sorted(k for k in known if k.startswith(value))) for value in exempt
    )
    shadowing = [(value, hits) for value, hits in shadowing if hits]
    if shadowing:
        fail = 1
        print(f"EXEMPTION for a value this tree DOES derive, in {EXEMPTIONS}:")
        for value, hits in shadowing:
            number, kind = exempt[value]
            print(f"  line {number}: {value} ({kind}) shadows {', '.join(h[:16] + '…' for h in hits)}")
        print("Remove them. An exempted value is never compared against the artifact that")
        print("produces it, so the exemption survives the artifact changing and the document")
        print("quoting it passes from then on regardless.")

    if unaccounted:
        fail = 1
        print("QUOTED HASH no current artifact or fixture produces:")
        for path, number, value, kind in unaccounted:
            print(f"  {path}:{number}: {kind} {value}")
        print()
        print("Each is either a document left behind by a hash change — regenerate the")
        print("artifact, re-read the diff, and update the prose — or a value this tree")
        print(f"genuinely cannot derive, which belongs in {EXEMPTIONS}")
        print("with its class and the reason, so the exception is reviewable rather than silent.")

    stale = sorted(set(exempt) - used)
    if stale:
        fail = 1
        print(f"STALE EXEMPTION in {EXEMPTIONS} — nothing quotes these any more:")
        for value in stale:
            number, kind = exempt[value]
            print(f"  line {number}: {value} ({kind})")
        print("Remove them. An exemption for a hash no document quotes pre-approves whatever")
        print("value lands on it next, which is how an exemption file becomes a blanket one.")

    if fail:
        return 1
    print(
        f"quoted hashes OK ({len(known)} authoritative values, "
        f"{len(exempt)} declared non-derivable) ✔"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
