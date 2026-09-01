#!/usr/bin/env python3
"""Fail unless generating twice from one spec produced the same artifact.

Two assertions, not a report. Determinism is not a nicety in this pipeline: the claim is that
a PolicySpec is a *complete* description of an artifact, so that a reviewer can regenerate the
crate and get the bytes they were shown. If codegen leaked a timestamp, an absolute path or a
map iteration order, the policy someone reviewed would not be the policy someone deployed, and
every hash quoted in the evidence documents would mean nothing.

The two comparisons answer different questions, which is why both are made:

  * every `.rs` file under `src/`, by sha256 of each — is the **source a reviewer reads** the
    same? That is the artifact the project asks people to audit by reading. Every file, not
    the crate root alone: emission produces a root carrying the header and a `contract.rs`
    carrying the policy, so comparing the root would compare the half that does not vary with
    the rule.
  * `build-manifest.json`'s `wasm_hash` — is the **deployed artifact** the same? Not implied by
    identical source: the compiler, the SDK version and the lockfile all land inside those
    bytes, which is also why the manifest records the toolchain identity next to the hash.

What this does *not* show: the crates it compares come from one spec in one run on one
machine, so the
scope is nondeterminism inside codegen and the build. Reproducibility across a clean rebuild is
a different claim, checked by the nightly wasm job.

Either mismatch exits non-zero and, under the caller's `set -e`, stops the demo.

Usage: assert_regenerated_identically.py <first-crate-dir> <second-crate-dir>
"""

import hashlib
import json
import pathlib
import sys


def source_hashes(crate: pathlib.Path) -> dict[str, str]:
    """Every Rust source file of `crate`, keyed by path relative to `src/`, digested.

    `rglob`, not `glob`, and keyed by relative path rather than by basename. The docstring
    said "every" while a non-recursive glob keyed by name would have skipped a nested
    module and collided two files sharing a basename — either of which lets this assertion
    report determinism over sources that differ. Nothing emitted today nests, which is
    exactly why the gap would have gone unnoticed until something did.
    """
    src = crate / "src"
    files = sorted(src.rglob("*.rs"))
    if not files:
        sys.exit(f"{crate}/src holds no .rs files; there is nothing to compare")
    return {
        path.relative_to(src).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }


def manifest_wasm_hash(crate: pathlib.Path) -> str:
    with open(crate / "build-manifest.json", encoding="utf-8") as handle:
        return json.load(handle)["wasm_hash"]


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    first, second = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])

    source_a, source_b = source_hashes(first), source_hashes(second)
    if source_a != source_b:
        print("  ASSERTION FAILED: CODEGEN IS NOT DETERMINISTIC")
        for name in sorted(set(source_a) | set(source_b)):
            print(f"    {first}/src/{name} : {source_a.get(name, '(absent)')}")
            print(f"    {second}/src/{name} : {source_b.get(name, '(absent)')}")
        return 1
    for name, digest in source_a.items():
        print(f"  source byte-identical : src/{name} {digest}")

    wasm_a, wasm_b = manifest_wasm_hash(first), manifest_wasm_hash(second)
    if wasm_a != wasm_b:
        print("  ASSERTION FAILED: WASM IS NOT REPRODUCIBLE")
        print(f"    {first} build manifest : {wasm_a}")
        print(f"    {second} build manifest : {wasm_b}")
        return 1
    print("  wasm byte-identical   :", wasm_a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
