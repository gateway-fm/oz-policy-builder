#!/usr/bin/env python3
"""Check the host-function imports of an exact pinned Wasm against a reviewed allowlist.

A verifier is accepted as an owner verifier only if nothing it accepts can change after
review: no ledger access (module `l`: storage, its own code, deployment), no calls into other
contracts (module `d`), and no reads of ledger context. The allowlist names the permitted
imports as `module.field` (the short names soroban-env-common's env.json assigns), each with
the host function it is, so a reviewer can read it. The SHA-256 check binds the result to the
exact artifact; this parser decodes only the import section.
"""

import hashlib
import re
import sys
from pathlib import Path


class InvalidWasm(ValueError):
    pass


def leb_u32(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    for shift in range(0, 35, 7):
        if pos >= len(data):
            raise InvalidWasm("truncated LEB128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
    raise InvalidWasm("unterminated LEB128")


def name(data: bytes, pos: int) -> tuple[str, int]:
    length, pos = leb_u32(data, pos)
    if pos + length > len(data):
        raise InvalidWasm("truncated name")
    return data[pos:pos + length].decode("utf-8"), pos + length


def function_imports(wasm: bytes) -> set[str]:
    if wasm[:8] != b"\0asm\x01\0\0\0":
        raise InvalidWasm("expected core Wasm magic and version 1")
    pos, imports = 8, None
    while pos < len(wasm):
        section_id = wasm[pos]
        size, pos = leb_u32(wasm, pos + 1)
        end = pos + size
        if end > len(wasm):
            raise InvalidWasm("truncated section")
        if section_id == 2:
            if imports is not None:
                raise InvalidWasm("duplicate import section")
            imports = set()
            count, p = leb_u32(wasm, pos)
            for _ in range(count):
                module, p = name(wasm, p)
                field, p = name(wasm, p)
                kind = wasm[p]
                p += 1
                if kind != 0:
                    raise InvalidWasm(f"non-function import {module}.{field}")
                _, p = leb_u32(wasm, p)
                imports.add(f"{module}.{field}")
            if p != end:
                raise InvalidWasm("trailing bytes in import section")
        pos = end
    return imports or set()


def allowlist(path: Path) -> set[str]:
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        token = line.split("#", 1)[0].strip()
        if token:
            entries.append(token)
    if not entries or entries != sorted(set(entries)):
        raise ValueError("import allowlist must be non-empty, sorted, without duplicates")
    for entry in entries:
        if not re.fullmatch(r"[a-z]\.[0-9a-zA-Z_$]+", entry):
            raise ValueError(f"invalid import name {entry!r}")
        if entry.split(".")[0] in ("l", "d"):
            raise ValueError(f"{entry} is ledger or contract-call access; never allowed")
    return set(entries)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: check-wasm-imports.py WASM ALLOWLIST EXPECTED_SHA256", file=sys.stderr)
        return 2
    wasm_path, allow_path, expected_hash = sys.argv[1:]
    try:
        wasm = Path(wasm_path).read_bytes()
        actual_hash = hashlib.sha256(wasm).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"Wasm hash mismatch: {actual_hash} != {expected_hash}")
        unexpected = sorted(function_imports(wasm) - allowlist(Path(allow_path)))
        if unexpected:
            raise ValueError(f"imports outside the reviewed allowlist: {unexpected}")
    except (OSError, ValueError) as exc:
        print(f"Wasm import check failed: {exc}", file=sys.stderr)
        return 1
    print(f"  imports are within {allow_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
