#!/usr/bin/env python3
"""Check the function exports of an exact pinned Wasm against a reviewed name list.

Only the export section is decoded here. The SHA-256 check binds the result to the
exact artifact; this parser does not validate all Wasm instructions or method behavior.
"""

import hashlib
import re
import sys
from pathlib import Path


class InvalidWasm(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise InvalidWasm("truncated section or field")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        result = 0
        for shift in range(0, 35, 7):
            byte = self.byte()
            if shift == 28 and byte > 0x0F:
                raise InvalidWasm("u32 LEB128 overflow")
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result
        raise InvalidWasm("unterminated u32 LEB128")

    def name(self) -> str:
        try:
            return self.take(self.u32()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidWasm("invalid UTF-8 export name") from exc

    def finished(self) -> bool:
        return self.pos == len(self.data)


def function_exports(wasm: bytes) -> set[str]:
    reader = Reader(wasm)
    if reader.take(8) != b"\0asm\x01\0\0\0":
        raise InvalidWasm("expected core Wasm magic and version 1")

    exports = None
    while not reader.finished():
        section_id = reader.byte()
        section = Reader(reader.take(reader.u32()))
        if section_id != 7:
            continue
        if exports is not None:
            raise InvalidWasm("duplicate export section")
        exports = set()
        all_names = set()
        for _ in range(section.u32()):
            name = section.name()
            kind = section.byte()
            section.u32()  # export index
            if name in all_names:
                raise InvalidWasm(f"duplicate export name {name!r}")
            all_names.add(name)
            if kind > 4:
                raise InvalidWasm(f"unknown export kind {kind}")
            if kind == 0:
                exports.add(name)
        if not section.finished():
            raise InvalidWasm("trailing bytes in export section")
    if exports is None:
        raise InvalidWasm("missing export section")
    return exports


def expected_names(path: Path) -> set[str]:
    names = path.read_text(encoding="utf-8").splitlines()
    if not names or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names):
        raise ValueError("expected-name fixture contains an empty or invalid name")
    if names != sorted(set(names)):
        raise ValueError("expected-name fixture must be sorted and contain no duplicates")
    return set(names)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: check-wasm-exports.py WASM EXPECTED_NAMES EXPECTED_SHA256", file=sys.stderr)
        return 2
    wasm_path, fixture_path, expected_hash = sys.argv[1:]
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        print("expected SHA-256 must be 64 lowercase hexadecimal characters", file=sys.stderr)
        return 2
    try:
        wasm = Path(wasm_path).read_bytes()
        actual_hash = hashlib.sha256(wasm).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"Wasm hash mismatch: {actual_hash} != {expected_hash}")
        actual = function_exports(wasm)
        expected = expected_names(Path(fixture_path))
        if actual != expected:
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            raise ValueError(f"function exports differ: missing={missing}, unexpected={unexpected}")
    except (OSError, ValueError) as exc:
        print(f"Wasm export check failed: {exc}", file=sys.stderr)
        return 1
    print(f"  {len(actual)} function exports match {fixture_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
