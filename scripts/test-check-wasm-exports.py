#!/usr/bin/env python3
"""Focused CLI checks for the pinned-Wasm function-export checker."""

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional

CHECKER = Path(__file__).with_name("check-wasm-exports.py")
MAGIC = b"\0asm\x01\0\0\0"


def u32(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def section(kind: int, content: bytes) -> bytes:
    return bytes([kind]) + u32(len(content)) + content


def minimal_wasm(exports: list[str]) -> bytes:
    # One [] -> [] function, which may be exported under multiple distinct names.
    type_section = section(1, b"\x01\x60\x00\x00")
    function_section = section(3, b"\x01\x00")
    entries = b"".join(u32(len(name.encode())) + name.encode() + b"\x00\x00" for name in exports)
    export_section = section(7, u32(len(exports)) + entries)
    code_section = section(10, b"\x01\x02\x00\x0b")
    return MAGIC + type_section + function_section + export_section + code_section


def check(
    wasm: bytes, expected: list[str], override_hash: Optional[str] = None
) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        wasm_path = Path(directory) / "contract.wasm"
        names_path = Path(directory) / "exports.txt"
        wasm_path.write_bytes(wasm)
        names_path.write_text("\n".join(expected) + "\n", encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(CHECKER),
                str(wasm_path),
                str(names_path),
                override_hash or hashlib.sha256(wasm).hexdigest(),
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class ExportCheckTests(unittest.TestCase):
    def test_exact_function_names_pass(self) -> None:
        result = check(minimal_wasm(["alpha", "beta"]), ["alpha", "beta"])
        self.assertEqual(result.returncode, 0)

    def test_missing_and_unexpected_names_fail(self) -> None:
        wasm = minimal_wasm(["alpha", "beta"])
        self.assertIn("unexpected=['beta']", check(wasm, ["alpha"]).stderr)
        self.assertIn("missing=['gamma']", check(wasm, ["alpha", "beta", "gamma"]).stderr)

    def test_duplicate_export_and_truncated_binary_fail(self) -> None:
        duplicate = check(minimal_wasm(["alpha", "alpha"]), ["alpha"])
        truncated = check(minimal_wasm(["alpha"])[:-1], ["alpha"])
        self.assertIn("duplicate export name", duplicate.stderr)
        self.assertIn("truncated section", truncated.stderr)

    def test_wrong_hash_fails_before_export_comparison(self) -> None:
        result = check(minimal_wasm(["alpha"]), ["alpha"], "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Wasm hash mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
