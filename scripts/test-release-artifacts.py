#!/usr/bin/env python3
"""Checks for scripts/release-artifacts.py with stand-in binaries and a stand-in MCP server.

The release workflow runs the real binaries only when a release is published or a dry run is
dispatched; this keeps the packaging, the wire-contract export and the assembly checked on every
pull request, in about a second and without a Rust build.
"""

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("release-artifacts.py")
ROOT = SCRIPT.resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("release_artifacts", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

LABEL = "v1.2.3-rc.1"
TARGETS = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
COMMIT = "0123456789abcdef0123456789abcdef01234567"

# A stand-in MCP server: reads the whole of stdin, as the real one does before stdin closes, and
# answers initialize and tools/list. FAKE_MODE selects a defect to exercise a refusal.
FAKE_SERVER = r'''#!/usr/bin/env python3
import json, os, sys
mode = os.environ.get("FAKE_MODE", "ok")
if os.environ.get("OZPB_LEAK"):
    mode = "leaked"
requests = [json.loads(line) for line in sys.stdin if line.strip()]
tool = {"name": "evaluate_spec", "description": "d",
        "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"}}
other = dict(tool, name="generate_code")
tools = [other, tool]
if mode == "no-output-schema":
    del tool["outputSchema"]
if mode == "duplicate":
    tools = [tool, dict(tool)]
if mode == "leaked":
    tools = [dict(tool, name="configured_only")]
for request in requests:
    if request.get("id") == 1:
        print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "x"}}))
    if request.get("id") == 2 and mode != "silent":
        if mode == "error":
            print(json.dumps({"jsonrpc": "2.0", "id": 2, "error": {"code": -1, "message": "no"}}))
        else:
            result = {"tools": tools}
            if mode == "paginated":
                result["nextCursor"] = "more"
            print("not json")
            print(json.dumps({"jsonrpc": "2.0", "id": 2, "result": result}))
'''


def executable(path, body):
    path.write_bytes(body)
    path.chmod(0o755)
    return path


class Archive(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.binary = executable(self.dir / "ozpb", b"\x7fELF stand-in")

    def tearDown(self):
        self.tmp.cleanup()

    def test_holds_the_binary_and_licence_files_with_fixed_metadata(self):
        path = release.archive(self.binary, LABEL, TARGETS[0], 1700000000, self.dir / "out")
        self.assertEqual(path.name, f"ozpb-{LABEL}-{TARGETS[0]}.tar.gz")
        base = f"ozpb-{LABEL}-{TARGETS[0]}"
        with tarfile.open(path) as tar:
            members = tar.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [base, f"{base}/LICENSE-APACHE", f"{base}/LICENSE-MIT", f"{base}/NOTICE",
                 f"{base}/ozpb"])
            for member in members:
                self.assertEqual((member.uid, member.gid, member.uname, member.gname),
                                 (0, 0, "", ""))
                self.assertEqual(member.mtime, 1700000000)
            modes = {member.name: member.mode for member in members}
            self.assertEqual(modes[f"{base}/ozpb"], 0o755)
            self.assertEqual(modes[f"{base}/NOTICE"], 0o644)
            self.assertEqual(tar.extractfile(f"{base}/ozpb").read(), b"\x7fELF stand-in")
            self.assertEqual(tar.extractfile(f"{base}/LICENSE-MIT").read(),
                             (ROOT / "LICENSE-MIT").read_bytes())

    def test_repackaging_the_same_binary_reproduces_the_archive(self):
        first = release.archive(self.binary, LABEL, TARGETS[0], 1, self.dir / "a").read_bytes()
        second = release.archive(self.binary, LABEL, TARGETS[0], 1, self.dir / "b").read_bytes()
        self.assertEqual(first, second)
        # Two packagings within one second match even with a clock in the header, so assert the
        # header itself: no flags (so no stored file name) and a zero timestamp.
        self.assertEqual(first[3:8], b"\0\0\0\0\0")

    def test_refuses_what_is_not_a_released_executable(self):
        other = executable(self.dir / "ozpb-other", b"x")
        plain = self.dir / "plain"
        plain.mkdir()
        not_executable = plain / "ozpb"
        not_executable.write_bytes(b"x")
        not_executable.chmod(0o644)
        cases = [
            (other, LABEL, TARGETS[0]),
            (not_executable, LABEL, TARGETS[0]),
            (self.binary, "1.2.3", TARGETS[0]),
            (self.binary, "v1.2", TARGETS[0]),
            (self.binary, LABEL + "\n", TARGETS[0]),
            (self.binary, LABEL, "x86_64"),
            (self.binary, LABEL, TARGETS[0] + "\n"),
        ]
        for binary, label, target in cases:
            with self.subTest(binary=binary.name, label=label, target=target):
                with self.assertRaises(release.ReleaseError):
                    release.archive(binary, label, target, 0, self.dir / "out")


class ErrorCodes(unittest.TestCase):
    def test_reads_every_arm_of_the_real_table(self):
        codes = release.error_codes(ROOT)
        source = (ROOT / release.ERROR_CODE_SOURCE).read_text(encoding="utf-8")
        self.assertEqual(len(codes), len(re.findall(r'=> "E_[A-Z0-9_]+",', source)))
        for code in ("E_SPEC_INVALID", "E_REGISTRY_ROOT_POLICY", "E_EVIDENCE_INCOHERENT"):
            self.assertIn(code, codes)

    def table(self, body):
        root = Path(self.tmp.name)
        path = root / release.ERROR_CODE_SOURCE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return root

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_a_table_it_cannot_read_completely(self):
        cases = {
            "unexpected line": 'error_codes! {\n    A => "E_A",\n    B => E_B,\n}\n',
            "duplicate": 'error_codes! {\n    A => "E_A",\n    B => "E_A",\n}\n',
            "unclosed": 'error_codes! {\n    A => "E_A",\n',
            "empty": "error_codes! {\n    // nothing\n}\n",
            "absent": "fn main() {}\n",
        }
        for name, body in cases.items():
            with self.subTest(name):
                with self.assertRaises(release.ReleaseError):
                    release.error_codes(self.table(body))

    def test_comments_and_doc_lines_are_not_codes(self):
        root = self.table('error_codes! {\n    // group\n    /// doc\n\n    A => "E_A",\n}\n')
        self.assertEqual(release.error_codes(root), ["E_A"])


class WireContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.server = executable(self.dir / "server", FAKE_SERVER.encode())
        self.saved = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved)
        self.tmp.cleanup()

    def export(self, mode="ok"):
        os.environ["FAKE_MODE"] = mode
        return release.wire_contract(self.server, LABEL, COMMIT, self.dir / "contract.json",
                                     root=ROOT, timeout=30)

    def test_exports_sorted_tools_and_the_error_vocabulary(self):
        document = json.loads(self.export().read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], "ozpb-wire-contract/v1")
        self.assertEqual((document["release"], document["commit"]), (LABEL, COMMIT))
        self.assertEqual([tool["name"] for tool in document["tools"]],
                         ["evaluate_spec", "generate_code"])
        self.assertEqual(document["error_codes"], release.error_codes(ROOT))

    def test_operator_configuration_does_not_reach_the_listing(self):
        os.environ["OZPB_LEAK"] = "1"
        document = json.loads(self.export().read_text(encoding="utf-8"))
        self.assertNotIn("configured_only", [tool["name"] for tool in document["tools"]])

    def test_refuses_an_incomplete_or_failed_listing(self):
        for mode in ("no-output-schema", "duplicate", "paginated", "error", "silent"):
            with self.subTest(mode):
                with self.assertRaises(release.ReleaseError):
                    self.export(mode)

    def test_refuses_an_abbreviated_commit(self):
        os.environ["FAKE_MODE"] = "ok"
        with self.assertRaises(release.ReleaseError):
            release.wire_contract(self.server, LABEL, COMMIT[:12], self.dir / "c.json", ROOT)


class Assemble(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.dist = self.dir / "dist"
        for target in TARGETS:
            binaries = self.dir / "bin" / target
            binaries.mkdir(parents=True)
            for binary in release.BINARIES:
                path = executable(binaries / binary, f"{binary} for {target}".encode())
                release.archive(path, LABEL, target, 0, self.dist / target)
            (self.dist / target / f"ozpb-wire-contract-{LABEL}.json").write_text("{}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def assert_refused(self):
        with self.assertRaises(release.ReleaseError):
            release.assemble(LABEL, self.dist, TARGETS, self.dir / "release")

    def test_lays_out_every_asset_once_with_matching_sums(self):
        sums = release.assemble(LABEL, self.dist, TARGETS, self.dir / "release")
        assets = sorted(path.name for path in sums.parent.iterdir())
        self.assertEqual(len(assets), len(TARGETS) * len(release.BINARIES) + 2)
        lines = sums.read_text(encoding="utf-8").splitlines()
        self.assertEqual([line.split("  ")[1] for line in lines],
                         [name for name in assets if name != "SHA256SUMS"])
        for line in lines:
            digest, name = line.split("  ")
            self.assertEqual(digest,
                             hashlib.sha256((sums.parent / name).read_bytes()).hexdigest())

    def test_the_sums_file_checks_with_the_standard_tool(self):
        sums = release.assemble(LABEL, self.dist, TARGETS, self.dir / "release")
        tool = (["sha256sum", "--check", "--strict"] if sys.platform.startswith("linux")
                else ["shasum", "-a", "256", "--check"])
        subprocess.run(tool + ["SHA256SUMS"], cwd=sums.parent, check=True,
                       stdout=subprocess.DEVNULL)

    def test_refuses_a_wire_contract_that_differs_between_targets(self):
        (self.dist / TARGETS[1] / f"ozpb-wire-contract-{LABEL}.json").write_text("{ }\n")
        self.assert_refused()

    def test_refuses_a_missing_archive(self):
        (self.dist / TARGETS[0] / f"ozpb-{LABEL}-{TARGETS[0]}.tar.gz").unlink()
        self.assert_refused()

    def test_refuses_an_unexpected_file(self):
        (self.dist / TARGETS[0] / "stray").write_text("x")
        self.assert_refused()

    def test_refuses_a_target_that_built_nothing(self):
        for path in (self.dist / TARGETS[1]).iterdir():
            path.unlink()
        self.assert_refused()

    def test_refuses_a_link_in_place_of_a_package(self):
        package = self.dist / TARGETS[0] / f"ozpb-{LABEL}-{TARGETS[0]}.tar.gz"
        package.unlink()
        package.symlink_to(ROOT / "LICENSE-MIT")
        self.assert_refused()

    def test_refuses_a_directory_in_place_of_a_package(self):
        package = self.dist / TARGETS[0] / f"ozpb-{LABEL}-{TARGETS[0]}.tar.gz"
        package.unlink()
        package.mkdir()
        self.assert_refused()

    def test_refuses_to_write_over_earlier_output(self):
        (self.dir / "release").mkdir()
        (self.dir / "release" / "old").write_text("x")
        self.assert_refused()


class CommandLine(unittest.TestCase):
    def test_a_refusal_exits_non_zero_with_a_message(self):
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "archive", "--binary", "/nonexistent/ozpb",
             "--label", LABEL, "--target", TARGETS[0], "--epoch", "0", "--out", "unused"],
            capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 1)
        self.assertIn("release-artifacts:", done.stderr)


if __name__ == "__main__":
    unittest.main()
