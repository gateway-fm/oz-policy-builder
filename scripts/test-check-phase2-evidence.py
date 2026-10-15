#!/usr/bin/env python3
"""Check gate failures without compiling Rust or depending on installed release tools."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
BASH = shutil.which("bash")


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scripts = self.root / "scripts"
        self.bin = self.root / "bin"
        self.scripts.mkdir()
        self.bin.mkdir()
        for name in ["check-phase2-evidence.sh", "verify-phase2.sh",
                     "check-unmodeled-acknowledged.py", "layer1-unmodeled-acknowledged.txt"]:
            shutil.copyfile(SCRIPTS / name, self.scripts / name)
        # Those gates have their own tests. Here their processes are controlled fixtures;
        # the two shell entry points and the JSON/acknowledgement checker remain real.
        for name in ["test-check-unmodeled-acknowledged.py", "test-check-phase2-evidence.py"]:
            (self.scripts / name).write_text("pass\n", encoding="utf-8")
        (self.scripts / "verify-phase1.sh").write_text(
            'printf "phase1 %s\\n" "$*" >> calls.log\nexit "${PHASE1_EXIT:-0}"\n', encoding="utf-8"
        )
        for name in ["bash", "python3", "dirname", "tail", "mktemp", "rm"]:
            target = sys.executable if name == "python3" else shutil.which(name)
            self.assertIsNotNone(target, name)
            (self.bin / name).symlink_to(target)
        self.tool("cargo", '''
import json, os, sys
from pathlib import Path
arguments = " ".join(sys.argv[1:])
with open("calls.log", "a") as log:
    log.write("cargo " + arguments + "\\n")
if os.environ.get("FAIL_MATCH") and os.environ["FAIL_MATCH"] in arguments:
    sys.exit(7)
if "reference-suite" in sys.argv:
    print(Path("report.json").read_text())
    sys.exit(int(os.environ.get("REPORT_EXIT", "0")))
count = 0 if sys.argv[-2:] != ["--", "--exact"] else 1
if os.environ.get("EMPTY_MATCH") and os.environ["EMPTY_MATCH"] in arguments:
    count = 0
print(f"test result: ok. {count} passed; 0 failed; 0 ignored; 10 filtered out;")
''')
        self.tool("stellar", '''
import os, sys
from pathlib import Path
mode = os.environ.get("WASM_BEHAVIOR", "module")
if mode == "fail":
    sys.exit(8)
if mode != "missing":
    output = Path(sys.argv[sys.argv.index("--out-dir") + 1])
    output.joinpath("generated_soroswap_swap_r0.wasm").write_bytes(
        b"\\x00asm\\x01\\x00\\x00\\x00" if mode == "module" else b"invalid")
''')
        for name in ["cargo-deny", "cargo-machete"]:
            self.tool(name, "pass\n")
        # The real checker reads the rule/policy projection; the fake Cargo process
        # isolates these shell tests from the CLI's separate full-spec validation.
        spec = self.root / "docs/examples/subscription-spec.json"
        spec.parent.mkdir(parents=True)
        spec.write_text(json.dumps({"rules": [{"policies": [
            {"reviewed": {"kind": "oz:spending_limit"}}, {"generated": {}},
        ]}]}), encoding="utf-8")
        (self.root / "report.json").write_text(json.dumps({
            "all_agree": True, "total": 2, "disagreements": 0,
            "missing_classes": [], "permit_only_classes": [],
            "unmodeled_reviewed_policies": ["rule[0]: oz:spending_limit"],
            "coverage": ["Original: 1", "WrongSigner: 1"],
            "report": {
                "layer": "layer1-reference-evaluator", "total": 2, "agreements": 2, "disagreements": 0,
                "expected_classes": {"0": ["original", "wrong_signer"]},
                "coverage": [["original", 1], ["wrong_signer", 1]],
                "coverage_by_rule": {"0": {"original": 1, "wrong_signer": 1}},
                "unmodeled_policies": [{"rule_index": 0, "kind": "oz:spending_limit"}],
                "outcomes": [
                    {"rule_index": 0, "class": "original", "expected": "permit", "actual": "permit", "agree": True},
                    {"rule_index": 0, "class": "wrong_signer", "expected": "deny", "actual": "deny(NoSignerMatched)", "agree": True},
                ],
            },
        }), encoding="utf-8")

    def tool(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + source, encoding="utf-8")
        path.chmod(0o755)

    def run_gate(self, script="check-phase2-evidence.sh", arguments=(), **changes):
        (self.root / "calls.log").unlink(missing_ok=True)
        environment = os.environ.copy()
        for key in ["PHASE1_EXIT", "FAIL_MATCH", "EMPTY_MATCH", "REPORT_EXIT", "WASM_BEHAVIOR"]:
            environment.pop(key, None)
        environment.update(PATH=str(self.bin), **changes)
        return subprocess.run([BASH, str(self.scripts / script), *arguments], cwd=self.root,
                              env=environment, capture_output=True, text=True, check=False)

    def assert_failure(self, result, message=""):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn("PHASE 2 CHECKS PASSED", result.stdout)

    def assert_wrapper_runs_evidence(self, result):
        self.assertIn("FOCUSED PHASE 2 CHECKS PASSED (all)", result.stdout)
        calls = (self.root / "calls.log").read_text().splitlines()
        self.assertTrue(calls[0].startswith("phase1 "), calls)
        for group in ["reference-suite", "-p ozpb-harness", "--test mcp_stdio_verification",
                      "--test generated_suite", "--test swap_generated_suite"]:
            self.assertTrue(any(group in call for call in calls[1:]), f"missing focused check: {group}")

    def test_each_mode_runs_only_its_named_evidence(self):
        for mode, host, contracts in [((), True, True), (("--host-only",), True, False),
                                      (("--contracts-only",), False, True)]:
            with self.subTest(mode=mode):
                result = self.run_gate(arguments=mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("reference agreement" in result.stdout, host)
                self.assertEqual("partial layer 2" in result.stdout, contracts)

    def test_a_removed_or_renamed_test_fails_every_group(self):
        for name in ["w1_blend_claim", "subscription_evidence", "w3_soroswap",
                     "verification_tools_are_listed", "generated_deny_suite", "swap_mutations"]:
            with self.subTest(name=name):
                self.assert_failure(self.run_gate(EMPTY_MATCH=name), "ASSERTED NOTHING")

    def test_cargo_failure_is_not_hidden_by_successful_output_checks(self):
        self.assert_failure(self.run_gate(FAIL_MATCH="generated_deny_suite"), "EVIDENCE CHECK FAILED")
        # Even valid JSON cannot hide a nonzero producer exit from the runner.
        self.assert_failure(self.run_gate(REPORT_EXIT="9"))

    def test_malformed_reference_report_stops_the_gate(self):
        (self.root / "report.json").write_text("not JSON", encoding="utf-8")
        self.assert_failure(self.run_gate(), "reference coverage check failed")

    def test_invalid_flags_stop_before_any_checks(self):
        for script in ["check-phase2-evidence.sh", "verify-phase2.sh"]:
            for arguments in [("--unknown",), ("--offline", "extra")]:
                with self.subTest(script=script, arguments=arguments):
                    result = self.run_gate(script, arguments)
                    self.assertEqual(result.returncode, 2)
                    self.assertFalse((self.root / "calls.log").exists())

    def test_release_requires_tools_and_does_not_silently_skip(self):
        (self.bin / "stellar").unlink()
        self.assert_failure(self.run_gate("verify-phase2.sh"), "requires stellar")
        self.assertFalse((self.root / "calls.log").exists())

    def test_offline_mode_is_explicit_and_reaches_the_reduced_phase1_gate(self):
        (self.bin / "stellar").unlink()
        result = self.run_gate("verify-phase2.sh", ("--offline",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("W3 Wasm build not run", result.stdout)
        self.assertIn("not full Tranche 2 acceptance", result.stdout)
        self.assertIn("phase1 --offline", (self.root / "calls.log").read_text())
        self.assert_wrapper_runs_evidence(result)

    def test_phase1_failure_stops_before_focused_checks(self):
        self.assert_failure(self.run_gate("verify-phase2.sh", PHASE1_EXIT="4"))
        self.assertNotIn("cargo", (self.root / "calls.log").read_text())

    def test_both_wrapper_modes_propagate_focused_check_failures(self):
        for arguments in [(), ("--offline",)]:
            for group in ["verification_tools_are_listed", "generated_deny_suite"]:
                with self.subTest(arguments=arguments, group=group):
                    self.assert_failure(self.run_gate("verify-phase2.sh", arguments, FAIL_MATCH=group),
                                        "EVIDENCE CHECK FAILED")

    def test_release_requires_a_successful_build_and_fresh_wasm_output(self):
        for mode in ["fail", "missing", "invalid"]:
            with self.subTest(mode=mode):
                result = self.run_gate("verify-phase2.sh", WASM_BEHAVIOR=mode)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("AUTOMATED PHASE 2 CHECKS PASSED", result.stdout)
        result = self.run_gate("verify-phase2.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AUTOMATED PHASE 2 CHECKS PASSED (release mode)", result.stdout)
        self.assertIn("not full Tranche 2 acceptance", result.stdout)
        self.assert_wrapper_runs_evidence(result)


if __name__ == "__main__":
    unittest.main()
