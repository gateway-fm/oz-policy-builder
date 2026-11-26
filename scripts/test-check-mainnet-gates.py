#!/usr/bin/env python3
"""The mainnet gate checker must fail whenever a test its document names cannot have run.

A fixture repository exercises the real shell entry point and plan reader with stand-in `cargo`
and `node` processes, so nothing compiles here. The last two tests read the committed document
against the real tree, statically, which is what keeps every named test there pointing at a
function or title that exists.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
BASH = shutil.which("bash")

ARCHITECTURE = """\
# Architecture

**Acceptance gates before any mainnet use** (checked in CI/review, not aspirational):

- First gate.
- Second gate, written across
  two lines.
- Third gate.
- Fourth gate.

**Maintenance:** nothing.
"""

DOC = """\
# Mainnet acceptance gates

| Gate | Requirement | Status | Evidence | Deviation |
| --- | --- | --- | --- | --- |
| G1 | First | **closed** | below | none |
| G2 | Second | **narrowed** | below | one shape |
| G3 | Third | **open** | below | missing |
| G4 | Fourth | **review** | audit | report |

```gate-evidence G1
ci  crates/demo/src/lib.rs  tests::alpha_holds
ci  crates/demo/tests/suite.rs  beta_holds
ci  contracts/differential/tests/generated_suite.rs  gamma_holds
```

```gate-evidence G2
# A test may serve two gates; it still runs once.
ci  crates/demo/src/lib.rs  tests::alpha_holds
ci  crates/tool/src/inner.rs  inner::tests::bin_holds
ci  wallet/tests/demo.test.mjs  the wallet's grant (exactly one) holds
ci  wallet/tests/demo.test.mjs  wallet refuses a foreign key before signing
release  contracts/differential/tests/account_wasm_invariants.rs  delta_holds
ci-step  .github/workflows/ci.yml  bash scripts/test-something.sh
```

```gate-evidence G3
ci  crates/demo/tests/suite.rs  epsilon_holds
```
"""

CI = """\
jobs:
  host:
    steps:
      - run: python3 scripts/test-check-mainnet-gates.py
      - run: bash scripts/check-mainnet-gates.sh --part host
      - run: bash scripts/test-something.sh
  contracts:
    steps:
      - run: bash scripts/check-mainnet-gates.sh --part contracts
  harness:
    steps:
      - run: |
          bash scripts/check-mainnet-gates.sh --part wallet
"""

FILES = {
    "docs/architecture.md": ARCHITECTURE,
    "docs/MAINNET-GATES.md": DOC,
    ".github/workflows/ci.yml": CI,
    "crates/demo/Cargo.toml": '[package]\nname = "ozpb-demo"\n',
    "crates/demo/src/lib.rs": "#[cfg(test)]\nmod tests {\n    #[test]\n    fn alpha_holds() {}\n}\n",
    "crates/demo/tests/suite.rs": "#[test]\nfn beta_holds() {}\n#[test]\nfn epsilon_holds() {}\n",
    "crates/tool/Cargo.toml": '[package]\nname = "ozpb-tool"\n\n[[bin]]\nname = "tool"\npath = "src/main.rs"\n',
    "crates/tool/src/main.rs": "mod inner;\nfn main() {}\n",
    "crates/tool/src/inner.rs": "#[cfg(test)]\nmod tests {\n    #[test]\n    fn bin_holds() {}\n}\n",
    "contracts/differential/Cargo.toml": '[package]\nname = "ozpb-differential"\n',
    "contracts/differential/tests/generated_suite.rs": "#[test]\nfn gamma_holds() {}\n",
    "contracts/differential/tests/account_wasm_invariants.rs": "#[test]\n#[ignore]\nfn delta_holds() {}\n",
    "wallet/tests/demo.test.mjs": (
        "test('the wallet\\'s grant (exactly one) holds', () => {});\n"
        "for (const name of ['a foreign key']) test(`wallet refuses ${name} before signing`, () => {});\n"
    ),
    "scripts/test-pinned-account-authorization.sh": (
        "set -euo pipefail\n"
        "# delta_holds is named here only in a comment, which requires nothing.\n"
        "cargo test --test account_wasm_invariants -- --ignored\n"
        "for test in delta_holds; do grep -qx \"test $test ... ok\" log; done\n"
        "cargo test --test policy_prediction -- --ignored\n"
        "for test in other_holds; do grep -qx \"test $test ... ok\" log; done\n"
    ),
    ".github/workflows/nightly-live.yml": (
        "jobs:\n  pinned:\n    steps:\n"
        "      - run: bash scripts/test-pinned-account-authorization.sh\n"
    ),
}

# Stand-ins. Cargo reports one passing test only when given a full name with `--exact`, as
# libtest does for a name that exists; EMPTY_MATCH and FAIL_MATCH model a rename and a failure.
CARGO = '''
import os, sys
arguments = " ".join(sys.argv[1:])
with open("calls.log", "a") as log:
    log.write("cargo " + arguments + "\\n")
if os.environ.get("FAIL_MATCH") and os.environ["FAIL_MATCH"] in arguments:
    print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;")
    sys.exit(101)
count = 1 if sys.argv[-2:] == ["--", "--exact"] else 0
if os.environ.get("EMPTY_MATCH") and os.environ["EMPTY_MATCH"] in arguments:
    count = 0
if os.environ.get("TWO_MATCH") and os.environ["TWO_MATCH"] in arguments:
    count = 2
print(f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;")
'''

# Node prints the file itself as one passing test when the pattern matches nothing, which is
# why the checker must look for the title's own line rather than a pass count.
NODE = r'''
import os, re, sys
pattern = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("--test-name-pattern="))
title = re.sub(r"\\(.)", r"\1", pattern[1:-1])
with open(os.path.join("..", "calls.log"), "a") as log:
    log.write("node " + " ".join(sys.argv[1:]) + "\n")
print("TAP version 13")
if os.environ.get("EMPTY_MATCH") and os.environ["EMPTY_MATCH"] in title:
    print("ok 1 - " + sys.argv[-1])
    print("# pass 1")
elif os.environ.get("FAIL_MATCH") and os.environ["FAIL_MATCH"] in title:
    print("not ok 1 - " + title)
    sys.exit(1)
elif os.environ.get("SKIP_MATCH") and os.environ["SKIP_MATCH"] in title:
    print("ok 1 - " + title + " # SKIP")
    print("# pass 0")
elif os.environ.get("NOT_OK_SUB") and os.environ["NOT_OK_SUB"] in title:
    print("    not ok 1 - a subtest inside it")
    print("ok 1 - " + title)
else:
    print("ok 1 - " + title)
    print("# pass 1")
'''


class FixtureCheckerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        for name in ["check-mainnet-gates.sh", "mainnet-gates-plan.py"]:
            shutil.copyfile(SCRIPTS / name, self.root / "scripts" / name)
        for path, text in FILES.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in [("cargo", CARGO), ("node", NODE)]:
            tool = self.bin / name
            tool.write_text(f"#!{sys.executable}\n" + source, encoding="utf-8")
            tool.chmod(0o755)

    def edit(self, path, old, new):
        target = self.root / path
        text = target.read_text(encoding="utf-8")
        self.assertIn(old, text)
        target.write_text(text.replace(old, new, 1), encoding="utf-8")

    def run_checker(self, *arguments, **environment):
        (self.root / "calls.log").unlink(missing_ok=True)
        env = os.environ.copy()
        for key in ["EMPTY_MATCH", "FAIL_MATCH", "TWO_MATCH", "SKIP_MATCH", "NOT_OK_SUB"]:
            env.pop(key, None)
        env.update(PATH=f"{self.bin}{os.pathsep}{env['PATH']}", **environment)
        return subprocess.run([BASH, str(self.root / "scripts/check-mainnet-gates.sh"), *arguments],
                              cwd=self.root, env=env, capture_output=True, text=True, check=False)

    def calls(self):
        log = self.root / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def assert_red(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(message, result.stdout + result.stderr)
        self.assertNotIn("CHECKS PASSED", result.stdout)

    def test_every_named_test_runs_once_by_exact_name(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MAINNET GATE CHECKS PASSED (all parts)", result.stdout)
        calls = self.calls()
        cargo = [call for call in calls if call.startswith("cargo ")]
        self.assertEqual(len(cargo), 5, calls)  # alpha once although two gates name it
        expected = [
            "-p ozpb-demo --lib tests::alpha_holds -- --exact",
            "-p ozpb-demo --test suite beta_holds -- --exact",
            "-p ozpb-demo --test suite epsilon_holds -- --exact",
            "-p ozpb-tool --bin tool inner::tests::bin_holds -- --exact",
            "--manifest-path contracts/Cargo.toml -p ozpb-differential --test generated_suite "
            "gamma_holds -- --exact",
        ]
        for fragment in expected:
            self.assertEqual(sum(fragment in call for call in cargo), 1, (fragment, cargo))
        self.assertTrue(all("--locked" in call for call in cargo), cargo)
        node = [call for call in calls if call.startswith("node ")]
        self.assertEqual(len(node), 2, calls)
        self.assertTrue(all("tests/demo.test.mjs" in call for call in node), node)

    def test_skipped_checks_are_named_not_silent(self):
        result = self.run_checker()
        self.assertIn("delta_holds", result.stdout)
        self.assertIn("scripts/test-pinned-account-authorization.sh", result.stdout)
        self.assertIn("bash scripts/test-something.sh", result.stdout)
        self.assertNotIn("delta_holds", "\n".join(self.calls()))

    def test_one_part_runs_only_its_tests_and_names_the_rest(self):
        result = self.run_checker("--part", "host")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MAINNET GATE CHECKS PASSED (part host)", result.stdout)
        calls = self.calls()
        self.assertTrue(calls and all(call.startswith("cargo -") or call.startswith("cargo test")
                                      for call in calls), calls)
        self.assertFalse(any("contracts/Cargo.toml" in call for call in calls), calls)
        self.assertIn("contracts", result.stdout)
        self.assertIn("wallet", result.stdout)

    def test_a_renamed_rust_test_fails_before_anything_runs(self):
        self.edit("docs/MAINNET-GATES.md", "beta_holds", "beta_renamed")
        self.assert_red(self.run_checker(), "beta_renamed")
        self.assertEqual(self.calls(), [])

    def test_a_test_removed_from_its_file_fails(self):
        self.edit("crates/demo/tests/suite.rs", "fn epsilon_holds", "fn epsilon_gone")
        self.assert_red(self.run_checker(), "epsilon_holds")

    def test_a_name_cargo_filters_to_zero_fails(self):
        for name in ["alpha_holds", "bin_holds", "gamma_holds"]:
            with self.subTest(name=name):
                self.assert_red(self.run_checker(EMPTY_MATCH=name), "ASSERTED NOTHING")

    def test_a_failing_rust_test_fails(self):
        self.assert_red(self.run_checker(FAIL_MATCH="gamma_holds"), "CHECK FAILED")

    def test_a_name_that_runs_two_tests_fails(self):
        self.assert_red(self.run_checker(TWO_MATCH="beta_holds"), "ASSERTED NOTHING")

    def test_a_skipped_wallet_test_fails(self):
        self.assert_red(self.run_checker(SKIP_MATCH="exactly one"), "ASSERTED NOTHING")

    def test_a_failing_subtest_under_a_passing_title_fails_even_when_node_exits_zero(self):
        self.assert_red(self.run_checker(NOT_OK_SUB="exactly one"), "ASSERTED NOTHING")

    def test_a_wallet_title_outside_a_test_call_is_not_a_test(self):
        self.edit("wallet/tests/demo.test.mjs", "test('the wallet\\'s grant (exactly one) holds'",
                  "assert.ok(true, 'the wallet\\'s grant (exactly one) holds'")
        self.assert_red(self.run_checker(), "exactly one")

    def test_a_wallet_title_that_is_absent_matches_nothing_or_fails_is_red(self):
        self.assert_red(self.run_checker(EMPTY_MATCH="exactly one"), "ASSERTED NOTHING")
        self.assert_red(self.run_checker(FAIL_MATCH="exactly one"), "CHECK FAILED")
        self.edit("wallet/tests/demo.test.mjs", "holds", "is held")
        self.assert_red(self.run_checker(), "exactly one")
        self.edit("wallet/tests/demo.test.mjs", "is held", "holds")
        self.edit("wallet/tests/demo.test.mjs", "before signing", "after signing")
        self.assert_red(self.run_checker(), "a foreign key")

    def test_a_release_test_the_release_gate_does_not_require_fails(self):
        self.edit("scripts/test-pinned-account-authorization.sh", "for test in delta_holds",
                  "for test in other")
        self.assert_red(self.run_checker(), "delta_holds")

    def test_a_release_test_required_from_another_binary_fails(self):
        self.edit("scripts/test-pinned-account-authorization.sh", "for test in delta_holds",
                  "for test in other")
        self.edit("scripts/test-pinned-account-authorization.sh", "for test in other_holds",
                  "for test in other_holds delta_holds")
        self.assert_red(self.run_checker(), "delta_holds")

    def test_a_release_name_outside_a_required_check_requires_nothing(self):
        self.edit("scripts/test-pinned-account-authorization.sh", "for test in delta_holds",
                  "echo delta_holds\nfor test in other")
        self.assert_red(self.run_checker(), "delta_holds")

    RELEASE = "scripts/test-pinned-account-authorization.sh"
    ERREXIT = "set -euo pipefail\n"
    DELTA_LOOP = 'for test in delta_holds; do grep -qx "test $test ... ok" log; done\n'

    def test_a_release_check_that_cannot_fail_the_script_requires_nothing(self):
        # Each case leaves delta_holds' name in place while letting the script finish green
        # without that test having passed.
        check = 'grep -qx "test $test ... ok" log'
        loops = {
            "no check": 'echo "$test"',
            "|| true": f"{check} || true",
            "|| :": f"{check} || :",
            "|| exit 0": f"{check} || exit 0",
            "|| echo": f"{check} || echo missing",
            "&& list": f"{check} && echo found",
            "if condition": f"if {check}; then :; fi",
            "negated": f"! {check}",
            "single-quoted $test": "grep -qx 'test $test ... ok' log",
            "group exits with echo's status": f"{check} || {{ echo missing; exit; }}",
            "exit 256 wraps to 0": f"{check} || exit 256",
            "conditional exit in the group": f"{check} || {{ if [ -n x ]; then exit 1; fi; }}",
            "continue in the group": f"{check} || {{ continue; exit 1; }}",
            "group piped": f"{check} || {{ echo missing; exit 1; }} | cat",
            "continue before the check": f"continue; {check} || exit 1",
        }
        cases = [(self.ERREXIT, f"for test in delta_holds; do {body}; done\n", name)
                 for name, body in loops.items()]
        cases += [
            (self.ERREXIT, 'for test in delta_holds; do grep -qx "test $test ... ok" log || exit 1; '
             "done | cat\n", "piped loop"),
            (self.ERREXIT, "grep -qx 'test delta_holds ... ok' log || true\n", "plain || true"),
            (self.ERREXIT, "grep -qx 'test delta_holds ... ok' log && echo found\n", "plain &&"),
            (self.ERREXIT, "grep -qx 'test delta_holds ... ok' log || { echo missing; exit 1; } &\n",
             "plain group in the background"),
            (self.ERREXIT, "never_called() {\n    grep -qx 'test delta_holds ... ok' log || exit 1\n}\n",
             "inside a function"),
            (self.ERREXIT, "if false; then\n    grep -qx 'test delta_holds ... ok' log || exit 1\nfi\n",
             "inside an if"),
            (self.ERREXIT, "if false; then\n    for test in delta_holds; do\n"
             '        grep -qx "test $test ... ok" log || exit 1\n    done\nfi\n', "loop inside an if"),
            ("", self.DELTA_LOOP, "no set -e"),
            ("", "grep -qx 'test delta_holds ... ok' log\n", "plain without set -e"),
            (self.ERREXIT + "set +e\n", self.DELTA_LOOP, "set +e"),
        ]
        for errexit, loop, name in cases:
            with self.subTest(case=name):
                self.setUp()
                self.edit(self.RELEASE, self.ERREXIT, errexit)
                self.edit(self.RELEASE, self.DELTA_LOOP, loop)
                self.assert_red(self.run_checker(), "does not require 'delta_holds'")

    def test_a_release_check_that_fails_the_script_requires_its_tests(self):
        cases = [
            ("", 'for test in delta_holds; do grep -qx "test $test ... ok" log || exit 1; done\n',
             "|| exit 1"),
            ("", 'for test in delta_holds; do grep -qx "test $test ... ok" log || exit; done\n',
             "|| exit"),
            ("", 'for test in \\\n    delta_holds; do\n'
                 '    grep -qx "test $test ... ok" "$work/log" || {\n'
                 '        echo "missing: $test" >&2\n        exit 1\n    }\ndone\n',
             "|| { ... exit 1 } across lines"),
            ("", "grep -qx 'test delta_holds ... ok' \\\n    log || {\n"
                 "    echo missing >&2\n    exit 1\n}\n", "plain check with a group"),
            ("set -o errexit\n", self.DELTA_LOOP, "set -o errexit"),
            (self.ERREXIT, "grep -qx 'test delta_holds ... ok' log\n", "plain under set -e"),
        ]
        for errexit, loop, name in cases:
            with self.subTest(case=name):
                self.setUp()
                self.edit(self.RELEASE, self.ERREXIT, errexit)
                self.edit(self.RELEASE, self.DELTA_LOOP, loop)
                result = self.run_checker()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_release_tests_need_the_scheduled_job_that_runs_the_release_gate(self):
        self.edit(".github/workflows/nightly-live.yml",
                  "- run: bash scripts/test-pinned-account-authorization.sh",
                  "# - run: bash scripts/test-pinned-account-authorization.sh")
        self.assert_red(self.run_checker(), "nightly-live.yml")

    def test_a_ci_step_the_workflow_does_not_run_fails(self):
        self.edit(".github/workflows/ci.yml", "      - run: bash scripts/test-something.sh\n", "")
        self.assert_red(self.run_checker(), "test-something.sh")

    def test_ci_must_run_this_self_test(self):
        self.edit(".github/workflows/ci.yml", "      - run: python3 scripts/test-check-mainnet-gates.py\n", "")
        self.assert_red(self.run_checker(), "test-check-mainnet-gates.py")

    def test_a_malformed_or_repeated_evidence_fence_is_refused(self):
        for new, message in [("``` gate-evidence G2", "an evidence fence must read exactly"),
                             ("```gate-evidence G2 (open)", "an evidence fence must read exactly"),
                             ("  ```gate-evidence G2", "an evidence fence must read exactly"),
                             ("~~~gate-evidence G2", "an evidence fence must read exactly"),
                             ("```gate-evidence G1", "G1 has a second evidence block")]:
            with self.subTest(fence=new):
                self.setUp()
                self.edit("docs/MAINNET-GATES.md", "```gate-evidence G2", new)
                self.assert_red(self.run_checker(), message)
                self.assertEqual(self.calls(), [])

    def test_a_gate_that_is_not_a_review_gate_needs_an_evidence_block(self):
        self.edit("docs/MAINNET-GATES.md",
                  "```gate-evidence G3\nci  crates/demo/tests/suite.rs  epsilon_holds\n```\n", "")
        self.assert_red(self.run_checker(), "G3 is open but has no evidence block")

    def test_a_closed_gate_needs_something_that_runs_in_ci(self):
        start = DOC.index("```gate-evidence G1")
        block = DOC[start:DOC.index("```\n", start + 3) + 4]
        self.edit("docs/MAINNET-GATES.md", block,
                  "```gate-evidence G1\nrelease  contracts/differential/tests/"
                  "account_wasm_invariants.rs  delta_holds\n```\n")
        self.assert_red(self.run_checker(), "G1 is closed but nothing it names runs in CI")

    def test_a_part_ci_does_not_run_fails(self):
        self.edit(".github/workflows/ci.yml", "--part wallet", "--part elsewhere")
        self.assert_red(self.run_checker(), "--part wallet")
        self.edit(".github/workflows/ci.yml", "--part elsewhere",
                  "--part elsewhere\n          # bash scripts/check-mainnet-gates.sh --part wallet")
        self.assert_red(self.run_checker(), "--part wallet")

    def test_the_table_must_match_the_architecture_gates(self):
        self.edit("docs/architecture.md", "- Fourth gate.\n", "- Fourth gate.\n- Fifth gate.\n")
        self.assert_red(self.run_checker(), "5")

    def test_status_and_evidence_rules(self):
        cases = [
            ("**closed** | below | none |", "**done** | below | none |", "G1"),
            ("```gate-evidence G3", "```gate-evidence G9\nci  crates/demo/tests/suite.rs  "
             "epsilon_holds\n```\n\n```gate-evidence G3", "no table row for G9"),
            ("| G4 | Fourth | **review**", "| G4 | Fourth | **closed**", "G4"),
            ("ci  crates/demo/tests/suite.rs  epsilon_holds", "ci  crates/demo/tests/suite.py  x", "suite.py"),
        ]
        for old, new, message in cases:
            with self.subTest(new=new):
                self.setUp()
                self.edit("docs/MAINNET-GATES.md", old, new)
                self.assert_red(self.run_checker(), message)

    def test_invalid_flags_stop_before_any_check(self):
        for arguments in [("--unknown",), ("--part",), ("--part", "nowhere"), ("--part", "host", "x")]:
            with self.subTest(arguments=arguments):
                result = self.run_checker(*arguments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.calls(), [])


class CommittedDocumentTests(unittest.TestCase):
    """Static only: every committed entry names something that exists in the real tree."""

    def plan(self, doc):
        return subprocess.run([sys.executable, str(SCRIPTS / "mainnet-gates-plan.py"),
                               "--root", str(ROOT), "--doc", str(doc)],
                              capture_output=True, text=True, check=False)

    def test_the_committed_document_passes_its_static_checks(self):
        result = self.plan(ROOT / "docs/MAINNET-GATES.md")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip(), "the plan names no checks")

    def test_renaming_any_committed_test_fails_the_static_checks(self):
        text = (ROOT / "docs/MAINNET-GATES.md").read_text(encoding="utf-8")
        entries = re.findall(r"^(?:ci|release)\s+\S+\s+(.+?)\s*$", text, flags=re.M)
        self.assertGreater(len(entries), 20, "too few named tests to be the committed document")
        with tempfile.TemporaryDirectory() as directory:
            doc = Path(directory) / "MAINNET-GATES.md"
            for name in sorted(set(entries)):
                with self.subTest(name=name):
                    renamed = re.sub(rf"^((?:ci|release)\s+\S+\s+){re.escape(name)}\s*$",
                                     lambda m: m.group(1) + name + "_renamed", text, flags=re.M)
                    doc.write_text(renamed, encoding="utf-8")
                    self.assertNotEqual(self.plan(doc).returncode, 0, name)


if __name__ == "__main__":
    unittest.main()
