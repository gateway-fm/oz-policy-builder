#!/usr/bin/env python3
"""Exercise coverage-gate failures against a passing permit/deny report."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).with_name("check-unmodeled-acknowledged.py")
ENTRY = "rule[0]: oz:spending_limit"
ACK = f"subscription|{ENTRY}\n"


def report() -> dict:
    return {
        "all_agree": True,
        "total": 2,
        "disagreements": 0,
        "missing_classes": [],
        "permit_only_classes": [],
        "unmodeled_reviewed_policies": [ENTRY],
        "report": {
            "layer": "layer1-reference-evaluator",
            "outcomes": [
                {"class": "original", "expected": "permit", "actual": "permit", "agree": True},
                {"class": "wrong_signer", "expected": "deny", "actual": "deny(NoSignerMatched)", "agree": True},
            ],
        },
    }


def run(value=None, ack=ACK, names=None, raw=None):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ack.txt"
        path.write_text(ack, encoding="utf-8")
        arguments = (["--known-specs", str(path), *names] if names is not None
                     else ["subscription", str(path)])
        return subprocess.run(
            [sys.executable, str(CHECKER), *arguments],
            input=raw if raw is not None else json.dumps(value if value is not None else report()),
            text=True, capture_output=True, check=False,
        )


class CoverageGateTests(unittest.TestCase):
    def assert_failure(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_exact_acknowledgement_passes_and_names_the_limitation(self):
        result = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"NOT MODELED BY LAYER 1: {ENTRY}", result.stdout)

    def test_no_composed_policy_needs_no_acknowledgement(self):
        value = report()
        value["unmodeled_reviewed_policies"] = []
        self.assertEqual(run(value, ack="# no gaps\n").returncode, 0)

    def test_new_and_stale_gaps_fail(self):
        self.assert_failure(run(ack=""), "unacknowledged policies=['rule[0]: oz:spending_limit']")
        value = report()
        value["unmodeled_reviewed_policies"] = []
        self.assert_failure(run(value), "stale acknowledgements=['rule[0]: oz:spending_limit']")

    def test_acknowledgement_cannot_hide_disagreement_or_missing_coverage(self):
        for key, value, error in [
            ("all_agree", False, "all_agree"),
            ("all_agree", "true", "all_agree"),
            ("disagreements", 1, "zero disagreements"),
            ("disagreements", False, "zero disagreements"),
            ("missing_classes", ["rule[0]: WrongSigner"], "missing required boundary"),
            ("total", 0, "positive number"),
            ("total", True, "positive number"),
        ]:
            with self.subTest(key=key, value=value):
                changed = report()
                changed[key] = value
                self.assert_failure(run(changed), error)

    def test_permit_only_classes_remain_visible(self):
        value = report()
        value["permit_only_classes"] = ["rule[0]: TimeBoundary"]
        result = run(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no denial demonstrated", result.stdout)

    def test_unchecked_specs_cannot_be_preacknowledged(self):
        self.assertEqual(run(names=["subscription"]).returncode, 0)
        self.assert_failure(run(ack=ACK + "future|rule[0]: oz:spending_limit\n",
                                names=["subscription"]), "unchecked specs: ['future']")
        self.assert_failure(run(names=["subscription", "subscription"]), "must be unique")

    def test_malformed_and_duplicate_acknowledgements_fail(self):
        for text in ["subscription", "|rule[0]: oz:spending_limit", "subscription|",
                     "subscription|rule[01]: oz:spending_limit", "subscription|x|y"]:
            with self.subTest(text=text):
                self.assert_failure(run(ack=text), "ack.txt:1:")
        self.assert_failure(run(ack=ACK + ACK), "duplicate acknowledgement")

    def test_missing_malformed_and_duplicate_report_fields_fail(self):
        for key in ["missing_classes", "permit_only_classes", "unmodeled_reviewed_policies"]:
            for bad in [None, "", [1], [""], ["duplicate", "duplicate"]]:
                with self.subTest(key=key, bad=bad):
                    value = report()
                    value[key] = bad
                    self.assert_failure(run(value), key)
        self.assert_failure(run(raw="[]"), "JSON object")
        self.assert_failure(run(raw='{"all_agree": false, "all_agree": true}'), "duplicate JSON key")
        self.assert_failure(run(raw="not JSON"), "reference coverage check failed")

    def test_summary_cannot_hide_missing_or_failed_outcomes(self):
        base = report()
        for mutation, message in [
            ({"layer": "layer2"}, "labeled layer1"),
            ({"outcomes": []}, "case count"),
            ({"outcomes": [{}, {}]}, "disagreeing outcome"),
        ]:
            value = copy.deepcopy(base)
            value["report"].update(mutation)
            self.assert_failure(run(value), message)
        for actual in ["permit", "indeterminate(UnmodeledPolicy)"]:
            value = report()
            value["report"]["outcomes"][1]["actual"] = actual
            self.assert_failure(run(value), "contradicts")

    def test_permit_and_deny_controls_are_required(self):
        for index, message in [(0, "original control"), (1, "denial control")]:
            value = report()
            value["report"]["outcomes"].pop(index)
            value["total"] = 1
            self.assert_failure(run(value), message)


if __name__ == "__main__":
    unittest.main()
