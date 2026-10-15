#!/usr/bin/env python3
"""Exercise coverage-gate failures against a passing permit/deny report."""

import copy
import json
import os
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
        "coverage": ["Original: 1", "WrongSigner: 1"],
        "report": {
            "layer": "layer1-reference-evaluator",
            "total": 2, "agreements": 2, "disagreements": 0,
            "expected_classes": {"0": ["original", "wrong_signer"]},
            "coverage": [["original", 1], ["wrong_signer", 1]],
            "coverage_by_rule": {"0": {"original": 1, "wrong_signer": 1}},
            "unmodeled_policies": [{"rule_index": 0, "kind": "oz:spending_limit"}],
            "outcomes": [
                {"rule_index": 0, "class": "original", "expected": "permit", "actual": "permit", "agree": True},
                {"rule_index": 0, "class": "wrong_signer", "expected": "deny", "actual": "deny(NoSignerMatched)", "agree": True},
            ],
        },
    }


def permit_only_report() -> dict:
    value = report()
    value["total"] = value["report"]["total"] = value["report"]["agreements"] = 3
    value["report"]["outcomes"].append({"rule_index": 0, "class": "time_boundary",
                                       "expected": "permit", "actual": "permit", "agree": True})
    value["report"]["coverage"].append(["time_boundary", 1])
    value["report"]["coverage_by_rule"]["0"]["time_boundary"] = 1
    value["report"]["expected_classes"]["0"].append("time_boundary")
    value["coverage"].append("TimeBoundary: 1")
    value["permit_only_classes"] = ["rule[0]: TimeBoundary"]
    return value


def two_rule_report() -> dict:
    value = report()
    value["total"] = value["report"]["total"] = value["report"]["agreements"] = 4
    value["coverage"] = ["Original: 2", "WrongSigner: 2"]
    value["report"]["coverage"] = [["original", 2], ["wrong_signer", 2]]
    value["report"]["coverage_by_rule"]["1"] = {"original": 1, "wrong_signer": 1}
    value["report"]["expected_classes"]["1"] = ["original", "wrong_signer"]
    value["report"]["outcomes"] += [dict(row, rule_index=1) for row in value["report"]["outcomes"]]
    return value


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


def run_specs(specs, ack=ACK, fail_spec="", raw=None, input_spec=None):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "ack.txt").write_text(ack, encoding="utf-8")
        (root / "report.json").write_text(raw if raw is not None else json.dumps(report()), encoding="utf-8")
        if input_spec is None:
            input_spec = {"rules": [{"policies": [{"reviewed": {"kind": "oz:spending_limit"}}, {"generated": {}}]}]}
        for binding in specs:
            _, separator, path = binding.partition("=")
            if separator and path:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(input_spec), encoding="utf-8")
        cargo = root / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
from pathlib import Path
root = Path(os.environ["GATE_FIXTURE"])
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
print((root / "report.json").read_text())
if Path(sys.argv[-1]).name == os.environ["GATE_FAIL_SPEC"]:
    sys.exit(9)
''', encoding="utf-8")
        cargo.chmod(0o755)
        environment = dict(os.environ, PATH=str(root), GATE_FIXTURE=str(root), GATE_FAIL_SPEC=fail_spec)
        result = subprocess.run([sys.executable, str(CHECKER), "--run", "ack.txt", *specs],
                                cwd=root, env=environment, text=True, capture_output=True, check=False)
        calls = root / "calls.jsonl"
        return result, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []


class CoverageGateTests(unittest.TestCase):
    def assert_failure(self, result, message=""):
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
        value["report"]["unmodeled_policies"] = []
        self.assertEqual(run(value, ack="# no gaps\n").returncode, 0)

    def test_new_and_stale_gaps_fail(self):
        self.assert_failure(run(ack=""), "unacknowledged policies=['rule[0]: oz:spending_limit']")
        value = report()
        value["unmodeled_reviewed_policies"] = []
        value["report"]["unmodeled_policies"] = []
        self.assert_failure(run(value), "stale acknowledgements=['rule[0]: oz:spending_limit']")

    def test_acknowledgement_cannot_hide_disagreement_or_missing_coverage(self):
        for key, value, error in [
            ("all_agree", False, "all_agree"),
            ("all_agree", "true", "all_agree"),
            ("disagreements", 1, "zero disagreements"),
            ("disagreements", False, "zero disagreements"),
            ("missing_classes", ["rule[0]: WrongSigner"], "missing_classes contradicts"),
            ("total", 0, "positive number"),
            ("total", True, "positive number"),
        ]:
            with self.subTest(key=key, value=value):
                changed = report()
                changed[key] = value
                self.assert_failure(run(changed), error)

    def test_permit_only_classes_remain_visible(self):
        value = permit_only_report()
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
        self.assert_failure(run(ack=ACK + ACK), "stale acknowledgements")

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
            value["total"] = value["report"]["total"] = value["report"]["agreements"] = 1
            self.assert_failure(run(value), message)

    def test_summary_cannot_hide_an_expected_class_without_outcomes(self):
        value = report()
        value["report"]["expected_classes"]["0"].append("numeric_boundary")
        self.assert_failure(run(value), "missing_classes contradicts evidence")
        value["missing_classes"] = ["rule[0]: NumericBoundary"]
        self.assert_failure(run(value), "missing required boundary classes")

    def test_each_declared_rule_needs_outcomes(self):
        value = report()
        value["report"]["expected_classes"]["1"] = ["original", "wrong_signer"]
        self.assert_failure(run(value), "rule[1] has no passing original control")

    def test_controls_are_required_per_rule(self):
        self.assertEqual(run(two_rule_report()).returncode, 0)
        for index, error in [(2, "original control"), (3, "denial control")]:
            value = two_rule_report()
            value["report"]["outcomes"].pop(index)
            value["total"] = value["report"]["total"] = value["report"]["agreements"] = 3
            self.assert_failure(run(value), f"rule[1] has no passing {error}")

    def test_summary_cannot_hide_a_permit_only_class(self):
        value = permit_only_report()
        value["permit_only_classes"] = []
        self.assert_failure(run(value), "permit_only_classes contradicts evidence")

    def test_summary_cannot_hide_an_unmodeled_policy(self):
        value = report()
        value["report"]["unmodeled_policies"].append({"rule_index": 0, "kind": "oz:other"})
        self.assert_failure(run(value), "unmodeled_reviewed_policies contradicts")

    def test_summary_cannot_contradict_nested_counts(self):
        for key, count in [("total", 3), ("agreements", 1), ("disagreements", 1), ("disagreements", False)]:
            value = report()
            value["report"][key] = count
            self.assert_failure(run(value), f"evidence {key} contradicts")

    def test_coverage_counts_must_match_actual_outcomes(self):
        for field, bad, error in [("coverage", [["original", 1]], "coverage contradicts"),
                                  ("coverage", [["original", True]], "positive integer"),
                                  ("coverage_by_rule", {"0": {"original": 2}}, "coverage_by_rule contradicts")]:
            value = report()
            value["report"][field] = bad
            self.assert_failure(run(value), error)
        value = report()
        value["coverage"] = ["Original: 20", "WrongSigner: 20"]
        self.assert_failure(run(value), "summary coverage contradicts")

    def test_duplicate_policy_kinds_need_the_exact_number_of_acknowledgements(self):
        value = report()
        value["report"]["unmodeled_policies"] *= 2
        value["unmodeled_reviewed_policies"] *= 2
        self.assertEqual(run(value, ack=ACK * 2).returncode, 0)
        self.assert_failure(run(value), "unacknowledged policies")
        self.assert_failure(run(value, ack=ACK * 3), "stale acknowledgements")
        value["unmodeled_reviewed_policies"].pop()
        self.assert_failure(run(value, ack=ACK * 2), "unmodeled_reviewed_policies contradicts")

    def test_rule_and_policy_evidence_rejects_malformed_fields(self):
        for bad in [None, {}, {"0": []}, {"01": ["original"]}, {"0": [1]}]:
            value = report()
            value["report"]["expected_classes"] = bad
            self.assert_failure(run(value))
        for key, bad in [("rule_index", True), ("rule_index", 1), ("class", None)]:
            value = report()
            value["report"]["outcomes"][0][key] = bad
            self.assert_failure(run(value))
        for bad in [None, [1], [{"rule_index": 0, "kind": ""}], [{"rule_index": 1, "kind": "oz:other"}]]:
            value = report()
            value["report"]["unmodeled_policies"] = bad
            self.assert_failure(run(value))

    def test_runner_executes_every_declared_spec_with_its_bound_path(self):
        result, calls = run_specs(["subscription=first spec.json", "other=second.json"],
                                 ack=ACK + f"other|{ENTRY}\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([Path(call[-1]).name for call in calls], ["first spec.json", "second.json"])
        self.assertTrue(all(call[-2] == "--spec" and Path(call[-1]).is_absolute() for call in calls))
        self.assertIn("All 2 declared reference suites ran and passed", result.stdout)

    def test_runner_rejects_unchecked_names_and_bad_bindings_before_running(self):
        for specs in [["other=other.json"], ["subscription"], ["subscription="],
                      ["subscription=a", "subscription=b"]]:
            result, calls = run_specs(specs)
            self.assert_failure(result)
            self.assertEqual(calls, [])

    def test_runner_checks_later_specs_and_propagates_producer_failure(self):
        result, calls = run_specs(["subscription=first.json", "other=second.json"],
                                 ack=ACK + f"other|{ENTRY}\n", fail_spec="second.json")
        self.assert_failure(result, "returned non-zero exit status 9")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("All 2 declared", result.stdout)
        result, _ = run_specs(["subscription=first.json"], raw="not JSON")
        self.assert_failure(result, "reference coverage check failed")

    def test_runner_catches_a_rule_omitted_from_evidence_and_summary(self):
        rule = {"policies": [{"reviewed": {"kind": "oz:spending_limit"}}]}
        result, _ = run_specs(["subscription=spec.json"], input_spec={"rules": [rule, rule]})
        self.assert_failure(result, "evidence rule set differs from the input spec")

    def test_runner_catches_reviewed_policy_omissions_and_preserves_multiplicity(self):
        for kind in ["oz:other", "oz:spending_limit"]:
            spec = {"rules": [{"policies": [{"reviewed": {"kind": "oz:spending_limit"}},
                                            {"reviewed": {"kind": kind}}]}]}
            result, _ = run_specs(["subscription=spec.json"], input_spec=spec)
            self.assert_failure(result, "evidence reviewed-policy counts differ from the input spec")
        value = report()
        value["report"]["unmodeled_policies"] *= 2
        value["unmodeled_reviewed_policies"] *= 2
        result, _ = run_specs(["subscription=spec.json"], input_spec=spec, raw=json.dumps(value), ack=ACK * 2)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runner_refuses_unrecognized_spec_shapes_before_execution(self):
        for spec in [{}, {"rules": []}, {"rules": [None]},
                     {"rules": [{"policies": [{"unknown": {}}]}]},
                     {"rules": [{"policies": [{"reviewed": {"kind": ""}}]}]}]:
            result, calls = run_specs(["subscription=spec.json"], input_spec=spec)
            self.assert_failure(result, "input spec")
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
