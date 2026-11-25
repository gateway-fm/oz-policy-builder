#!/usr/bin/env python3
"""Focused checks for the hosted-build checker's producer record assertion."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "check_hosted_build", Path(__file__).with_name("check-hosted-build.py")
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

COMMIT = "a" * 40


def manifest(toolkit_source):
    return {"producer": {"toolkit_source": toolkit_source, "template_pack": "0" * 64, "build_image": None}}


class ToolkitSourceTest(unittest.TestCase):
    def test_the_clean_commit_the_image_was_built_from_passes(self):
        self.assertIsNone(CHECKER.toolkit_source_problem(manifest({"commit": COMMIT, "dirty": False}), COMMIT))

    def test_no_recorded_commit_is_refused(self):
        self.assertIsNotNone(CHECKER.toolkit_source_problem(manifest(None), COMMIT))
        self.assertIsNotNone(CHECKER.toolkit_source_problem({}, COMMIT))

    def test_another_commit_is_refused(self):
        self.assertIsNotNone(CHECKER.toolkit_source_problem(manifest({"commit": "b" * 40, "dirty": False}), COMMIT))

    def test_a_dirty_checkout_is_refused(self):
        self.assertIsNotNone(CHECKER.toolkit_source_problem(manifest({"commit": COMMIT, "dirty": True}), COMMIT))


if __name__ == "__main__":
    unittest.main()
