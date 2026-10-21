#!/usr/bin/env python3
"""Exercise immutable overlay inputs and refusal before changing an upstream checkout."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("overlay", Path(__file__).with_name("apply-pollywallet.py"))
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def commit(root):
    git(root, "add", ".")
    git(root, "-c", "commit.gpgsign=false", "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    return git(root, "rev-parse", "HEAD").decode().strip()


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.repo, self.checkout = base / "toolkit", base / "upstream"
        for root in [self.repo, self.checkout]:
            root.mkdir()
            git(root, "init", "-q")
            git(root, "config", "core.hooksPath", "/dev/null")
        for name in overlay.PATCH_PATHS | {"README.md"}:
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("before\n")
        self.upstream = commit(self.checkout)
        for name in overlay.REQUIRED:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        self.write("wallet/overlay/upstream.patch",
                   "--- a/src/lib/passkey.ts\n+++ b/src/lib/passkey.ts\n"
                   "@@ -1 +1 @@\n-before\n+after\n")
        self.write("wallet/overlay/files/src/routes/policy-builder.tsx", "fixture route\n")
        self.revision = commit(self.repo)
        self.patch = patch.object(overlay, "UPSTREAM", self.upstream)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write(self, relative, value):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def apply(self):
        return overlay.apply(self.repo, self.revision, self.checkout)

    def assert_unchanged(self):
        self.assertEqual((self.checkout / "src/lib/passkey.ts").read_text(), "before\n")
        self.assertFalse((self.checkout / "src/policy-builder").exists())

    def test_reads_immutable_tree_and_preserves_license_not_dirty_working_copy(self):
        self.write("wallet/overlay/files/src/routes/policy-builder.tsx", "uncommitted secret")
        tree = self.apply()
        self.assertEqual(tree, git(self.repo, "rev-parse", self.revision + "^{tree}").decode().strip())
        self.assertEqual((self.checkout / "src/routes/policy-builder.tsx").read_text(), "fixture route\n")
        self.assertEqual((self.checkout / "src/lib/passkey.ts").read_text(), "after\n")
        self.assertEqual((self.checkout / "src/policy-builder/LICENSE-APACHE").read_text(), "fixture\n")

    def test_wrong_revision_dirty_or_untracked_checkout_is_refused(self):
        for kind in ("revision", "dirty", "untracked"):
            with self.subTest(kind=kind):
                if kind == "revision":
                    with patch.object(overlay, "UPSTREAM", "0" * 40), self.assertRaises(overlay.Refused):
                        self.apply()
                elif kind == "dirty":
                    target = self.checkout / "README.md"
                    target.write_text("dirty")
                    with self.assertRaises(overlay.Refused):
                        self.apply()
                    git(self.checkout, "checkout", "--", "README.md")
                else:
                    target = self.checkout / "untracked"
                    target.write_text("fixture")
                    with self.assertRaises(overlay.Refused):
                        self.apply()
                    target.unlink()
                self.assert_unchanged()

    def test_incomplete_or_symlink_source_is_refused(self):
        target = self.repo / "wallet/package-lock.json"
        target.unlink()
        self.revision = commit(self.repo)
        with self.assertRaises(overlay.Refused):
            self.apply()
        self.assert_unchanged()
        target.symlink_to("../LICENSE-MIT")
        self.revision = commit(self.repo)
        with self.assertRaises(overlay.Refused):
            self.apply()
        self.assert_unchanged()

    def test_patch_cannot_rename_an_unlisted_upstream_path(self):
        self.write("wallet/overlay/upstream.patch",
                   "diff --git a/README.md b/stolen.md\nsimilarity index 100%\n"
                   "rename from README.md\nrename to stolen.md\n")
        self.revision = commit(self.repo)
        with self.assertRaises(overlay.Refused):
            self.apply()
        self.assert_unchanged()
        self.assertTrue((self.checkout / "README.md").exists())

    def test_patch_cannot_modify_unlisted_binary_without_text_headers(self):
        target = self.checkout / "README.md"
        target.write_bytes(b"before\x00")
        self.upstream = commit(self.checkout)
        target.write_bytes(b"after\x00")
        data = git(self.checkout, "diff", "--binary")
        git(self.checkout, "checkout", "--", "README.md")
        self.write("wallet/overlay/upstream.patch", data.decode())
        self.revision = commit(self.repo)
        with patch.object(overlay, "UPSTREAM", self.upstream), self.assertRaises(overlay.Refused):
            self.apply()
        self.assertEqual(target.read_bytes(), b"before\x00")
        self.assert_unchanged()

    def test_existing_ignored_destination_and_symlink_are_refused(self):
        git(self.checkout, "config", "status.showUntrackedFiles", "no")
        (self.checkout / ".git/info/exclude").write_text("src/policy-builder/\n")
        target = self.checkout / "src/policy-builder"
        target.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(overlay.Refused):
            self.apply()
        self.assertEqual((self.checkout / "src/lib/passkey.ts").read_text(), "before\n")


if __name__ == "__main__":
    unittest.main()
