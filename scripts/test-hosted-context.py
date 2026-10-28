#!/usr/bin/env python3
"""Exercise the container publication boundary against a real temporary Git repository."""

import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


EXPORTER = Path(__file__).with_name("hosted-context.py")


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        for name in (
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE-APACHE", "LICENSE-MIT",
            "deployment/Dockerfile", "deployment/entrypoint.sh", "deployment/install-tools.sh",
            "deployment/verify-offline.sh", "deployment/cargo-config.toml",
            "contracts/golden-transfer-policy/Cargo.lock",
            "contracts/golden-transfer-policy/Cargo.toml",
            "contracts/golden-transfer-policy/rust-toolchain.toml",
            "contracts/golden-transfer-policy/src/lib.rs",
            "contracts/golden-transfer-policy/src/contract.rs",
            "docs/examples/subscription-spec.json",
            "crates/example/Cargo.toml", "crates/example/src/lib.rs",
            ".github/workflows/nightly-live.yml",
        ):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("committed " + name)
        self.git("add", ".")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE)

    def commit(self):
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c",
                 "commit.gpgsign=false", "commit", "-qm", "fixture")

    def export(self):
        return subprocess.run(["python3", str(EXPORTER), "--repo", str(self.repo), "HEAD"],
                              capture_output=True, check=False)

    def files(self, data):
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            return {entry.name: archive.extractfile(entry).read() for entry in archive}

    def test_only_reviewed_paths_enter_context_even_when_other_files_are_tracked(self):
        for name in ("secret.env", "crates/example/tests/private.txt", "crates/example/src/private.env",
                     "testnet-harness/runs/secret.json", "deployment/token.secret", ".gitconfig"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("DO-NOT-PUBLISH")
        self.git("add", ".")
        self.commit()
        (self.repo / "crates/example/src/untracked.rs").write_text("DO-NOT-PUBLISH")
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"DO-NOT-PUBLISH", result.stdout)
        files = self.files(result.stdout)
        self.assertIn("crates/example/src/lib.rs", files)
        self.assertIn("LICENSE-APACHE", files)

    def test_dirty_working_copy_cannot_override_committed_content(self):
        (self.repo / "crates/example/src/lib.rs").write_text("DO-NOT-PUBLISH")
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.files(result.stdout)["crates/example/src/lib.rs"],
                         b"committed crates/example/src/lib.rs")

    def test_export_is_byte_identical(self):
        first, second = self.export(), self.export()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_selected_symlink_refuses_export(self):
        path = self.repo / "crates/example/src/lib.rs"
        path.unlink()
        path.symlink_to("/etc/passwd")
        self.git("add", ".")
        self.commit()
        result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"regular file", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_missing_toolchain_refuses_export(self):
        self.git("rm", "-q", "rust-toolchain.toml")
        self.commit()
        result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"required", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_crate_submodule_refuses_export(self):
        commit = self.git("rev-parse", "HEAD").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "160000," + commit + ",crates/external")
        self.commit()
        result = self.export()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"submodule", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_a_revision_cannot_be_a_git_option(self):
        result = subprocess.run(["python3", str(EXPORTER), "--repo", str(self.repo), "--", "--help"],
                                capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
