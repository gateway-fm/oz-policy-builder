#!/usr/bin/env python3
"""Exercise the container publication boundary against a real temporary Git repository."""

import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest


EXPORTER = Path(__file__).with_name("hosted-context.py")
REPO = Path(__file__).resolve().parent.parent


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

    def test_a_build_script_never_enters_the_context(self):
        # build-runner's build.rs would set OZPB_TOOLKIT_SOURCE from git, which the context lacks,
        # and so overwrite the commit the image build passes in with an empty claim.
        (self.repo / "crates/example/build.rs").write_text("DO-NOT-PUBLISH")
        self.git("add", ".")
        self.commit()
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("crates/example/build.rs", self.files(result.stdout))

    def test_a_revision_cannot_be_a_git_option(self):
        result = subprocess.run(["python3", str(EXPORTER), "--repo", str(self.repo), "--", "--help"],
                                capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


class ImageRecordsTheExportedCommitTests(unittest.TestCase):
    """The API image's BuildManifests name the commit whose tree its context is, and no other.

    The context has no `.git` and no build script, so build-runner's producer record reads
    OZPB_TOOLKIT_SOURCE from the compiler's environment: the build stage's build argument.
    """

    def test_the_build_stage_takes_the_toolkit_source_before_compiling(self):
        dockerfile = (REPO / "deployment/Dockerfile").read_text()
        stage = dockerfile.split(" AS build\n", 1)[1].split("\nFROM ", 1)[0]
        declared = re.search(r"(?m)^ARG OZPB_TOOLKIT_SOURCE(=)?$", stage)
        self.assertIsNotNone(declared, "the build stage must declare ARG OZPB_TOOLKIT_SOURCE")
        self.assertLess(declared.start(), stage.index("cargo build"))
        self.assertNotIn("OZPB_TOOLKIT_SOURCE", dockerfile.split(" AS build\n", 1)[0])

    def test_each_image_workflow_claims_the_commit_it_exports(self):
        for workflow in ("self-hosted.yml", "publish-image.yml"):
            with self.subTest(workflow=workflow):
                text = (REPO / ".github/workflows" / workflow).read_text().replace("\\\n", " ")
                assigned = re.findall(r"(?m)^\s*(\w+)=\$\(git rev-parse --verify 'HEAD\^\{commit\}'\)$", text)
                exported = re.findall(r'python3 scripts/hosted-context\.py "\$(\w+)"', text)
                self.assertEqual(len(exported), 1, "one context export")
                self.assertIn(exported[0], assigned, "the export names a commit, not a moving ref")
                builds = [line for line in text.splitlines() if "docker build " in line]
                api = [line for line in builds if "--target proxy" not in line]
                self.assertEqual(len(api), 1, "one API image build")
                self.assertIn(f'--build-arg OZPB_TOOLKIT_SOURCE="${exported[0]}"', api[0])
                for line in builds:
                    if "--target proxy" in line:
                        self.assertNotIn("OZPB_TOOLKIT_SOURCE", line, "the proxy stage takes none")
                # The container check is told the same commit and refuses an image recording another.
                check = text.index("bash scripts/test-hosted-container.sh")
                told = re.findall(
                    r"(?m)^\s*export OZPB_TOOLKIT_COMMIT=\"\$\(git rev-parse --verify 'HEAD\^\{commit\}'\)\"$",
                    text[:check],
                )
                self.assertEqual(len(told), 1, "the container check is told the exported commit")
                self.assertIn("python3 -B scripts/test-check-hosted-build.py", text, "its comparator is tested")
                self.assertIn("python3 -B scripts/test-check-hosted-retention.py", text,
                              "its retention reader is tested")

    def test_the_container_check_reads_what_the_tool_session_retains(self):
        script = (REPO / "scripts/test-hosted-container.sh").read_text().replace("\\\n", " ")
        kept = script.index("logging: {driver: json-file}")
        override = script.index('compose+=(-f "$WORK/keep-output.yaml")')
        tool_session = script.index("scripts/check-hosted-build.py")
        retention = script.index("python3 scripts/check-hosted-retention.py")
        self.assertLess(kept, override, "the override that keeps output is written before it is used")
        self.assertLess(override, tool_session, "the tool session's containers keep their output")
        self.assertLess(tool_session, retention, "the retention check reads that session")
        for service in ("api", "tls"):
            self.assertIn(f"  {service}: {{logging: {{driver: json-file}}}}", script)


if __name__ == "__main__":
    unittest.main()
