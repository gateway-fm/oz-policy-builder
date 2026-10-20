#!/usr/bin/env python3
"""Protocol and launcher tests; kernel containment is tested separately on Linux."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("worker_launcher", ROOT / "deployment/worker-launcher.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def config():
    return dict(image="sha256:" + "a" * 64, timeout_seconds=600, cpus=2,
                memory_mib=4096, pids=256, tmpfs_mib=3072, jobs=1)


def job():
    return dict(schema="build-worker-job/v1", crate_name="fixture", timeout_seconds=1, jobs=1,
                files=[dict(path=name, body="fixture") for name in sorted(worker.FILES)])


class LauncherTests(unittest.TestCase):
    def test_configuration_requires_immutable_image_and_safe_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for changes in ({"image": "example.com/worker:latest"}, {"timeout_seconds": 0},
                            {"cpus": 0}, {"pids": 10000}, {"tmpfs_mib": 5000},
                            {"jobs": 3}, {"privileged": True}):
                path.write_text(json.dumps(config() | changes))
                with self.subTest(changes=changes), self.assertRaises(worker.Refused):
                    worker.load_config(path)
            path.write_text(json.dumps(config()))
            self.assertEqual(worker.load_config(path), config())
            path.chmod(0o666)
            with self.assertRaises(worker.Refused):
                worker.load_config(path)

    def test_duplicate_json_keys_cannot_override_the_job(self):
        with self.assertRaises(worker.Refused):
            worker.decode('{"jobs":1,"jobs":2}')

    def test_extra_traversal_duplicate_and_oversized_files_are_refused(self):
        for mutation in ("../Cargo.toml", "build.rs", "src/contract.rs"):
            value = job()
            value["files"][0]["path"] = mutation
            with self.subTest(path=mutation), self.assertRaises(worker.Refused):
                worker.validate_job(json.dumps(value).encode(), config())
        value = job()
        value["files"][0]["body"] = "x" * (2 * 1024 * 1024 + 1)
        with self.assertRaises(worker.Refused):
            worker.validate_job(json.dumps(value).encode(), config())

    def test_job_cannot_select_resources_above_operator_limits(self):
        for changes in ({"jobs": 2}, {"timeout_seconds": 601}, {"image": "evil"}, {"command": ["sh"]}):
            with self.subTest(changes=changes), self.assertRaises(worker.Refused):
                worker.validate_job(json.dumps(job() | changes).encode(), config())

    def test_container_options_enforce_private_state_and_independent_deadline(self):
        args = worker.command(config(), "ozpb-job-test", job())
        # Podman rejects any DNS option together with the disconnected network mode.
        self.assertNotIn("--dns", args)
        for flag, value in (("--network", "none"), ("--pid", "private"), ("--ipc", "private"),
                            ("--userns", "nomap"), ("--pull", "never"), ("--timeout", "36"),
                            ("--cap-drop", "ALL"), ("--memory", "4096m"),
                            ("--memory-swap", "4096m"), ("--log-driver", "none")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--read-only-tmpfs=false", args)
        self.assertIn("--unsetenv-all", args)
        self.assertIn("--http-proxy=false", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--volume", args)
        self.assertNotIn("--mount", args)
        self.assertIn("exec,nosuid,nodev", args[args.index("--tmpfs") + 1])
        self.assertEqual(args[-2:], [config()["image"], "/usr/local/bin/ozpb-build-worker"])

    def test_worker_cannot_forge_the_launcher_cleanup_frame(self):
        forged = dict(schema="contained-build-result/v1", containment="removed", job_hash="a" * 64, result=None)
        with self.assertRaises(worker.Refused):
            worker.worker_result(json.dumps(forged).encode())

    def test_success_is_framed_only_after_confirmed_removal(self):
        events = []
        def run(args, *_):
            events.append("run")
            return 0, b'{"schema":"build-worker-result/v1","artifact":null}'
        def removed(_):
            events.append("removed")
            return True
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", run), mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        self.assertEqual(events, ["run", "removed"])
        self.assertEqual(frame["containment"], "removed")

    def test_unconfirmed_cleanup_never_emits_a_result(self):
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", return_value=(1, b"secret")), mock.patch.object(worker, "removed", return_value=False):
            with self.assertRaises(worker.Refused):
                worker.launch(json.dumps(job()).encode(), config())

    def test_timeout_cleans_up_before_returning_a_redacted_failure(self):
        removed = mock.Mock(return_value=True)
        with mock.patch.object(worker, "preflight"), mock.patch.object(worker, "bounded", side_effect=worker.Refused()), mock.patch.object(worker, "removed", removed):
            frame = worker.launch(json.dumps(job()).encode(), config())
        removed.assert_called_once()
        self.assertIsNone(frame["result"])

    def test_storage_error_is_not_successful_removal(self):
        for code in (0, 125):
            with mock.patch.object(worker, "bounded", side_effect=[(0, b""), (code, b"")]):
                self.assertFalse(worker.removed("ozpb-job-test"))
        with mock.patch.object(worker, "bounded", side_effect=[(1, b""), (1, b"")]):
            self.assertTrue(worker.removed("ozpb-job-test"))

    def test_validation_before_launch_does_not_poison_capacity(self):
        with mock.patch.object(worker, "preflight", side_effect=worker.Refused()), mock.patch.object(worker, "bounded") as run:
            frame = worker.launch(json.dumps(job()).encode(), config())
        run.assert_not_called()
        self.assertEqual(frame["containment"], "removed")

    def test_output_capture_is_actually_bounded(self):
        with self.assertRaises(worker.Refused):
            worker.bounded([sys.executable, "-c", "import sys;sys.stdout.write('x'*8192)"], 2, 1024)
        self.assertEqual(worker.bounded([sys.executable, "-c", "print('ok')"], 2, 1024), (0, b"ok\n"))


if __name__ == "__main__":
    unittest.main()
