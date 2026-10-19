#!/usr/bin/env python3
"""Exercise actual rootless kernel containment, including independent cleanup after SIGKILL.

Run on the intended Linux host under a dedicated unprivileged account with cgroup v2
delegation. Images must already be loaded; no registry contact or publication occurs here.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("worker_launcher", ROOT / "deployment/worker-launcher.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def run(*args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=True)
    return result.stdout


def assert_no_job_processes(name, identities):
    if subprocess.run([worker.PODMAN, "container", "exists", name], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=10).returncode != 1:
        raise RuntimeError("runtime did not remove the disposable container")
    for pid, identity in identities.items():
        path = Path("/proc") / pid / "stat"
        try:
            current = path.read_text().split(") ", 1)[1].split()[19]
        except FileNotFoundError:
            continue
        if current == identity:
            raise RuntimeError("a process escaped disposable container teardown")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable local image ID")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        parser.error("use the immutable local image ID, including sha256:")
    worker.preflight()
    if subprocess.run([worker.PODMAN, "ps", "--all", "--filter", "label=org.ozpb.worker=true", "--quiet"],
                      stdout=subprocess.PIPE, check=True).stdout.strip():
        raise SystemExit("use a dedicated account with no existing worker jobs")

    with tempfile.TemporaryDirectory(prefix="ozpb-containment-") as directory:
        private = Path(directory)
        canary = private / "host-secret"
        canary.write_text("secret canary must not enter any worker")
        config = dict(image=args.image, timeout_seconds=600, cpus=2, memory_mib=4096,
                      pids=256, tmpfs_mib=3072, jobs=1)
        golden = ROOT / "contracts/golden-transfer-policy"
        files = {path: (golden / path).read_text() for path in worker.FILES if path != "rustfmt.toml"}
        files["rustfmt.toml"] = ""
        raw = json.dumps(dict(schema="build-worker-job/v1",
            crate_name=tomllib.loads(files["Cargo.toml"])["package"]["name"],
            timeout_seconds=600, jobs=1,
            files=[dict(path=path, body=body) for path, body in sorted(files.items())])).encode()
        artifacts = []
        for _ in range(2):
            frame = worker.launch(raw, config)
            result = frame["result"]
            if frame["containment"] != "removed" or result is None or result["artifact"] is None:
                raise RuntimeError("real disposable compilation failed")
            artifact = result["artifact"]
            wasm = base64.b64decode(artifact["wasm_base64"], validate=True)
            if (not wasm.startswith(b"\0asm\x01\0\0\0")
                    or hashlib.sha256(wasm).hexdigest() != artifact["wasm_hash"]
                    or artifact["toolchain"]["builder"] != "local-unattested"):
                raise RuntimeError("real disposable artifact identity failed")
            artifacts.append(artifact)
        if artifacts[0] != artifacts[1]:
            raise RuntimeError("separate disposable builds did not reproduce")
        print("real offline Wasm reproduced in two fresh disposable workers: passed")
        # A synthetic worker image tests hostile process behavior under the exact production
        # launcher command. Only an immutable image ID enters that command.
        probe_context = private / "probe-context"
        probe_context.mkdir()
        (probe_context / "worker-probe.py").write_bytes((ROOT / "scripts/worker-probe.py").read_bytes())
        (probe_context / "Containerfile").write_text(
            "FROM " + args.image + "\nCOPY --chmod=0555 worker-probe.py /usr/local/bin/ozpb-build-worker\n")
        probe_image = run(worker.PODMAN, "build", "--pull=never", "--quiet", "--file", str(probe_context / "Containerfile"),
                          str(probe_context), timeout=180).decode().strip().splitlines()[-1]
        if not probe_image.startswith("sha256:"):
            probe_image = "sha256:" + probe_image
        config["image"] = probe_image
        config_path = private / "worker.json"
        config_path.write_text(json.dumps(config))
        worker.load_config(config_path)
        def job(name):
            return json.dumps(dict(schema="build-worker-job/v1", crate_name=name, timeout_seconds=1, jobs=1,
                                   files=[dict(path=path, body=str(canary)) for path in sorted(worker.FILES)])).encode()

        # The wrapper calls the production launcher implementation with a private test config.
        # It changes neither command flags nor cleanup logic.
        wrapper = private / "launcher.py"
        wrapper.write_text("import importlib.util,json,sys\n"
            + "spec=importlib.util.spec_from_file_location('launcher'," + repr(str(ROOT / "deployment/worker-launcher.py")) + ")\n"
            + "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
            + "from pathlib import Path\n"
            + "print(json.dumps(m.launch(sys.stdin.buffer.read(m.MAX_JOB+1),m.load_config(Path(" + repr(str(config_path)) + ")))))\n")
        launcher_environment = dict(os.environ, OZPB_SECRET_CANARY="secret", OZPB_HTTP_BEARER_TOKEN="must-not-enter-worker")
        try:
            for _ in range(2):
                response = subprocess.run([sys.executable, "-I", str(wrapper)], input=job("probe-clean"),
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=launcher_environment, timeout=60, check=True)
                frame = worker.decode(response.stdout)
                if frame["containment"] != "removed" or frame["result"] is None:
                    raise RuntimeError("secret/egress/private-cache/resource-limit probe failed")
            print("worker secret, egress, readonly root, resource ceilings and fresh cache: passed")

            config_path.write_text(json.dumps(config | dict(cpus=1, memory_mib=256, pids=16, tmpfs_mib=64)))
            response = subprocess.run([sys.executable, "-I", str(wrapper)], input=job("probe-exhaustion"),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=launcher_environment, timeout=60, check=True)
            if worker.decode(response.stdout)["result"] is None:
                raise RuntimeError("PID or tmpfs exhaustion did not stop at the configured ceiling")
            config_path.write_text(json.dumps(config))
            print("adversarial fork and tmpfs writes stopped at small configured limits: passed")

            for kill_launcher in (False, True):
                with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as output:
                    source.write(job("probe-escape")); source.seek(0)
                    process = subprocess.Popen([sys.executable, "-I", str(wrapper)], stdin=source,
                        stdout=output, stderr=subprocess.DEVNULL, env=launcher_environment, start_new_session=True)
                    name, identities = None, {}
                    try:
                        for _ in range(100):
                            names = run(worker.PODMAN, "ps", "--filter", "label=org.ozpb.worker=true", "--format", "{{.Names}}").decode().splitlines()
                            if names:
                                name = names[0]
                                marker = subprocess.run([worker.PODMAN, "exec", name, "test", "-f", "/tmp/ozpb/escaped-marker"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                                if marker.returncode != 0:
                                    time.sleep(0.1)
                                    continue
                                pids = run(worker.PODMAN, "top", name, "hpid").decode().splitlines()[1:]
                                if len(pids) >= 2:
                                    for pid in pids:
                                        pid = pid.strip()
                                        identities[pid] = (Path("/proc") / pid / "stat").read_text().split(") ", 1)[1].split()[19]
                                    break
                            time.sleep(0.1)
                        if not name or len(identities) < 2:
                            raise RuntimeError("escaped-session probe did not start")
                        if kill_launcher:
                            process.kill()
                        # Runtime timeout is 1s job +35s tool-probe grace. It must survive
                        # launcher death; do not call cleanup until this assertion is done.
                        deadline = time.monotonic() + 45
                        while time.monotonic() < deadline:
                            exists = subprocess.run([worker.PODMAN, "container", "exists", name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode
                            if exists == 1:
                                break
                            time.sleep(0.2)
                        assert_no_job_processes(name, identities)
                        process.wait(timeout=10)
                        if not kill_launcher:
                            output.seek(0)
                            frame = worker.decode(output.read(worker.MAX_OUTPUT + 1))
                            if process.returncode != 0 or frame["containment"] != "removed" or frame["result"] is not None:
                                raise RuntimeError("runtime timeout did not produce a confirmed, redacted failure")
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                        if name:
                            subprocess.run([worker.PODMAN, "rm", "--force", "--time", "0", name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                print("setsid descendants removed" + (" after launcher SIGKILL" if kill_launcher else " at runtime deadline") + ": passed")

            response = subprocess.run([sys.executable, "-I", str(wrapper)], input=job("probe-clean"),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=launcher_environment, timeout=60, check=True)
            if worker.decode(response.stdout)["result"] is None:
                raise RuntimeError("following job inherited escaped-job state")
            print("following job has no escaped process state or writable cache: passed")
        finally:
            subprocess.run([worker.PODMAN, "image", "rm", probe_image], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError, worker.Refused):
        raise SystemExit("worker containment acceptance failed; inspect the dedicated test runtime") from None
