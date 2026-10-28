#!/usr/bin/python3
"""Adversarial fixture for the disposable-runtime acceptance test; never a production worker."""
import json
import errno
import os
from pathlib import Path
import socket
import sys
import time

job = json.load(sys.stdin)
root = Path("/tmp/ozpb")
if job["crate_name"] == "probe-escape":
    if os.fork() == 0:
        os.setsid()
        (root / "escaped-marker").write_text("escaped process")
        while True:
            time.sleep(1)
    while True:
        time.sleep(1)

if "OZPB_SECRET_CANARY" in os.environ or "OZPB_HTTP_BEARER_TOKEN" in os.environ:
    raise SystemExit(1)
canary = Path(job["files"][0]["body"])
if canary.exists() or Path("/run/ozpb/bearer-token").exists():
    raise SystemExit(1)
if (root / "previous-job").exists() or (root / "escaped-marker").exists():
    raise SystemExit(1)
if any((root / "target").iterdir()):
    raise SystemExit(1)
try:
    socket.create_connection(("1.1.1.1", 443), timeout=1).close()
except OSError:
    pass
else:
    raise SystemExit(1)
exhaustion = job["crate_name"] == "probe-exhaustion"
memory_mib, pids, cpus, tmpfs_mib = (256, 16, 1, 64) if exhaustion else (4096, 256, 2, 3072)
if int(Path("/sys/fs/cgroup/memory.max").read_text()) != memory_mib * 1024 * 1024:
    raise SystemExit(1)
if int(Path("/sys/fs/cgroup/memory.swap.max").read_text()) != 0:
    raise SystemExit(1)
if int(Path("/sys/fs/cgroup/pids.max").read_text()) != pids:
    raise SystemExit(1)
quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
if quota != cpus * period:
    raise SystemExit(1)
filesystem = os.statvfs(root)
if filesystem.f_blocks * filesystem.f_frsize != tmpfs_mib * 1024 * 1024:
    raise SystemExit(1)
try:
    # This image directory belongs to uid10001; permissions alone would allow the write.
    Path("/var/cache/ozpb/writable-root-probe").write_text("must fail")
except OSError:
    pass
else:
    raise SystemExit(1)
if exhaustion:
    children, capped = [], False
    try:
        for _ in range(24):
            try:
                pid = os.fork()
            except OSError as error:
                if error.errno != errno.EAGAIN:
                    raise
                capped = True
                break
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    if not capped:
        raise SystemExit(1)
    capped = False
    filling = root / "fill-tmpfs"
    try:
        with filling.open("wb", buffering=0) as output:
            for _ in range(65):
                output.write(b"x" * (1024 * 1024))
    except OSError as error:
        if error.errno != errno.ENOSPC:
            raise
        capped = True
    finally:
        filling.unlink(missing_ok=True)
    if not capped:
        raise SystemExit(1)
(root / "previous-job").write_text("must disappear")
(root / "target" / "poisoned-cache").write_text("must disappear")
print(json.dumps({"schema": "build-worker-result/v1", "artifact": None}))
