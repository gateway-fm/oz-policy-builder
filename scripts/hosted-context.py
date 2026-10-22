#!/usr/bin/env python3
"""Write an allowlisted, immutable Git tree as a deterministic Docker build-context tar.

Untracked files and working-copy edits never enter this stream. This boundary limits paths;
review and the publication gate still decide whether the committed source is public.
"""

import argparse
import io
from pathlib import Path
import re
import subprocess
import sys
import tarfile


REQUIRED = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "LICENSE-APACHE", "LICENSE-MIT",
    "deployment/Dockerfile", "deployment/entrypoint.sh", "deployment/install-tools.sh",
    "deployment/verify-offline.sh", "deployment/cargo-config.toml",
    "contracts/golden-transfer-policy/Cargo.lock", "contracts/golden-transfer-policy/Cargo.toml",
    "contracts/golden-transfer-policy/rust-toolchain.toml",
    "contracts/golden-transfer-policy/src/lib.rs", "contracts/golden-transfer-policy/src/contract.rs",
    "docs/examples/subscription-spec.json", ".github/workflows/nightly-live.yml",
}
SOURCE = re.compile(r"crates/[a-z0-9-]+/(?:Cargo\.toml|src/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+\.rs)\Z")
MAX_FILE_BYTES = 16 * 1024 * 1024


def export(repo, revision):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)

    tree = git("rev-parse", "--verify", "--end-of-options", revision + "^{tree}").strip().decode("ascii")
    files = []
    for record in git("ls-tree", "-rz", tree).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        mode, kind, oid = metadata.decode("ascii").split()
        selected = path in REQUIRED or SOURCE.fullmatch(path)
        if kind == "commit" and path.startswith("crates/"):
            raise ValueError("build-context crate cannot be a submodule")
        if not selected:
            continue
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError("build-context input must be a regular file: " + path)
        size = int(git("cat-file", "-s", oid))
        if size > MAX_FILE_BYTES:
            raise ValueError("build-context input exceeds size bound: " + path)
        files.append((path, mode, git("cat-file", "blob", oid)))
    missing = REQUIRED - {path for path, _, _ in files}
    if missing:
        raise ValueError("required build-context files missing: " + ", ".join(sorted(missing)))
    if not any(SOURCE.fullmatch(path) for path, _, _ in files):
        raise ValueError("required crate sources are missing")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path, mode, content in sorted(files):
            info = tarfile.TarInfo(path)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("revision", help="Git commit or tree to build; working-copy edits are ignored")
    args = parser.parse_args()
    try:
        data = export(args.repo, args.revision)
    except (ValueError, UnicodeError, subprocess.CalledProcessError) as error:
        # Git diagnostics can quote user-supplied paths. Keep the failure bounded and do not
        # dump subprocess output or any file bytes into a build log.
        message = str(error) if isinstance(error, ValueError) else "cannot read the selected Git tree"
        print("hosted context: " + message, file=sys.stderr)
        return 1
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
