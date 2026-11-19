#!/usr/bin/env python3
"""Package a release's binaries, export its MCP wire contract, and assemble its assets.

`.github/workflows/release-binaries.yml` runs this; `scripts/test-release-artifacts.py` runs it
against stand-in binaries, so the packaging path is checked on every pull request without a Rust
build. Policy for what the assets promise is `docs/VERSIONING.md`.

    archive        one binary with LICENSE-APACHE, LICENSE-MIT and NOTICE, as
                   <binary>-<label>-<target>.tar.gz
    wire-contract  start the built MCP server over stdio, ask it `tools/list`, and add the E_*
                   vocabulary from the one table the ErrorCode enum is generated from
    assemble       check every target's packages, keep one wire contract (each target's must be
                   byte-identical), and write SHA256SUMS

Archives are deterministic for the same binary: sorted members, a fixed owner, the commit's time
as every mtime, and a gzip header without a name or timestamp. Repackaging a binary therefore
reproduces its archive's digest; the binaries themselves are not claimed byte-reproducible.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARIES = ("ozpb", "ozpb-mcp-server", "ozpb-execution-runtime")
LICENSE_FILES = ("LICENSE-APACHE", "LICENSE-MIT", "NOTICE")
WIRE_CONTRACT_SCHEMA = "ozpb-wire-contract/v1"
ERROR_CODE_SOURCE = "crates/api-types/src/lib.rs"
# `v` plus a semver version, pre-release allowed: the same shape the tag check accepts.
LABEL = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
TARGET = re.compile(r"^[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_-]+$")
ARM = re.compile(r'^\s*[A-Z][A-Za-z0-9]*\s*=>\s*"(E_[A-Z0-9_]+)",\s*$')


class ReleaseError(Exception):
    pass


def check_label(label):
    if not LABEL.match(label):
        raise ReleaseError(f"label {label!r} is not 'v' followed by a semver version")


def check_target(target):
    if not TARGET.match(target):
        raise ReleaseError(f"target {target!r} is not a target triple")


def archive_name(binary, label, target):
    return f"{binary}-{label}-{target}.tar.gz"


def wire_contract_name(label):
    return f"ozpb-wire-contract-{label}.json"


def archive(binary_path, label, target, epoch, out_dir, root=ROOT):
    """Write <binary>-<label>-<target>.tar.gz holding the binary and the licence files."""
    check_label(label)
    check_target(target)
    binary_path = Path(binary_path)
    name = binary_path.name
    if name not in BINARIES:
        raise ReleaseError(f"{name!r} is not a released binary ({', '.join(BINARIES)})")
    if not binary_path.is_file() or not os.access(binary_path, os.X_OK):
        raise ReleaseError(f"{binary_path} is not an executable file")
    if epoch < 0:
        raise ReleaseError("the archive time must not be negative")
    base = f"{name}-{label}-{target}"
    members = [(f"{base}/{name}", binary_path.read_bytes(), 0o755)]
    for licence in LICENSE_FILES:
        members.append((f"{base}/{licence}", (Path(root) / licence).read_bytes(), 0o644))
    members.sort()

    def info(path, size, mode, kind=tarfile.REGTYPE):
        entry = tarfile.TarInfo(path)
        entry.type, entry.size, entry.mode, entry.mtime = kind, size, mode, epoch
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = ""
        return entry

    raw = io.BytesIO()
    # No file name and a zero timestamp in the gzip header: both would otherwise make two
    # packagings of the same binary differ.
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            tar.addfile(info(base, 0, 0o755, tarfile.DIRTYPE))
            for path, body, mode in members:
                tar.addfile(info(path, len(body), mode), io.BytesIO(body))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target_path = out_dir / archive_name(name, label, target)
    target_path.write_bytes(raw.getvalue())
    return target_path


def error_codes(root=ROOT):
    """The E_* codes, read from the `error_codes!` table in api-types.

    That table is the single source the enum, `ErrorCode::ALL`, the Serde spelling and the JSON
    Schema are all generated from, and api-types' own tests hold those four to it. Reading it
    here needs no build. Any line in the table that is not an arm, a comment or blank stops the
    export, so a change of shape cannot silently drop codes from the published list.
    """
    lines = (Path(root) / ERROR_CODE_SOURCE).read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "error_codes! {"]
    if len(starts) != 1:
        raise ReleaseError(f"{ERROR_CODE_SOURCE}: expected one 'error_codes! {{' table")
    codes = []
    for number, line in enumerate(lines[starts[0] + 1:], starts[0] + 2):
        stripped = line.strip()
        if stripped == "}":
            break
        if not stripped or stripped.startswith("//"):
            continue
        match = ARM.match(line)
        if not match:
            raise ReleaseError(f"{ERROR_CODE_SOURCE}:{number}: not an error-code arm: {stripped}")
        codes.append(match.group(1))
    else:
        raise ReleaseError(f"{ERROR_CODE_SOURCE}: the error_codes! table is not closed")
    if not codes:
        raise ReleaseError(f"{ERROR_CODE_SOURCE}: the error_codes! table is empty")
    duplicates = sorted({code for code in codes if codes.count(code) > 1})
    if duplicates:
        raise ReleaseError(f"{ERROR_CODE_SOURCE}: duplicate codes {duplicates}")
    return codes


def served_tools(server, timeout):
    """Ask the server for `tools/list` over stdio, as the MCP stdio tests do."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "ozpb-release", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    payload = "".join(json.dumps(request) + "\n" for request in requests)
    # The listing must be what an unconfigured server serves; operator settings in the
    # environment of whoever runs this must not shape it.
    env = {key: value for key, value in os.environ.items() if not key.startswith("OZPB_")}
    try:
        done = subprocess.run([str(server)], input=payload, capture_output=True, text=True,
                              timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(f"could not run {server}: {error}") from error
    responses = {}
    for line in done.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict) and message.get("id") in (1, 2):
            responses[message["id"]] = message
    for request_id, method in ((1, "initialize"), (2, "tools/list")):
        reply = responses.get(request_id)
        if reply is None or "result" not in reply:
            raise ReleaseError(f"{server} gave no {method} result (exit {done.returncode}): "
                               f"{reply if reply is not None else done.stderr.strip()[-2000:]}")
    result = responses[2]["result"]
    # A paginated listing would make this export silently partial.
    if result.get("nextCursor"):
        raise ReleaseError("tools/list is paginated; the export would be incomplete")
    tools = result.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ReleaseError("tools/list returned no tools")
    names = []
    for tool in tools:
        name = tool.get("name") if isinstance(tool, dict) else None
        if not isinstance(name, str) or not name:
            raise ReleaseError(f"a listed tool has no name: {tool}")
        for field in ("inputSchema", "outputSchema"):
            if not isinstance(tool.get(field), dict):
                raise ReleaseError(f"tool {name} has no {field}")
        names.append(name)
    if len(set(names)) != len(names):
        raise ReleaseError(f"tools/list names a tool twice: {sorted(names)}")
    return sorted(tools, key=lambda tool: tool["name"])


def wire_contract(server, label, commit, out_path, root=ROOT, timeout=120):
    check_label(label)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ReleaseError(f"commit {commit!r} is not a full lowercase git object id")
    document = {
        "schema": WIRE_CONTRACT_SCHEMA,
        "release": label,
        "commit": commit,
        "tools": served_tools(server, timeout),
        "error_codes": error_codes(root),
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    return out_path


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def assemble(label, dist, targets, out_dir):
    """Check each target's directory, then lay out the release assets and SHA256SUMS."""
    check_label(label)
    if not targets:
        raise ReleaseError("no targets named")
    dist, out_dir = Path(dist), Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ReleaseError(f"{out_dir} is not empty")
    contract = wire_contract_name(label)
    contracts = {}
    for target in targets:
        check_target(target)
        expected = {archive_name(binary, label, target) for binary in BINARIES} | {contract}
        directory = dist / target
        present = {entry.name for entry in directory.iterdir()} if directory.is_dir() else set()
        if present != expected:
            raise ReleaseError(f"{directory}: missing {sorted(expected - present)}, "
                               f"unexpected {sorted(present - expected)}")
        contracts[target] = (directory / contract).read_bytes()
    reference = targets[0]
    differing = [target for target in targets if contracts[target] != contracts[reference]]
    if differing:
        raise ReleaseError(f"the wire contract served on {differing} differs from {reference}'s")
    out_dir.mkdir(parents=True, exist_ok=True)
    for target in targets:
        for binary in BINARIES:
            name = archive_name(binary, label, target)
            shutil.copyfile(dist / target / name, out_dir / name)
    (out_dir / contract).write_bytes(contracts[reference])
    # `sha256sum --check` and `shasum -a 256 --check` both read this: digest, two spaces, name.
    lines = [f"{sha256(path)}  {path.name}\n" for path in sorted(out_dir.iterdir())]
    sums = out_dir / "SHA256SUMS"
    sums.write_text("".join(lines), encoding="utf-8")
    return sums


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    one = commands.add_parser("archive", help="package one binary with the licence files")
    one.add_argument("--binary", required=True)
    one.add_argument("--label", required=True)
    one.add_argument("--target", required=True)
    one.add_argument("--epoch", required=True, type=int, help="mtime for every member")
    one.add_argument("--out", required=True)

    contract = commands.add_parser("wire-contract", help="export tools/list and the E_* codes")
    contract.add_argument("--server", required=True)
    contract.add_argument("--label", required=True)
    contract.add_argument("--commit", required=True)
    contract.add_argument("--out", required=True)
    contract.add_argument("--timeout", type=int, default=120)

    assembly = commands.add_parser("assemble", help="check packages, write SHA256SUMS")
    assembly.add_argument("--label", required=True)
    assembly.add_argument("--dist", required=True)
    assembly.add_argument("--out", required=True)
    assembly.add_argument("targets", nargs="+")

    args = parser.parse_args(argv)
    try:
        if args.command == "archive":
            print(archive(args.binary, args.label, args.target, args.epoch, args.out))
        elif args.command == "wire-contract":
            print(wire_contract(args.server, args.label, args.commit, args.out,
                                timeout=args.timeout))
        else:
            print(assemble(args.label, args.dist, args.targets, args.out).read_text(), end="")
    except (ReleaseError, OSError) as error:
        print(f"release-artifacts: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
