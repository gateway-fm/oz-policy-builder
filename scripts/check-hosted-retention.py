#!/usr/bin/env python3
"""Drive the packaged endpoint with canary input, then read what its containers kept.

Run it against a fresh Compose project whose two services log with a driver that keeps their
output (the container test swaps the package's `none` for `json-file`), so what the processes
print can be read. Over TLS it sends a canary bearer token without authorization, then, in an
authenticated session, builds a spec whose name is a canary and sends a signed envelope with a
canary signature to the two tools a hosted server refuses it in. It reads every file in each
container's tmpfs mounts and `/dev/shm`, stops both containers, and reads their stdout and stderr
and each file `docker diff` lists outside their mounts. It fails if any of them holds the bearer
token or a canary, or if the output is anything but the server's startup line. It prints check
labels and where a canary was found, never a canary, the token or a body.
"""

import argparse
import base64
import http.client
import io
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tarfile
import time
from urllib.parse import urlsplit
from hosted_mcp import read_response


PROTOCOL = "2025-11-25"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
TOKEN_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
# The one line the server prints when it starts (crates/mcp-server/src/http.rs). Finding it shows
# the output is kept and read, so an empty result is not a log driver that kept nothing.
STARTUP_LINE = b"ozpb MCP streamable-HTTP endpoint on "
# What the server's code writes there (a refusal) when it gets a signed envelope.
SIGNED_REFUSAL = "live authorizations"
ENVELOPE_TYPE_TX = (2).to_bytes(4, "big")


def signed_envelope(unsigned_base64, hint, signature):
    """The unsigned v1 envelope with one decorated signature: its last field, `signatures<20>`,
    goes from an empty array to `hint` (opaque[4]) and `signature` (opaque<64>)."""
    raw = base64.b64decode(unsigned_base64, validate=True)
    if len(hint) != 4 or len(signature) != 64:
        raise ValueError("a decorated signature is a 4-byte hint and a 64-byte signature")
    if raw[:4] != ENVELOPE_TYPE_TX or raw[-4:] != bytes(4):
        raise ValueError("the example envelope is not an unsigned v1 transaction envelope")
    signed = raw[:-4] + (1).to_bytes(4, "big") + hint + (64).to_bytes(4, "big") + signature
    return base64.b64encode(signed).decode("ascii")


def output_problem(service, stdout, stderr):
    """Why a service's kept output is not exactly what it should print, or None: the API writes
    its startup line to stderr and nothing else, the proxy nothing at all. Exact, so a line about
    a request passes neither, whatever it names."""
    if stdout:
        return f"{service}: wrote {len(stdout)} bytes to stdout"
    if service == "api":
        lines = stderr.count(b"\n")
        if not stderr.startswith(STARTUP_LINE) or lines != 1 or not stderr.endswith(b"\n"):
            return f"api: its stderr is not exactly the startup line ({lines} line(s))"
        return None
    if stderr:
        return f"{service}: wrote {len(stderr)} bytes to stderr"
    return None


def found(data, needles):
    """The labels of the needles `data` contains."""
    return [label for label, needle in needles.items() if needle in data]


def redact(text, needles):
    """`text` with every needle that is text replaced by its label, for printing a path."""
    for label, needle in needles.items():
        try:
            text = text.replace(needle.decode("ascii"), f"<{label}>")
        except UnicodeDecodeError:
            pass
    return text


def paths_to_read(diff, mounts):
    """The added or changed entries of `docker diff` output to read: each that no other entry
    lies under (a directory listed because of what changed inside it is read through those
    entries, not whole), and that is not a mount, inside one, or a directory holding one. A
    mount's content is the operator's input or a tmpfs read on its own; reading a bind mount
    through `docker cp` would read the token file itself."""
    entries = [line.partition(" ")[::2] for line in diff.splitlines()]
    listed = [path for _, path in entries]
    paths = []
    for kind, path in entries:
        if kind not in {"A", "C"} or not path.startswith("/"):
            continue
        if any(other.startswith(path + "/") for other in listed):
            continue
        if any(path == mount or path.startswith(mount + "/") or mount.startswith(path + "/")
               for mount in mounts):
            continue
        paths.append(path)
    return paths


def docker(*args, stdin=None):
    return subprocess.run(["docker", *args], capture_output=True, check=False, input=stdin)


def scan_tar(stream, needles, where, findings):
    """Read each regular file of an uncompressed tar stream; return how many were read."""
    count = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            for label in found(member.name.encode("utf-8", "surrogateescape"), needles):
                findings.append((label, f"{where}: a file name"))
            if not member.isfile():
                continue
            content = archive.extractfile(member).read()
            count += 1
            for label in found(content, needles):
                findings.append((label, f"{where}: /{redact(member.name.lstrip('/'), needles)}"))
    return count


def mounts_of(container):
    result = docker("inspect", container)
    if result.returncode != 0:
        raise SystemExit("docker inspect failed for a service container")
    info = json.loads(result.stdout)[0]
    host = info.get("HostConfig") or {}
    tmpfs = set(host.get("Tmpfs") or {})
    tmpfs |= {mount["Destination"] for mount in info.get("Mounts") or [] if mount.get("Type") == "tmpfs"}
    # Docker gives each container a writable /dev/shm tmpfs, read-only root or not, unless IPC is off.
    if host.get("IpcMode") != "none":
        tmpfs.add("/dev/shm")
    others = {mount["Destination"] for mount in info.get("Mounts") or []}
    return sorted(tmpfs), sorted(others | tmpfs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--envelope-bundle", required=True, type=Path,
                        help="an import bundle whose envelope_xdr_base64 is an unsigned v1 envelope")
    parser.add_argument("--api-container", required=True)
    parser.add_argument("--proxy-container", required=True)
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme != "https" or url.path != "/v1/mcp" or url.username or url.password or url.query or url.fragment:
        parser.error("use the credential-free HTTPS /v1/mcp URL")
    with args.token_file.open("rb") as source:
        token = source.read(130).rstrip(b"\n")
    if not 32 <= len(token) <= 128 or any(byte not in TOKEN_BYTES for byte in token):
        parser.error("invalid token file")
    context = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    containers = {"api": args.api_container, "proxy": args.proxy_container}

    canary_token = secrets.token_urlsafe(48)
    spec_canary = secrets.token_hex(9)
    hint, signature = secrets.token_bytes(4), secrets.token_bytes(64)
    bundle = json.loads(args.envelope_bundle.read_bytes())
    envelope = signed_envelope(bundle["envelope_xdr_base64"], hint, signature)
    spec = json.loads(args.spec.read_bytes())
    spec["name"] = "c-" + spec_canary
    needles = {
        "bearer token": token,
        "canary token": canary_token.encode("ascii"),
        "canary spec name": spec_canary.encode("ascii"),
        "signed canary envelope": envelope.encode("ascii"),
        # Its head carries the example's source account: a truncated or unsigned copy starts so.
        "signed canary envelope (first 64 characters)": envelope[:64].encode("ascii"),
        "canary signature": signature,
        "canary signature (hex)": signature.hex().encode("ascii"),
        "canary signature (base64)": base64.b64encode(signature),
    }
    session = None

    def connect(authorization, timeout=750):
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": authorization, "MCP-Protocol-Version": PROTOCOL}
        if session:
            headers["Mcp-Session-Id"] = session
        client = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=timeout, context=context)
        return client, headers

    def rpc(method, params=None, request_id=None):
        nonlocal session
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if request_id is not None:
            message["id"] = request_id
        client, headers = connect("Bearer " + token.decode("ascii"))
        deadline = time.monotonic() + 750
        try:
            client.request("POST", "/v1/mcp", json.dumps(message).encode(), headers)
            response = client.getresponse()
            if request_id is None:
                if response.status != 202:
                    raise SystemExit("MCP initialization notification was not accepted")
                return None
            if response.status != 200:
                raise SystemExit(f"MCP {method} returned HTTP {response.status}")
            session = response.getheader("Mcp-Session-Id") or session
            result = read_response(response, request_id, MAX_RESPONSE_BYTES, deadline, client)
            if not isinstance(result, dict) or result.get("id") != request_id or "error" in result:
                raise SystemExit(f"MCP {method} did not return a bounded JSON-RPC result")
            return result.get("result")
        finally:
            client.close()

    def tool(name, arguments, request_id):
        result = rpc("tools/call", {"name": name, "arguments": arguments}, request_id)
        if not isinstance(result, dict) or not isinstance(result.get("structuredContent"), dict):
            raise SystemExit(f"MCP {name} returned no structured result")
        return result

    # Refused before the body is read; the token reaches the proxy and the server's guard.
    refused_call = {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                    "params": {"name": "preflight_transaction", "arguments": {"envelope_xdr_base64": envelope}}}
    client, headers = connect("Bearer " + canary_token, timeout=15)
    try:
        client.request("POST", "/v1/mcp", json.dumps(refused_call).encode(), headers)
        status = client.getresponse().status
    finally:
        client.close()
    if status != 401:
        raise SystemExit(f"a canary bearer token was answered with HTTP {status}, not 401")
    print("canary bearer token refused: 401")

    initialized = rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "ozpb-retention-check", "version": "1"}}, 1)
    if not isinstance(initialized, dict) or initialized.get("protocolVersion") != PROTOCOL:
        raise SystemExit("MCP protocol negotiation failed")
    rpc("notifications/initialized")
    built = tool("generate_code", {"spec": spec, "rule_index": 0}, 2)
    if built.get("isError") or spec_canary not in built["structuredContent"].get("files", {}).get("Cargo.toml", ""):
        raise SystemExit("the canary spec was not built into a crate named after it")
    print("canary spec built through the compiler")
    for request_id, name, arguments in (
        (3, "preflight_transaction", {"rpc_url": "https://soroban-testnet.stellar.org",
                                      "network_passphrase": "Test SDF Network ; September 2015",
                                      "envelope_xdr_base64": envelope}),
        (4, "record_simulation", {"rpc_source": "testnet", "envelope_xdr_base64": envelope}),
    ):
        refused = tool(name, arguments, request_id)
        content = refused["structuredContent"]
        if (not refused.get("isError") or content.get("code") != "E_UNSUPPORTED_ENVELOPE"
                or SIGNED_REFUSAL not in str(content.get("message", ""))):
            raise SystemExit(f"MCP {name} did not refuse the signed canary envelope")
        print(f"signed canary envelope refused by {name}")

    findings, problems = [], []
    stops = []
    for service, container in containers.items():
        tmpfs, mounts = mounts_of(container)
        stops.append((service, container, mounts))
        if not tmpfs:
            raise SystemExit(f"{service}: no tmpfs mount to read")
        # Read while the container runs: a tmpfs is gone once it stops.
        with subprocess.Popen(["docker", "exec", container, "tar", "-cf", "-", "-C", "/",
                               *[path.lstrip("/") for path in tmpfs]],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as reader:
            count = scan_tar(reader.stdout, needles, f"{service} tmpfs", findings)
        if reader.returncode != 0:
            raise SystemExit(f"{service}: its tmpfs mounts could not be read")
        print(f"{service} tmpfs: {count} file(s) read in {', '.join(tmpfs)}")
    # Stopping first makes the output complete: whatever a shutdown prints is in it.
    if docker("stop", "-t", "20", *containers.values()).returncode != 0:
        raise SystemExit("the service containers did not stop")
    for service, container, mounts in stops:
        logs = docker("logs", container)
        if logs.returncode != 0:
            raise SystemExit(f"{service}: docker logs failed; run it with a logging driver that keeps output")
        problem = output_problem(service, logs.stdout, logs.stderr)
        if problem:
            problems.append(problem)
        for stream in ("stdout", "stderr"):
            for label in found(getattr(logs, stream), needles):
                findings.append((label, f"{service} {stream}"))
        print(f"{service} output: {len(logs.stdout)} stdout and {len(logs.stderr)} stderr bytes read")
        diff = docker("diff", container)
        if diff.returncode != 0:
            raise SystemExit(f"{service}: docker diff failed")
        paths = paths_to_read(diff.stdout.decode("utf-8", "surrogateescape"), mounts)
        files = 0
        for path in paths:
            copy = docker("cp", f"{container}:{path}", "-")
            if copy.returncode != 0:
                raise SystemExit(f"{service}: a changed path could not be read")
            files += scan_tar(io.BytesIO(copy.stdout), needles, f"{service} layer", findings)
        print(f"{service} layer: {len(paths)} changed path(s) outside its mounts, {files} file(s) read")

    for label, where in findings:
        print(f"RETAINED: {label} in {where}")
    for problem in problems:
        print(f"UNEXPECTED OUTPUT: {problem}")
    if findings or problems:
        raise SystemExit("the endpoint retained the token, canary request content or other output")
    print("output is the startup line alone; no token or canary request content in any output or file the run left")


if __name__ == "__main__":
    main()
