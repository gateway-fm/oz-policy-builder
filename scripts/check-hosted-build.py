#!/usr/bin/env python3
"""Generate and reproduce the committed fixture through a real TLS MCP session.

Print only checks, never credentials, generated source, artifact bytes or response bodies.
"""

import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit


PROTOCOL = "2025-11-25"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme != "https" or url.path != "/v1/mcp" or url.username or url.password or url.query or url.fragment:
        parser.error("use the credential-free HTTPS /v1/mcp URL")
    with args.token_file.open("rb") as source:
        token = source.read(130).rstrip(b"\n")
    if not 32 <= len(token) <= 128 or any(byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-" for byte in token):
        parser.error("invalid token file")
    context = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    session = None

    def rpc(method, params=None, request_id=None):
        nonlocal session
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if request_id is not None:
            message["id"] = request_id
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + token.decode("ascii"), "MCP-Protocol-Version": PROTOCOL}
        if session:
            headers["Mcp-Session-Id"] = session
        client = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=750, context=context)
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
            if response.getheader("Content-Type", "").startswith("text/event-stream"):
                remaining = MAX_RESPONSE_BYTES
                result = None
                while remaining > 0 and time.monotonic() < deadline:
                    if client.sock:
                        client.sock.settimeout(max(0.01, deadline - time.monotonic()))
                    line = response.readline(remaining + 1)
                    remaining -= len(line)
                    if not line or remaining < 0:
                        break
                    if line.startswith(b"data: "):
                        candidate = json.loads(line[6:])
                        if isinstance(candidate, dict) and candidate.get("id") == request_id:
                            result = candidate
                            break
            else:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                result = json.loads(raw) if len(raw) <= MAX_RESPONSE_BYTES else None
            if not isinstance(result, dict) or result.get("id") != request_id or "error" in result:
                raise SystemExit(f"MCP {method} did not return a bounded successful response")
            return result.get("result")
        finally:
            client.close()

    initialized = rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                    "clientInfo": {"name": "ozpb-build-check", "version": "1"}}, 1)
    if not isinstance(initialized, dict) or initialized.get("protocolVersion") != PROTOCOL:
        raise SystemExit("MCP protocol negotiation failed")
    rpc("notifications/initialized")
    with args.spec.open("rb") as source:
        raw_spec = source.read(2 * 1024 * 1024 + 1)
    if len(raw_spec) > 2 * 1024 * 1024:
        raise SystemExit("fixture exceeds size bound")
    spec = json.loads(raw_spec)

    def tool(name, arguments, request_id):
        result = rpc("tools/call", {"name": name, "arguments": arguments}, request_id)
        if not isinstance(result, dict) or result.get("isError") or not isinstance(result.get("structuredContent"), dict):
            raise SystemExit(f"MCP {name} did not produce a successful structured artifact")
        return result["structuredContent"]

    generated = tool("generate_code", {"spec": spec, "rule_index": 0}, 2)
    wasm = base64.b64decode(generated["wasm_base64"], validate=True)
    if not wasm.startswith(b"\0asm") or hashlib.sha256(wasm).hexdigest() != generated.get("wasm_hash"):
        raise SystemExit("generated Wasm identity mismatch")
    if generated["build_manifest"]["toolchain"]["builder"] != "local-unattested":
        raise SystemExit("fixture did not use the real compiler")
    print("TLS MCP generation: real Wasm with matching digest")
    verified = tool("verify", {
        "spec": spec, "rule_index": 0,
        "claimed_generated_files": {key: value for key, value in generated["files"].items() if key != "Cargo.lock"},
        "claimed_wasm_base64": generated["wasm_base64"],
        "claimed_build_manifest": generated["build_manifest"],
    }, 3)
    if (verified.get("matches") is not True
            or verified.get("source_reproduction") != "reproduced: generated non-lock files are byte-identical"
            or verified.get("wasm_reproduction") != "reproduced: Wasm and BuildManifest are identical"):
        raise SystemExit("TLS MCP artifact reproduction failed")
    print("TLS MCP verification: matching source, Wasm and manifest")


if __name__ == "__main__":
    main()
