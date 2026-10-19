#!/usr/bin/env python3
"""Check a fresh, isolated TLS endpoint without logging its token or response bodies.

The quota test intentionally exhausts the supplied fixed-window quota. Do not point it at a
shared running service. TLS certificate verification is always enabled.
"""

import argparse
import http.client
import json
from pathlib import Path
import ssl
import time
from urllib.parse import urlsplit


INITIALIZE = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
               "clientInfo": {"name": "ozpb-hosted-check", "version": "1"}},
}).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--body-limit", required=True, type=int)
    parser.add_argument("--quota", required=True, type=int)
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme != "https" or url.path != "/v1/mcp" or url.username or url.password or url.query or url.fragment:
        parser.error("URL must be the credential-free HTTPS /v1/mcp endpoint")
    if not 2 <= args.quota <= 100 or not 4096 <= args.body_limit <= 25165824:
        parser.error("use a fresh endpoint with quota 2..100 and body limit 4096..25165824")
    with args.token_file.open("rb") as source:
        token = source.read(130).rstrip(b"\n")
    if not 32 <= len(token) <= 128 or any(byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-" for byte in token):
        parser.error("token file must contain 32..128 URL-safe characters")
    context = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)

    def request(body=INITIALIZE, authorized=True, path="/v1/mcp", headers=None):
        request_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if authorized:
            request_headers["Authorization"] = "Bearer " + token.decode("ascii")
        request_headers.update(headers or {})
        connection = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=15, context=context)
        try:
            connection.request("POST", path, body=body, headers=request_headers)
            response = connection.getresponse()
            if response.status == 200:
                if response.getheader("Content-Type", "").startswith("text/event-stream"):
                    remaining = 65536
                    payload = None
                    while remaining > 0:
                        line = response.readline(remaining + 1)
                        remaining -= len(line)
                        if not line or remaining < 0:
                            break
                        if line.startswith(b"data: "):
                            payload = json.loads(line[6:])
                            break
                else:
                    raw = response.read(65537)
                    payload = json.loads(raw) if len(raw) <= 65536 else None
                if not isinstance(payload, dict) or payload.get("result", {}).get("protocolVersion") != "2025-11-25":
                    raise SystemExit("initialization response did not contain the requested MCP protocol")
            return response.status
        finally:
            connection.close()

    def expect(label, actual, allowed):
        if actual not in allowed:
            raise SystemExit(f"{label}: unexpected HTTP status {actual}")
        print(label + ": passed")

    expect("unauthenticated request refused", request(authorized=False), {401})
    expect("wrong token refused", request(headers={"Authorization": "Bearer invalid"}), {401})
    expect("browser origin refused", request(headers={"Origin": "https://other.invalid"}), {403})
    expect("wrong host refused", request(headers={"Host": "other.invalid"}), {404, 421})
    expect("unversioned endpoint absent", request(path="/mcp"), {404})
    start = time.monotonic()
    expect("MCP initialization admitted", request(), {200})
    expect("oversized body refused", request(body=b" " * (args.body_limit + 1)), {413})
    for _ in range(args.quota - 2):
        expect("remaining request quota admitted", request(), {200})
    if time.monotonic() - start >= 55:
        raise SystemExit("quota check crossed its timing bound; repeat with a fresh endpoint")
    expect("exhausted request quota refused", request(), {429})


if __name__ == "__main__":
    main()
