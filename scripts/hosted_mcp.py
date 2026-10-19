"""Bounded MCP smoke-test response reader; never report response bodies in diagnostics."""
import json
import time


def read_response(response, request_id, limit, deadline=None, connection=None):
    def decode(raw):
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise SystemExit("MCP response contained invalid JSON") from None

    stream = response.getheader("Content-Type", "").startswith("text/event-stream")
    remaining, data, pending = limit, [], bytearray()
    while remaining > 0:
        if deadline is not None:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                return None
            if connection is not None and connection.sock:
                connection.sock.settimeout(seconds)
        # read1 performs at most one buffered/raw read, unlike read/readline which can
        # receive repeatedly while a peer drips an unfinished JSON value or SSE line.
        chunk = response.read1(min(65536, remaining + 1))
        remaining -= len(chunk)
        if remaining < 0:
            return None
        if deadline is not None and time.monotonic() >= deadline:
            return None
        if not chunk:
            if stream:
                return None
            candidate = decode(pending)
            return candidate if isinstance(candidate, dict) and candidate.get("id") == request_id else None
        pending.extend(chunk)
        if stream:
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                line = line.rstrip(b"\r")
                if not line:
                    raw = b"\n".join(data)
                    data = []
                    # Empty priming events, comments and notifications are not responses.
                    if not raw.strip():
                        continue
                    candidate = decode(raw)
                    if isinstance(candidate, dict) and candidate.get("id") == request_id:
                        return candidate
                elif line.startswith(b"data:"):
                    value = line[5:]
                    data.append(value[1:] if value.startswith(b" ") else value)
    return None
