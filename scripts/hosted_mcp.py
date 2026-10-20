"""Bounded MCP smoke-test response reader; never report response bodies in diagnostics."""
import json
import http.client
import socket
import threading
import time


def read_response(response, request_id, limit, deadline=None, connection=None):
    # HTTPResponse's chunk parser can perform several socket reads inside read1().
    # Interrupt the socket itself so a drip-fed chunk extension cannot reset the bound.
    transport = getattr(connection, "sock", None)
    if transport is None:
        transport = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    if deadline is None:
        return _read_response(response, request_id, limit, deadline, connection)
    if transport is None:
        result = _read_response(response, request_id, limit, deadline, connection)
        return result if time.monotonic() < deadline else None
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        return None
    expired = threading.Event()

    def interrupt():
        expired.set()
        try:
            transport.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(seconds, interrupt)
    timer.daemon = True
    timer.start()
    try:
        result = _read_response(response, request_id, limit, deadline, connection)
        return result if not expired.is_set() and time.monotonic() < deadline else None
    except (OSError, http.client.HTTPException):
        if expired.is_set() or time.monotonic() >= deadline:
            return None
        raise
    finally:
        timer.cancel()
        timer.join()  # No delayed shutdown may affect a reused connection.


def _read_response(response, request_id, limit, deadline=None, connection=None):
    def decode(raw):
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise SystemExit("MCP response contained invalid JSON") from None

    stream = response.getheader("Content-Type", "").startswith("text/event-stream")
    remaining, data, pending = limit, [], bytearray()
    while remaining >= 0:
        if deadline is not None:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                return None
            if connection is not None and connection.sock:
                connection.sock.settimeout(seconds)
        # Keep the application-body read bounded, including one EOF/overflow probe
        # for a JSON response that consumes the exact byte budget.
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
