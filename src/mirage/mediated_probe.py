"""Adversarial mediator workload for the Linux namespace experiment."""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from urllib.parse import parse_qs, urlsplit


def connect_unix(path: str, payload: bytes) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(1.0)
    try:
        client.connect(path)
        client.sendall(payload)
        response = client.recv(32)
        return {"connected": True, "response": response.decode("ascii", "replace")}
    except OSError as exc:
        return {"connected": False, "error": type(exc).__name__}
    finally:
        client.close()


def connect_tcp(port: int) -> dict:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(0.5)
    start = time.monotonic_ns()
    try:
        client.connect(("127.0.0.1", port))
        return {"connected": True, "elapsed_ns": time.monotonic_ns() - start}
    except OSError as exc:
        return {"connected": False, "error": type(exc).__name__, "elapsed_ns": time.monotonic_ns() - start}
    finally:
        client.close()


def request_confined(value: str) -> bool:
    parsed = urlsplit(value)
    parameters = parse_qs(parsed.query)
    return not (parsed.scheme or parsed.netloc or "target" in parameters or "url" in parameters)


def main() -> int:
    if len(sys.argv) != 6:
        return 2
    upstream, management, prohibited_port, canary_name, canary_value = sys.argv[1:]
    approved = connect_unix(upstream, b"GET /approved\n")
    management_attempt = connect_unix(management, b"ADMIN\n")
    escape = connect_tcp(int(prohibited_port))
    result = {
        "approved_upstream": approved,
        "arbitrary_request_rejected": not request_confined("/?target=https://prohibited.invalid/"),
        "prohibited_external": escape,
        "management_plane": management_attempt,
        "credential_visible": os.environ.get(canary_name) == canary_value,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
