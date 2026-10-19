"""Small TCP services and probes used only by the disposable topology test."""

from __future__ import annotations

import argparse
import base64
import errno
import http.client
import json
import os
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit


def request(host: str, port: int, payload: bytes = b"GET package\n", limit: int = 4096, *, ca: str | None = None, server_name: str | None = None, timeout: float = 0.25) -> dict:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout)
    stage = "connect"
    try:
        client.connect((host, port))
        stage = "send"
        channel = client
        if ca:
            context = ssl.create_default_context(cafile=ca)
            channel = context.wrap_socket(client, server_hostname=server_name)
        channel.sendall(payload)
        stage = "recv"
        response = channel.recv(limit + 1)
        return {"connected": True, "response": response[:limit].decode("ascii", "replace"), "over_limit": len(response) > limit}
    except OSError as exc:
        return {"connected": False, "error": type(exc).__name__, "error_stage": stage,
                "errno_name": errno.errorcode.get(exc.errno), "over_limit": False}
    finally:
        client.close()


def http_get(url: str) -> dict:
    """Fetch through the one permitted mediator; return bounded bytes to root supervisor."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in {"10.77.2.2", "10.77.2.1", "10.77.1.1", "203.0.113.10"}
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or not url.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in url)):
        raise ValueError("HTTP URL is outside the disposable test topology")
    try:
        with socket.create_connection(("10.77.1.1", 18080), timeout=3.0) as channel:
            channel.settimeout(3.0)
            request_bytes = (f"GET {url} HTTP/1.1\r\nHost: {parsed.netloc}\r\nConnection: close\r\n\r\n").encode("ascii")
            channel.sendall(request_bytes)
            response = http.client.HTTPResponse(channel)
            response.begin()
            body = response.read(131073)
            return {"connected": True, "status_code": response.status,
                    "over_limit": len(body) > 131072,
                    "body_base64": base64.b64encode(body).decode("ascii")}
    except (OSError, http.client.HTTPException) as exc:
        return {"connected": False, "error": type(exc).__name__, "over_limit": False}


def serve(bind: str, port: int, mode: str, *, cert: str | None = None, key: str | None = None,
          hit_log: str | None = None, package_artifact: str | None = None) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind, port))
    server.listen(16)
    while True:
        connection, _ = server.accept()
        if cert and key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            try:
                connection = context.wrap_socket(connection, server_side=True)
            except ssl.SSLError:
                connection.close()
                continue
        with connection:
            payload = connection.recv(1024)
            if hit_log is not None:
                with Path(hit_log).open("ab") as log:
                    log.write(b"hit\n")
                    log.flush()
                    os.fsync(log.fileno())
            if mode == "upstream":
                if b"REDIRECT" in payload:
                    response = b"REDIRECT http://203.0.113.10/forbidden\n"
                elif b"BULK" in payload:
                    response = b"X" * 8192
                else:
                    response = b"PACKAGE OK\n"
            elif mode == "http-upstream":
                if b"REDIRECT" in payload:
                    response = b"HTTP/1.1 302 Found\r\nLocation: http://203.0.113.10/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                else:
                    request_line = payload.split(b"\r\n", 1)[0]
                    target = request_line.split(b" ")
                    if package_artifact and len(target) >= 2 and target[1] == b"/hello_2.10-3_amd64.deb":
                        body = Path(package_artifact).read_bytes()
                    else:
                        body = b"X" * 8192 if b"BULK" in payload else b"REAL PROXY PACKAGE OK\n"
                    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + body
            else:
                response = b"UNEXPECTED SERVICE\n"
            connection.sendall(response)


def proxy(bind: str, port: int, upstream_host: str, upstream_port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind, port))
    server.listen(16)
    while True:
        connection, _ = server.accept()
        with connection:
            payload = connection.recv(1024)
            result = request(upstream_host, upstream_port, payload)
            connection.sendall(json.dumps(result, sort_keys=True).encode("ascii") + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("--bind", required=True)
    server.add_argument("--port", required=True, type=int)
    server.add_argument("--mode", required=True)
    server.add_argument("--cert")
    server.add_argument("--key")
    server.add_argument("--hit-log")
    server.add_argument("--package-artifact")
    forward = commands.add_parser("proxy")
    forward.add_argument("--bind", required=True)
    forward.add_argument("--port", required=True, type=int)
    forward.add_argument("--upstream-host", required=True)
    forward.add_argument("--upstream-port", required=True, type=int)
    client = commands.add_parser("client")
    client.add_argument("--host", required=True)
    client.add_argument("--port", required=True, type=int)
    client.add_argument("--payload", default="GET package")
    client.add_argument("--limit", default=4096, type=int)
    client.add_argument("--ca")
    client.add_argument("--server-name")
    client.add_argument("--timeout", default=0.25, type=float)
    get = commands.add_parser("http-get")
    get.add_argument("--url", required=True)
    args = parser.parse_args()
    if args.command == "server":
        serve(args.bind, args.port, args.mode, cert=args.cert, key=args.key,
              hit_log=args.hit_log, package_artifact=args.package_artifact)
    elif args.command == "proxy":
        proxy(args.bind, args.port, args.upstream_host, args.upstream_port)
    elif args.command == "http-get":
        print(json.dumps(http_get(args.url), sort_keys=True))
    else:
        payload = args.payload.encode("ascii")
        if b"\r\n" not in payload:
            payload += b"\n"
        print(json.dumps(request(args.host, args.port, payload, args.limit, ca=args.ca, server_name=args.server_name, timeout=args.timeout), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
