"""Single-use remote witness service for experimental validation."""

from __future__ import annotations

import argparse
import json
import socket
import time

from .witness import OneTimeWitness, encode_receipt, public_key_fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    witness, public = OneTimeWitness.generate()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    server.settimeout(120)
    print(json.dumps({"host": args.host, "port": server.getsockname()[1], "fingerprint": public_key_fingerprint(public)}, sort_keys=True), flush=True)
    try:
        connection, _ = server.accept()
        with connection, connection.makefile("rwb", buffering=0) as stream:
            connection.settimeout(5)
            if stream.readline(128) != b"ARM\n":
                return 2
            armed_ns = time.monotonic_ns()
            stream.write(b"ARMED\n")
            if stream.readline(128) != b"ALERT\n":
                return 2
            alert_latency_ns = time.monotonic_ns() - armed_ns
            stream.write(f"ALERTED {alert_latency_ns}\n".encode("ascii"))
            connection.settimeout(120)
            line = stream.readline(256).strip().decode("ascii")
            if not line.startswith("SIGN "):
                return 2
            digest = bytes.fromhex(line[5:])
            if len(digest) != 32:
                return 2
            signed_material = digest + alert_latency_ns.to_bytes(8, "big")
            wrapper = {
                "alert_latency_ns": alert_latency_ns,
                "receipt": json.loads(encode_receipt(public, witness.sign(signed_material))),
            }
            stream.write(json.dumps(wrapper, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
