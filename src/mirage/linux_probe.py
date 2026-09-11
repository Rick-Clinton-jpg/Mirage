"""Workload executed inside the Linux isolation boundary.

This module reports observations only. The trusted parent independently checks
the host marker and matched control before converting observations to evidence.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def _network(port: int) -> dict:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return {"connected": True}
    except OSError as exc:
        return {"connected": False, "error": type(exc).__name__}


def _filesystem(marker: str) -> dict:
    try:
        Path(marker).write_text("modified-by-probe", encoding="utf-8")
        return {"modified": True}
    except OSError as exc:
        return {"modified": False, "error": type(exc).__name__}


def _credentials(canary_name: str, canary_value: str) -> dict:
    environment_match = os.environ.get(canary_name) == canary_value
    proc_match = False
    try:
        proc_match = canary_value.encode() in Path("/proc/1/environ").read_bytes()
    except OSError:
        pass
    return {"environment_match": environment_match, "proc_match": proc_match}


def _processes(attempts: int) -> dict:
    children: list[subprocess.Popen] = []
    failures = 0
    for _ in range(attempts):
        try:
            children.append(subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            ))
        except OSError:
            failures += 1
    for child in children:
        child.terminate()
    for child in children:
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    return {"attempted": attempts, "started": len(children), "failed": failures}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--benchmark"]:
        started = time.monotonic_ns()
        accumulator = 0
        for value in range(200_000):
            accumulator = (accumulator * 33 + value) & 0xFFFFFFFF
        print(json.dumps({
            "completed": True,
            "accumulator": accumulator,
            "elapsed_ns": time.monotonic_ns() - started,
        }, sort_keys=True, separators=(",", ":")))
        return 0
    if len(args) != 4:
        raise SystemExit("expected marker, port, canary name, and canary value")
    marker, port, canary_name, canary_value = args
    started = time.monotonic_ns()
    result = {
        "network": _network(int(port)),
        "filesystem": _filesystem(marker),
        "credentials": _credentials(canary_name, canary_value),
        "processes": _processes(64),
    }
    result["elapsed_ns"] = time.monotonic_ns() - started
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
