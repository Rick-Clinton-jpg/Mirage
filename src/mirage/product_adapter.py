"""Measure the apt-cacher-ng process serving a specific topology trial."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess


class ProductAdapterError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_process_identity(actual_executable: Path, executable: Path, command: list[bytes], status: str, target_network: int, own_network: int, configuration: Path) -> None:
    try:
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        cap_line = next(line for line in status.splitlines() if line.startswith("CapEff:"))
        uids = [int(value) for value in uid_line.split()[1:]]
        capabilities = int(cap_line.split()[1], 16)
    except (StopIteration, ValueError) as exc:
        raise ProductAdapterError("cannot parse the tested proxy identity") from exc
    if actual_executable != executable.resolve() or str(configuration).encode() not in command:
        raise ProductAdapterError("tested proxy executable or configuration differs")
    if len(uids) != 4 or any(uid != 65534 for uid in uids) or capabilities != 0:
        raise ProductAdapterError("tested proxy retains elevated identity or capabilities")
    if target_network != own_network:
        raise ProductAdapterError("product probe and tested proxy are in different network namespaces")


def _process_identity(pid: int, executable: Path, configuration: Path) -> dict:
    proc = Path("/proc") / str(pid)
    try:
        actual_executable = (proc / "exe").resolve(strict=True)
        command = (proc / "cmdline").read_bytes().split(b"\0")
        status = (proc / "status").read_text(encoding="ascii")
        target_network = (proc / "ns/net").stat().st_ino
        own_network = Path("/proc/self/ns/net").stat().st_ino
    except OSError as exc:
        raise ProductAdapterError("cannot measure the tested proxy process") from exc
    _validate_process_identity(actual_executable, executable, command, status, target_network, own_network, configuration)
    return {"pid": pid, "uid": 65534, "cap_eff": 0, "network_namespace_inode": target_network}


def probe_apt_cacher_ng(*, pid: int, configuration: str | Path, host: str, port: int) -> dict:
    """Run from inside the same network namespace as the tested process."""
    executable_name = shutil.which("apt-cacher-ng", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable_name:
        raise ProductAdapterError("apt-cacher-ng is not installed")
    executable = Path(executable_name)
    config = Path(configuration).resolve(strict=True)
    process = _process_identity(pid, executable, config.parent)
    version_result = subprocess.run(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "apt-cacher-ng"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
    )
    if version_result.returncode != 0 or not version_result.stdout.strip():
        raise ProductAdapterError("cannot measure apt-cacher-ng package version")
    request = b"GET /acng-report.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=2) as client:
            client.sendall(request)
            response = client.recv(512)
    except OSError as exc:
        raise ProductAdapterError("tested apt-cacher-ng did not answer its live endpoint") from exc
    status = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    if not status.startswith("HTTP/1."):
        raise ProductAdapterError("tested apt-cacher-ng returned a non-HTTP response")
    return {
        "name": "apt-cacher-ng",
        "version": version_result.stdout.strip(),
        "executable": str(executable.resolve()),
        "executable_sha256": _sha256(Path("/proc") / str(pid) / "exe"),
        "configuration_sha256": _sha256(config),
        "configuration_file": str(config),
        "endpoint": f"{host}:{port}",
        "live_http_status": status,
        "process": process,
        "live": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        result = probe_apt_cacher_ng(pid=args.pid, configuration=args.configuration, host=args.host, port=args.port)
    except (OSError, ProductAdapterError) as exc:
        parser.exit(1, f"{exc}\n")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
