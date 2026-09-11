"""Measured adapter for a live apt-cacher-ng repository mediator."""

from __future__ import annotations

import hashlib
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


def probe_apt_cacher_ng(host: str = "127.0.0.1", port: int = 3142) -> dict:
    executable = shutil.which("apt-cacher-ng", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise ProductAdapterError("apt-cacher-ng is not installed")
    version_result = subprocess.run(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "apt-cacher-ng"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False,
    )
    if version_result.returncode != 0 or not version_result.stdout.strip():
        raise ProductAdapterError("cannot measure apt-cacher-ng package version")
    config_paths = [path for path in (Path("/etc/apt-cacher-ng/acng.conf"), Path("/etc/apt-cacher-ng/security.conf")) if path.is_file()]
    if not config_paths:
        raise ProductAdapterError("apt-cacher-ng configuration is absent")
    request = b"GET /acng-report.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=2) as client:
            client.sendall(request)
            response = client.recv(512)
    except OSError as exc:
        raise ProductAdapterError("apt-cacher-ng did not answer its live endpoint") from exc
    status = response.split(b"\r\n", 1)[0].decode("ascii", "replace")
    if not status.startswith("HTTP/1."):
        raise ProductAdapterError("apt-cacher-ng returned a non-HTTP response")
    try:
        configuration = {str(path): _sha256(path) for path in config_paths}
    except OSError as exc:
        raise ProductAdapterError("cannot measure apt-cacher-ng configuration") from exc
    combined = hashlib.sha256(
        "\n".join(f"{path}:{configuration[path]}" for path in sorted(configuration)).encode("ascii")
    ).hexdigest()
    return {
        "name": "apt-cacher-ng",
        "version": version_result.stdout.strip(),
        "executable": executable,
        "executable_sha256": _sha256(Path(executable)),
        "configuration_sha256": combined,
        "configuration_files": configuration,
        "endpoint": f"{host}:{port}",
        "live_http_status": status,
        "live": True,
    }
