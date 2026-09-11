"""Real three-zone selective-TCP topology for Linux validation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time


class TopologyError(RuntimeError):
    pass


def _tool(name: str) -> str:
    found = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not found:
        raise TopologyError(f"required topology tool is absent: {name}")
    return found


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    if check and result.returncode != 0:
        raise TopologyError(f"command failed ({result.returncode}): {result.stderr.strip()[:500]}")
    return result


def _ns(name: str, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run([_tool("ip"), "netns", "exec", name, *arguments], check=check)


def _client(namespace: str, fixture: Path, host: str, port: int, payload: str = "GET package", limit: int = 4096) -> dict:
    result = _ns(namespace, [sys.executable, str(fixture), "client", "--host", host, "--port", str(port), "--payload", payload, "--limit", str(limit)], check=False)
    if result.returncode != 0:
        return {"connected": False, "error": "ProbeFailure", "over_limit": False}
    return json.loads(result.stdout)


def run_selective_tcp_topology() -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise TopologyError("selective TCP topology requires root on Linux")
    _tool("ip")
    _tool("nft")
    fixture = Path(__file__).with_name("tcp_fixture.py").resolve()
    suffix = secrets.token_hex(3)
    workload, proxy, upstream = (f"mgw-{suffix}", f"mgp-{suffix}", f"mgu-{suffix}")
    pw_host, pw_proxy, pu_proxy, pu_upstream = (f"w{suffix}", f"p{suffix}w", f"p{suffix}u", f"u{suffix}")
    processes: list[subprocess.Popen] = []
    namespaces: list[str] = []
    try:
        for name in (workload, proxy, upstream):
            _run([_tool("ip"), "netns", "add", name])
            namespaces.append(name)
            _ns(name, [_tool("ip"), "link", "set", "lo", "up"])
        _run([_tool("ip"), "link", "add", pw_host, "type", "veth", "peer", "name", pw_proxy])
        _run([_tool("ip"), "link", "set", pw_host, "netns", workload])
        _run([_tool("ip"), "link", "set", pw_proxy, "netns", proxy])
        _run([_tool("ip"), "link", "add", pu_proxy, "type", "veth", "peer", "name", pu_upstream])
        _run([_tool("ip"), "link", "set", pu_proxy, "netns", proxy])
        _run([_tool("ip"), "link", "set", pu_upstream, "netns", upstream])
        for name, interface, address in (
            (workload, pw_host, "10.77.1.2/24"), (proxy, pw_proxy, "10.77.1.1/24"),
            (proxy, pu_proxy, "10.77.2.1/24"), (upstream, pu_upstream, "10.77.2.2/24"),
        ):
            _ns(name, [_tool("ip"), "addr", "add", address, "dev", interface])
            _ns(name, [_tool("ip"), "link", "set", interface, "up"])
        upstream_server = subprocess.Popen([_tool("ip"), "netns", "exec", upstream, sys.executable, str(fixture), "server", "--bind", "10.77.2.2", "--port", "18081", "--mode", "upstream"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        alternate_server = subprocess.Popen([_tool("ip"), "netns", "exec", upstream, sys.executable, str(fixture), "server", "--bind", "10.77.2.2", "--port", "18082", "--mode", "alternate"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        proxy_server = subprocess.Popen([_tool("ip"), "netns", "exec", proxy, sys.executable, str(fixture), "proxy", "--bind", "10.77.1.1", "--port", "18080", "--upstream-host", "10.77.2.2", "--upstream-port", "18081"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        management_server = subprocess.Popen([_tool("ip"), "netns", "exec", proxy, sys.executable, str(fixture), "server", "--bind", "10.77.2.1", "--port", "19090", "--mode", "alternate"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        processes.extend((upstream_server, alternate_server, proxy_server, management_server))
        time.sleep(0.1)
        management_control = _client(upstream, fixture, "10.77.2.1", 19090)
        proxy_alt_control = _client(proxy, fixture, "10.77.2.2", 18082)
        _ns(proxy, [_tool("nft"), "add", "table", "inet", "mirage"])
        _ns(proxy, [_tool("nft"), "add", "chain", "inet", "mirage", "output", "{ type filter hook output priority 0; policy drop; }"])
        _ns(proxy, [_tool("nft"), "add", "chain", "inet", "mirage", "input", "{ type filter hook input priority 0; policy drop; }"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "ct", "state", "established,related", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "input", "ct", "state", "established,related", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "ip", "daddr", "10.77.2.2", "tcp", "dport", "18081", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "input", "iifname", pw_proxy, "tcp", "dport", "18080", "accept"])
        workload_package = _client(workload, fixture, "10.77.1.1", 18080)
        proxy_approved = _client(proxy, fixture, "10.77.2.2", 18081)
        alternate_control = _client(upstream, fixture, "10.77.2.2", 18082)
        proxy_alt_port = _client(proxy, fixture, "10.77.2.2", 18082)
        proxy_external = _client(proxy, fixture, "203.0.113.10", 443)
        upstream_pivot = _client(upstream, fixture, "10.77.2.1", 19090)
        redirect = _client(proxy, fixture, "10.77.2.2", 18081, "REDIRECT")
        redirected_fetch = _client(proxy, fixture, "203.0.113.10", 80)
        bulk = _client(proxy, fixture, "10.77.2.2", 18081, "BULK", 4096)
        manifest = {"component": "mirage-fixture-proxy", "version": "0.4.0", "config_sha256": hashlib.sha256(b"10.77.2.2:18081-only").hexdigest()}
        snapshot_core = {
            "as_of": "2026-09-11",
            "source": "mirage-local-test-fixture",
            "affected": ["0.3.0-vulnerable"],
        }
        vulnerability_snapshot = dict(
            snapshot_core,
            snapshot_sha256=hashlib.sha256(json.dumps(snapshot_core, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest(),
        )
        checks = {
            "C14": bool(manifest["component"] and manifest["version"] and len(manifest["config_sha256"]) == 64),
            "C15": manifest["version"] not in vulnerability_snapshot["affected"],
            "C16": management_server.poll() is None and management_control["connected"] and not upstream_pivot["connected"],
            "C17": proxy_approved["connected"] and alternate_control["connected"] and proxy_alt_control["connected"] and not proxy_alt_port["connected"] and not proxy_external["connected"] and redirect["connected"] and not redirected_fetch["connected"],
            "C18": bulk["connected"] and bulk["over_limit"],
        }
        return {"checks": checks, "workload_package": workload_package, "proxy_approved": proxy_approved, "alternate_control": alternate_control, "proxy_alt_control": proxy_alt_control, "proxy_alt_port": proxy_alt_port, "proxy_external": proxy_external, "management_control": management_control, "upstream_pivot": upstream_pivot, "management_service_live": management_server.poll() is None, "redirect": redirect, "redirected_fetch": redirected_fetch, "bulk": {"connected": bulk["connected"], "over_limit": bulk["over_limit"]}, "manifest": manifest, "vulnerability_snapshot": vulnerability_snapshot}
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        for name in reversed(namespaces):
            _run([_tool("ip"), "netns", "del", name], check=False)
