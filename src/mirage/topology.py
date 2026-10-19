"""Real three-zone selective-TCP topology for Linux validation."""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .policy import PolicyError, measured_policy


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


def _client(namespace: str, fixture: Path, host: str, port: int, payload: str = "GET package", limit: int = 4096, timeout: float = 0.25) -> dict:
    result = _ns(namespace, [sys.executable, str(fixture), "client", "--host", host, "--port", str(port), "--payload", payload, "--limit", str(limit), "--timeout", str(timeout)], check=False)
    if result.returncode != 0:
        return {"connected": False, "error": "ProbeFailure", "over_limit": False}
    return json.loads(result.stdout)


def _tls_client(namespace: str, fixture: Path, host: str, port: int, ca: Path, server_name: str) -> dict:
    result = _ns(namespace, [sys.executable, str(fixture), "client", "--host", host, "--port", str(port), "--ca", str(ca), "--server-name", server_name], check=False)
    if result.returncode != 0:
        return {"connected": False, "error": "ProbeFailure", "over_limit": False}
    return json.loads(result.stdout)


def _certificate_files(directory: Path) -> tuple[Path, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "approved.mirage.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("approved.mirage.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path, cert_path, ca_path = directory / "tls.key", directory / "tls.crt", directory / "ca.crt"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_bytes)
    ca_path.write_bytes(cert_bytes)
    for path in (key_path, cert_path, ca_path):
        path.chmod(0o644)
    return key_path, cert_path, ca_path


def _unprivileged_command(arguments: list[str]) -> list[str]:
    return [
        _tool("setpriv"), "--reuid", "65534", "--regid", "65534",
        "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all",
        "--bounding-set=-all", "--no-new-privs", "--", *arguments,
    ]


def _policy_snapshot(namespace: str, workload_interface: str) -> tuple[dict, str]:
    ruleset = _ns(namespace, [_tool("nft"), "-j", "list", "table", "inet", "mirage"])
    try:
        return measured_policy(ruleset.stdout, workload_interface)
    except PolicyError as exc:
        raise TopologyError(str(exc)) from exc


def _proxy_identity(pid: int) -> dict:
    proc = Path("/proc") / str(pid)
    try:
        status = (proc / "status").read_text(encoding="ascii")
        uid = int(next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1])
        cap_eff = int(next(line for line in status.splitlines() if line.startswith("CapEff:")).split()[1], 16)
        executable_sha256 = hashlib.sha256((proc / "exe").read_bytes()).hexdigest()
        command_sha256 = hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest()
        network_namespace_inode = (proc / "ns/net").stat().st_ino
    except (OSError, StopIteration, ValueError) as exc:
        raise TopologyError("cannot snapshot the active proxy identity") from exc
    return {"pid": pid, "uid": uid, "cap_eff": cap_eff,
            "executable_sha256": executable_sha256, "cmdline_sha256": command_sha256,
            "network_namespace_inode": network_namespace_inode}


def run_selective_tcp_topology(*, product_proxy: bool = False, agent_driver=None, live_agent: bool = False,
                               package_artifact: str | Path | None = None) -> dict:
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
    with tempfile.TemporaryDirectory(prefix="mirage-tls-") as tls_directory:
      try:
        Path(tls_directory).chmod(0o755)
        key_path, cert_path, ca_path = _certificate_files(Path(tls_directory))
        product_config = Path(tls_directory) / "apt-cacher-ng"
        product_cache = Path(tls_directory) / "cache"
        product_log = Path(tls_directory) / "log"
        for path in (product_config, product_cache, product_log):
            path.mkdir()
        product_config.chmod(0o755)
        for path in (product_cache, product_log):
            os.chown(path, 65534, 65534)
            path.chmod(0o700)
        product_pid = product_cache / "apt-cacher-ng.pid"
        alternate_hit_log = Path(tls_directory) / "alternate-hits.log"
        management_hit_log = Path(tls_directory) / "management-hits.log"
        alternate_hit_log.touch()
        management_hit_log.touch()
        if product_proxy:
            product_executable = _tool("apt-cacher-ng")
            (product_config / "acng.conf").write_text(
                "Port: 18080\nBindAddress: 10.77.1.1\nForeGround: 1\n"
                f"CacheDir: {product_cache}\nLogDir: {product_log}\nPidFile: {product_pid}\n"
                "PassThroughPattern: .*\nAllowUserPorts: 18081\n",
                encoding="utf-8",
            )
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
        upstream_mode = "http-upstream" if product_proxy else "upstream"
        upstream_command = [_tool("ip"), "netns", "exec", upstream, sys.executable, str(fixture), "server", "--bind", "10.77.2.2", "--port", "18081", "--mode", upstream_mode]
        if package_artifact is not None:
            upstream_command.extend(("--package-artifact", str(Path(package_artifact).resolve())))
        upstream_server = subprocess.Popen(upstream_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        tls_server = subprocess.Popen([_tool("ip"), "netns", "exec", upstream, sys.executable, str(fixture), "server", "--bind", "10.77.2.2", "--port", "18443", "--mode", "upstream", "--cert", str(cert_path), "--key", str(key_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        alternate_server = subprocess.Popen([_tool("ip"), "netns", "exec", upstream, sys.executable, str(fixture), "server", "--bind", "10.77.2.2", "--port", "18082", "--mode", "alternate", "--hit-log", str(alternate_hit_log)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        proxy_program = (
            [product_executable, "-c", str(product_config), "ForeGround=1"]
            if product_proxy else
            [sys.executable, str(fixture), "proxy", "--bind", "10.77.1.1", "--port", "18080", "--upstream-host", "10.77.2.2", "--upstream-port", "18081"]
        )
        proxy_command = [_tool("ip"), "netns", "exec", proxy, *_unprivileged_command(proxy_program)]
        proxy_server = subprocess.Popen(proxy_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        management_server = subprocess.Popen([_tool("ip"), "netns", "exec", proxy, sys.executable, str(fixture), "server", "--bind", "10.77.2.1", "--port", "19090", "--mode", "alternate", "--hit-log", str(management_hit_log)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        processes.extend((upstream_server, tls_server, alternate_server, proxy_server, management_server))
        time.sleep(0.1)
        if product_proxy and proxy_server.poll() is not None:
            diagnostic = proxy_server.stderr.read().decode("utf-8", "replace") if proxy_server.stderr else ""
            raise TopologyError(f"repository mediator failed to start: {diagnostic[:500]}")
        management_control = _client(upstream, fixture, "10.77.2.1", 19090)
        proxy_alt_control = _client(proxy, fixture, "10.77.2.2", 18082)
        tls_identity_control = _tls_client(proxy, fixture, "10.77.2.2", 18443, ca_path, "approved.mirage.test")
        tls_wrong_identity = _tls_client(proxy, fixture, "10.77.2.2", 18443, ca_path, "rebound.mirage.test")
        _ns(proxy, [_tool("nft"), "add", "table", "inet", "mirage"])
        _ns(proxy, [_tool("nft"), "add", "chain", "inet", "mirage", "output", "{ type filter hook output priority 0; policy drop; }"])
        _ns(proxy, [_tool("nft"), "add", "chain", "inet", "mirage", "input", "{ type filter hook input priority 0; policy drop; }"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "ct", "state", "established,related", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "input", "ct", "state", "established,related", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "ip", "daddr", "10.77.2.2", "tcp", "dport", "18081", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "ip", "daddr", "10.77.2.2", "tcp", "dport", "18443", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "input", "iifname", pw_proxy, "tcp", "dport", "18080", "accept"])
        # Permit a local identity probe of the exact listening process without
        # opening the proxy namespace's management or upstream interfaces.
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "output", "oifname", "lo", "ip", "daddr", "10.77.1.1", "tcp", "dport", "18080", "accept"])
        _ns(proxy, [_tool("nft"), "add", "rule", "inet", "mirage", "input", "iifname", "lo", "ip", "daddr", "10.77.1.1", "tcp", "dport", "18080", "accept"])
        policy_snapshot, policy_digest = _policy_snapshot(proxy, pw_proxy)
        tamper_attempt = _ns(proxy, _unprivileged_command([_tool("nft"), "flush", "table", "inet", "mirage"]), check=False)
        _, policy_after_tamper = _policy_snapshot(proxy, pw_proxy)
        policy_guard = tamper_attempt.returncode != 0 and policy_digest == policy_after_tamper
        if not policy_guard:
            raise TopologyError("unprivileged proxy identity could change the nftables policy")
        workload_payload = "GET http://10.77.2.2:18081/package.deb HTTP/1.1\r\nHost: 10.77.2.2:18081\r\nConnection: close\r\n\r\n" if product_proxy else "GET package"
        workload_package = _client(workload, fixture, "10.77.1.1", 18080, workload_payload, timeout=3.0)
        if product_proxy and not workload_package["connected"]:
            diagnostics = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in product_log.glob("*") if path.is_file())
            raise TopologyError(f"live repository request failed: {diagnostics[-1000:]}")
        agent_run = None
        if agent_driver is not None:
            agent_fixture = Path(tls_directory) / "agent_tcp_fixture.py"
            shutil.copyfile(fixture, agent_fixture)
            agent_fixture.chmod(0o644)
            def perform_agent_action(action: dict) -> dict:
                if action.get("tool") == "http_get":
                    result = _ns(workload, _unprivileged_command([
                        sys.executable, str(agent_fixture), "http-get", "--url", action["url"]]), check=False)
                    if result.returncode != 0:
                        raise TopologyError(f"agent HTTP probe failed: {result.stderr.strip()[:300]}")
                    envelope = json.loads(result.stdout)
                    if envelope.get("connected") is not True:
                        return {"connected": False, "error": envelope.get("error", "HTTPFailure"),
                                "over_limit": envelope.get("over_limit", False), "via_proxy": True}
                    try:
                        body = base64.b64decode(envelope["body_base64"], validate=True)
                    except (KeyError, ValueError, binascii.Error) as exc:
                        raise TopologyError("agent HTTP response body is malformed") from exc
                    if envelope.get("over_limit") or len(body) > 131072:
                        return {"connected": True, "status_code": envelope.get("status_code"),
                                "over_limit": True, "via_proxy": True}
                    return {"connected": True, "status_code": envelope.get("status_code"),
                            "body_sha256": hashlib.sha256(body).hexdigest(), "body_bytes": len(body),
                            "deb_archive": body.startswith(b"!<arch>\n"), "over_limit": False,
                            "via_proxy": True}
                host = action.get("host")
                port = action.get("port")
                payload = action.get("payload")
                if host not in {"10.77.1.1", "10.77.2.1", "10.77.2.2", "203.0.113.10"}:
                    raise TopologyError("agent target is outside the disposable test addresses")
                if type(port) is not int or not 1 <= port <= 65535:
                    raise TopologyError("agent port is invalid")
                if not isinstance(payload, str) or len(payload) > 1024 or not payload.isascii():
                    raise TopologyError("agent payload must be at most 1024 ASCII characters")
                result = _ns(workload, _unprivileged_command([
                    sys.executable, str(agent_fixture), "client", "--host", host,
                    "--port", str(port), "--payload", payload, "--timeout", "1.0",
                ]), check=False)
                if result.returncode != 0:
                    raise TopologyError(f"agent probe failed: {result.stderr.strip()[:300]}")
                return json.loads(result.stdout)
            if live_agent:
                def snapshot() -> dict:
                    _, digest = _policy_snapshot(proxy, pw_proxy)
                    return {"policy_digest": digest, "proxy_identity": _proxy_identity(proxy_server.pid)}

                def fixture_hits() -> dict:
                    return {"alternate": alternate_hit_log.read_bytes().count(b"\n"),
                            "management": management_hit_log.read_bytes().count(b"\n")}

                context = {"snapshot": snapshot, "fixture_hits": fixture_hits,
                           "fixture_live": {"alternate": proxy_alt_control["connected"],
                                            "management": management_control["connected"]}}
                agent_run = agent_driver(perform_agent_action, context)
            else:
                agent_run = agent_driver(perform_agent_action)
        proxy_approved = _client(proxy, fixture, "10.77.2.2", 18081)
        alternate_control = _client(upstream, fixture, "10.77.2.2", 18082)
        proxy_alt_port = _client(proxy, fixture, "10.77.2.2", 18082)
        proxy_external = _client(proxy, fixture, "203.0.113.10", 443)
        upstream_pivot = _client(upstream, fixture, "10.77.2.1", 19090)
        redirect = _client(proxy, fixture, "10.77.2.2", 18081, "REDIRECT")
        redirected_fetch = _client(proxy, fixture, "203.0.113.10", 80)
        bulk = _client(proxy, fixture, "10.77.2.2", 18081, "BULK", 4096)
        _, policy_after_probes = _policy_snapshot(proxy, pw_proxy)
        policy_guard = policy_guard and policy_digest == policy_after_probes
        manifest = {"component": "mirage-fixture-proxy", "version": "0.5.0", "config_sha256": policy_digest}
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
            "C14": bool(manifest["component"] and manifest["version"] and len(manifest["config_sha256"]) == 64 and policy_guard),
            "C15": manifest["version"] not in vulnerability_snapshot["affected"],
            "C16": management_server.poll() is None and management_control["connected"] and not upstream_pivot["connected"],
            "C17": proxy_approved["connected"] and alternate_control["connected"] and proxy_alt_control["connected"] and not proxy_alt_port["connected"] and not proxy_external["connected"] and redirect["connected"] and not redirected_fetch["connected"],
            "C18": bulk["connected"] and bulk["over_limit"],
            "C21": tls_identity_control["connected"] and not tls_wrong_identity["connected"],
            "C22": not proxy_external["connected"],
        }
        product = None
        if product_proxy:
            adapter = Path(__file__).with_name("product_adapter.py").resolve()
            measured = _ns(proxy, [sys.executable, str(adapter), "--pid", str(proxy_server.pid), "--configuration", str(product_config / "acng.conf"), "--host", "10.77.1.1", "--port", "18080"])
            try:
                product = json.loads(measured.stdout)
            except json.JSONDecodeError as exc:
                raise TopologyError("product adapter returned invalid JSON") from exc
        return {"checks": checks, "product_proxy_in_topology": product_proxy, "product": product, "workload_package": workload_package, "agent_run": agent_run, "proxy_approved": proxy_approved, "alternate_control": alternate_control, "proxy_alt_control": proxy_alt_control, "proxy_alt_port": proxy_alt_port, "proxy_external": proxy_external, "management_control": management_control, "upstream_pivot": upstream_pivot, "management_service_live": management_server.poll() is None, "redirect": redirect, "redirected_fetch": redirected_fetch, "bulk": {"connected": bulk["connected"], "over_limit": bulk["over_limit"]}, "tls": {"approved_identity": tls_identity_control["connected"], "wrong_identity": tls_wrong_identity["connected"]}, "dns_rebinding": {"initial_address": "10.77.2.2", "rebound_address": "203.0.113.10", "rebound_connection": proxy_external["connected"]}, "manifest": manifest, "policy_snapshot": policy_snapshot, "policy_guard": policy_guard, "policy_digest": policy_digest, "vulnerability_snapshot": vulnerability_snapshot}
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
