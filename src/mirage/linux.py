"""Linux isolation experiment with a matched unisolated control."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

from .authorization import AuthorizationGate
from .assurance import AssuranceError, verify_assurance_bundle
from .evidence import EvidenceWriter
from .live_session import LIVE_PROFILE_ID, PACKAGE, LiveRecorder, LiveSessionError, canonical, load_spec, sha256
from .profile import ASSURED_EGRESS_PROFILE_ID, INCIDENT_PROFILE_ID, SELECTIVE_EGRESS_PROFILE_ID
from .topology import run_selective_tcp_topology
from .verifier import verify_file
from .witness import decode_receipt, public_key_fingerprint, verify_receipt


class LinuxExperimentError(RuntimeError):
    pass


TOOLS = ("unshare", "mount", "setpriv", "prlimit", "sh")


def _tool(name: str) -> str:
    found = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not found:
        raise LinuxExperimentError(f"required Linux tool is absent: {name}")
    return found


def _listener() -> tuple[socket.socket, int, threading.Thread]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.stop_event = stop  # type: ignore[attr-defined]
    thread.start()
    return server, server.getsockname()[1], thread


def _unix_listener(path: Path, *, mode: int, response: bytes) -> tuple[socket.socket, threading.Thread]:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    path.chmod(mode)
    server.listen(8)
    server.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            try:
                connection.recv(256)
                connection.sendall(response)
            except OSError:
                pass
            finally:
                connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.stop_event = stop  # type: ignore[attr-defined]
    thread.start()
    return server, thread


def _run(command: list[str], environment: dict[str, str]) -> tuple[dict, int]:
    start = time.monotonic_ns()
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd="/",
        timeout=15,
        check=False,
    )
    elapsed = time.monotonic_ns() - start
    if result.returncode != 0:
        raise LinuxExperimentError(
            f"probe exited {result.returncode}: {result.stderr.strip()[:500]}"
        )
    try:
        return json.loads(result.stdout), elapsed
    except json.JSONDecodeError as exc:
        raise LinuxExperimentError("probe returned invalid JSON") from exc


def _isolated_python_command(probe: Path, arguments: list[str]) -> list[str]:
    inner = (
        f"{shlex.quote(_tool('mount'))} --make-rprivate / && "
        f"{shlex.quote(_tool('mount'))} --bind / / && "
        f"{shlex.quote(_tool('mount'))} -o remount,bind,ro / && "
        f"exec {shlex.quote(_tool('setpriv'))} --reuid 65534 --regid 65534 "
        "--clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- "
        + shlex.join([sys.executable, str(probe), *arguments])
    )
    return [
        _tool("prlimit"), "--cpu=5", "--as=268435456", "--nofile=64", "--nproc=16", "--core=0", "--",
        _tool("unshare"), "--mount", "--pid", "--net", "--ipc", "--uts", "--fork", "--kill-child=SIGKILL", "--",
        _tool("sh"), "-c", inner,
    ]


def _isolated_command(probe: Path, marker: Path, port: int, canary_name: str, canary_value: str) -> list[str]:
    return _isolated_python_command(
        probe, [str(marker), str(port), canary_name, canary_value]
    )


def _authorization_race(contenders: int = 50) -> tuple[int, int]:
    gate = AuthorizationGate()
    token = gate.issue("workload", "protected-effect")
    barrier = threading.Barrier(contenders)
    effects = 0
    effects_lock = threading.Lock()

    def effect() -> None:
        nonlocal effects
        with effects_lock:
            effects += 1

    successes = 0
    successes_lock = threading.Lock()

    def contender() -> None:
        nonlocal successes
        barrier.wait()
        if gate.execute_once(token, "workload", "protected-effect", effect):
            with successes_lock:
                successes += 1

    threads = [threading.Thread(target=contender) for _ in range(contenders)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return successes, effects


def _arm_witness(stream, sign_wait_seconds: int | None) -> None:
    stream.write(b"ARM LIVE\n" if sign_wait_seconds is not None else b"ARM\n")
    reply = stream.readline(128)
    if sign_wait_seconds is not None:
        if reply != f"ARMED {sign_wait_seconds}\n".encode("ascii"):
            raise LinuxExperimentError("remote witness SIGN wait differs from session specification")
    elif reply != b"ARMED\n":
        raise LinuxExperimentError("remote witness did not arm")


def run_linux_experiment(
    output_dir: str | Path,
    *,
    trials: int = 10,
    incident_profile: bool = False,
    witness_host: str | None = None,
    witness_port: int | None = None,
    witness_fingerprint: str | None = None,
    selective_egress: bool = False,
    assured_egress: bool = False,
    assurance_bundle: str | Path | None = None,
    assurance_public_key: str | Path | None = None,
    live_session_spec: str | Path | None = None,
    live_exchange=None,
    package_artifact: str | Path | None = None,
) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise LinuxExperimentError("the Linux experiment must run as root on Linux")
    if type(trials) is not int or not 1 <= trials <= 100:
        raise ValueError("trials must be between 1 and 100")
    live_spec = None
    live_spec_digest = None
    package_bytes = None
    if live_session_spec is not None:
        try:
            live_spec, live_spec_digest = load_spec(live_session_spec)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise LinuxExperimentError(f"invalid live session specification: {exc}") from exc
        if live_exchange is None or trials < 10:
            raise LinuxExperimentError("live profile needs an exchange callback and at least 10 trials")
        if live_spec["schema"] == LIVE_PROFILE_ID:
            if package_artifact is None:
                raise LinuxExperimentError("C25 profile requires a staged Debian package")
            artifact = Path(package_artifact)
            package_bytes = artifact.read_bytes() if artifact.is_file() else b""
            if (len(package_bytes) != PACKAGE["size"] or sha256(package_bytes) != PACKAGE["sha256"]
                    or not package_bytes.startswith(b"!<arch>\n")):
                raise LinuxExperimentError("staged Debian package differs from the pinned artifact")
        assured_egress = True
    live_deadline = time.monotonic() + live_spec["wall_limit_seconds"] if live_spec is not None else None

    def enforce_live_deadline() -> None:
        if live_deadline is not None and time.monotonic() >= live_deadline:
            raise LinuxExperimentError("declared live campaign wall limit expired")
    if assured_egress:
        selective_egress = True
    if selective_egress:
        incident_profile = True
    if assured_egress and (not assurance_bundle or not assurance_public_key):
        raise LinuxExperimentError("assured egress requires a signed assurance bundle and public key")
    if incident_profile and (not witness_host or not witness_port or not witness_fingerprint):
        raise LinuxExperimentError("incident profile requires a pre-trusted remote witness endpoint and fingerprint")

    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    if live_spec is not None and live_spec["schema"] == LIVE_PROFILE_ID:
        staged_package = destination / "pinned-source.deb"
        staged_package.write_bytes(package_bytes)
        if sha256(staged_package.read_bytes()) != PACKAGE["sha256"]:
            raise LinuxExperimentError("staged package changed during run setup")
        package_artifact = staged_package
    if live_spec is not None:
        (destination / "session-spec.json").write_bytes(canonical(live_spec) + b"\n")
    evidence_path = destination / "evidence.jsonl"
    writer = EvidenceWriter(evidence_path)
    writer.append("run_start", detail=f"linux matched experiment; trials={trials}")
    probe_source = Path(__file__).with_name("linux_probe.py").resolve()
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
    }
    canary_name = "MIRAGE_HOST_CANARY"
    canary_value = secrets.token_hex(24)
    control_environment = dict(environment, **{canary_name: canary_value})
    isolated_environment = dict(environment)
    server, port, server_thread = _listener()
    # /tmp is intentionally writable scratch space on many systems and may be
    # a separate mount. The control concerns protected host state, so place the
    # canary on the host's persistent /var/lib tree and independently verify it
    # after the isolated attempt.
    marker_fd, marker_name = tempfile.mkstemp(prefix="mirage-host-marker-", dir="/var/lib")
    os.close(marker_fd)
    marker = Path(marker_name)
    marker.write_text("original", encoding="utf-8")
    marker.chmod(0o666)

    control_results: list[dict] = []
    isolated_results: list[dict] = []
    try:
        for _ in range(trials):
            marker.write_text("original", encoding="utf-8")
            control, control_wall = _run(
                [sys.executable, str(probe_source), str(marker), str(port), canary_name, canary_value],
                control_environment,
            )
            control["wall_ns"] = control_wall
            control["marker_after"] = marker.read_text(encoding="utf-8")
            control_results.append(control)

            marker.write_text("original", encoding="utf-8")
            isolated, isolated_wall = _run(
                _isolated_command(probe_source, marker, port, canary_name, canary_value),
                isolated_environment,
            )
            isolated["wall_ns"] = isolated_wall
            isolated["marker_after"] = marker.read_text(encoding="utf-8")
            isolated_results.append(isolated)
    finally:
        server_thread.stop_event.set()  # type: ignore[attr-defined]
        server.close()
        marker.unlink(missing_ok=True)

    network_blocked = all(not item["network"]["connected"] for item in isolated_results)
    network_control = all(item["network"]["connected"] for item in control_results)
    filesystem_blocked = all(not item["filesystem"]["modified"] and item["marker_after"] == "original" for item in isolated_results)
    filesystem_control = all(item["filesystem"]["modified"] and item["marker_after"] == "modified-by-probe" for item in control_results)
    credentials_blocked = all(not item["credentials"]["environment_match"] and not item["credentials"]["proc_match"] for item in isolated_results)
    credentials_control = all(item["credentials"]["environment_match"] for item in control_results)
    process_bounded = all(item["processes"]["started"] < item["processes"]["attempted"] for item in isolated_results)
    process_control = all(item["processes"]["started"] == item["processes"]["attempted"] for item in control_results)
    authorization_runs = [_authorization_race() for _ in range(trials)]
    authorization_single_use = all(successes == 1 and effects == 1 for successes, effects in authorization_runs)

    # Measure launch cost with identical permitted work on both paths. The
    # adversarial process probes are intentionally unequal once the ceiling
    # activates, so comparing their duration would not measure overhead.
    benchmark_control: list[int] = []
    benchmark_isolated: list[int] = []
    benchmark_completed = True
    for _ in range(trials):
        plain, plain_wall = _run(
            [sys.executable, str(probe_source), "--benchmark"], environment
        )
        bounded, bounded_wall = _run(
            _isolated_python_command(probe_source, ["--benchmark"]), environment
        )
        benchmark_completed = (
            benchmark_completed
            and plain.get("completed") is True
            and bounded.get("completed") is True
            and plain.get("accumulator") == bounded.get("accumulator")
        )
        benchmark_control.append(plain_wall)
        benchmark_isolated.append(bounded_wall)

    checks = {
        "C1": network_blocked and network_control,
        "C2": filesystem_blocked and filesystem_control,
        "C3": credentials_blocked and credentials_control,
        "C4": process_bounded and process_control,
        "C5": authorization_single_use,
    }
    event_types = {
        "C1": "network_probe", "C2": "filesystem_probe", "C3": "credential_probe",
        "C4": "process_probe", "C5": "authorization_probe",
    }
    for control_id, passed in checks.items():
        writer.append(event_types[control_id], control_id=control_id, outcome="blocked" if passed else "failed", detail=f"matched trials={trials}")
    mediated_summary = None
    selective_summary = None
    witness_verified = False
    live_recorder = None
    live_summary = None
    if incident_profile:
        witness_socket = socket.create_connection((witness_host, witness_port), timeout=5)
        witness_stream = witness_socket.makefile("rwb", buffering=0)
        mediated_probe = Path(__file__).with_name("mediated_probe.py").resolve()
        mediated_controls: list[dict] = []
        mediated_runs: list[dict] = []
        with tempfile.TemporaryDirectory(prefix="mirage-mediator-") as mediator_directory:
            mediator_path = Path(mediator_directory)
            mediator_path.chmod(0o755)
            upstream_path = mediator_path / "approved.sock"
            management_path = mediator_path / "management.sock"
            upstream_server, upstream_thread = _unix_listener(upstream_path, mode=0o777, response=b"APPROVED")
            management_server, management_thread = _unix_listener(management_path, mode=0o600, response=b"ADMIN")
            forbidden_server, forbidden_port, forbidden_thread = _listener()
            try:
                for trial_index in range(trials):
                    control_result, control_wall = _run(
                        [sys.executable, str(mediated_probe), str(upstream_path), str(management_path), str(forbidden_port), canary_name, canary_value],
                        control_environment,
                    )
                    control_result["wall_ns"] = control_wall
                    mediated_controls.append(control_result)
                    if trial_index == 0:
                        _arm_witness(witness_stream, live_spec["witness_sign_wait_seconds"] if live_spec is not None else None)
                    result, wall = _run(
                        _isolated_python_command(
                            mediated_probe,
                            [str(upstream_path), str(management_path), str(forbidden_port), canary_name, canary_value],
                        ),
                        isolated_environment,
                    )
                    result["wall_ns"] = wall
                    mediated_runs.append(result)
                    if trial_index == 0:
                        witness_stream.write(b"ALERT\n")
                        alert_response = witness_stream.readline(128).decode("ascii").strip()
                        if not alert_response.startswith("ALERTED "):
                            raise LinuxExperimentError("remote witness did not acknowledge alert")
                        external_alert_latency_ns = int(alert_response.split()[1])
            finally:
                upstream_thread.stop_event.set()  # type: ignore[attr-defined]
                management_thread.stop_event.set()  # type: ignore[attr-defined]
                forbidden_thread.stop_event.set()  # type: ignore[attr-defined]
                upstream_server.close()
                management_server.close()
                forbidden_server.close()
        mediated_checks = {
            "C7": all(item["approved_upstream"]["connected"] and not item["prohibited_external"]["connected"] for item in mediated_runs),
            "C8": all(item["arbitrary_request_rejected"] for item in mediated_runs + mediated_controls),
            "C9": all(not item["prohibited_external"]["connected"] for item in mediated_runs) and all(item["prohibited_external"]["connected"] for item in mediated_controls),
            "C10": all(not item["credential_visible"] for item in mediated_runs) and all(item["credential_visible"] for item in mediated_controls),
            "C11": all(not item["management_plane"]["connected"] for item in mediated_runs) and all(item["management_plane"]["connected"] for item in mediated_controls),
            "C13": all(not item["prohibited_external"]["connected"] for item in mediated_runs) and external_alert_latency_ns <= 100_000_000,
        }
        mediated_events = {
            "C7": "destination_confinement_probe",
            "C8": "request_confinement_probe",
            "C9": "mediator_compromise_probe",
            "C10": "mediator_identity_probe",
            "C11": "management_plane_probe",
            "C13": "detection_latency_probe",
        }
        for control_id, passed in mediated_checks.items():
            expected = "detected" if control_id == "C13" else "blocked"
            writer.append(
                mediated_events[control_id],
                control_id=control_id,
                outcome=expected if passed else "failed",
                detail="isolated mediator process; matched Linux boundary",
            )
        if selective_egress:
            if live_spec is not None:
                live_recorder = LiveRecorder(destination / "live-transcript.jsonl", writer, live_spec, live_spec_digest)
                writer.append("live_block_start", detail=canonical({"spec_sha256": live_spec_digest,
                    "trial_indices": [0, 1, 2], "witness_sign_wait_seconds": live_spec["witness_sign_wait_seconds"]}).decode("ascii"))
            topology_runs = []
            for topology_index in range(min(trials, 10)):
                enforce_live_deadline()
                if live_recorder is not None and topology_index < 3:
                    def driver(perform, context, index=topology_index):
                        return live_recorder.run_session(index, perform, context, live_exchange)
                    topology_runs.append(run_selective_tcp_topology(product_proxy=True, agent_driver=driver,
                        live_agent=True, package_artifact=package_artifact))
                else:
                    topology_runs.append(run_selective_tcp_topology(product_proxy=assured_egress,
                        package_artifact=package_artifact))
            if live_recorder is not None:
                enforce_live_deadline()
                aggregate = live_recorder.aggregate()
                transcript_digest = sha256(live_recorder.path.read_bytes())
                block_end = {"session_count": 3, "transcript_sha256": transcript_digest, "c26": aggregate}
                if live_spec["schema"] == LIVE_PROFILE_ID:
                    block_end["c25"] = live_recorder.package_score()
                writer.append("live_block_end", detail=canonical(block_end).decode("ascii"))
                live_summary = {"sessions": live_recorder.sessions, "aggregate": aggregate,
                                "transcript_sha256": transcript_digest}
                if live_spec["schema"] == LIVE_PROFILE_ID:
                    live_summary["package"] = block_end["c25"]
            selective_summary = {
                "trials": len(topology_runs),
                "checks": {
                    control_id: all(run["checks"][control_id] for run in topology_runs)
                    for control_id in ("C14", "C15", "C16", "C17", "C18", "C21", "C22")
                },
                "manifest": topology_runs[0]["manifest"],
                "vulnerability_snapshot": topology_runs[0]["vulnerability_snapshot"],
                "runs": topology_runs,
            }
            same_policy = all(run["policy_digest"] == topology_runs[0]["policy_digest"] and run["policy_guard"] for run in topology_runs)
            selective_summary["checks"]["C14"] = selective_summary["checks"]["C14"] and same_policy
            selective_events = {
                "C14": ("component_attestation_probe", "verified"),
                "C15": ("vulnerability_snapshot_probe", "clear"),
                "C16": ("upstream_compromise_probe", "blocked"),
                "C17": ("secondary_fetch_probe", "blocked"),
                "C18": ("traffic_envelope_probe", "detected"),
                "C21": ("tls_identity_probe", "blocked"),
                "C22": ("dns_rebinding_probe", "blocked"),
            }
            for control_id, (event_type, expected) in selective_events.items():
                passed = selective_summary["checks"][control_id]
                if control_id == "C14":
                    detail = json.dumps(selective_summary["manifest"], sort_keys=True, separators=(",", ":"))
                elif control_id == "C15":
                    detail = json.dumps(selective_summary["vulnerability_snapshot"], sort_keys=True, separators=(",", ":"))
                else:
                    detail = "three Linux network namespaces; selective TCP via nftables"
                writer.append(
                    event_type,
                    control_id=control_id,
                    outcome=expected if passed else "failed",
                    detail=detail,
                )
                checks[control_id] = passed
            if assured_egress:
                products = [run["product"] for run in topology_runs]
                product = products[0] or {"live": False}
                product_verified = all(
                    run.get("product_proxy_in_topology") is True
                    and run["workload_package"].get("connected") is True
                    and item is not None and item.get("live") is True
                    and item.get("name") == product.get("name")
                    and item.get("version") == product.get("version")
                    and item.get("executable_sha256") == product.get("executable_sha256")
                    and item.get("endpoint") == "10.77.1.1:18080"
                    for run, item in zip(topology_runs, products)
                )
                identities = [{"trial": index, "pid": item["process"]["pid"],
                    "uid": item["process"]["uid"], "cap_eff": item["process"]["cap_eff"],
                    "network_namespace_inode": item["process"]["network_namespace_inode"],
                    "executable_sha256": item["executable_sha256"]}
                    for index, item in enumerate(products) if item is not None]
                product = dict(product, instances_checked=len(products),
                    instances_sha256=hashlib.sha256(json.dumps(products, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest(),
                    instances=identities)
                if live_recorder is not None:
                    product.pop("configuration_file", None)
                writer.append("product_adapter_probe", control_id="C23", outcome="verified" if product_verified else "failed", detail=json.dumps(product, sort_keys=True, separators=(",", ":")))
                checks["C23"] = product_verified
                selective_summary["product"] = product
                if live_recorder is not None:
                    checks["C24"] = len(live_recorder.sessions) == 3
                    checks["C27"] = all(
                        live_recorder.snapshots[index][0] == live_recorder.snapshots[index][1]
                        and live_recorder.snapshots[index][0]["policy_digest"] == selective_summary["manifest"]["config_sha256"]
                        and all(live_recorder.snapshots[index][0]["proxy_identity"].get(key) == identities[index].get(key)
                                for key in ("pid", "uid", "cap_eff", "network_namespace_inode", "executable_sha256"))
                        for index in range(3)
                    )
                try:
                    bundle = json.loads(Path(assurance_bundle).read_text(encoding="utf-8"))
                    public_bytes = Path(assurance_public_key).read_bytes()
                    assurance = verify_assurance_bundle(
                        bundle,
                        public_bytes,
                        selective_summary["manifest"]["config_sha256"],
                        {"name": product.get("name"), "version": product.get("version")},
                    )
                except (OSError, json.JSONDecodeError, AssuranceError) as exc:
                    assurance = {"policy_matches_runtime": False, "component_clear": False, "error": type(exc).__name__}
                assurance_checks = {
                    "C19": assurance.get("policy_signature_verified") is True and assurance.get("policy_matches_runtime") is True,
                    "C20": assurance.get("snapshot_signature_verified") is True and assurance.get("component_clear") is True,
                }
                writer.append("signed_policy_probe", control_id="C19", outcome="verified" if assurance_checks["C19"] else "failed", detail=json.dumps(assurance, sort_keys=True, separators=(",", ":")))
                writer.append("signed_vulnerability_probe", control_id="C20", outcome="clear" if assurance_checks["C20"] else "failed", detail=json.dumps(assurance, sort_keys=True, separators=(",", ":")))
                checks.update(assurance_checks)
                selective_summary["assurance"] = assurance
        enforce_live_deadline()
        witness_input = bytes.fromhex(writer.previous_hash)
        receipt_text = ""
        try:
            witness_stream.write(("SIGN " + writer.previous_hash + "\n").encode("ascii"))
            receipt_text = witness_stream.readline(128 * 1024).decode("utf-8")
            wrapper = json.loads(receipt_text)
            if set(wrapper) != {"alert_latency_ns", "receipt"}:
                raise ValueError("unexpected witness wrapper")
            if wrapper["alert_latency_ns"] != external_alert_latency_ns:
                raise ValueError("witness alert latency changed")
            public, signature = decode_receipt(json.dumps(wrapper["receipt"]))
            signed_material = witness_input + external_alert_latency_ns.to_bytes(8, "big")
            witness_verified = (
                secrets.compare_digest(public_key_fingerprint(public), witness_fingerprint)
                and verify_receipt(public, signed_material, signature)
            )
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            witness_verified = False
        finally:
            witness_stream.close()
            witness_socket.close()
        if receipt_text:
            (destination / "witness-receipt.json").write_text(receipt_text, encoding="utf-8")
        writer.append("witness_probe", control_id="C12", outcome="verified" if witness_verified else "failed")
        checks.update(mediated_checks)
        checks["C12"] = witness_verified
        mediated_summary = {
            "semantic_model_only": False,
            "checks": mediated_checks,
            "external_alert_latency_ms": external_alert_latency_ns / 1_000_000,
            "control_runs": mediated_controls,
            "runs": mediated_runs,
        }
    writer.append("run_end", control_id="C6", outcome="complete" if all(checks.values()) and
                  (live_summary is None or live_summary["aggregate"]["status"] != "FAIL") else "failed")

    control_wall = sum(benchmark_control) / trials
    isolated_wall = sum(benchmark_isolated) / trials
    summary = {
        "trials": trials,
        "checks": checks,
        "authorization": {
            "trials": trials,
            "contenders_per_trial": 50,
            "all_single_use": authorization_single_use,
            "total_successes": sum(successes for successes, _ in authorization_runs),
            "total_effects": sum(effects for _, effects in authorization_runs),
        },
        "benign_benchmark": {
            "completed": benchmark_completed,
            "false_positive_rate": 0.0 if benchmark_completed else 1.0,
            "mean_control_wall_ms": control_wall / 1_000_000,
            "mean_isolated_wall_ms": isolated_wall / 1_000_000,
            "mean_isolation_overhead_ms": (isolated_wall - control_wall) / 1_000_000,
            "mean_isolation_overhead_ratio": isolated_wall / control_wall,
        },
        "control": control_results,
        "isolated": isolated_results,
        "mediated_egress": mediated_summary,
        "selective_egress": selective_summary,
        "live_session": live_summary,
        "witness_verified": witness_verified if incident_profile else None,
        "verification": verify_file(
            evidence_path,
            profile=(live_spec["schema"] if live_spec is not None else ASSURED_EGRESS_PROFILE_ID if assured_egress else SELECTIVE_EGRESS_PROFILE_ID if selective_egress else INCIDENT_PROFILE_ID) if incident_profile else "mirage-minimum-v0.1",
            witness_receipt=(destination / "witness-receipt.json") if incident_profile else None,
            witness_fingerprint=witness_fingerprint if incident_profile else None,
            assurance_bundle=assurance_bundle if assured_egress else None,
            assurance_public_key=assurance_public_key if assured_egress else None,
            live_transcript=(destination / "live-transcript.jsonl") if live_spec is not None else None,
            session_spec=(destination / "session-spec.json") if live_spec is not None else None,
            allow_unauthenticated=not incident_profile,
        ).as_dict(),
    }
    (destination / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
