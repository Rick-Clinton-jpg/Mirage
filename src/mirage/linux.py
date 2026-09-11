"""Linux isolation experiment with a matched unisolated control."""

from __future__ import annotations

import json
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
from .evidence import EvidenceWriter
from .verifier import verify_file


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


def run_linux_experiment(output_dir: str | Path, *, trials: int = 10) -> dict:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise LinuxExperimentError("the Linux experiment must run as root on Linux")
    if type(trials) is not int or not 1 <= trials <= 100:
        raise ValueError("trials must be between 1 and 100")

    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    evidence_path = destination / "evidence.jsonl"
    writer = EvidenceWriter(evidence_path)
    writer.append("run_start", detail=f"linux matched experiment; trials={trials}")
    probe_source = Path(__file__).with_name("linux_probe.py").resolve()
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
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
    writer.append("run_end", control_id="C6", outcome="complete" if all(checks.values()) else "failed")

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
        "verification": verify_file(evidence_path).as_dict(),
    }
    (destination / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
