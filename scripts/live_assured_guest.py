"""Run the witnessed Mirage campaign; relay model turns over authenticated stdio."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import select
import sys
import tempfile
import time

from mirage.linux import run_linux_experiment
from mirage.live_session import canonical, load_spec


def emit(value: dict) -> None:
    sys.stdout.buffer.write(canonical(value) + b"\n")
    sys.stdout.buffer.flush()


def read_message(timeout: float) -> dict:
    ready, _, _ = select.select([sys.stdin.buffer], [], [], timeout)
    if not ready:
        raise TimeoutError("controller message exceeded declared campaign deadline")
    line = sys.stdin.buffer.readline(100_001)
    if not line or not line.endswith(b"\n") or len(line) > 100_000:
        raise RuntimeError("controller disconnected or exceeded message bound")
    value = json.loads(line)
    if type(value) is not dict:
        raise ValueError("controller message must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--witness-host", required=True)
    parser.add_argument("--witness-port", type=int, required=True)
    parser.add_argument("--witness-fingerprint", required=True)
    parser.add_argument("--assurance-bundle", type=Path, required=True)
    parser.add_argument("--assurance-public-key", type=Path, required=True)
    args = parser.parse_args()
    bootstrap = read_message(30)
    if set(bootstrap) != {"event", "spec"} or bootstrap["event"] != "session_spec":
        raise ValueError("session specification must be the first controller message")
    with tempfile.TemporaryDirectory(prefix="mirage-session-spec-") as temporary:
        spec_path = Path(temporary) / "session-spec.json"
        spec_path.write_bytes(canonical(bootstrap["spec"]) + b"\n")
        spec, _ = load_spec(spec_path)
        deadline = time.monotonic() + spec["wall_limit_seconds"]

        def exchange(event: dict):
            emit(event)
            if event["event"] == "observation":
                return None
            return read_message(max(0.01, deadline - time.monotonic()))

        result = run_linux_experiment(args.output, trials=args.trials,
            witness_host=args.witness_host, witness_port=args.witness_port,
            witness_fingerprint=args.witness_fingerprint,
            assurance_bundle=args.assurance_bundle,
            assurance_public_key=args.assurance_public_key,
            live_session_spec=spec_path, live_exchange=exchange)
    emit({"event": "complete", "verification": result["verification"],
          "output": str(args.output.resolve())})
    return 0 if result["verification"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
