"""Synthetic controller smoke test for the full witnessed live-session path."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from mirage.linux import run_linux_experiment
from mirage.live_session import ACTION_SCHEMA, LIVE_PROFILE_ID, SCENARIOS, TARGETS, canonical


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--assurance-bundle", type=Path, required=True)
    parser.add_argument("--assurance-public-key", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mirage-live-ci-") as temporary:
        spec_path = Path(temporary) / "session-spec.json"
        spec = {"schema": LIVE_PROFILE_ID, "session_id": "synthetic-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
                "model": "deterministic-test-controller", "checkpoint_sha256": "0" * 64,
                "runtime": "local synthetic test", "settings": {}, "system_prompt": "Synthetic test controller",
                "scenario_prompts": {name: name for name in SCENARIOS}, "action_budget": 4,
                "action_schema": ACTION_SCHEMA, "scenarios": list(SCENARIOS),
                "targets": {name: list(target) for name, target in TARGETS.items()},
                "controller_revision": "synthetic-ci", "guest_revision": "synthetic-ci",
                "wall_limit_seconds": 600, "witness_sign_wait_seconds": 300}
        spec_path.write_bytes(canonical(spec) + b"\n")
        witness = subprocess.Popen([sys.executable, "-m", "mirage.witness_server", "--host", "127.0.0.1",
            "--sign-wait-seconds", "300"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            identity = json.loads(witness.stdout.readline())

            def exchange(event: dict):
                if event["event"] == "observation":
                    return None
                trial = event["trial"]
                if trial < 2:
                    host, port = TARGETS["alternate" if trial == 0 else "management"]
                    action = {"host": host, "port": port, "payload": "GET package"}
                else:
                    action = {"host": "10.77.1.1", "port": 18080,
                              "payload": "GET http://10.77.2.2:18081/package.deb HTTP/1.1\r\nHost: 10.77.2.2:18081\r\nConnection: close\r\n\r\n"}
                return {"session_id": spec["session_id"], "trial": trial, "step": event["step"],
                        "visible_model_response": json.dumps(action), "action": action}

            result = run_linux_experiment(args.output, trials=10,
                witness_host=identity["host"], witness_port=identity["port"],
                witness_fingerprint=identity["fingerprint"],
                assurance_bundle=args.assurance_bundle, assurance_public_key=args.assurance_public_key,
                live_session_spec=spec_path, live_exchange=exchange)
            witness.wait(timeout=10)
            print(json.dumps({"verification": result["verification"], "live_session": result["live_session"]}, indent=2))
            return 0 if result["verification"]["status"] == "PASS" else 1
        finally:
            if witness.poll() is None:
                witness.terminate()
                witness.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
