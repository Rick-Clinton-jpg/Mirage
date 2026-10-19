"""Run a full-count CI campaign with explicitly synthetic assurance inputs.

The witness and signing authority run on this same CI host. This exercises the
protocol but cannot serve as independent reproduction or a separate trust
boundary receipt.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from mirage.assurance import generate_keypair, sign_payload
from mirage.linux import run_linux_experiment


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="mirage-ci-authority-") as temporary:
        private = Path(temporary) / "authority.pem"
        public = Path(temporary) / "authority.raw"
        generate_keypair(private, public)
        now = datetime.now(timezone.utc)
        issued_at = (now - timedelta(minutes=1)).isoformat()
        expires_at = (now + timedelta(hours=2)).isoformat()
        bundle = {
            "policy": sign_payload("policy-attestation", policy, private, issued_at=issued_at, expires_at=expires_at),
            "vulnerabilities": sign_payload(
                "vulnerability-snapshot",
                {"source": "CI synthetic fixture; no NVD assessment", "affected_components": []},
                private,
                issued_at=issued_at,
                expires_at=expires_at,
            ),
        }
        bundle_path = Path(temporary) / "assurance-bundle.json"
        bundle_path.write_text(json.dumps(bundle, sort_keys=True) + "\n", encoding="utf-8")
        witness = subprocess.Popen(
            [sys.executable, "-m", "mirage.witness_server", "--host", "127.0.0.1"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            if witness.stdout is None:
                raise RuntimeError("witness stdout is unavailable")
            identity = json.loads(witness.stdout.readline())
            result = run_linux_experiment(
                args.output,
                trials=100,
                assured_egress=True,
                witness_host=identity["host"],
                witness_port=identity["port"],
                witness_fingerprint=identity["fingerprint"],
                assurance_bundle=bundle_path,
                assurance_public_key=public,
            )
            if witness.wait(timeout=10) != 0:
                raise RuntimeError("witness did not finish cleanly")
        finally:
            if witness.poll() is None:
                witness.terminate()
                witness.wait(timeout=5)
        shutil.copyfile(bundle_path, args.output / "assurance-bundle.json")
        shutil.copyfile(public, args.output / "assurance-public.raw")
        summary = {
            "status": result["verification"]["status"],
            "profile": result["verification"]["profile"],
            "base_trials": result["trials"],
            "topology_trials": result["selective_egress"]["trials"],
            "control_results": {item["control_id"]: item["status"] for item in result["verification"]["controls"]},
            "assurance_source": "CI synthetic fixture; no NVD assessment",
            "witness_boundary": "same CI host; not independent",
            "evidence_sha256": _sha256(args.output / "evidence.jsonl"),
            "results_sha256": _sha256(args.output / "results.json"),
            "witness_receipt_sha256": _sha256(args.output / "witness-receipt.json"),
        }
        (args.output / "campaign-manifest.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["status"] == "PASS" and summary["base_trials"] == 100 and summary["topology_trials"] == 10 else 1


if __name__ == "__main__":
    raise SystemExit(main())
