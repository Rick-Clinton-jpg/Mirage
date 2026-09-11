"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .assurance import generate_keypair, sign_payload
from .demo import write_demo, write_incident_demo
from .linux import run_linux_experiment
from .model import ReportStatus
from .verifier import verify_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="write deterministic example evidence")
    demo.add_argument("--output", required=True)
    demo.add_argument("--incident-profile", action="store_true")
    verify = commands.add_parser("verify", help="verify an evidence JSONL file")
    verify.add_argument("evidence")
    verify.add_argument("--profile", default="mirage-minimum-v0.1")
    experiment = commands.add_parser("linux-experiment", help="run matched Linux containment trials")
    experiment.add_argument("--output", required=True)
    experiment.add_argument("--trials", type=int, default=10)
    experiment.add_argument("--incident-profile", action="store_true")
    experiment.add_argument("--witness-host")
    experiment.add_argument("--witness-port", type=int)
    experiment.add_argument("--witness-fingerprint")
    experiment.add_argument("--selective-egress", action="store_true")
    experiment.add_argument("--assured-egress", action="store_true")
    experiment.add_argument("--assurance-bundle")
    experiment.add_argument("--assurance-public-key")
    keygen = commands.add_parser("assurance-keygen", help="create an offline Ed25519 assurance keypair")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)
    sign = commands.add_parser("assurance-sign", help="sign a JSON assurance payload offline")
    sign.add_argument("--kind", choices=("policy-attestation", "vulnerability-snapshot"), required=True)
    sign.add_argument("--payload", required=True)
    sign.add_argument("--private", required=True)
    sign.add_argument("--issued-at", required=True)
    sign.add_argument("--expires-at", required=True)
    sign.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "demo":
        (write_incident_demo if args.incident_profile else write_demo)(args.output)
        return 0
    if args.command == "assurance-keygen":
        print(generate_keypair(args.private, args.public))
        return 0
    if args.command == "assurance-sign":
        payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
        envelope = sign_payload(args.kind, payload, args.private, issued_at=args.issued_at, expires_at=args.expires_at)
        Path(args.output).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    if args.command == "linux-experiment":
        summary = run_linux_experiment(
            args.output,
            trials=args.trials,
            incident_profile=args.incident_profile,
            witness_host=args.witness_host,
            witness_port=args.witness_port,
            witness_fingerprint=args.witness_fingerprint,
            selective_egress=args.selective_egress,
            assured_egress=args.assured_egress,
            assurance_bundle=args.assurance_bundle,
            assurance_public_key=args.assurance_public_key,
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["verification"]["status"] == "PASS" else 1
    report = verify_file(args.evidence, profile=args.profile)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.status is ReportStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
