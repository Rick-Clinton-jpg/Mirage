"""Command-line interface."""

from __future__ import annotations

import argparse
import json

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
    args = parser.parse_args(argv)
    if args.command == "demo":
        (write_incident_demo if args.incident_profile else write_demo)(args.output)
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
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["verification"]["status"] == "PASS" else 1
    report = verify_file(args.evidence, profile=args.profile)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.status is ReportStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
