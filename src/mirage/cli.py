"""Command-line interface."""

from __future__ import annotations

import argparse
import json

from .demo import write_demo
from .linux import run_linux_experiment
from .model import ReportStatus
from .verifier import verify_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="write deterministic example evidence")
    demo.add_argument("--output", required=True)
    verify = commands.add_parser("verify", help="verify an evidence JSONL file")
    verify.add_argument("evidence")
    experiment = commands.add_parser("linux-experiment", help="run matched Linux containment trials")
    experiment.add_argument("--output", required=True)
    experiment.add_argument("--trials", type=int, default=10)
    args = parser.parse_args(argv)
    if args.command == "demo":
        write_demo(args.output)
        return 0
    if args.command == "linux-experiment":
        summary = run_linux_experiment(args.output, trials=args.trials)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["verification"]["status"] == "PASS" else 1
    report = verify_file(args.evidence)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.status is ReportStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
