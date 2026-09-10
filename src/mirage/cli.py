"""Command-line interface."""

from __future__ import annotations

import argparse
import json

from .demo import write_demo
from .model import ReportStatus
from .verifier import verify_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="write deterministic example evidence")
    demo.add_argument("--output", required=True)
    verify = commands.add_parser("verify", help="verify an evidence JSONL file")
    verify.add_argument("evidence")
    args = parser.parse_args(argv)
    if args.command == "demo":
        write_demo(args.output)
        return 0
    report = verify_file(args.evidence)
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    return 0 if report.status is ReportStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())

