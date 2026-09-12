"""Canonical hash-linked JSONL evidence.

Hash linking detects modification, deletion in the middle, reordering, and
truncation when a verifier expects a terminal ``run_end`` record. It does not
authenticate the recorder; deployments should sign and externally preserve the
final digest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

GENESIS = "0" * 64
MAX_LINE_BYTES = 64 * 1024
MAX_RECORDS = 10_000
ALLOWED_KEYS = frozenset({"id", "type", "control_id", "outcome", "detail", "prev_hash", "hash"})


class EvidenceError(ValueError):
    pass


def _canonical(record: Mapping[str, object]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(record_without_hash: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(record_without_hash)).hexdigest()


@dataclass
class EvidenceWriter:
    path: Path
    previous_hash: str = GENESIS
    count: int = 0

    def append(self, event_type: str, *, control_id: str = "", outcome: str = "", detail: str = "") -> str:
        if not event_type or len(event_type) > 64:
            raise EvidenceError("invalid event type")
        if len(control_id) > 32 or len(outcome) > 32 or len(detail.encode("utf-8")) > 4096:
            raise EvidenceError("evidence field exceeds its bound")
        record = {
            "id": f"e{self.count + 1:06d}",
            "type": event_type,
            "control_id": control_id,
            "outcome": outcome,
            "detail": detail,
            "prev_hash": self.previous_hash,
        }
        record["hash"] = _digest(record)
        encoded = _canonical(record) + b"\n"
        if len(encoded) > MAX_LINE_BYTES:
            raise EvidenceError("evidence record is too large")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
        self.previous_hash = record["hash"]
        self.count += 1
        return record["id"]


def load_records(path: str | Path) -> tuple[dict, ...]:
    source = Path(path)
    previous = GENESIS
    records: list[dict] = []
    seen_ids: set[str] = set()
    with source.open("rb") as stream:
        for line_number, raw in enumerate(stream, 1):
            if line_number > MAX_RECORDS:
                raise EvidenceError(f"evidence stream exceeds {MAX_RECORDS} records")
            if not raw.endswith(b"\n"):
                raise EvidenceError(f"line {line_number}: incomplete record")
            if len(raw) > MAX_LINE_BYTES:
                raise EvidenceError(f"line {line_number}: record too large")
            try:
                record = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EvidenceError(f"line {line_number}: invalid JSON") from exc
            if type(record) is not dict or set(record) != ALLOWED_KEYS:
                raise EvidenceError(f"line {line_number}: unexpected schema")
            if any(type(record[key]) is not str for key in ALLOWED_KEYS):
                raise EvidenceError(f"line {line_number}: fields must be strings")
            if record["id"] in seen_ids:
                raise EvidenceError(f"line {line_number}: duplicate evidence id")
            if record["id"] != f"e{line_number:06d}":
                raise EvidenceError(f"line {line_number}: non-sequential evidence id")
            if record["prev_hash"] != previous:
                raise EvidenceError(f"line {line_number}: broken hash link")
            supplied = record["hash"]
            material = {key: value for key, value in record.items() if key != "hash"}
            if supplied != _digest(material):
                raise EvidenceError(f"line {line_number}: invalid record hash")
            seen_ids.add(record["id"])
            previous = supplied
            records.append(record)
    if not records:
        raise EvidenceError("empty evidence stream")
    return tuple(records)
