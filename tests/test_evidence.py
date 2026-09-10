import json

import pytest

from mirage.demo import write_demo
from mirage.evidence import EvidenceError, load_records


def test_demo_chain_loads(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    records = load_records(path)
    assert records[0]["type"] == "run_start"
    assert records[-1]["type"] == "run_end"


def test_modified_record_is_rejected(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    lines = path.read_text().splitlines()
    record = json.loads(lines[2])
    record["outcome"] = "allowed"
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(EvidenceError, match="invalid record hash"):
        load_records(path)


def test_deleted_middle_record_is_rejected(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2] + lines[3:]))
    with pytest.raises(EvidenceError, match="broken hash link"):
        load_records(path)


def test_incomplete_final_line_is_rejected(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with pytest.raises(EvidenceError, match="incomplete record"):
        load_records(path)

