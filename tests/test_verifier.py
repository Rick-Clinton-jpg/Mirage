from mirage.demo import write_demo
from mirage.model import ReportStatus
from mirage.verifier import verify_file


def test_complete_demo_passes(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    report = verify_file(path)
    assert report.status is ReportStatus.PASS
    assert len(report.controls) == 6


def test_missing_probe_is_not_evaluated(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    lines = path.read_bytes().splitlines(keepends=True)
    # Removing a linked record invalidates the chain, which is stronger than
    # merely reporting the corresponding control as absent.
    path.write_bytes(b"".join(lines[:3] + lines[4:]))
    assert verify_file(path).status is ReportStatus.FAIL


def test_missing_file_fails(tmp_path):
    report = verify_file(tmp_path / "missing.jsonl")
    assert report.status is ReportStatus.FAIL


def test_truncated_stream_fails_terminal_check(tmp_path):
    path = tmp_path / "evidence.jsonl"
    write_demo(path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    report = verify_file(path)
    assert report.status is ReportStatus.NOT_EVALUATED or report.status is ReportStatus.FAIL
    assert any(item.control_id == "TERMINAL" for item in report.controls)

