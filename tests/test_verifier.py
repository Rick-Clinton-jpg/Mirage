from pathlib import Path
import tempfile
import unittest

from mirage.demo import write_demo
from mirage.model import ReportStatus
from mirage.verifier import verify_file


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "evidence.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def test_complete_demo_passes(self):
        write_demo(self.path)
        report = verify_file(self.path)
        self.assertIs(report.status, ReportStatus.PASS)
        self.assertEqual(len(report.controls), 6)

    def test_missing_probe_breaks_chain(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:3] + lines[4:]))
        self.assertIs(verify_file(self.path).status, ReportStatus.FAIL)

    def test_missing_file_fails(self):
        self.assertIs(verify_file(self.path).status, ReportStatus.FAIL)

    def test_truncated_stream_fails_terminal_check(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:-1]))
        report = verify_file(self.path)
        self.assertIs(report.status, ReportStatus.FAIL)
        self.assertTrue(any(item.control_id == "TERMINAL" for item in report.controls))


if __name__ == "__main__":
    unittest.main()

