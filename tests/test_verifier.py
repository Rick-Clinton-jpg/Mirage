from pathlib import Path
import tempfile
import unittest

from mirage.demo import write_demo, write_incident_demo
from mirage.model import ReportStatus
from mirage.verifier import verify_file
from mirage.profile import INCIDENT_PROFILE_ID, SELECTIVE_EGRESS_PROFILE_ID


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

    def test_incident_profile_requires_all_thirteen_controls(self):
        write_incident_demo(self.path)
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.PASS)
        self.assertEqual(len(report.controls), 13)

    def test_old_evidence_does_not_pass_incident_profile(self):
        write_demo(self.path)
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.NOT_EVALUATED)

    def test_unknown_profile_fails(self):
        write_demo(self.path)
        self.assertIs(verify_file(self.path, profile="unknown").status, ReportStatus.FAIL)

    def test_thirteen_control_evidence_cannot_pass_selective_egress_profile(self):
        write_incident_demo(self.path)
        report = verify_file(self.path, profile=SELECTIVE_EGRESS_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.NOT_EVALUATED)

    def test_truncated_stream_fails_terminal_check(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:-1]))
        report = verify_file(self.path)
        self.assertIs(report.status, ReportStatus.FAIL)
        self.assertTrue(any(item.control_id == "TERMINAL" for item in report.controls))


if __name__ == "__main__":
    unittest.main()
