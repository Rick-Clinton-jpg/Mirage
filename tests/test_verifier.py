import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from mirage.demo import write_demo, write_incident_demo
from mirage.evidence import load_records
from mirage.model import ReportStatus
from mirage.verifier import verify_file
from mirage.profile import ASSURED_EGRESS_PROFILE_ID, INCIDENT_PROFILE_ID, SELECTIVE_EGRESS_PROFILE_ID
from mirage.witness import OneTimeWitness, encode_receipt, public_key_fingerprint


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "evidence.jsonl"

    def tearDown(self):
        self.temporary.cleanup()

    def rechain(self, records):
        previous = "0" * 64
        for record in records:
            record["prev_hash"] = previous
            material = {key: value for key, value in record.items() if key != "hash"}
            record["hash"] = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
            previous = record["hash"]
        self.path.write_text("\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records) + "\n")

    def authenticated_incident(self, *, c1_outcome="blocked"):
        write_incident_demo(self.path)
        if c1_outcome != "blocked":
            records = [json.loads(line) for line in self.path.read_text().splitlines()]
            records[1]["outcome"] = c1_outcome
            self.rechain(records)
        c12 = next(record for record in load_records(self.path) if record["control_id"] == "C12")
        latency = 1_000_000
        witness, public = OneTimeWitness.generate()
        signature = witness.sign(bytes.fromhex(c12["prev_hash"]) + latency.to_bytes(8, "big"))
        receipt = Path(self.temporary.name) / "receipt.json"
        receipt.write_text(json.dumps({"alert_latency_ns": latency, "receipt": json.loads(encode_receipt(public, signature))}))
        return receipt, public_key_fingerprint(public)

    def test_complete_demo_passes(self):
        write_demo(self.path)
        report = verify_file(self.path, allow_unauthenticated=True)
        self.assertIs(report.status, ReportStatus.PASS)
        self.assertEqual(len(report.controls), 6)

    def test_missing_probe_breaks_chain(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:3] + lines[4:]))
        self.assertIs(verify_file(self.path, allow_unauthenticated=True).status, ReportStatus.FAIL)

    def test_missing_file_fails(self):
        self.assertIs(verify_file(self.path).status, ReportStatus.FAIL)

    def test_minimum_profile_cannot_silently_claim_authenticated_pass(self):
        write_demo(self.path)
        report = verify_file(self.path)
        self.assertIs(report.status, ReportStatus.FAIL)
        self.assertTrue(any(item.control_id == "AUTHENTICITY" for item in report.controls))

    def test_incident_profile_requires_all_thirteen_controls(self):
        receipt, fingerprint = self.authenticated_incident()
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID, witness_receipt=receipt, witness_fingerprint=fingerprint)
        self.assertIs(report.status, ReportStatus.PASS)
        self.assertEqual(len(report.controls), 14)

    def test_rewritten_and_rechained_failure_is_rejected_by_witness(self):
        receipt, fingerprint = self.authenticated_incident(c1_outcome="failed")
        records = [json.loads(line) for line in self.path.read_text().splitlines()]
        records[1]["outcome"] = "blocked"
        self.rechain(records)
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID, witness_receipt=receipt, witness_fingerprint=fingerprint)
        self.assertIs(report.status, ReportStatus.FAIL)
        self.assertTrue(any(item.control_id == "AUTHENTICITY" and item.status is ReportStatus.FAIL for item in report.controls))

    def test_substituted_witness_identity_is_rejected(self):
        receipt, _ = self.authenticated_incident()
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID, witness_receipt=receipt, witness_fingerprint="0" * 64)
        self.assertIs(report.status, ReportStatus.FAIL)

    def test_old_evidence_does_not_pass_incident_profile(self):
        write_demo(self.path)
        report = verify_file(self.path, profile=INCIDENT_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.FAIL)

    def test_unknown_profile_fails(self):
        write_demo(self.path)
        self.assertIs(verify_file(self.path, profile="unknown").status, ReportStatus.FAIL)

    def test_thirteen_control_evidence_cannot_pass_selective_egress_profile(self):
        write_incident_demo(self.path)
        report = verify_file(self.path, profile=SELECTIVE_EGRESS_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.FAIL)

    def test_older_evidence_cannot_pass_assured_egress_profile(self):
        write_incident_demo(self.path)
        report = verify_file(self.path, profile=ASSURED_EGRESS_PROFILE_ID)
        self.assertIs(report.status, ReportStatus.FAIL)

    def test_truncated_stream_fails_terminal_check(self):
        write_demo(self.path)
        lines = self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(b"".join(lines[:-1]))
        report = verify_file(self.path, allow_unauthenticated=True)
        self.assertIs(report.status, ReportStatus.FAIL)
        self.assertTrue(any(item.control_id == "TERMINAL" for item in report.controls))


if __name__ == "__main__":
    unittest.main()
