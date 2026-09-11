from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from mirage.assurance import AssuranceError, generate_keypair, sign_payload, verify_assurance_bundle, verify_envelope


class AssuranceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.private, self.public = root / "private.pem", root / "public.raw"
        generate_keypair(self.private, self.public)
        self.now = datetime(2026, 9, 11, 12, tzinfo=timezone.utc)
        self.issued = (self.now - timedelta(minutes=1)).isoformat()
        self.expires = (self.now + timedelta(hours=1)).isoformat()

    def tearDown(self):
        self.temporary.cleanup()

    def envelope(self, kind, payload):
        return sign_payload(kind, payload, self.private, issued_at=self.issued, expires_at=self.expires)

    def test_public_key_verifies_but_cannot_sign(self):
        envelope = self.envelope("policy-attestation", {"config_sha256": "a" * 64})
        self.assertEqual(verify_envelope(envelope, self.public.read_bytes(), expected_kind="policy-attestation", now=self.now)["config_sha256"], "a" * 64)
        with self.assertRaises(ValueError):
            sign_payload("policy-attestation", {}, self.public, issued_at=self.issued, expires_at=self.expires)

    def test_tampering_fails(self):
        envelope = self.envelope("policy-attestation", {"config_sha256": "a" * 64})
        envelope["payload"]["config_sha256"] = "b" * 64
        with self.assertRaisesRegex(AssuranceError, "signature"):
            verify_envelope(envelope, self.public.read_bytes(), expected_kind="policy-attestation", now=self.now)

    def test_expired_envelope_fails(self):
        envelope = sign_payload("policy-attestation", {}, self.private, issued_at=(self.now - timedelta(hours=2)).isoformat(), expires_at=(self.now - timedelta(hours=1)).isoformat())
        with self.assertRaisesRegex(AssuranceError, "not currently valid"):
            verify_envelope(envelope, self.public.read_bytes(), expected_kind="policy-attestation", now=self.now)

    def test_bundle_binds_policy_and_component(self):
        bundle = {
            "policy": self.envelope("policy-attestation", {"config_sha256": "a" * 64}),
            "vulnerabilities": self.envelope("vulnerability-snapshot", {"source": "NVD JSON 2.0 pinned export", "affected_components": ["proxy@0.4.0"]}),
        }
        result = verify_assurance_bundle(bundle, self.public.read_bytes(), "a" * 64, {"name": "proxy", "version": "0.5.0"}, now=self.now)
        self.assertTrue(result["policy_matches_runtime"])
        self.assertTrue(result["component_clear"])


if __name__ == "__main__":
    unittest.main()
