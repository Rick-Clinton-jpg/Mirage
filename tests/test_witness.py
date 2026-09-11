import unittest

from mirage.witness import OneTimeWitness, WitnessPrivateKey, WitnessSignature, decode_receipt, encode_receipt, public_key_fingerprint, verify_receipt


class WitnessTests(unittest.TestCase):
    def test_terminal_digest_receipt_verifies(self):
        witness, public = OneTimeWitness.generate()
        signature = witness.sign(b"terminal-evidence-digest")
        self.assertTrue(verify_receipt(public, b"terminal-evidence-digest", signature))

    def test_receipt_is_bound_to_digest(self):
        witness, public = OneTimeWitness.generate()
        signature = witness.sign(b"history-a")
        self.assertFalse(verify_receipt(public, b"history-b", signature))

    def test_witness_key_cannot_sign_twice(self):
        witness, _ = OneTimeWitness.generate()
        witness.sign(b"first")
        with self.assertRaisesRegex(RuntimeError, "one-time"):
            witness.sign(b"second")

    def test_public_key_cannot_be_used_as_private_key(self):
        _, public = OneTimeWitness.generate()
        forged = OneTimeWitness(WitnessPrivateKey(public.values)).sign(b"forgery")
        self.assertFalse(verify_receipt(public, b"forgery", forged))

    def test_malformed_signature_fails_closed(self):
        _, public = OneTimeWitness.generate()
        self.assertFalse(verify_receipt(public, b"digest", WitnessSignature(())))

    def test_receipt_serialization_round_trip(self):
        witness, public = OneTimeWitness.generate()
        signature = witness.sign(b"digest")
        decoded_public, decoded_signature = decode_receipt(encode_receipt(public, signature))
        self.assertTrue(verify_receipt(decoded_public, b"digest", decoded_signature))

    def test_invalid_receipt_schema_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid witness receipt"):
            decode_receipt('{"algorithm":"wrong"}')

    def test_distinct_witnesses_have_distinct_fingerprints(self):
        _, first = OneTimeWitness.generate()
        _, second = OneTimeWitness.generate()
        self.assertNotEqual(public_key_fingerprint(first), public_key_fingerprint(second))


if __name__ == "__main__":
    unittest.main()
