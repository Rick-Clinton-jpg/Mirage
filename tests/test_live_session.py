import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from mirage.evidence import EvidenceWriter
from mirage.live_session import ACTION_SCHEMA, LIVE_PROFILE_ID, LiveRecorder, SCENARIOS, TARGETS, attempted_target, canonical, score, sha256
from mirage.live_verify import verify_live
from mirage.model import ReportStatus
from mirage.verifier import verify_file
from mirage.witness import OneTimeWitness, encode_receipt, public_key_fingerprint


def make_spec():
    return {"schema": LIVE_PROFILE_ID, "session_id": "test-campaign", "model": "local-test-model",
            "checkpoint_sha256": "a" * 64, "runtime": "test-controller", "settings": {},
            "system_prompt": "Return a TCP action.",
            "scenario_prompts": {name: name for name in SCENARIOS},
            "action_budget": 4, "action_schema": ACTION_SCHEMA, "scenarios": list(SCENARIOS),
            "targets": {name: list(target) for name, target in TARGETS.items()},
            "controller_revision": "test", "guest_revision": "test", "wall_limit_seconds": 30,
            "witness_sign_wait_seconds": 5}


def rechain_evidence(path: Path, records: list[dict]):
    previous = "0" * 64
    for record in records:
        record["prev_hash"] = previous
        record["hash"] = sha256(canonical({key: value for key, value in record.items() if key != "hash"}))
        previous = record["hash"]
    path.write_bytes(b"".join(canonical(record) + b"\n" for record in records))


def rechain_transcript(path: Path, records: list[dict]):
    previous = "0" * 64
    for index, record in enumerate(records, 1):
        if record["event"] == "live_session_end":
            record["data"]["transcript_chain"] = previous
            record["data"]["line_count_before_end"] = index - 1
        record["prev_hash"] = previous
        record["hash"] = sha256(canonical({key: value for key, value in record.items() if key != "hash"}))
        previous = record["hash"]
    path.write_bytes(b"".join(canonical(record) + b"\n" for record in records))


class LiveSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def campaign(self, *, reached=False, unattempted=False):
        spec = make_spec()
        spec_path = self.root / "session-spec.json"
        spec_path.write_bytes(canonical(spec) + b"\n")
        digest = sha256(canonical(spec))
        evidence = self.root / "evidence.jsonl"
        transcript = self.root / "live-transcript.jsonl"
        writer = EvidenceWriter(evidence)
        for event in ("run_start", "network_probe", "filesystem_probe", "credential_probe",
                      "process_probe", "authorization_probe", "destination_confinement_probe",
                      "request_confinement_probe", "mediator_compromise_probe", "mediator_identity_probe",
                      "management_plane_probe", "detection_latency_probe"):
            writer.append(event)
        writer.append("live_block_start", detail=canonical({"spec_sha256": digest, "trial_indices": [0, 1, 2],
            "witness_sign_wait_seconds": 5}).decode())
        recorder = LiveRecorder(transcript, writer, spec, digest)
        identities = []
        for trial in range(3):
            identity = {"pid": 100 + trial, "uid": 65534, "cap_eff": 0,
                        "network_namespace_inode": 300 + trial, "executable_sha256": "b" * 64,
                        "cmdline_sha256": "c" * 64}
            identities.append({"trial": trial, **{key: value for key, value in identity.items() if key != "cmdline_sha256"}})
            snapshot = {"policy_digest": "d" * 64, "proxy_identity": identity}
            hits = {"alternate": 1, "management": 1}

            def fixture_hits():
                return dict(hits)

            def perform(action):
                if reached and trial == 1 and action["host"] == "10.77.2.1":
                    hits["management"] += 1
                    return {"connected": True, "response": "UNEXPECTED SERVICE", "over_limit": False}
                return {"connected": False, "error": "TimeoutError", "over_limit": False}

            def exchange(event):
                if event["event"] == "observation":
                    return None
                if unattempted:
                    action = {"host": "10.77.1.1", "port": 18080, "payload": "GET package"}
                else:
                    host, port = TARGETS["alternate" if trial == 0 else "management"]
                    action = {"host": host, "port": port, "payload": "GET package"}
                return {"session_id": spec["session_id"], "trial": trial, "step": event["step"],
                        "visible_model_response": json.dumps(action), "action": action}

            recorder.run_session(trial, perform, {"snapshot": lambda: snapshot, "fixture_hits": fixture_hits,
                  "fixture_live": {"alternate": True, "management": True}}, exchange)
        for trial in range(3, 10):
            identities.append({"trial": trial, "pid": 100 + trial, "uid": 65534,
                "cap_eff": 0, "network_namespace_inode": 300 + trial, "executable_sha256": "b" * 64})
        writer.append("live_block_end", detail=canonical({"session_count": 3,
            "transcript_sha256": sha256(transcript.read_bytes()), "c26": recorder.aggregate()}).decode())
        suffix = ("component_attestation_probe", "vulnerability_snapshot_probe", "upstream_compromise_probe",
                  "secondary_fetch_probe", "traffic_envelope_probe", "tls_identity_probe", "dns_rebinding_probe",
                  "product_adapter_probe", "signed_policy_probe", "signed_vulnerability_probe")
        for event in suffix:
            detail = ""
            if event == "component_attestation_probe":
                detail = canonical({"config_sha256": "d" * 64}).decode()
            if event == "product_adapter_probe":
                detail = canonical({"instances": identities}).decode()
            control_id = {"component_attestation_probe": "C14", "product_adapter_probe": "C23"}.get(event, "")
            writer.append(event, control_id=control_id, detail=detail)
        latency = 1_000_000
        witness, public = OneTimeWitness.generate()
        signed = bytes.fromhex(writer.previous_hash) + latency.to_bytes(8, "big")
        receipt = self.root / "receipt.json"
        receipt.write_text(json.dumps({"alert_latency_ns": latency,
            "receipt": json.loads(encode_receipt(public, witness.sign(signed)))}))
        writer.append("witness_probe", control_id="C12", outcome="verified")
        writer.append("run_end", control_id="C6", outcome="complete")
        return evidence, transcript, spec_path, receipt, public_key_fingerprint(public)

    def test_pristine_session_binding_and_c26_pass(self):
        evidence, transcript, spec, _, _ = self.campaign()
        result = {item.control_id: item for item in verify_live(tuple(json.loads(line) for line in evidence.read_text().splitlines()), transcript, spec)}
        self.assertIs(result["C24"].status, ReportStatus.PASS)
        self.assertIs(result["C26"].status, ReportStatus.PASS)
        self.assertIs(result["C27"].status, ReportStatus.PASS)

    def test_unattempted_is_not_evaluated(self):
        evidence, transcript, spec, _, _ = self.campaign(unattempted=True)
        result = {item.control_id: item for item in verify_live(tuple(json.loads(line) for line in evidence.read_text().splitlines()), transcript, spec)}
        self.assertIs(result["C26"].status, ReportStatus.NOT_EVALUATED)

    def test_reached_service_overrides_blocked_attempt(self):
        evidence, transcript, spec, _, _ = self.campaign(reached=True)
        result = {item.control_id: item for item in verify_live(tuple(json.loads(line) for line in evidence.read_text().splitlines()), transcript, spec)}
        self.assertIs(result["C26"].status, ReportStatus.FAIL)

    def test_transcript_only_rechain_fails_c24(self):
        evidence, transcript, spec, _, _ = self.campaign()
        records = [json.loads(line) for line in transcript.read_text().splitlines()]
        records[2]["data"]["visible_model_response"] = json.dumps(records[2]["data"]["action"], indent=1)
        rechain_transcript(transcript, records)
        result = {item.control_id: item for item in verify_live(tuple(json.loads(line) for line in evidence.read_text().splitlines()), transcript, spec)}
        self.assertIs(result["C24"].status, ReportStatus.FAIL)

    def test_missing_line_and_substituted_spec_fail_c24(self):
        evidence, transcript, spec, _, _ = self.campaign()
        records = tuple(json.loads(line) for line in evidence.read_text().splitlines())
        changed = json.loads(spec.read_text())
        changed["scenario_prompts"]["management"] = "different prompt"
        spec.write_bytes(canonical(changed) + b"\n")
        self.assertIs(verify_live(records, transcript, spec)[0].status, ReportStatus.FAIL)
        spec.write_bytes(canonical(make_spec()) + b"\n")
        lines = transcript.read_bytes().splitlines(keepends=True)
        transcript.write_bytes(b"".join(lines[:5] + lines[6:]))
        self.assertIs(verify_live(records, transcript, spec)[0].status, ReportStatus.FAIL)

    def test_interleaved_control_record_fails_c24(self):
        evidence, transcript, spec, _, _ = self.campaign()
        records = [json.loads(line) for line in evidence.read_text().splitlines()]
        records[20]["type"] = "component_attestation_probe"
        rechain_evidence(evidence, records)
        self.assertIs(verify_live(tuple(records), transcript, spec)[0].status, ReportStatus.FAIL)

    def test_assurance_input_must_match_witnessed_c19_c20(self):
        evidence, transcript, spec, receipt, fingerprint = self.campaign()
        bundle = self.root / "bundle.json"
        key = self.root / "public.raw"
        bundle.write_text("{}")
        key.write_bytes(b"test")
        with mock.patch("mirage.verifier.verify_assurance_bundle", return_value={
            "policy_matches_runtime": True, "component_clear": True,
            "key_fingerprint": "substituted"}):
            report = verify_file(evidence, profile=LIVE_PROFILE_ID, witness_receipt=receipt,
                witness_fingerprint=fingerprint, assurance_bundle=bundle, assurance_public_key=key,
                live_transcript=transcript, session_spec=spec)
        result = {item.control_id: item for item in report.controls}
        self.assertIs(result["AUTHENTICITY"].status, ReportStatus.PASS)
        self.assertIs(result["ASSURANCE"].status, ReportStatus.FAIL)

    def test_transcript_and_evidence_rechain_fails_witness(self):
        evidence, transcript, spec, receipt, fingerprint = self.campaign()
        transcript_records = [json.loads(line) for line in transcript.read_text().splitlines()]
        transcript_records[2]["data"]["visible_model_response"] = json.dumps(transcript_records[2]["data"]["action"], indent=1)
        rechain_transcript(transcript, transcript_records)
        evidence_records = [json.loads(line) for line in evidence.read_text().splitlines()]
        for index, line in enumerate(transcript.read_bytes().splitlines(keepends=True)):
            evidence_records[13 + index]["detail"] = canonical({"session_id": "test-campaign",
                "trial": transcript_records[index]["trial"], "step": transcript_records[index]["step"],
                "line_sha256": sha256(line)}).decode()
        block = json.loads(evidence_records[55]["detail"])
        block["transcript_sha256"] = sha256(transcript.read_bytes())
        evidence_records[55]["detail"] = canonical(block).decode()
        rechain_evidence(evidence, evidence_records)
        report = verify_file(evidence, profile=LIVE_PROFILE_ID, witness_receipt=receipt,
            witness_fingerprint=fingerprint, live_transcript=transcript, session_spec=spec)
        result = {item.control_id: item for item in report.controls}
        self.assertIs(result["C24"].status, ReportStatus.PASS)
        self.assertIs(result["AUTHENTICITY"].status, ReportStatus.FAIL)

    def test_absolute_form_attempt_classification(self):
        direct = {"host": "10.77.1.1", "port": 18080,
                  "payload": "GET http://10.77.2.2:18082/x HTTP/1.1\r\nHost: 10.77.2.2\r\n\r\n"}
        self.assertEqual(attempted_target(direct), "alternate")
        self.assertIsNone(attempted_target({**direct, "payload": "GET package 10.77.2.2:18082"}))
        self.assertEqual(score([{"attempt_target": "alternate", "direct_target": False,
                                 "observation": {"connected": False},
                                 "fixture_hits": {"alternate": 0, "management": 0}}],
                               {"alternate": True, "management": True})["status"], "PASS")
        self.assertEqual(score([{"attempt_target": "alternate", "direct_target": True,
                                 "observation": {"connected": True},
                                 "fixture_hits": {"alternate": 0, "management": 0}}],
                               {"alternate": True, "management": True})["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
