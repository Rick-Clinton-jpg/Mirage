"""Fail-closed verification of a bounded evidence profile."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from .assurance import AssuranceError, verify_assurance_bundle
from .evidence import EvidenceError, load_records
from .model import ControlResult, ReportStatus, VerificationReport
from .profile import ASSURED_EGRESS_CONTROLS, ASSURED_EGRESS_PROFILE_ID, CONTROLS, INCIDENT_CONTROLS, INCIDENT_PROFILE_ID, PROFILE_ID, SELECTIVE_EGRESS_CONTROLS, SELECTIVE_EGRESS_PROFILE_ID
from .witness import decode_receipt, public_key_fingerprint, verify_receipt

PASS_OUTCOME = "blocked"


PROFILES = {
    PROFILE_ID: CONTROLS,
    INCIDENT_PROFILE_ID: INCIDENT_CONTROLS,
    SELECTIVE_EGRESS_PROFILE_ID: SELECTIVE_EGRESS_CONTROLS,
    ASSURED_EGRESS_PROFILE_ID: ASSURED_EGRESS_CONTROLS,
}


AUTHENTICATED_PROFILES = frozenset({INCIDENT_PROFILE_ID, SELECTIVE_EGRESS_PROFILE_ID, ASSURED_EGRESS_PROFILE_ID})


def verify_file(
    path: str | Path,
    *,
    profile: str = PROFILE_ID,
    witness_receipt: str | Path | None = None,
    witness_fingerprint: str | None = None,
    assurance_bundle: str | Path | None = None,
    assurance_public_key: str | Path | None = None,
    allow_unauthenticated: bool = False,
) -> VerificationReport:
    controls = PROFILES.get(profile)
    if controls is None:
        return VerificationReport(
            profile,
            (ControlResult("PROFILE", ReportStatus.FAIL, f"unknown profile: {profile}"),),
        )
    try:
        records = load_records(path)
    except (OSError, EvidenceError) as exc:
        return VerificationReport(
            profile,
            (ControlResult("EVIDENCE", ReportStatus.FAIL, str(exc)),),
        )

    by_type: dict[str, list[dict]] = {}
    for record in records:
        by_type.setdefault(record["type"], []).append(record)

    results: list[ControlResult] = []

    if profile == PROFILE_ID and not allow_unauthenticated:
        results.append(ControlResult(
            "AUTHENTICITY",
            ReportStatus.FAIL,
            "minimum-profile evidence is integrity-only; authenticated compliance verification requires a witnessed profile",
        ))

    # The mediated and stronger profiles make an authenticity claim, so an
    # internally consistent hash chain is insufficient.  Require the
    # pre-declared witness identity and verify its signature over the exact
    # prefix that existed immediately before C12 was appended.
    if profile in AUTHENTICATED_PROFILES:
        if witness_receipt is None or witness_fingerprint is None:
            results.append(ControlResult("AUTHENTICITY", ReportStatus.FAIL, "authenticated profile requires a witness receipt and pre-trusted fingerprint"))
        else:
            try:
                wrapper = json.loads(Path(witness_receipt).read_text(encoding="utf-8"))
                if type(wrapper) is not dict or set(wrapper) != {"alert_latency_ns", "receipt"}:
                    raise ValueError("unexpected witness wrapper")
                latency = wrapper["alert_latency_ns"]
                if type(latency) is not int or not 0 <= latency <= 100_000_000:
                    raise ValueError("invalid witness alert latency")
                witness_records = [r for r in records if r["type"] == "witness_probe" and r["control_id"] == "C12"]
                if len(witness_records) != 1:
                    raise ValueError("exactly one C12 witness record is required")
                if records[-2] is not witness_records[0]:
                    raise ValueError("C12 must authenticate the complete prefix immediately before run_end")
                public, signature = decode_receipt(json.dumps(wrapper["receipt"]))
                if not secrets.compare_digest(public_key_fingerprint(public), witness_fingerprint):
                    raise ValueError("witness fingerprint mismatch")
                signed_material = bytes.fromhex(witness_records[0]["prev_hash"]) + latency.to_bytes(8, "big")
                if not verify_receipt(public, signed_material, signature):
                    raise ValueError("witness signature does not match evidence prefix")
                results.append(ControlResult("AUTHENTICITY", ReportStatus.PASS, "pre-trusted witness authenticated the evidence prefix", (witness_records[0]["id"],)))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                results.append(ControlResult("AUTHENTICITY", ReportStatus.FAIL, str(exc)))

    if profile == ASSURED_EGRESS_PROFILE_ID:
        if assurance_bundle is None or assurance_public_key is None:
            results.append(ControlResult("ASSURANCE", ReportStatus.FAIL, "assured profile requires the signed assurance bundle and public key"))
        else:
            try:
                c14 = [r for r in records if r["control_id"] == "C14" and r["type"] == "component_attestation_probe"]
                c23 = [r for r in records if r["control_id"] == "C23" and r["type"] == "product_adapter_probe"]
                if len(c14) != 1 or len(c23) != 1:
                    raise AssuranceError("runtime attestation evidence is incomplete")
                manifest, component = json.loads(c14[0]["detail"]), json.loads(c23[0]["detail"])
                if type(manifest) is not dict or type(component) is not dict or type(manifest.get("config_sha256")) is not str:
                    raise AssuranceError("runtime attestation evidence is malformed")
                bundle = json.loads(Path(assurance_bundle).read_text(encoding="utf-8"))
                assurance = verify_assurance_bundle(
                    bundle,
                    Path(assurance_public_key).read_bytes(),
                    manifest["config_sha256"],
                    {"name": component.get("name"), "version": component.get("version")},
                )
                if assurance.get("policy_matches_runtime") is not True or assurance.get("component_clear") is not True:
                    raise AssuranceError("signed assurance does not approve the measured runtime")
                results.append(ControlResult("ASSURANCE", ReportStatus.PASS, "signed policy and vulnerability inputs match the measured runtime", (c14[0]["id"], c23[0]["id"])))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, AssuranceError) as exc:
                results.append(ControlResult("ASSURANCE", ReportStatus.FAIL, str(exc)))
    for control in controls:
        matches = [r for r in by_type.get(control.required_event, []) if r["control_id"] == control.control_id]
        if not matches:
            results.append(ControlResult(control.control_id, ReportStatus.NOT_EVALUATED, "required evidence is absent"))
            continue
        if len(matches) != 1:
            results.append(ControlResult(control.control_id, ReportStatus.FAIL, "control has duplicate results", tuple(r["id"] for r in matches)))
            continue
        record = matches[0]
        expected = control.expected_outcome
        status = ReportStatus.PASS if record["outcome"] == expected else ReportStatus.FAIL
        reason = "control produced the expected outcome" if status is ReportStatus.PASS else f"unexpected outcome: {record['outcome']!r}"
        results.append(ControlResult(control.control_id, status, reason, (record["id"],)))

    starts = [record for record in records if record["type"] == "run_start"]
    ends = [record for record in records if record["type"] == "run_end"]
    if len(starts) != 1 or records[0]["type"] != "run_start":
        results.append(ControlResult("RUN_STRUCTURE", ReportStatus.FAIL, "exactly one initial run_start record is required"))
    if len(ends) != 1 or records[-1]["type"] != "run_end":
        results.append(ControlResult("TERMINAL", ReportStatus.FAIL, "terminal run_end record is absent", (records[-1]["id"],)))
    return VerificationReport(profile, tuple(results))
