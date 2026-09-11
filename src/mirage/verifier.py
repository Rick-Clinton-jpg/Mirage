"""Fail-closed verification of a bounded evidence profile."""

from __future__ import annotations

from pathlib import Path

from .evidence import EvidenceError, load_records
from .model import ControlResult, ReportStatus, VerificationReport
from .profile import ASSURED_EGRESS_CONTROLS, ASSURED_EGRESS_PROFILE_ID, CONTROLS, INCIDENT_CONTROLS, INCIDENT_PROFILE_ID, PROFILE_ID, SELECTIVE_EGRESS_CONTROLS, SELECTIVE_EGRESS_PROFILE_ID

PASS_OUTCOME = "blocked"


PROFILES = {
    PROFILE_ID: CONTROLS,
    INCIDENT_PROFILE_ID: INCIDENT_CONTROLS,
    SELECTIVE_EGRESS_PROFILE_ID: SELECTIVE_EGRESS_CONTROLS,
    ASSURED_EGRESS_PROFILE_ID: ASSURED_EGRESS_CONTROLS,
}


def verify_file(path: str | Path, *, profile: str = PROFILE_ID) -> VerificationReport:
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

    if records[-1]["type"] != "run_end":
        results.append(ControlResult("TERMINAL", ReportStatus.FAIL, "terminal run_end record is absent", (records[-1]["id"],)))
    return VerificationReport(profile, tuple(results))
