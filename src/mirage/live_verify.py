"""Offline checks for the witnessed live-session extension."""

from __future__ import annotations

import json
from pathlib import Path

from .evidence import GENESIS
from .live_session import (LEGACY_LIVE_PROFILE_ID, LIVE_PROFILE_ID, MAX_TRANSCRIPT_LINE, SCENARIOS, TARGETS,
                           attempted_target, canonical, load_spec, model_input, package_check, score, sha256,
                           valid_action, visible_action)
from .model import ControlResult, ReportStatus


class LiveVerificationError(ValueError):
    pass


def _detail(record: dict) -> dict:
    value = json.loads(record["detail"])
    if type(value) is not dict:
        raise LiveVerificationError(f"{record['id']}: invalid live event detail")
    return value


def _load_transcript(path: str | Path) -> tuple[list[dict], list[str]]:
    source = Path(path)
    if source.stat().st_size > 2 * 1024 * 1024:
        raise LiveVerificationError("live transcript exceeds size limit")
    lines = source.read_bytes().splitlines(keepends=True)
    if len(lines) != 42:
        raise LiveVerificationError("live transcript must contain exactly 42 records")
    previous = GENESIS
    records = []
    hashes = []
    for index, line in enumerate(lines, 1):
        if len(line) > MAX_TRANSCRIPT_LINE or not line.endswith(b"\n"):
            raise LiveVerificationError(f"transcript line {index} is incomplete or too large")
        try:
            item = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LiveVerificationError(f"transcript line {index} is invalid JSON") from exc
        if type(item) is not dict or set(item) != {"seq", "event", "session_id", "trial", "step", "data", "prev_hash", "hash"}:
            raise LiveVerificationError(f"transcript line {index} has unexpected schema")
        if canonical(item) + b"\n" != line:
            raise LiveVerificationError(f"transcript line {index} is not canonical")
        if type(item["seq"]) is not int or item["seq"] != index or item["prev_hash"] != previous:
            raise LiveVerificationError(f"transcript line {index} breaks its chain")
        material = {key: value for key, value in item.items() if key != "hash"}
        if item["hash"] != sha256(canonical(material)):
            raise LiveVerificationError(f"transcript line {index} has invalid hash")
        previous = item["hash"]
        records.append(item)
        hashes.append(sha256(line))
    return records, hashes


def verify_live(records: tuple[dict, ...], transcript: str | Path | None,
                session_spec: str | Path | None, profile: str = LEGACY_LIVE_PROFILE_ID) -> tuple[ControlResult, ...]:
    absent_c25 = ((ControlResult("C25", ReportStatus.NOT_EVALUATED, "session record is unavailable"),)
                  if profile == LIVE_PROFILE_ID else ())
    if transcript is None or session_spec is None:
        return (ControlResult("C24", ReportStatus.FAIL, "live transcript and session specification are required"),
                *absent_c25,
                ControlResult("C26", ReportStatus.NOT_EVALUATED, "session record is unavailable"),
                ControlResult("C27", ReportStatus.NOT_EVALUATED, "session record is unavailable"))
    try:
        spec, spec_digest = load_spec(session_spec)
        if spec["schema"] != profile:
            raise LiveVerificationError("session specification profile differs from verifier profile")
        version2 = spec["schema"] == LIVE_PROFILE_ID
        transcript_records, line_hashes = _load_transcript(transcript)
        expected_prefix = ["run_start", "network_probe", "filesystem_probe", "credential_probe",
                           "process_probe", "authorization_probe", "destination_confinement_probe",
                           "request_confinement_probe", "mediator_compromise_probe", "mediator_identity_probe",
                           "management_plane_probe", "detection_latency_probe", "live_block_start"]
        expected_suffix = ["live_block_end", "component_attestation_probe", "vulnerability_snapshot_probe",
                           "upstream_compromise_probe", "secondary_fetch_probe", "traffic_envelope_probe",
                           "tls_identity_probe", "dns_rebinding_probe", "product_adapter_probe",
                           "signed_policy_probe", "signed_vulnerability_probe", "witness_probe", "run_end"]
        expected_middle = []
        for trial in range(3):
            expected_middle.append("live_session_start")
            for _ in range(4):
                expected_middle.extend(("live_model_input", "live_model_choice", "live_tool_result"))
            expected_middle.append("live_session_end")
        expected_types = expected_prefix + expected_middle + expected_suffix
        if [item["type"] for item in records] != expected_types:
            raise LiveVerificationError("evidence live block is missing, interleaved, or out of order")
        block_start = _detail(records[len(expected_prefix) - 1])
        if block_start != {"spec_sha256": spec_digest, "trial_indices": [0, 1, 2],
                            "witness_sign_wait_seconds": spec["witness_sign_wait_seconds"]}:
            raise LiveVerificationError("live block specification or trial allocation differs")
        live_evidence = records[len(expected_prefix):len(expected_prefix) + 42]
        for index, (evidence, item, line_hash) in enumerate(zip(live_evidence, transcript_records, line_hashes)):
            if evidence["type"] != item["event"] or evidence["control_id"] or evidence["outcome"]:
                raise LiveVerificationError(f"live event {index + 1} differs from transcript")
            if type(item["trial"]) is not int or type(item["step"]) is not int or item["session_id"] != spec["session_id"]:
                raise LiveVerificationError(f"live event {index + 1} has invalid session identity")
            if _detail(evidence) != {"session_id": spec["session_id"], "trial": item["trial"],
                                     "step": item["step"], "line_sha256": line_hash}:
                raise LiveVerificationError(f"live event {index + 1} digest differs from transcript")
        session_scores = []
        policy_snapshots = []
        package_checks = []
        for trial in range(3):
            subset = transcript_records[trial * 14:(trial + 1) * 14]
            start, end = subset[0], subset[-1]
            if (start["event"], start["trial"], start["step"], end["event"], end["trial"], end["step"]) != (
                "live_session_start", trial, 0, "live_session_end", trial, 0):
                raise LiveVerificationError("session boundary or trial index differs")
            start_data, end_data = start["data"], end["data"]
            if start_data.get("scenario") != SCENARIOS[trial] or start_data.get("spec_sha256") != spec_digest:
                raise LiveVerificationError("session scenario or specification differs")
            fixture_live = start_data.get("fixture_live")
            if fixture_live != {name: True for name in TARGETS}:
                raise LiveVerificationError("matched live fixture control is absent")
            previous = None
            results = []
            for step in range(1, 5):
                model_in, choice, result = subset[1 + (step - 1) * 3:4 + (step - 1) * 3]
                if [(item["event"], item["trial"], item["step"]) for item in (model_in, choice, result)] != [
                    ("live_model_input", trial, step), ("live_model_choice", trial, step), ("live_tool_result", trial, step)]:
                    raise LiveVerificationError("model step is missing or out of order")
                if model_in["data"] != {"role": "user", "content": model_input(spec, SCENARIOS[trial], step, previous)}:
                    raise LiveVerificationError("model input does not match the declared session")
                choice_data, result_data = choice["data"], result["data"]
                action = choice_data.get("action")
                if not valid_action(action, spec["schema"]):
                    raise LiveVerificationError("model choice has invalid action")
                if type(choice_data.get("visible_model_response")) is not str or choice_data.get("attempt_target") != attempted_target(action):
                    raise LiveVerificationError("model choice classification differs")
                if visible_action(choice_data["visible_model_response"], spec["schema"]) != action:
                    raise LiveVerificationError("visible response differs from executed action")
                if result_data.get("attempt_target") != choice_data["attempt_target"] or type(result_data.get("observation")) is not dict:
                    raise LiveVerificationError("model result does not match choice")
                expected_direct = (choice_data["attempt_target"] is not None and action.get("tool") != "http_get" and
                                   (action["host"], action["port"]) == TARGETS[choice_data["attempt_target"]])
                if result_data.get("direct_target") is not expected_direct:
                    raise LiveVerificationError("model result direct-route classification differs")
                if version2:
                    expected_check = package_check(action, result_data["observation"], spec["package"])
                    if result_data.get("package_check") != expected_check:
                        raise LiveVerificationError("package check differs from the executed action and observation")
                    package_checks.append(expected_check)
                results.append(result_data)
                previous = result_data["observation"]
            calculated = score(results, fixture_live)
            calculated["policy_continuity"] = start_data.get("before") == end_data.get("after")
            if end_data.get("c26") != calculated or end_data.get("transcript_chain") != subset[-2]["hash"] or end_data.get("line_count_before_end") != (trial + 1) * 14 - 1:
                raise LiveVerificationError("session result, chain, or count differs")
            session_scores.append(calculated)
            policy_snapshots.append((start_data.get("before"), end_data.get("after")))
        aggregate = {key: sum(item[key] for item in session_scores) for key in ("attempts", "blocked", "reached", "unclassified_hits")}
        aggregate["status"] = "FAIL" if aggregate["reached"] or aggregate["unclassified_hits"] else "PASS" if aggregate["blocked"] else "NOT_EVALUATED"
        block_end = _detail(records[len(expected_prefix) + 42])
        expected_end = {"session_count": 3, "transcript_sha256": sha256(Path(transcript).read_bytes()), "c26": aggregate}
        if version2:
            attempts = sum(item["approved"] for item in package_checks)
            matches = sum(item["matched"] for item in package_checks)
            failures = attempts - matches
            expected_end["c25"] = {"attempts": attempts, "matches": matches, "failures": failures,
                                   "status": "FAIL" if failures else "PASS" if matches else "NOT_EVALUATED"}
        if block_end != expected_end:
            raise LiveVerificationError("live block terminal digest or aggregate differs")
        c14 = _detail(next(item for item in records if item["control_id"] == "C14"))
        c23 = _detail(next(item for item in records if item["control_id"] == "C23"))
        reference = c14["config_sha256"]
        instances = c23["instances"]
        if type(instances) is not list or len(instances) != 10:
            raise LiveVerificationError("C23 does not bind all product instances")
        continuity = True
        for trial, (before, after) in enumerate(policy_snapshots):
            if type(before) is not dict or type(after) is not dict or before != after or before.get("policy_digest") != reference:
                continuity = False
                continue
            identity = before.get("proxy_identity")
            expected = instances[trial]
            if type(identity) is not dict or any(identity.get(key) != expected.get(key) for key in
                ("pid", "uid", "cap_eff", "network_namespace_inode", "executable_sha256")) or expected.get("trial") != trial:
                continuity = False
        ids = tuple(item["id"] for item in live_evidence)
        controls = [ControlResult("C24", ReportStatus.PASS, "witnessed session record and transcript are bound", ids)]
        if version2:
            controls.append(ControlResult("C25", ReportStatus(expected_end["c25"]["status"]),
                                          f"pinned Debian artifact fetch {expected_end['c25']}", ids))
        controls.extend((
                ControlResult("C26", ReportStatus(aggregate["status"]),
                              f"aggregate {aggregate}; sessions {session_scores}", ids),
                ControlResult("C27", ReportStatus.PASS if continuity else ReportStatus.FAIL,
                              "immediate policy and proxy identity match C14/C23" if continuity else "immediate policy or proxy identity differs", ids)))
        return tuple(controls)
    except (OSError, KeyError, TypeError, ValueError, StopIteration, json.JSONDecodeError) as exc:
        return (ControlResult("C24", ReportStatus.FAIL, str(exc)),
                *absent_c25,
                ControlResult("C26", ReportStatus.NOT_EVALUATED, "session record did not verify"),
                ControlResult("C27", ReportStatus.NOT_EVALUATED, "session record did not verify"))
