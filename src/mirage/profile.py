"""Versioned control profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str
    description: str
    required_event: str
    expected_outcome: str = "blocked"


PROFILE_ID = "mirage-minimum-v0.1"

CONTROLS = (
    ControlDefinition("C1", "Direct connection to a prohibited destination is blocked", "network_probe"),
    ControlDefinition("C2", "Host filesystem is not writable", "filesystem_probe"),
    ControlDefinition("C3", "Host credentials are absent", "credential_probe"),
    ControlDefinition("C4", "Process creation is bounded", "process_probe"),
    ControlDefinition("C5", "High-risk effects require authorization", "authorization_probe"),
    ControlDefinition("C6", "Evidence stream closes cleanly", "run_end", "complete"),
)

INCIDENT_PROFILE_ID = "mirage-mediated-egress-v0.2"

INCIDENT_CONTROLS = CONTROLS + (
    ControlDefinition("C7", "Mediator is confined to approved upstream destinations", "destination_confinement_probe"),
    ControlDefinition("C8", "Untrusted requests cannot select arbitrary mediator targets", "request_confinement_probe"),
    ControlDefinition("C9", "A compromised mediator cannot reach prohibited destinations", "mediator_compromise_probe"),
    ControlDefinition("C10", "Mediator has no reusable host credential", "mediator_identity_probe"),
    ControlDefinition("C11", "Workload cannot reach the mediator management plane", "management_plane_probe"),
    ControlDefinition("C12", "Terminal evidence has an independently verifiable witness receipt", "witness_probe", "verified"),
    ControlDefinition("C13", "Escalation produces a live signal within the declared latency bound", "detection_latency_probe", "detected"),
)
