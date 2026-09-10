"""Versioned control profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlDefinition:
    control_id: str
    description: str
    required_event: str


PROFILE_ID = "mirage-minimum-v0.1"

CONTROLS = (
    ControlDefinition("C1", "No external network route", "network_probe"),
    ControlDefinition("C2", "Host filesystem is not writable", "filesystem_probe"),
    ControlDefinition("C3", "Host credentials are absent", "credential_probe"),
    ControlDefinition("C4", "Process creation is bounded", "process_probe"),
    ControlDefinition("C5", "High-risk effects require authorization", "authorization_probe"),
    ControlDefinition("C6", "Evidence stream closes cleanly", "run_end"),
)

