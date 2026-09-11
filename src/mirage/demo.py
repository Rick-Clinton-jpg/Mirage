"""Deterministic demonstration evidence; not a kernel containment test."""

from __future__ import annotations

from pathlib import Path

from .evidence import EvidenceWriter
from .profile import INCIDENT_CONTROLS


def write_demo(path: str | Path) -> None:
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite {target}")
    writer = EvidenceWriter(target)
    writer.append("run_start", detail="deterministic verifier demonstration")
    writer.append("network_probe", control_id="C1", outcome="blocked")
    writer.append("filesystem_probe", control_id="C2", outcome="blocked")
    writer.append("credential_probe", control_id="C3", outcome="blocked")
    writer.append("process_probe", control_id="C4", outcome="blocked")
    writer.append("authorization_probe", control_id="C5", outcome="blocked")
    writer.append("run_end", control_id="C6", outcome="complete")


def write_incident_demo(path: str | Path) -> None:
    """Write schema-complete example evidence; this is not a containment test."""
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite {target}")
    writer = EvidenceWriter(target)
    writer.append("run_start", detail="deterministic mediated-egress verifier demonstration")
    for control in (item for item in INCIDENT_CONTROLS if item.control_id != "C6"):
        writer.append(
            control.required_event,
            control_id=control.control_id,
            outcome=control.expected_outcome,
        )
    terminal = next(item for item in INCIDENT_CONTROLS if item.control_id == "C6")
    writer.append(terminal.required_event, control_id=terminal.control_id, outcome=terminal.expected_outcome)
