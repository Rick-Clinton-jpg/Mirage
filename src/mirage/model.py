"""Typed verification results with no ambiguous boolean shortcut."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ReportStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    status: ReportStatus
    reason: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationReport:
    profile: str
    controls: tuple[ControlResult, ...]

    @property
    def status(self) -> ReportStatus:
        if any(item.status is ReportStatus.FAIL for item in self.controls):
            return ReportStatus.FAIL
        if any(item.status is ReportStatus.NOT_EVALUATED for item in self.controls):
            return ReportStatus.NOT_EVALUATED
        return ReportStatus.PASS

    def as_dict(self) -> dict:
        return {
            "profile": self.profile,
            "status": self.status.value,
            "controls": [
                {
                    "control_id": item.control_id,
                    "status": item.status.value,
                    "reason": item.reason,
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in self.controls
            ],
        }

