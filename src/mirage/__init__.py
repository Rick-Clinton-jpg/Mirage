"""Mirage containment-evidence verifier."""

from .model import ControlResult, ReportStatus, VerificationReport
from .verifier import verify_file

__all__ = ["ControlResult", "ReportStatus", "VerificationReport", "verify_file"]
__version__ = "0.5.0"
