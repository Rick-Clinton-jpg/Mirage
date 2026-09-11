"""Incident-shaped model for a permitted mediator and an external policy guard.

This module tests policy semantics in-process. It deliberately does not claim
that the guard is a kernel firewall; the Linux adapter must establish that
property separately before a deployment claim is made.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import queue
import time
from urllib.parse import parse_qs, urlsplit


class Principal(str, Enum):
    WORKLOAD = "workload"
    MEDIATOR = "mediator"
    OPERATOR = "operator"


class Destination(str, Enum):
    MEDIATOR_DATA = "mediator-data"
    MEDIATOR_MANAGEMENT = "mediator-management"
    APPROVED_UPSTREAM = "approved-upstream"
    PROHIBITED_EXTERNAL = "prohibited-external"


@dataclass(frozen=True)
class Decision:
    principal: Principal
    destination: Destination
    allowed: bool
    monotonic_ns: int


class ExternalNetworkGuard:
    """Policy outside the mediator; mediator compromise cannot rewrite it."""

    def __init__(self, events: queue.SimpleQueue[Decision] | None = None):
        self._events = events or queue.SimpleQueue()

    @property
    def events(self) -> queue.SimpleQueue[Decision]:
        return self._events

    def connect(self, principal: Principal, destination: Destination) -> bool:
        allowed = (principal, destination) in {
            (Principal.WORKLOAD, Destination.MEDIATOR_DATA),
            (Principal.MEDIATOR, Destination.APPROVED_UPSTREAM),
            (Principal.OPERATOR, Destination.MEDIATOR_MANAGEMENT),
        }
        self._events.put(Decision(principal, destination, allowed, time.monotonic_ns()))
        return allowed


class FixedUpstreamMediator:
    def __init__(self, guard: ExternalNetworkGuard):
        self.guard = guard
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

    def request(self, request_target: str) -> bool:
        """Reject authority-bearing URLs and always use the configured upstream."""
        parsed = urlsplit(request_target)
        parameters = parse_qs(parsed.query)
        if parsed.scheme or parsed.netloc or "target" in parameters or "url" in parameters:
            return False
        return self.guard.connect(Principal.MEDIATOR, Destination.APPROVED_UPSTREAM)

    def compromised_forward(self, destination: Destination) -> bool:
        """Model arbitrary code execution in the mediator process."""
        return self.guard.connect(Principal.MEDIATOR, destination)


@dataclass(frozen=True)
class MediatedResult:
    destination_confined: bool
    request_confined: bool
    compromise_contained: bool
    identity_separated: bool
    management_isolated: bool
    detection_latency_ms: float
    detected_within_bound: bool


def run_mediated_experiment(*, latency_bound_ms: float = 100.0) -> MediatedResult:
    if latency_bound_ms <= 0:
        raise ValueError("latency bound must be positive")
    guard = ExternalNetworkGuard()
    mediator = FixedUpstreamMediator(guard)

    approved = mediator.request("/packages/example.whl")
    arbitrary_request = mediator.request(
        "/packages/example.whl?target=https://prohibited.invalid/"
    )
    attempt_started = time.monotonic_ns()
    compromised_escape = mediator.compromised_forward(Destination.PROHIBITED_EXTERNAL)
    decision = guard.events.get(timeout=1.0)
    while decision.destination is not Destination.PROHIBITED_EXTERNAL:
        decision = guard.events.get(timeout=1.0)
    latency_ms = (time.monotonic_ns() - attempt_started) / 1_000_000

    management_access = guard.connect(Principal.WORKLOAD, Destination.MEDIATOR_MANAGEMENT)
    sensitive_names = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "GITHUB_TOKEN"}
    identity_separated = not sensitive_names.intersection(mediator.environment)
    return MediatedResult(
        destination_confined=approved and not compromised_escape,
        request_confined=not arbitrary_request,
        compromise_contained=not compromised_escape,
        identity_separated=identity_separated,
        management_isolated=not management_access,
        detection_latency_ms=latency_ms,
        detected_within_bound=(not decision.allowed and latency_ms <= latency_bound_ms),
    )
