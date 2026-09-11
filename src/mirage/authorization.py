"""Single-use authorization gate used by the containment experiment."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class _Grant:
    subject: str
    action: str
    expires_at: float


class AuthorizationGate:
    """Issue bounded grants and atomically consume them with one effect."""

    def __init__(self, *, max_pending: int = 1024) -> None:
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self._max_pending = max_pending
        self._pending: dict[bytes, _Grant] = {}
        self._lock = threading.Lock()

    def issue(self, subject: str, action: str, *, ttl_seconds: float = 60.0) -> str:
        if not subject or not action or len(subject) > 256 or len(action) > 256:
            raise ValueError("subject and action must be bounded nonempty strings")
        if type(ttl_seconds) not in (int, float) or not 0 < ttl_seconds <= 300:
            raise ValueError("ttl must be between 0 and 300 seconds")
        token = secrets.token_urlsafe(32)
        key = hashlib.sha256(token.encode("ascii")).digest()
        now = time.monotonic()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}
            if len(self._pending) >= self._max_pending:
                raise RuntimeError("authorization capacity exhausted")
            self._pending[key] = _Grant(subject, action, now + ttl_seconds)
        return token

    def execute_once(self, token: object, subject: str, action: str, effect) -> bool:
        """Consume a matching grant and perform ``effect`` under one lock.

        The effect must be short and local. Holding the lock makes the
        authorization decision and protected effect a single transaction.
        """
        if type(token) is not str or len(token) != 43 or not token.isascii():
            return False
        key = hashlib.sha256(token.encode("ascii")).digest()
        with self._lock:
            grant = self._pending.get(key)
            if grant is None or grant.expires_at <= time.monotonic():
                self._pending.pop(key, None)
                return False
            if grant.subject != subject or grant.action != action:
                return False
            del self._pending[key]
            effect()
            return True

