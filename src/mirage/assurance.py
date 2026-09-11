"""Offline Ed25519 assurance envelopes for policy and vulnerability inputs."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class AssuranceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def public_fingerprint(public_bytes: bytes) -> str:
    return hashlib.sha256(public_bytes).hexdigest()


def generate_keypair(private_path: str | Path, public_path: str | Path) -> str:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_target, public_target = Path(private_path), Path(public_path)
    if private_target.exists() or public_target.exists():
        raise AssuranceError("refusing to replace an assurance key")
    private_target.write_bytes(private_bytes)
    private_target.chmod(0o600)
    public_target.write_bytes(public_bytes)
    return public_fingerprint(public_bytes)


def sign_payload(kind: str, payload: dict, private_path: str | Path, *, issued_at: str, expires_at: str) -> dict:
    if kind not in {"policy-attestation", "vulnerability-snapshot"}:
        raise AssuranceError("unsupported assurance kind")
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise AssuranceError("assurance key must be Ed25519")
    public_bytes = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    body = {
        "schema": "mirage-assurance-v1",
        "kind": kind,
        "key_fingerprint": public_fingerprint(public_bytes),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "payload": payload,
    }
    return dict(body, signature=base64.b64encode(private.sign(canonical_json(body))).decode("ascii"))


def _instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AssuranceError("invalid assurance timestamp") from exc
    if parsed.tzinfo is None:
        raise AssuranceError("assurance timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def verify_envelope(envelope: dict, public_bytes: bytes, *, expected_kind: str, now: datetime | None = None) -> dict:
    required = {"schema", "kind", "key_fingerprint", "issued_at", "expires_at", "payload", "signature"}
    if type(envelope) is not dict or set(envelope) != required:
        raise AssuranceError("unexpected assurance envelope schema")
    if envelope["schema"] != "mirage-assurance-v1" or envelope["kind"] != expected_kind:
        raise AssuranceError("unexpected assurance envelope identity")
    if envelope["key_fingerprint"] != public_fingerprint(public_bytes):
        raise AssuranceError("assurance key fingerprint mismatch")
    body = {key: envelope[key] for key in required if key != "signature"}
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, canonical_json(body))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise AssuranceError("invalid assurance signature") from exc
    issued, expires = _instant(envelope["issued_at"]), _instant(envelope["expires_at"])
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued > instant or expires <= instant or issued >= expires:
        raise AssuranceError("assurance envelope is not currently valid")
    if type(envelope["payload"]) is not dict:
        raise AssuranceError("assurance payload must be an object")
    return envelope["payload"]


def verify_assurance_bundle(bundle: dict, public_bytes: bytes, actual_policy_digest: str, component: dict, *, now: datetime | None = None) -> dict:
    if type(bundle) is not dict or set(bundle) != {"policy", "vulnerabilities"}:
        raise AssuranceError("unexpected assurance bundle schema")
    policy = verify_envelope(bundle["policy"], public_bytes, expected_kind="policy-attestation", now=now)
    snapshot = verify_envelope(bundle["vulnerabilities"], public_bytes, expected_kind="vulnerability-snapshot", now=now)
    policy_match = policy.get("config_sha256") == actual_policy_digest
    identity = f"{component.get('name')}@{component.get('version')}"
    affected = snapshot.get("affected_components")
    if type(affected) is not list or not all(type(item) is str for item in affected):
        raise AssuranceError("invalid affected-components list")
    return {
        "policy_signature_verified": True,
        "policy_matches_runtime": policy_match,
        "snapshot_signature_verified": True,
        "snapshot_source": snapshot.get("source"),
        "component_identity": identity,
        "component_clear": identity not in affected,
        "key_fingerprint": public_fingerprint(public_bytes),
    }
