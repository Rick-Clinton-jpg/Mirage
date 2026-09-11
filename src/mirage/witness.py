"""One-time, verifier-only-public-key witness receipts.

The Lamport construction is intentionally limited to one terminal receipt per
key. It uses only SHA-256 and demonstrates the trust separation without adding
a package dependency. Production deployments should use a reviewed signature
library and managed Ed25519 keys.
"""

from __future__ import annotations

import hashlib
import base64
import json
import secrets
from dataclasses import dataclass


HASH_BYTES = 32
BITS = HASH_BYTES * 8


def _sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def public_key_fingerprint(public: "WitnessPublicKey") -> str:
    material = b"".join(value for pair in public.values for value in pair)
    return hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class WitnessPublicKey:
    values: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class WitnessPrivateKey:
    values: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class WitnessSignature:
    values: tuple[bytes, ...]


class OneTimeWitness:
    def __init__(self, private: WitnessPrivateKey):
        if type(private) is not WitnessPrivateKey or len(private.values) != BITS:
            raise ValueError("invalid private key")
        self._private = private.values
        self._used = False

    @classmethod
    def generate(cls) -> tuple["OneTimeWitness", WitnessPublicKey]:
        private = tuple((secrets.token_bytes(HASH_BYTES), secrets.token_bytes(HASH_BYTES)) for _ in range(BITS))
        public = WitnessPublicKey(tuple((_sha(zero), _sha(one)) for zero, one in private))
        return cls(WitnessPrivateKey(private)), public

    def sign(self, terminal_digest: bytes) -> WitnessSignature:
        if self._used:
            raise RuntimeError("witness key is one-time and has already been used")
        digest = _sha(terminal_digest)
        selected = []
        for index in range(BITS):
            bit = (digest[index // 8] >> (7 - index % 8)) & 1
            selected.append(self._private[index][bit])
        self._used = True
        return WitnessSignature(tuple(selected))


def verify_receipt(public: WitnessPublicKey, terminal_digest: bytes, signature: WitnessSignature) -> bool:
    if len(public.values) != BITS or len(signature.values) != BITS:
        return False
    digest = _sha(terminal_digest)
    for index, disclosed in enumerate(signature.values):
        if len(disclosed) != HASH_BYTES:
            return False
        bit = (digest[index // 8] >> (7 - index % 8)) & 1
        if not secrets.compare_digest(_sha(disclosed), public.values[index][bit]):
            return False
    return True


def encode_receipt(public: WitnessPublicKey, signature: WitnessSignature) -> str:
    payload = {
        "algorithm": "lamport-sha256-ots",
        "public": [[base64.b64encode(a).decode("ascii"), base64.b64encode(b).decode("ascii")] for a, b in public.values],
        "signature": [base64.b64encode(value).decode("ascii") for value in signature.values],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def decode_receipt(encoded: str) -> tuple[WitnessPublicKey, WitnessSignature]:
    try:
        payload = json.loads(encoded)
        if set(payload) != {"algorithm", "public", "signature"} or payload["algorithm"] != "lamport-sha256-ots":
            raise ValueError("unexpected receipt schema")
        public = WitnessPublicKey(tuple((base64.b64decode(a, validate=True), base64.b64decode(b, validate=True)) for a, b in payload["public"]))
        signature = WitnessSignature(tuple(base64.b64decode(value, validate=True) for value in payload["signature"]))
    except (TypeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid witness receipt") from exc
    return public, signature
