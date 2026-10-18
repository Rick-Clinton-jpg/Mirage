"""Measure the installed nftables policy, excluding volatile rule handles."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class PolicyError(ValueError):
    pass


def policy_digest(snapshot: dict) -> str:
    material = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def measured_policy(raw: str, workload_interface: str) -> tuple[dict, str]:
    """Return a stable snapshot and digest of ``nft -j list table inet mirage``.

    Interface names are random per trial, so the one name created by Mirage is
    replaced with a marker. Everything else, including each rule expression,
    chain policy, and rule order, remains part of the signed digest.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError("nft returned invalid JSON") from exc
    if type(document) is not dict or type(document.get("nftables")) is not list:
        raise PolicyError("nft ruleset has an unexpected shape")

    def stable(value: Any) -> Any:
        if type(value) is dict:
            return {key: stable(item) for key, item in value.items() if key != "handle"}
        if type(value) is list:
            return [stable(item) for item in value]
        if value == workload_interface:
            return "MIRAGE_WORKLOAD_INTERFACE"
        return value

    entries = [stable(item) for item in document["nftables"] if type(item) is dict and "metainfo" not in item]
    tables = [item["table"] for item in entries if "table" in item]
    chains = [item["chain"] for item in entries if "chain" in item]
    rules = [item["rule"] for item in entries if "rule" in item]
    if len(entries) != 1 + 2 + 7 or len(tables) != 1 or len(chains) != 2 or len(rules) != 7:
        raise PolicyError("unexpected nft table, chain, or rule count")
    if tables[0].get("family") != "inet" or tables[0].get("name") != "mirage":
        raise PolicyError("unexpected nft table identity")
    if {chain.get("name") for chain in chains} != {"input", "output"}:
        raise PolicyError("expected input and output chains")
    if any(chain.get("policy") != "drop" for chain in chains):
        raise PolicyError("nft chain must default to drop")
    snapshot = {"nftables": entries}
    return snapshot, policy_digest(snapshot)
