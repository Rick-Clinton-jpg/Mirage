"""Export bounded model-action transcripts without model reasoning or host details.

The input is a local campaign manifest and its trial directories. The output
contains only model-selected actions, tool observations, and response metadata.
The raw transcript digests remain in the manifest as provenance references;
raw transcripts are intentionally not published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = json.loads(args.manifest.read_text(encoding="utf-8"))
    records = []
    trial_manifest = []
    for trial in source["trials"]:
        raw = (args.manifest.parent / trial["path"] / "transcript.jsonl").read_bytes()
        guest_raw = (args.manifest.parent / trial["path"] / "guest-result.json").read_bytes()
        guest_result = json.loads(guest_raw)
        if digest(raw) != trial["transcript_sha256"]:
            raise ValueError(f"raw transcript digest mismatch for trial {trial['number']}")
        lines = [json.loads(line) for line in raw.splitlines()]
        if len(lines) != trial["actions"]:
            raise ValueError(f"action count mismatch for trial {trial['number']}")
        if guest_result["agent_run"] != [
            {key: line[key] for key in ("step", "action", "observation")}
            for line in lines
        ]:
            raise ValueError(f"guest action record mismatch for trial {trial['number']}")
        if guest_result["policy_digest"] != trial["policy_digest"]:
            raise ValueError(f"policy digest mismatch for trial {trial['number']}")
        for line in lines:
            response = line["model_response"]
            records.append({
                "trial": trial["number"],
                "scenario": trial["scenario"],
                "step": line["step"],
                "action": line["action"],
                "observation": line["observation"],
                "model_metadata": {
                    "finish_reason": response["choices"][0].get("finish_reason"),
                    "usage": response.get("usage", {}),
                },
            })
        trial_manifest.append({
            "trial": trial["number"],
            "scenario": trial["scenario"],
            "actions": trial["actions"],
            "connected_actions": trial["connected_actions"],
            "approved_package_path_live": trial["approved_package_path_live"],
            "policy_guard": trial["policy_guard"],
            "all_topology_checks_pass": trial["all_topology_checks_pass"],
            "topology_checks": guest_result["checks"],
            "policy_digest": guest_result["policy_digest"],
            "raw_transcript_sha256_private": trial["transcript_sha256"],
            "raw_guest_result_sha256_private": digest(guest_raw),
        })
    output = b"".join((json.dumps(record, sort_keys=True) + "\n").encode("utf-8") for record in records)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "transcripts.jsonl").write_bytes(output)
    public_manifest = {
        "date": source["date"],
        "model_file_sha256": source["model_file_sha256"],
        "model_file_bytes": source["model_file_bytes"],
        "model_runtime": source["model_runtime"],
        "linux_guest": source["linux_guest"],
        "policy_digest": source["trials"][0]["policy_digest"],
        "trials": trial_manifest,
        "totals": source["totals"],
        "transcripts_sha256": digest(output),
        "scope": source["scope"],
        "sanitization": "Removed local guest identity, paths, raw API responses, and hidden reasoning. Preserved model actions and tool observations.",
    }
    (args.output / "manifest.json").write_text(
        json.dumps(public_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
