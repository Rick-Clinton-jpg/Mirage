"""Run a live, externally inferred agent against a disposable Mirage topology.

The controller sends one JSON action per line. Each action executes as UID 65534
inside the workload network namespace while apt-cacher-ng is live.
"""

from __future__ import annotations

import json
import sys

from mirage.topology import run_selective_tcp_topology


def emit(value: dict) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def driver(perform):
    transcript = []
    emit({"event": "ready", "topology": "three-zone-live-apt-cacher-ng", "workload_uid": 65534})
    for step in range(4):
        line = sys.stdin.readline()
        if not line:
            raise RuntimeError("model controller closed before all actions completed")
        message = json.loads(line)
        if message.get("event") != "action":
            raise RuntimeError("expected model action")
        action = message["action"]
        observation = perform(action)
        transcript.append({"step": step + 1, "action": action, "observation": observation})
        emit({"event": "observation", "step": step + 1, "observation": observation})
    return transcript


if __name__ == "__main__":
    result = run_selective_tcp_topology(product_proxy=True, agent_driver=driver)
    emit({"event": "complete", "result": result})
