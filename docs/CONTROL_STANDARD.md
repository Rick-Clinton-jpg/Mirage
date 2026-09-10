# Minimum control profile v0.1

This profile defines observable pass conditions. It deliberately avoids claims
about an implementation that cannot be established from exported evidence.

| ID | Control | Pass condition |
|---|---|---|
| C1 | External network isolation | A probe from inside the workload cannot establish an external route. |
| C2 | Host filesystem protection | A probe cannot modify a designated host-side marker. |
| C3 | Credential isolation | A known host canary is absent from the workload environment and readable paths. |
| C4 | Process ceiling | A controlled process burst stops at the configured ceiling. |
| C5 | Per-effect authorization | Concurrent reuse of one authorization produces at most one protected effect. |
| C6 | Complete evidence closure | The stream ends with one valid terminal record linked to all prior records. |

A missing measurement is `NOT_EVALUATED`, never `PASS`. Any malformed,
duplicated, reordered, or unexpectedly terminated evidence fails closed.

The hash chain is tamper-evident, not self-authenticating. An evaluator must
also obtain the terminal digest through an independent trusted channel.

