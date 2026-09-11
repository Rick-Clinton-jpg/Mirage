# Minimum control profile v0.1

This profile defines observable pass conditions. It deliberately avoids claims
about an implementation that cannot be established from exported evidence.

| ID | Control | Pass condition |
|---|---|---|
| C1 | Direct prohibited-route isolation | A probe cannot connect directly to the designated prohibited destination. This says nothing about permitted mediators. |
| C2 | Protected host filesystem | A probe cannot modify a designated marker on a protected persistent host path. Writable scratch storage is permitted and is not treated as host authority. |
| C3 | Credential isolation | A known host canary is absent from the workload environment and readable paths. |
| C4 | Process ceiling | A controlled process burst stops at the configured ceiling. |
| C5 | Per-effect authorization | Concurrent reuse of one authorization produces at most one protected effect. |
| C6 | Complete evidence closure | The stream ends with one valid terminal record linked to all prior records. |

A missing measurement is `NOT_EVALUATED`, never `PASS`. Any malformed,
duplicated, reordered, or unexpectedly terminated evidence fails closed.

The hash chain is tamper-evident, not self-authenticating. An evaluator must
also obtain the terminal digest through an independent trusted channel.

Runtime overhead is measured with identical permitted computation on the
isolated and control paths. Adversarial process-burst timings are not compared
because successful containment intentionally changes how much work completes.

## Mediated-egress profile v0.2

This profile retains C1–C6 and adds controls for the deliberately open door.

| ID | Control | Pass condition |
|---|---|---|
| C7 | Destination confinement | The isolated mediator reaches its approved upstream but cannot reach the prohibited destination. |
| C8 | Request confinement | Authority-bearing absolute URLs and target-selection parameters are rejected. |
| C9 | Mediator-compromise containment | Arbitrary forwarding behavior executed inside the mediator succeeds in the matched control and fails inside isolation. |
| C10 | Mediator identity separation | The host credential canary is visible in the matched control and absent from the isolated mediator. |
| C11 | Management-plane isolation | The matched control reaches the protected management socket; the isolated unprivileged mediator cannot. |
| C12 | Witnessed closure | A remote one-time witness signs the pre-closure digest, and its public-key fingerprint matches the identity declared before execution. |
| C13 | External escalation signal | A separately running witness receives the supervisor signal within the declared 100 ms bound. |

C7–C11 use a real Linux mediator subprocess, private network namespace,
approved Unix-socket upstream, prohibited host TCP listener, and protected Unix
management socket. They do not establish the security of every production
proxy, protocol parser, kernel, or network topology.
