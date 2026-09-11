# Threat model

## In scope

- Untrusted agent code attempts network access, host-file modification,
  credential discovery, process exhaustion, or unauthorized protected effects.
- Evidence is modified, reordered, duplicated, truncated, or incompletely
  supplied after a run.
- Authorization is concurrently reused beyond its intended count.
- A permitted mediator is fully compromised and attempts arbitrary forwarding.
- A workload tries to select an arbitrary mediator target or access its
  management plane.
- A recorder substitutes an untrusted witness identity after execution.

## Trusted boundary

The host kernel, containment launcher, supervisor, policy configuration, and
verification software are trusted. The workload and mediator must not be able
to modify them. For the mediated-egress profile, the witness runs on a separate
machine and its public-key fingerprint is trusted before the experiment begins.

The Linux experiment requires root only for namespace and mount construction.
The probe itself runs as UID/GID 65534 with cleared groups, an empty capability
bounding set, `no_new_privs`, a private network namespace, a read-only mount
namespace, and explicit CPU, address-space, file-descriptor, process, and core
limits.

## Out of scope

- Kernel, hypervisor, hardware, or host-administrator compromise.
- A malicious recorder can still omit an entire run, lie before the supervisor
  derives its alert, or attack the witness communication channel. A substituted
  witness receipt is rejected, but this prototype does not provide a public
  transparency log, certificate hierarchy, or durable escrow service.
- Side channels, unknown kernel vulnerabilities, and attacks not represented by
  a declared probe.
- Claims that a passing test generalizes to every operating-system version.
- Vulnerabilities in real artifact servers or proxy parsers beyond the explicit
  arbitrary-forwarding and target-selection probes.
- Production platforms that do not implement the demonstrated Linux namespace
  boundary. The control profile is portable; this adapter is not universal.

## Evidence interpretation

A passing report means only that every required probe in the named profile
produced its expected result in the supplied complete stream. It is not proof
that no other escape path exists.
