# Threat model

## In scope

- Untrusted agent code attempts network access, host-file modification,
  credential discovery, process exhaustion, or unauthorized protected effects.
- Evidence is modified, reordered, duplicated, truncated, or incompletely
  supplied after a run.
- Authorization is concurrently reused beyond its intended count.

## Trusted boundary

The host kernel, containment launcher, recorder, policy configuration, and
verification software are trusted for the v0.1 result. The workload must not be
able to modify them.

The Linux experiment requires root only for namespace and mount construction.
The probe itself runs as UID/GID 65534 with cleared groups, an empty capability
bounding set, `no_new_privs`, a private network namespace, a read-only mount
namespace, and explicit CPU, address-space, file-descriptor, process, and core
limits.

## Out of scope

- Kernel, hypervisor, hardware, or host-administrator compromise.
- A malicious recorder capable of inventing an internally consistent history.
- Side channels, unknown kernel vulnerabilities, and attacks not represented by
  a declared probe.
- Claims that a passing test generalizes to every operating-system version.

## Evidence interpretation

A passing report means only that every required probe in the named profile
produced its expected result in the supplied complete stream. It is not proof
that no other escape path exists.
