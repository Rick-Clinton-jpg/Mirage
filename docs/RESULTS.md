# Ubuntu validation results

## v0.5 assured-egress campaign

The candidate completed 100 matched base trials and 10 freshly constructed
three-zone network trials on Ubuntu 26.04.1 AArch64. The unit suite passed
38/38 tests with zero skips, and the 23-control profile verified `PASS`.

Every topology trial ran the Ubuntu `apt-cacher-ng` 3.7.5-1.1 package inside
the proxy namespace. The workload received a package through that process,
while nftables restricted the proxy to the declared upstream address and
ports. Alternate ports, arbitrary external TCP, redirect follow-up, and the
upstream-to-management reverse pivot failed. The approved TLS identity passed
and the mismatched identity failed.

The product adapter measured an `HTTP/1.1 200 OK` live endpoint, package
version, executable SHA-256, and configuration SHA-256. An offline Ed25519
authority signed the expected runtime-policy digest and a pinned NVD CVE API
2.0 response for `apt-cacher-ng`. Both signatures verified under the public
key supplied to the VM, the policy digest matched, and none of the six returned
records identified the installed 3.7.5-1.1 version as affected. That last
statement is a bounded manual applicability result, not a claim of universal
vulnerability freedom.

The independent witness verified the pre-closure digest and measured 17.45 ms
from escalation arming to receipt. The narrow benign benchmark completed in
100/100 isolated trials with a measured 0% false-positive rate. Mean matched
wall time was 25.35 ms without isolation and 28.55 ms with isolation, a 3.19 ms
mean addition (12.60%) for this launch-dominated benchmark.

These results establish the supplied topology and evidence protocol. They do
not establish resistance to unknown vulnerabilities, production-scale load,
all DNS or TLS attacks, or a compromised kernel, recorder, witness, or offline
assurance authority.

## v0.4 selective-egress development result

The release candidate constructed workload, proxy, and approved-upstream
network namespaces joined by two veth pairs. Package retrieval through the
proxy succeeded. Before nftables activation, the alternate upstream port and
proxy management service were both reachable. After activation, the same paths
were blocked, as were arbitrary external TCP and redirect follow-up. An
upstream reverse-pivot attempt also failed while the protected management
service remained live.

This is a purpose-built TCP fixture. It does not run Artifactory, claim that a
real product is free from zero-days, or consume a live CVE feed. Final repeated
campaign counts and artifact hashes are recorded in the external evidence
bundle rather than embedded recursively in the tested source archive.

## v0.3 mediated-egress campaign

The v0.3 candidate completed 100 matched trials on the environment documented
below. All thirteen controls passed. In every unisolated mediator control, the
approved upstream, protected management socket, host credential canary, and
prohibited TCP destination were reachable. In every isolated mediator run:

- the approved upstream remained reachable;
- arbitrary target-selection requests were rejected;
- arbitrary forwarding to the prohibited destination failed;
- the host credential canary was absent; and
- the protected management socket was inaccessible.

A one-time witness on a separate host published its public-key fingerprint
before the run, received the supervisor escalation signal in 17.59 ms, and
signed the pre-closure evidence digest. One hundred authorization races again
produced exactly one protected effect from 50 contenders per race.

These results demonstrate this test topology, not the absence of every proxy,
kernel, protocol, or telemetry vulnerability. Exact final artifact hashes and
raw results are distributed with the external evidence bundle.

## v0.2 minimum-profile campaign

## Environment

- Architecture: AArch64
- Kernel: Linux 7.0.0-31-generic
- Python: 3.14.4
- Trials: 100 matched control/isolation pairs
- Source archive SHA-256: `6f618a9535e219423c29cce041e78d83d96785d1cc7d935a1bb1ed88e575d036`

## Results

| Measurement | Unisolated control | Isolated execution |
|---|---:|---:|
| Connections to the host listener | 100/100 | 0/100 |
| Modifications to the protected host marker | 100/100 | 0/100 |
| Host canary visible in the environment | 100/100 | 0/100 |
| Child processes started from 64 attempts | 64/64 in every trial | 15/64 in every trial |

One hundred independent authorization races were also run. Each race placed 50
simultaneous contenders against one single-use grant. Exactly one protected
effect occurred in every race: 100 effects from 5,000 attempts.

The identical permitted-computation benchmark completed in 100/100 isolated
runs, giving an observed false-positive rate of 0% for that narrow benign
workload. Mean wall time was 22.12 ms without isolation and 24.72 ms with
isolation: 2.60 ms mean added launch cost, or 11.73% for this short benchmark.
This is launch-dominated and must not be generalized to long-running agents.

All six profile controls verified as `PASS`. The dependency-free unit suite
also passed 12/12 tests with zero skips after clean extraction on Ubuntu.

## Evidence integrity

- Evidence JSONL SHA-256: `0ccc0e05c8ded623d4a3ccddb87790f3382a2b7076ccd80dd38a919a44e51901`
- Raw results SHA-256: `5caced39e1c8b3450d82aff0f562ff739b4b10820f441039a1ee0a41c21e701d`

These file hashes authenticate copies only when obtained through an independent
trusted channel. The internal record chain detects mutation and truncation but
does not prove that the recorder itself was honest.

## Finding during validation

The first Linux campaign failed the filesystem control because its marker was
placed in `/tmp`, which was a writable scratch submount. The boundary correctly
protected the root mount but the experiment had overstated what it measured.
The control was narrowed to a marker on a protected persistent host path, and
the documentation now explicitly permits writable scratch storage. The full
campaign was then restarted from a newly packaged archive.

## Limits

This experiment tests five concrete attacks and one evidence-closure property.
It does not test kernel exploits, side channels, malicious host administrators,
all filesystem mount layouts, or arbitrary agent behavior. A 0% observed rate
across 100 trials is not proof that the true failure probability is zero.
