# Ubuntu validation results

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

