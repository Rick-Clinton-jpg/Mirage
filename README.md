# Mirage

Mirage is a small, auditable toolkit for producing evidence about whether an
AI-agent execution environment enforced its declared containment controls.

It separates three questions that are often collapsed into one:

1. **Policy:** what controls did the operator promise?
2. **Execution:** what did the environment report while the workload ran?
3. **Verification:** does the exported evidence support the claimed result?

Mirage does not claim that a passing report proves universal containment. It
checks a bounded control profile against a complete, hash-linked evidence
stream. Kernel vulnerabilities, a compromised recorder, and a compromised
host remain outside that result unless independently measured.

## Current milestone (v0.2)

The initial milestone provides:

- a versioned minimum-control profile;
- canonical, hash-linked JSONL evidence;
- strict parsing and fail-closed verification;
- explicit `PASS`, `FAIL`, and `NOT_EVALUATED` outcomes;
- a deterministic demonstration and unit tests.

The Linux experiment runs matched isolated and unisolated probes for network,
protected-host-filesystem, credential, and process controls, plus a 50-contender
authorization race. Mirage remains a research harness rather than a deployable
sandbox or proof against unknown escape techniques.

## Quick start

```bash
python -m pip install -e .
mirage demo --output evidence.jsonl
mirage verify evidence.jsonl
python -m unittest discover -s tests -v
```

On a disposable Linux machine where the operator can create namespaces and
remount the isolated mount namespace read-only:

```bash
sudo mirage linux-experiment --output ./evidence-run --trials 10
mirage verify ./evidence-run/evidence.jsonl
```

See [the control standard](docs/CONTROL_STANDARD.md) and
[threat model](docs/THREAT_MODEL.md) before interpreting a result. The first
clean Ubuntu campaign is recorded in [validation results](docs/RESULTS.md).
