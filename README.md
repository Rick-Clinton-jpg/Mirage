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

## Current milestone

The initial milestone provides:

- a versioned minimum-control profile;
- canonical, hash-linked JSONL evidence;
- strict parsing and fail-closed verification;
- explicit `PASS`, `FAIL`, and `NOT_EVALUATED` outcomes;
- a deterministic demonstration and unit tests.

Linux enforcement probes and quantitative workload experiments are the next
milestone. Until those land, Mirage is a verifier prototype rather than a
deployable sandbox.

## Quick start

```bash
python -m pip install -e .
mirage demo --output evidence.jsonl
mirage verify evidence.jsonl
python -m pytest
```

See [the control standard](docs/CONTROL_STANDARD.md) and
[threat model](docs/THREAT_MODEL.md) before interpreting a result.

