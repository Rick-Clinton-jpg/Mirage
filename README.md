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

## Current milestone (v0.4)

The toolkit provides:

- a versioned minimum-control profile;
- canonical, hash-linked JSONL evidence;
- strict parsing and fail-closed verification;
- explicit `PASS`, `FAIL`, and `NOT_EVALUATED` outcomes;
- a deterministic demonstration and unit tests.

The incident-shaped profile separates direct network isolation from mediated
egress. Its Linux experiment gives an isolated mediator access to one approved
Unix-socket upstream, then deliberately executes arbitrary forwarding behavior
inside that mediator. A matched control proves that the prohibited route,
management interface, and credential canary were reachable without isolation.

The terminal pre-closure digest is signed by a single-use witness on a separate
machine. The witness public-key fingerprint must be declared before the run;
the recorder cannot make an untrusted replacement key pass verification. The
witness also measures receipt latency for a supervisor escalation signal.

Mirage remains a research harness rather than a deployable sandbox or proof
against unknown escape techniques. Its current Linux adapter uses namespaces
and requires root for boundary construction.

The selective-egress experiment adds a real three-zone TCP topology:

```text
workload namespace -> proxy namespace -> approved-upstream namespace
```

Two veth links and an nftables policy allow package traffic only to the
declared upstream address and port. Matched control-removal probes establish
that the alternate service and management service are live before the policy
is applied. The experiment then tests alternate ports, arbitrary external TCP,
redirect follow-up, an upstream reverse pivot, and a bounded response envelope.

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

The mediated-egress profile additionally requires a separately running witness:

```bash
# On the witness machine; record the printed fingerprint and port first.
python -m mirage.witness_server --host WITNESS_ADDRESS

# On Linux, using that pre-declared identity.
sudo mirage linux-experiment --incident-profile --trials 10 \
  --witness-host WITNESS_ADDRESS --witness-port PORT \
  --witness-fingerprint SHA256_FINGERPRINT --output ./incident-run
mirage verify --profile mirage-mediated-egress-v0.2 ./incident-run/evidence.jsonl
```

Add `--selective-egress` to construct the v0.4 three-zone topology and require
the eighteen-control `mirage-selective-egress-v0.3` profile.

See [the control standard](docs/CONTROL_STANDARD.md) and
[threat model](docs/THREAT_MODEL.md) before interpreting a result. The first
clean Ubuntu campaign is recorded in [validation results](docs/RESULTS.md).
