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

## Current development milestone (after v0.5.2)

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

## Evaluation paths and review-driven work

Mirage was built for the [Apart Research AI Incident Response Sprint](https://apartresearch.com/sprints/projects/mirage-verifiable-containment-evidence-for-mediated-ai-agent-sandboxes-ll9o).
The sprint submission intentionally used deterministic synthetic probes so an
outside operator could reproduce the same boundary tests and verify the
resulting evidence. Its three-zone topology uses a **live** `apt-cacher-ng`
mediator; “synthetic” describes the workload probes, not the proxy.

Two public reviews on that project page motivated the current follow-on work:
the assured synthetic campaign tightens measurement of the permitted proxy and
installed policy, and the [20-action local-model pilot](docs/LIVE_MODEL_PILOT.md)
lets a model choose TCP actions against that same live topology. Phase 1 now
offers a separate witnessed `mirage-live-session-v0.1` runner, described in the
[reproduction protocol](docs/REPRODUCIBILITY.md#live-model-session-extension).
It binds three predeclared four-action model-directed sessions to the assured
evidence stream. The earlier pilot remains unwitnessed. The v0.2 extension adds
a bounded `http_get` action for a [pinned Debian `hello` package](https://packages.debian.org/bookworm/amd64/hello/download),
served by the approved upstream and fetched through the live proxy. It checks
the returned bytes in the guest supervisor and records C25; a model that does
not request the package receives `NOT_EVALUATED` for C25. The v0.1 Qwen bundle
remains a TCP-only record. Neither profile exercises a full autonomous coding
agent, shell, package installation, or APT workflow.
The first-party [witnessed Qwen evidence bundle](evidence/live-qwen35-9b-2026-10-19/README.md)
contains the exact transcript and offline verification inputs.
The separate [v0.2 Qwen package-fetch bundle](evidence/live-qwen35-9b-package-2026-10-19/README.md)
contains the witnessed C25 run and its offline inputs.

The selective-egress experiment adds a real three-zone TCP topology:

```text
workload namespace -> proxy namespace -> approved-upstream namespace
```

Two veth links and an nftables policy allow package traffic only to the
declared upstream address and port. Matched control-removal probes establish
that the alternate service and management service are live before the policy
is applied. The experiment then tests alternate ports, arbitrary external TCP,
redirect follow-up, an upstream reverse pivot, and a bounded response envelope.

The assured-egress profile places a live `apt-cacher-ng` process in the proxy
namespace, retrieves a package-shaped fixture response through it, and measures its package version,
executable, configuration, live endpoint, UID, capabilities, and namespace from
that same process in every topology trial. The proxy runs as UID/GID 65534 with
no effective capabilities, and a matched policy-tamper attempt must fail.
The network-policy digest is computed from the installed nftables table, with
volatile handles and trial-specific interface names normalized. An offline
Ed25519-signed reference snapshot must match that measurement. Mirage also
evaluates the measured proxy version against a signed, pinned NVD CVE
API response, tests TLS service identity, and attempts a rebound destination.
Only the public assurance key enters the experiment; signing keys remain
offline. The Phase 1 live-model campaign uses a signed **synthetic**
vulnerability input with an empty affected-components list; its C20 result
does not establish that the proxy is free of published vulnerabilities.

## Quick start

```bash
python -m pip install .
mirage demo --output evidence.jsonl
mirage verify --profile mirage-minimum-v0.1 --integrity-only evidence.jsonl
python -m unittest discover -s tests -v
```

Run the test command after installation. Mirage uses a `src/` package layout,
so importing it directly from an uninstalled source directory is intentionally
not supported. For source-only testing, use
`PYTHONPATH=src python -m unittest discover -s tests -v`.

On a disposable Linux machine where the operator can create namespaces and
remount the isolated mount namespace read-only:

```bash
sudo mirage linux-experiment --output ./evidence-run --trials 10
mirage verify --profile mirage-minimum-v0.1 --integrity-only ./evidence-run/evidence.jsonl
```

The mediated-egress profile additionally requires a separately running witness:

```bash
# On the witness machine; record the printed fingerprint and port first.
python -m mirage.witness_server --host WITNESS_ADDRESS

# On Linux, using that pre-declared identity.
sudo mirage linux-experiment --incident-profile --trials 10 \
  --witness-host WITNESS_ADDRESS --witness-port PORT \
  --witness-fingerprint SHA256_FINGERPRINT --output ./incident-run
mirage verify --profile mirage-mediated-egress-v0.2 \
  --witness-receipt ./incident-run/witness-receipt.json \
  --witness-fingerprint SHA256_FINGERPRINT ./incident-run/evidence.jsonl
```

Add `--selective-egress` to construct the v0.4 three-zone topology and require
the eighteen-control `mirage-selective-egress-v0.3` profile.

For the 23-control assured profile, first measure a disposable reference
topology on the intended Linux platform. Review its `policy_snapshot`, then
transfer `policy.json` to the offline authority. Create and sign policy and
vulnerability payloads on an offline authority machine, combine the two
envelopes into a bundle, and transfer only the bundle and raw public key:

```bash
# On the Linux reference host, before the assured campaign:
sudo mirage policy-reference --output policy.json

# On the offline authority, after reviewing policy.json:
mirage assurance-keygen --private authority.pem --public authority.raw
mirage assurance-sign --kind policy-attestation --payload policy.json \
  --private authority.pem --issued-at ISSUED_AT_UTC \
  --expires-at EXPIRES_AT_UTC --output policy-envelope.json

# Back on Linux with the combined signed bundle and public key:
sudo mirage linux-experiment --assured-egress --trials 100 \
  --assurance-bundle assurance-bundle.json \
  --assurance-public-key authority.raw \
  --witness-host WITNESS_ADDRESS --witness-port PORT \
  --witness-fingerprint SHA256_FINGERPRINT --output ./assured-run
```

`--assured-egress` intentionally fails if `apt-cacher-ng`, the assurance
inputs, the remote witness, or any required Linux boundary mechanism is absent.
The mediated, selective, and assured profiles fail verification unless the
matching receipt and pre-trusted witness fingerprint are supplied. Recomputing
an altered JSONL hash chain cannot produce an authenticated `PASS`.
For the assured profile, `mirage verify` additionally requires
`--assurance-bundle` and `--assurance-public-key`; it independently checks the
signatures against the measured policy digest and component identity.

There is deliberately no default verification profile. The minimum profile is
an unauthenticated format/integrity demonstration and only runs when the caller
explicitly supplies `--integrity-only`; without that acknowledgement it returns
`FAIL`. Compliance claims must use a witnessed profile.

See [the control standard](docs/CONTROL_STANDARD.md) and
[threat model](docs/THREAT_MODEL.md) before interpreting a result. The first
clean Ubuntu campaign is recorded in [validation results](docs/RESULTS.md).
The steps for an outside operator are in the
[independent reproduction protocol](docs/REPRODUCIBILITY.md).
