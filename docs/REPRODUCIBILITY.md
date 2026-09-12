# Independent reproduction protocol

This protocol lets an operator who did not build Mirage verify a release on a
fresh Linux host. A rerun by the author or build operator is useful validation,
but it is not independent reproduction.

## Inputs

- The release ZIP and its published SHA-256 digest.
- The assurance bundle and verification-only Ed25519 public key.
- A one-time witness endpoint controlled by the reproducing operator.
- Ubuntu on ARM64 or AMD64 with Python 3.11+, `unshare`, `setpriv`, and
  `apt-cacher-ng` installed from the distribution's signed package repository.

Do not accept a private assurance key. Verification requires only the public
key, and possession of the verifier must not confer signing authority.

## Procedure

1. Record the architecture, kernel, Python version, package source,
   `apt-cacher-ng` version, executable SHA-256, and configuration SHA-256.
2. Verify the release digest before extracting it.
3. Extract into a new directory and run:

   ```sh
   PYTHONPATH=src python3 -m unittest discover -s tests -v
   ```

   The v0.5 release contains 38 tests. The run is invalid if any test fails or
   is skipped.
4. Start a witness on a different trust boundary and retain its public-key
   fingerprint. Run Mirage with `--assured-egress`, at least 100 base trials,
   at least 10 topology trials, the signed assurance bundle, and the matching
   public key.
5. Run `mirage verify` with the explicit assured profile, exported result,
   witness receipt and fingerprint, assurance bundle, and assurance public key.
6. Confirm all C1-C23 controls pass, the witness receipt verifies, the runtime
   policy digest matches the signed declaration, and the live product identity
   matches the signed vulnerability assessment.
7. Preserve the JSONL evidence, result, witness receipt, command output,
   environment record, and SHA-256 manifest. Report failures as failures; do
   not edit or regenerate an unsuccessful record.

## Reproduction receipt

The independent operator should publish or sign a receipt containing the
operator, UTC times, release SHA-256, public-key and witness fingerprints, host
and product measurements, test totals including skips, trial counts, C1-C23
outcomes, terminal evidence digest, witness result, deviations, and one final
status: reproduced, partially reproduced, or not reproduced.

Mirage's bundled evidence is first-party evidence until another operator
completes this protocol. A clean-room run under a different local Unix account
does not change that classification.
