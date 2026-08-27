# M28 Adversarial Assurance

M28 adds a deterministic, dependency-free assurance runner for the reference
implementation. It tests failure boundaries that ordinary unit tests do not
cover while keeping CI bounded and reproducible.

## Evidence profile

Run the standard CI profile with:

```bash
python -m evaluation.m28_assurance \
  --check --property-traces 128 --fuzz-cases 32 \
  --output reports/m28-assurance.json
```

The report records the seed, category counts, pass/fail totals, selected scope,
and any first failures. The default seed is `20260826`; a different seed can be
used for a local exploration run.

The current bounded profile covers:

- independent direct/interceptor property checks and execution gates
- malformed service requests, including wrong types, missing fields, and
  hostile structured values
- four selected mutations: inclusive expiry, under-quorum approval, empty
  rollback reason, and default-allow behavior
- delegation, identity, and approval time boundaries plus policy expiry
  fail-closed behavior
- SQLite transaction rollback for state, idempotency, and execution claims under
  an injected pre-commit crash

## Interpretation and limits

This is evidence of tested invariants, not exhaustive fuzzing, formal
verification, or a claim of exactly-once external side effects. The fuzz corpus
is intentionally finite for CI. The M25 service integration and recovery of
pending service state remain tracked separately in issue #29.
