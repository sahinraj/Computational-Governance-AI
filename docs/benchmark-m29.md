# M29 Realistic Trace Benchmark

M29 extends GovernanceBench with a small, hand-auditable operational corpus and
two dependency-free external runtime contracts. The goal is contract evidence,
not a vendor integration or a performance claim.

## Reproduce the report

```bash
python -m evaluation.m29_benchmark --check
```

The command validates the corpus, runs both adapters, and writes
`reports/m29-benchmark.json`.

## Corpus and adapters

The corpus contains 14 scenarios and 19 trace steps across deployment,
rollback, secrets access, incident response, infrastructure changes, and the
existing ten benchmark categories. It includes approval escalation and human
override, delegation and expiry, identity failure, replay, malformed input,
and an external operation with an unknown outcome.

`webhook-gateway` serializes a versioned JSON event envelope. `message-queue`
serializes a typed message envelope with a message identifier. Both adapters
apply the same governed decision contract and record execution only for
`Allow` decisions.

## Current evidence

- 14 scenarios / 19 labeled trace steps
- 2 external adapter contracts
- 100% exact label accuracy for both adapters
- 0 unauthorized execution attempts
- 1 explicitly recorded unknown external outcome

The unknown outcome is deliberately not treated as success. A production
integration must reconcile it with the external system before retrying. The
reference adapters are test doubles and do not establish vendor compatibility,
availability, latency, or exactly-once side-effect guarantees.
