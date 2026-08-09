# Reproducible reports

These JSON files are generated artifacts for the GovernanceBench v0.2 release:

```bash
python -m evaluation.run_benchmark --check
python -m evaluation.failure_harness --check
```

`governancebench.json` contains the 30-scenario, 39-step
reference-versus-static-baseline comparison. Per-decision overhead is measured
on the local runner and is therefore informative rather than a cross-machine
performance claim.
`failure-taxonomy.json` records the injected failure, decision, execution
containment, and human-readable log for each M11 case.

`performance.json` records a local decision-overhead measurement. It is a
release sanity check, not a cross-machine performance claim.
