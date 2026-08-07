# Contributing

This is early-stage research. Contributions, critiques, and benchmark scenarios are welcome.

## Ground rules

- **Theory is frozen at Foundations v1.** Changes to `spec/foundations.md` are admissible only with one of: a failed test the current semantics cannot express, an ambiguous semantics found during implementation, or concrete reviewer evidence. Record any change in the foundations change log with its justification.
- **The benchmark stays runtime-agnostic.** Anything in `governancebench/` must not import from `governance/`. Scenarios reference capabilities, actors, and rules abstractly.
- **Every milestone has a test.** New implementation work lands with acceptance tests, following the milestone plan in `spec/implementation-spec.md`.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Adding a GovernanceBench scenario

Use the schema in `governancebench/schema.py` and validate the dataset with
`python -m evaluation.run_benchmark --check`. Each scenario needs a stable id,
one of the ten declared categories, abstract rule definitions, actors with
explicit intrinsic capabilities where relevant, optional setup (delegations or
prior state), and a trace whose steps carry the expected decision, expected
escalation role where applicable, and the rule each tests. The benchmark
package must remain independent of `governance/`; reference-specific adapters
belong in `evaluation/`.
