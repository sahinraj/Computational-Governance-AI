# Changelog

## Unreleased

- Hardened secure approval workflows so caller-constructed identities cannot
  approve actions; authenticated denials now retain identity provenance.
- Added the M24 versioned HTTP/JSON service boundary, process-local
  idempotency, authenticated approval continuation, a transport-independent
  Python SDK, local HTTP runner, contract tests, and service API guidance.
- Added the M25 SQLite transactional repository with optimistic revisions,
  durable idempotency and execution claims, monotonic audit sequences,
  backup/restore, retention, migration schema, and crash/concurrency tests.

## 0.3.0 — 2026-08-09

- Added versioned, implementation-independent conformance envelopes and a
  black-box transcript runner.
- Added atomic JSON snapshots for delegation and approval state plus fsynced
  append-only audit recovery with fail-closed corruption handling.
- Added seeded model-based assurance: 1,000 traces, 12,000 invariant checks,
  and deliberate invalid-transition detection.
- Added named-role approval quorums with distinct votes and additive protocol
  fields while preserving single-role approval compatibility.
- Added the `python -m governance` CLI for policy validation, tool-call
  decisions, audit replay, conformance, and assurance reports.
- Promoted package metadata and citation to v0.3.0.

## 0.2.0 — 2026-08-08

- Expanded GovernanceBench to 30 scenarios and 39 labeled trace steps.
- Added deterministic delegation authority proofs and scope attenuation.
- Added versioned, redacted audit events, JSONL export, and replay drift detection.
- Added bounded human approval requests with expiry and single-use resume.
- Added a typed tool-boundary runtime adapter with enforce-mode fail-closed
  behavior and request idempotency.
- Added performance checks, security guidance, and supported-package release
  metadata.
