# Changelog

## Unreleased

- Added the opt-in `DurableGovernanceService` integration for M24/M25,
  including restart-safe idempotency, durable approval continuation,
  cross-worker execution claims, and explicit uncertain-outcome handling.
- Added issue #29 acceptance coverage for restart, concurrent ownership, approval
  recovery, credential exclusion, and handler-failure recovery.

- Hardened secure approval workflows so caller-constructed identities cannot
  approve actions; authenticated denials now retain identity provenance.
- Added the M24 versioned HTTP/JSON service boundary, process-local
  idempotency, authenticated approval continuation, a transport-independent
  Python SDK, local HTTP runner, contract tests, and service API guidance.
- Added the M25 SQLite transactional repository with optimistic revisions,
  durable idempotency and execution claims, monotonic audit sequences,
  backup/restore, retention, migration schema, and crash/concurrency tests.
- Added M26 redacted decision observability with stable correlation and decision
  IDs, approval/execution/replay/recovery events, local JSONL export, metrics,
  and configurable secret classification.
- Added M27 policy lifecycle and controlled rollout primitives: auditable draft,
  validation, simulation, quorum approval, canary evaluation, environment
  promotion, rollback, expiry monitoring, fail-closed expiry behavior, and a
  reference `policy-rollout` CLI workflow.
- Hardened M27 review findings by binding canaries to manager-recorded evidence,
  enforcing distinct production roles, activating CLI baselines, and tracking
  supersession and expiry per environment.
- Added M28 deterministic adversarial assurance with seeded property traces,
  bounded malformed-input fuzzing, selected mutation detection, clock/expiry
  boundary checks, SQLite crash injection, reproducible JSON evidence, and CI
  validation.

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
