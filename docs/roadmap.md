# Professionalization Roadmap

**Project:** Computational Governance for Autonomous Systems  
**Current release:** v0.3.0  
**Current state:** Phase 3 complete; Phase 4 starting  
**Roadmap date:** 2026-08-10

## North-star direction

Turn the research reference implementation into an auditable policy-enforcement
and approval control plane for autonomous-agent tool execution.

The project should remain deliberately narrow. It is not becoming a general
agent framework, model-training system, or generic workflow platform. The
load-bearing boundary is:

```text
Agent or runtime
    -> authenticated tool gateway
    -> governance decision engine
    -> policy, identity, approval, and audit systems
    -> approved tool execution
```

## Starting point: v0.3

Completed capabilities:

- Frozen Foundations v1 formal model
- Runtime policy compiler and interceptor
- Delegation, attenuation, expiry, revocation, and authority proofs
- Versioned audit events and deterministic replay
- Bounded human approval and named-role quorum approval
- Versioned conformance protocol and black-box fixtures
- Local crash-safe state snapshots and append-only audit recovery
- Seeded model assurance: 1,000 traces and 12,000 invariant checks
- Runtime-agnostic GovernanceBench: 30 scenarios and 39 trace steps
- Python CLI, CI matrix, CodeQL, protected `main`, and GitHub Pages

The project is not yet production-ready. The main gaps are authenticated
identity, a service boundary, production persistence, observability, policy
lifecycle controls, independent security evidence, and a real-world pilot.

## Phase 4 — Production Trust Boundary

**Suggested duration:** 6–8 weeks  
**Objective:** Build the smallest credible production kernel around the
existing deterministic governance engine.

| Milestone | Objective | Dependency |
|---|---|---|
| M22 | Stable policy and protocol versioning | None; first |
| M23 | Cryptographic workload and actor identity | M22 |
| M24 | Service API and production SDK | M22, M23 |
| M25 | Transactional durable storage | M22, M23 |
| M26 | Observability and decision telemetry | M24, M25 |
| M27 | Policy lifecycle and controlled rollout | M22–M26 |

### M22 — Stable policy and protocol versioning

Deliver policy IDs, versions, content hashes, provenance, compatibility rules,
migrations, semantic diffs, bundle import/export, rollback protection, and
backward-compatibility tests for protocol v1.

**Boundary:** Do not redesign Foundations v1 or introduce a new policy language
without implementation evidence. The existing line DSL remains supported as a
reference authoring format.

**Acceptance:** policy bundles validate deterministically; incompatible versions
fail closed; compatible bundles round-trip; policy fingerprints are stable; a
policy diff identifies semantic changes; rollback to an older version is
explicit and auditable.

### M23 — Cryptographic workload and actor identity

Replace free-form actor identity at the trust boundary with authenticated
identity, trust domains, identity-to-role mapping, credential expiry, rotation,
and verified delegation provenance.

SPIFFE/SPIRE is the preferred integration direction; cryptography should not be
implemented from scratch.

**Boundary:** No multi-tenant identity platform or custom certificate authority
in this milestone. Build a provider-neutral identity interface and one tested
reference provider.

**Acceptance:** unauthenticated, expired, wrong-domain, and impersonated actors
are rejected; valid identities map deterministically to roles; authority proofs
carry verified identity references; rotation and restart tests pass.

### M24 — Service API and production SDK

Expose the engine through a typed HTTP or gRPC decision service and a Python
client SDK. Add authentication middleware, idempotency keys, timeouts, retries,
async approval continuation, and one reference runtime adapter.

**Boundary:** No dashboard, hosted SaaS, or broad vendor-specific agent
framework. Keep the core engine usable as a library.

**Acceptance:** the service handles allow, block, escalate, timeout, retry,
duplicate-request, and approval-resume paths; schemas are versioned; the SDK
has contract tests; no tool operation runs without an allow decision.

### M25 — Transactional durable storage

Add a production persistence backend, initially PostgreSQL or an equivalent
single-region transactional store. Persist policy state, grants, approvals,
decision events, and sequence numbers with optimistic concurrency, backups,
retention, encryption, and recovery tests.

**Boundary:** Do not build multi-region consensus or distributed deployment yet.
Prove the single-region consistency model first.

**Acceptance:** concurrent updates cannot lose or duplicate approvals; crash
recovery preserves state and audit ordering; backups restore successfully;
retention and encryption behavior are documented; recovery targets are measured.

### M26 — Observability and decision telemetry

Adopt OpenTelemetry conventions for traces, metrics, logs, and events. Every
governed action receives a correlation ID, decision ID, policy version, actor
identity, approval reference, execution outcome, latency, and failure reason.

**Boundary:** Never emit raw secrets or unrestricted tool parameters. Telemetry
must be redacted by default.

**Acceptance:** a single tool call can be followed end-to-end; dashboards or
query examples show decision latency, blocks, escalations, approvals, failures,
and recovery events; telemetry schemas are documented and tested.

### M27 — Policy lifecycle and controlled rollout

Implement the operational policy workflow:

```text
Author -> validate -> simulate -> review -> approve -> deploy -> monitor -> rollback
```

Add dry runs, historical-trace simulation, semantic policy diffs, canary rollout,
environment promotion, rollback, policy ownership, expiry dates, and two-person
approval for production policy changes.

**Acceptance:** a policy can move from draft to production through an auditable
workflow; a canary can be rolled back; changed decisions are visible before
deployment; production policy changes require the configured quorum.

## Phase 5 — Assurance and security evidence

**Suggested duration:** 4–6 weeks.

- M28: property-based, fuzz, mutation, clock-skew, and crash-injection testing
- M29: expanded benchmark with realistic traces and external adapters
- M30: threat model and red-team suite covering replay, identity substitution,
  policy downgrade, approval collusion, confused deputy, and recovery failures
- M31: independent security review
- M32: reproducibility package, dataset documentation, and research release

The goal is evidence that the system is safe under adversarial conditions, not
just evidence that the happy path works.

## Phase 6 — One narrow production pilot

Start with production deployment governance for autonomous DevOps agents. This
vertical has clear tool calls, understandable approval roles, reversible actions,
and strong audit requirements.

Pilot requirements:

- one real runtime or agent integration
- one tool gateway
- one approval channel
- one durable backend
- one operator-facing audit view
- 30–60 days of trace data
- documented false positives, blocked actions, approvals, and incidents

Proposed pilot targets:

- 100% of governed actions produce a decision record
- no unauthorized execution in adversarial tests
- no approval replay after restart
- p95 end-to-end decision latency below 100 ms
- recovery target such as RTO below 5 minutes
- successful policy rollback demonstration

These are targets to validate, not current project results.

## Phase 7 — Professional open-source release

After the pilot and security review:

- publish signed GitHub and PyPI releases
- generate SBOMs and build provenance
- add `CODEOWNERS`, dependency automation, coverage, linting, typing, and
  dependency auditing
- enforce branch protection for administrators
- require signed releases and, where practical, signed commits
- publish a threat model, operator runbook, data-retention policy, and API
  stability/deprecation policy
- define the path from v0.3 to v0.4 and eventually v1.0

## Decision gates

### Gate A — Production kernel

Do not start a pilot until identity, service boundary, durable storage, and
observability work together in one end-to-end deployment.

### Gate B — Independent assurance

Do not claim production readiness until red-team tests, recovery tests, and an
independent review show no unresolved critical bypass.

### Gate C — Pilot evidence

Do not broaden scope until one narrow workflow meets measured reliability,
latency, auditability, and operator-acceptance targets.

## Explicit non-goals

- General-purpose autonomous-agent orchestration
- Model training or fine-tuning
- Multi-tenant SaaS before a single-tenant pilot is proven
- Multi-region consensus before single-region durability is proven
- Custom cryptography or identity infrastructure
- A large UI before the service and audit APIs stabilize
- Changing Foundations v1 merely to accommodate implementation convenience

## Immediate next action

Create the Phase 4 GitHub milestone and issues M22–M27, then begin M22 on a
dedicated branch with acceptance tests before implementation.
