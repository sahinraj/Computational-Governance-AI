# Computational Governance for Autonomous Systems

> Existing governance systems evaluate **requests**. Computational Governance evaluates **evolving decision processes**.

A formal model, a reference implementation, and a runtime-agnostic benchmark for deciding whether an autonomous agent's intended action is permitted **before it executes** — accounting for delegated authority, human escalation, revocation, and runtime context change.

The theory is frozen at **Foundations v1**. The reference implementation's
v0.3 release completes milestones M1–M21. GovernanceBench v0.2
remains hand-authored so its labels remain auditable. Phase 3 adds
implementation-independent conformance, durable recovery, model-based
assurance, quorum approvals, and a focused CLI while preserving the frozen
Foundations v1 theory.

---

## Why

Autonomous agents increasingly act inside organizations bound by explicit rules. The rules live in natural-language policy documents; the agent's behavior is governed by prompts. Nothing guarantees the two agree.

Existing policy-as-code (OPA/Rego, RBAC, ABAC) assumes a deterministic caller making a static, pre-declared request. Agents reason, choose actions at runtime, and delegate to other agents. This project defines and implements governance for that harder setting.

## The core problem

Given a governance state `S = (A, C, Γ, Δ, κ)` and an intended action `α = (actor, capability, params)`, compute

```
𝒢(S, α) → Decision ∈ { Allow, Block, Escalate(role) }
```

subject to rule soundness, delegation validity, escalation totality, and context currency. Full statement in [`spec/foundations.md`](spec/foundations.md).

## Repository layout

```
governance/        reference implementation of 𝒢 and tool-boundary adapter
governancebench/   runtime-agnostic benchmark schema, dataset, and scorer
evaluation/        reference adapter, static baseline, and reproducible runners
tests/             acceptance checks, one set per milestone
reports/           reproducible benchmark and failure-taxonomy outputs
spec/
  foundations.md          formal model (FROZEN v1): entities, state, axioms, semantics, theorems
  field-and-benchmark.md  field positioning + GovernanceBench spec
  implementation-spec.md  the build plan and milestones
docs/              GitHub Pages site
```

## Status

| Milestone | Description | State |
|-----------|-------------|-------|
| M1 | Repo and harness | ✅ |
| M2 | Law parser | ✅ |
| M3 | Single-rule semantics | ✅ |
| M4 | Composition and inheritance | ✅ |
| M5 | Compiler + validation | ✅ |
| M6 | Interceptor, shadow mode | ✅ |
| M7 | Delegation graph | ✅ |
| M8 | Enforce mode + escalation | ✅ |
| M9 | GovernanceBench dataset | ✅ |
| M10 | Evaluation vs static baseline | ✅ |
| M11 | Failure taxonomy harness | ✅ |
| M12 | GovernanceBench v0.2 corpus | ✅ |
| M13 | Delegation and authority hardening | ✅ |
| M14 | Auditability and deterministic replay | ✅ |
| M15 | Bounded human approval lifecycle | ✅ |
| M16 | Runtime adapter and release hardening | ✅ |
| M17 | Versioned conformance protocol | ✅ |
| M18 | Durable state and crash-safe recovery | ✅ |
| M19 | Deterministic model-based assurance | ✅ |
| M20 | Quorum-based human approvals | ✅ |
| M21 | v0.3 end-to-end integration release | ✅ |
| M22 | Stable policy and protocol versioning | ✅ |
| M23 | Authenticated workload and actor identity | ✅ |
| M24 | Versioned service API and Python SDK | 🚧 |

## Quickstart

```bash
git clone https://github.com/sahinraj/Computational-Governance-AI.git
cd Computational-Governance-AI
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m evaluation.run_benchmark --check
python -m evaluation.failure_harness --check
python -m evaluation.performance --check
python -m evaluation.model_assurance --check
```

The v0.3 CLI validates policies, evaluates one tool call, replays a redacted
audit event, and runs the conformance and assurance reports:

```bash
python -m governance validate-policy examples/phase3-policy.law \
  --role ReleaseManager --role SecurityLead --role FinanceLead
python -m governance conformance
python -m governance assurance --check
```

Parse a policy and evaluate a rule:

```python
from governance import parse_laws, Actor, Action, Capability, Context

rules = parse_laws("""
LAW-001
  capability: payment.send
  authority_level: >= 3
  constraint: amount <= 100
  on_violation: escalate
""")

action = Action(Actor("agent-1", authority_level=5),
                Capability("payment.send"), {"amount": 150})

print(rules[0].evaluate(action, Context()))   # Result.VIOLATED
```

The benchmark and failure harness are standard-library runners:

```bash
python -m evaluation.run_benchmark
python -m evaluation.failure_harness
```

GovernanceBench v0.2 contains 30 canonical scenarios across 10 categories and
39 labeled trace steps, with at least three scenarios per category. The
reference implementation scores 1.0 exact accuracy; the static baseline
remains weaker on the dynamic categories. Generated JSON artifacts live in
`reports/`.

For integrations, `governance.RuntimeAdapter` is the single pre-execution
entry point for typed `ToolCall` envelopes. Enforce mode invokes the supplied
operation only after `Allow`, fails closed on governance errors, and rejects a
completed request id a second time. The M24 service boundary and SDK are
documented in [`docs/service-api.md`](docs/service-api.md). See
[`SECURITY.md`](SECURITY.md) for integration boundaries.

Phase 3 persistence is intentionally narrow: `AtomicJsonStore` saves versioned
governance snapshots with same-directory replacement and `JsonlAuditStore`
recovers fsynced decision events. Corrupt or incompatible state raises a
`StoreError` so callers can fail closed instead of guessing at recovery.
The M19 assurance runner generates 1,000 seeded traces, compares delegation
state with an independent finite-state oracle, and exercises invalid
transitions such as widening, cycles, stale approvals, and replay.
Approval-required laws may use `approval_policy: quorum 2 of ReleaseManager,
SecurityLead, FinanceLead`; enforce mode records distinct reviewer votes and
resumes only after the exact threshold is reached.

## Design commitments

- **Deterministic enforcement.** A decision depends only on state and action, never on execution outcome. Governance decides *before*, and independently of, execution.
- **Benchmark independence.** GovernanceBench references capabilities, actors, and rules abstractly and scores any system through an adapter. It imports nothing from this implementation, so it can outlive it.
- **Frozen theory, evidence-gated changes.** Foundations v1 changes only on a failed test, an ambiguous semantics found in implementation, or concrete reviewer evidence.

## Roadmap

The reference implementation ships first as the load-bearing systems result. GovernanceBench is built in parallel. Later theory papers (delegation algebra, identity, governance complexity, temporal and cross-system governance) extend the frozen foundations rather than replacing them. See [`spec/field-and-benchmark.md`](spec/field-and-benchmark.md).

The professionalization plan is tracked in [`docs/roadmap.md`](docs/roadmap.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Citing

See [CITATION.cff](CITATION.cff).
