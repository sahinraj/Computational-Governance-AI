# Computational Governance for Autonomous AI Systems

**A policy language and compiler that enforces organizational rules on autonomous agents at runtime.**

Owner: Sahin Raj
Status: Reference implementation v0.2 — M1–M17 complete; Phase 3 in progress
Last updated: 2026-08-09

---

## 0. TL;DR for the agent

Build a system that takes organizational rules written in a formal language, compiles them into an enforcement layer, and blocks or escalates an autonomous agent's actions at runtime when they would violate those rules. Build it in shadow mode first so it can be validated against real action traces without risk. The deliverable is a working reference implementation plus a benchmark that proves it catches violations a static policy engine misses.

If running this in a loop: start at Section 8, pick the lowest-numbered incomplete milestone, implement it, run its acceptance check, mark it done, and move to the next. Do not skip milestones. Do not add scope not listed here without recording it in Section 11.

## 1. The problem

Autonomous agents act inside organizations bound by explicit rules. Those rules live in natural-language documents while agent behavior is governed by prompts. There is no guaranteed link between the two.

Existing policy-as-code systems such as OPA/Rego, RBAC, and ABAC assume deterministic callers making static, pre-declared requests. Agents reason, select actions at runtime, and delegate to other agents. A static check on a single caller cannot govern a chain of autonomous actors where authority is passed down and must remain revocable.

The gap is a way to express organizational authority and obligation in a form that can be compiled and enforced at runtime against intended actions before execution.

## 2. The idea

Three linked components:

1. **A formal policy language.** Composable, inheritable laws with authority levels, capabilities, context predicates, and required human approvals. Delegation constraints are enforced by the separate delegation graph API.
2. **A compiler.** Translates the language into an enforcement artifact.
3. **A runtime interceptor.** Sits between an agent and its tools. Every intended action is checked and allowed, blocked, or escalated before it executes.

The wedge over existing policy engines is delegable and revocable authority across an agent chain, with enforcement on runtime-selected actions rather than pre-declared static requests.

## 3. Scope

**In scope**

- Policy-language grammar and semantics
- Compiler from source language to enforcement artifact
- Runtime interceptor with shadow and enforce modes
- Delegation and revocation across an agent chain
- A domain benchmark of correct and violating action sequences
- A failure taxonomy for governed agent organizations

**Out of scope for the reference implementation**

- Building the agents themselves
- Model training or fine-tuning
- A production UI; CLI and structured logs are sufficient
- Distributed deployment and multi-tenant hardening

## 4. Prior art and the wedge

Position against and differentiate from:

- **OPA/Rego, policy-as-code.** Static evaluation of declared input against rules. No runtime action selection or delegation chain.
- **RBAC, ABAC, and capability systems.** Rich access-control models for human or service principals with fixed roles, but no revocable delegation across autonomous goal-seeking actors.
- **Constitutional AI.** Shapes model behavior through training. This project constrains actions independently of model output.
- **Distributed-systems trust and reputation models.** Adjacent and useful, but focused on trust between nodes rather than authority delegation in an organizational agent hierarchy.

State the wedge in every paper:

> Existing systems govern deterministic callers making static requests; this system governs non-deterministic agents choosing runtime actions and delegating authority down a revocable chain.

## 5. The policy language

Design goals: readable by a compliance officer, parseable by a machine, composable, and inheritable.

A law has:

- `id` — stable identifier such as `LAW-001`
- `authority_level` — integer rank the actor must hold
- `capability` — governed action class such as `payment.send`, `deploy.production`, or `github.write`
- `constraint` — condition that must hold, such as `amount <= 100`
- `constraint` — comparison over action parameters, actor fields, or context (`budget_used`, `now`, and approval count)
- `forbidden_classes` — actor classes that may never exercise the capability
- `parent` — optional inherited rule id
- `requires_approval` — human role that must approve before execution
- `on_violation` — `block` or `escalate`

Implemented syntax:

```text
LAW-001
  capability: payment.send
  authority_level: >= 3
  constraint: amount <= 100
  requires_approval: FinanceLead
  on_violation: escalate

LAW-014
  capability: deploy.production
  authority_level: >= 4
  parent: LAW-001
  on_violation: block

LAW-022
  capability: github.write
  authority_level: >= 2
  forbidden_classes: intern
  on_violation: block
```

Semantics to define precisely:

- What it means for an action to satisfy or violate a law
- How applicable laws compose; default all-pass with most-restrictive-wins conflict resolution
- How laws inherit down an organizational hierarchy
- Proof that composition preserves every parent rule and that a child cannot grant authority denied by a parent

## 6. The compiler and runtime interceptor

### Compiler

Parse source into structured rules, validate it, and emit an immutable enforcement artifact consisting of a deterministic decision function. Validation includes contradictions, dangling roles, missing parents, inheritance cycles, and an explicit optional default-deny mode for unmatched capabilities. Delegation remains runtime state supplied to the artifact.

### Interceptor

```python
decision = interceptor.check(action, context)
# action:  { actor, capability, params }
# actor:   { id, authority_level, class, capabilities }
# context: { budget_used, prior_approvals, timestamp }
# decision: ALLOW | BLOCK | ESCALATE(role) + reason + matched_laws
```

Every intended action passes through `check()` before execution.

- **Shadow mode:** log the decision while allowing the action to proceed.
- **Enforce mode:** make the decision binding.

### Delegation

When actor A delegates capability X to actor B, record an edge containing the granting law, scope, remaining depth, expiry where applicable, and a revocation handle. B's actions are checked against both intrinsic and delegated authority. Revoking A's grant must invalidate all authority derived through it by the next check.

## 7. Evaluation: GovernanceBench and failure science

Build labeled action sequences in enterprise domains:

- Crew-rest or duty-time limits
- Payment approval chains
- Two-reviewer production deployment
- Delegation abuse such as an intern receiving `github.write`

Report precision and recall on interception, escalation accuracy, and per-decision overhead. Compare against at least one static policy baseline and, where useful, a prompt-only guardrail.

Failure classes exercised by the M11 harness:

- Authority leakage
- Delegation loops
- Escalation deadlock
- Silent bypass caused by capability-taxonomy gaps

The reference adapter and static baseline live in `evaluation/`; the
`governancebench/` package imports no reference implementation code.

The benchmark and taxonomy should be reusable artifacts, not one-off test fixtures.

## 8. Build plan

Work in order. Do not proceed until the milestone acceptance check passes.

- **M1 — Repo and harness.** Project skeleton, test runner, logging. *Accept:* tests execute cleanly.
- **M2 — Language parser.** Parse the law syntax into structured objects. *Accept:* example laws parse; malformed laws produce clear errors.
- **M3 — Semantics core.** Implement single-rule evaluation. *Accept:* tests cover satisfy, violate, and not-applicable for every field type.
- **M4 — Composition and inheritance.** Multiple applicable rules, most-restrictive-wins, and parent-to-child tightening only. *Accept:* a child cannot loosen a parent rule.
- **M5 — Compiler.** AST to enforcement artifact plus contradiction and dangling-role validation. *Accept:* contradictory policies fail compilation with a named reason.
- **M6 — Interceptor, shadow mode.** `check()` returns and logs decisions while actions proceed. *Accept:* replay a mixed trace and log every decision with reason and matched laws.
- **M7 — Delegation graph.** Grant, depth limits, expiry, and revocation. *Accept:* revoking a grant invalidates derived authority within one check cycle.
- **M8 — Enforce mode.** Decisions become binding and escalation routes to a human-approval stub. *Accept:* violating actions are blocked; approval-required actions pause and resume correctly.
- **M9 — GovernanceBench dataset.** Build labeled scenarios. *Accept:* every scenario loads and carries the expected decision and tested rule.
- **M10 — Evaluation run.** Score the implementation and a static baseline. *Accept:* produce a report showing separation on delegation, revocation, and runtime-context cases.
- **M11 — Failure taxonomy harness.** Inject authority leakage, delegation loops, escalation deadlock, and capability-taxonomy gaps. *Accept:* every failure has a reproducible test and logged containment outcome.
- **M12 — GovernanceBench v0.2 corpus.** Expand the labeled, runtime-agnostic dataset to at least three scenarios per category, with adversarial pairs and state-transition cases. *Accept:* at least 30 scenarios validate, the reference adapter is exact, and the report records per-category coverage.
- **M13 — Delegation and authority hardening.** Enforce capability attenuation, record grant provenance, reject widening scopes, and expose deterministic authority proofs. *Accept:* adversarial and generated invariant tests pass and every delegated decision can report its authority path.
- **M14 — Auditability and replay.** Emit versioned, redacted decision events with policy/state/action/context fingerprints and replay drift detection. *Accept:* shadow and enforce checks serialize consistently and changed policy or state is detected.
- **M15 — Bounded human approval.** Add request identity, exact-state binding, pending/approved/denied/expired states, timeout, and single-use resume on top of enforce mode. *Accept:* pending, denied, expired, stale, and replayed approvals never execute; a valid approval resumes exactly one action.
- **M16 — Runtime adapter and release hardening.** Add a typed tool-call boundary, enforce-mode fail-closed errors, idempotency, performance checks, security guidance, and v0.2 package metadata. *Accept:* a clean install runs the quickstart and CI covers tests, benchmark, failure, performance, and package checks.
- **M17 — Versioned conformance protocol.** Define implementation-independent JSON envelopes and a black-box adapter runner. *Accept:* protocol fixtures round-trip, the independent transcript adapter passes exactly, and the conformance package imports no reference implementation.

## 9. Definition of done

- All M1–M17 acceptance checks pass
- Shadow and enforce modes run on the same trace
- Benchmark results show measurable separation from a static baseline
- Failure taxonomy includes a reproducible test for each class
- README states the wedge in its opening section

## 10. Loop instructions

1. Find the lowest-numbered incomplete milestone.
2. Implement only that milestone.
3. Run its acceptance check.
4. Record completion in Section 11 only after the check passes.
5. Repeat until the definition of done is satisfied.
6. Record and justify any scope expansion before implementing it.

Prefer deterministic logic in the enforcement path. Enforcement must not depend on another model's unverified output.

## 11. Progress log

- [2026-08-05] M1 — repository and pytest harness created; tests run cleanly.
- [2026-08-05] M2 — line-based policy DSL parser implemented; example laws parse and malformed input raises line-numbered `ParseError`.
- [2026-08-05] M3 — single-rule semantics implemented for capability applicability, authority, forbidden actor class, and numeric predicates; 13 tests pass including determinism.
- [2026-08-05] Scope note — initial runtime-agnostic GovernanceBench schema created in parallel in `governancebench/schema.py`.
- [2026-08-06] M4 — deterministic composition, conflict resolution, and parent-to-child inheritance implemented; child policies cannot loosen validated parent conditions.
- [2026-08-06] M5 — compiler emits an immutable policy artifact and rejects contradictory rules, dangling roles, missing parents, and inheritance cycles.
- [2026-08-06] M6 — interceptor supports shadow mode with structured in-memory events and optional logging.
- [2026-08-06] M7 — delegation graph supports bounded grants, capability scopes, expiry, and transitive revocation.
- [2026-08-06] M8 — enforce mode blocks violating actions and routes escalation decisions through a synchronous approval stub.
- [2026-08-06] M4–M8 acceptance suite — 29 tests pass.
- [2026-08-06] M9 — 10 canonical runtime-agnostic scenarios across all benchmark categories; schema validation and round-trip checks added.
- [2026-08-06] M10 — reference adapter and static baseline added; reference exact accuracy 1.0 across 13 steps, baseline exact accuracy 0.5385 (7/13) with separation on delegation, context, revocation, and multi-agent categories.
- [2026-08-06] M11 — four injected failure classes produce reproducible logged containment outcomes; default-deny capability handling and delegation-cycle rejection close the observed bypasses.
- [2026-08-08] M12 — GovernanceBench v0.2 expanded to 30 scenarios and 39 trace steps, with at least three scenarios per category, a labeling protocol, and per-category report coverage.
- [2026-08-08] M13 — delegation grants now enforce explicit scope attenuation and expose deterministic intrinsic/delegated authority proofs, including grant paths and optional granting-rule provenance.
- [2026-08-08] M14 — versioned decision events, append-only JSONL audit export, policy/state/action/context fingerprints, and deterministic replay drift detection added; the legacy in-memory event API remains compatible.
- [2026-08-08] M15 — bounded approval manager added with pending/approved/denied/expired states, exact action/context/policy/state binding, expiry, and single-use enforce-mode resume; synchronous ApprovalStub remains compatible.
- [2026-08-08] M16 — typed RuntimeAdapter and ToolCall added with enforce fail-closed governance errors, request idempotency, local performance runner, security policy, changelog, and package version 0.2.0.
- [2026-08-09] M17 — implementation-independent conformance package added with versioned ToolCall, Decision, and audit-event envelopes, canonical JSON, schemas, fixtures, and a black-box transcript runner.

## 12. Open implementation questions

- Concrete syntax: resolved at M2 as a small line-based DSL
- Capability taxonomy: hierarchical namespace such as `payment.send`; authority proofs now retain the selected intrinsic/delegated path.
- Context integration: `Context` fields are implemented; external runtimes provide the adapter that supplies current state.
- Escalation behavior: synchronous human stub in the reference implementation; asynchronous continuation and multi-reviewer quorum remain integration paths.
- Benchmark breadth: resolved for v0.2 at three hand-authored scenarios per category; future releases may add domain-specific packs without changing the core schema.
- Delegation identity: provenance is explicit within the reference graph; cryptographic credentials and external identity-provider integration remain out of scope.
- Audit retention: the reference implementation exports append-only JSONL; centralized storage and distributed tracing remain integration responsibilities.
- Approval integration: the reference manager is in-memory and role-based; external identity, email/chat delivery, durable storage, and quorum remain integration paths.
- Conformance: v1.0 JSON envelopes and additive compatibility rules are defined; network transport and authentication remain integration paths.
