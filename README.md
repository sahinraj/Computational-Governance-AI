# Computational Governance for Autonomous Systems

> Existing governance systems evaluate **requests**. Computational Governance evaluates **evolving decision processes**.

A formal model, a reference implementation, and a runtime-agnostic benchmark for deciding whether an autonomous agent's intended action is permitted **before it executes** — accounting for delegated authority, human escalation, revocation, and runtime context change.

This is early-stage research. The theory is frozen at **Foundations v1**; the implementation is building milestone by milestone against it.

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
governance/        reference implementation of 𝒢
governancebench/   runtime-agnostic benchmark schema (imports nothing from governance/)
tests/             acceptance checks, one set per milestone
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
| M4 | Composition and inheritance | ▫️ |
| M5 | Compiler + validation | ▫️ |
| M6 | Interceptor, shadow mode | ▫️ |
| M7 | Delegation graph | ▫️ |
| M8 | Enforce mode + escalation | ▫️ |
| M9 | GovernanceBench dataset | ▫️ |
| M10 | Evaluation vs static baseline | ▫️ |
| M11 | Failure taxonomy harness | ▫️ |

## Quickstart

```bash
git clone https://github.com/sahinraj/Computational-Governance-AI.git
cd Computational-Governance-AI
python -m pip install -r requirements-dev.txt
python -m pytest -q
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

## Design commitments

- **Deterministic enforcement.** A decision depends only on state and action, never on execution outcome. Governance decides *before*, and independently of, execution.
- **Benchmark independence.** GovernanceBench references capabilities, actors, and rules abstractly and scores any system through an adapter. It imports nothing from this implementation, so it can outlive it.
- **Frozen theory, evidence-gated changes.** Foundations v1 changes only on a failed test, an ambiguous semantics found in implementation, or concrete reviewer evidence.

## Roadmap

The reference implementation ships first as the load-bearing systems result. GovernanceBench is built in parallel. Later theory papers (delegation algebra, identity, governance complexity, temporal and cross-system governance) extend the frozen foundations rather than replacing them. See [`spec/field-and-benchmark.md`](spec/field-and-benchmark.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Citing

See [CITATION.cff](CITATION.cff).
