# Foundations of Computational Governance

**A formal model for runtime governance of autonomous systems.**

Owner: Sahin Raj
Status: Frozen v1 — theory foundations
Last updated: 2026-08-06
Companion to: `field-and-benchmark.md` and `implementation-spec.md`.

This document contains no code, no compiler, and no benchmark. Its purpose is to define the theoretical foundations that every implementation and evaluation paper references. It is the specification a governance system is proven correct against.

---

## 0. The wedge sentence

> Existing governance systems evaluate **requests**. Computational Governance evaluates **evolving decision processes**.

A request is a single, static, pre-declared input. A decision process is a sequence of runtime-chosen actions by actors whose authority is delegated along a chain and whose context changes as the process runs. The second is strictly harder, and it is what makes this a computational model rather than a policy filter.

## 1. Core entities

The model is built from six entities.

- **Actor** `a ∈ A` — an autonomous agent that selects actions. Each actor has an authority level and a class. Actors may hold delegated authority.
- **Capability** `c ∈ C` — a namespaced, hierarchical action class such as `payment.send` or `deploy.production`.
- **Authority** `auth` — the right of an actor to exercise a capability. Authority is intrinsic or delegated.
- **Context** `κ ∈ K` — mutable state against which a decision is made: budget consumed, approvals obtained, time elapsed, and prior actions.
- **Rule** `γ ∈ Γ` — a condition that must hold for an action to be permitted. A rule binds a capability to a predicate over actor, action parameters, and context, plus a violation disposition (`block` or `escalate`). The concrete policy keyword `Law` denotes a Rule in this model.
- **Decision** `d ∈ D = {Allow, Block, Escalate(role)}` — the output of governance for a single intended action.

## 2. The governance state

A **governance state** captures everything the model needs to decide the next action.

```
S = (A, C, Γ, Δ, κ)
```

`A` is the actor set, `C` the capability namespace, `Γ` the active rule set, `Δ` the delegation state, and `κ` the current context. The state is not static: `κ` and `Δ` evolve as actions are decided and executed. A governance state plus a stream of intended actions defines a decision process.

## 3. The Runtime Governance Problem

Let an intended action be `α = (a, c, p)`: actor `a` attempts capability `c` with parameters `p`.

> **Runtime Governance Problem.** Given governance state `S = (A, C, Γ, Δ, κ)` and intended action `α`, compute
>
> `𝒢(S, α) → d ∈ {Allow, Block, Escalate(role)}`
>
> such that:
> 1. **Rule soundness:** `Allow` occurs only if every applicable rule is satisfied under `κ`.
> 2. **Delegation validity:** delegated authority is valid along the actor's delegation chain at decision time.
> 3. **Escalation totality:** a failed rule with escalation disposition yields `Escalate(role)`, not `Allow` or ordinary `Block`.
> 4. **Context currency:** the decision is computed against current `κ`, so the same action may receive a different decision later.

The decision function `𝒢` is the object of study. The compiler and interceptor are one realization. GovernanceBench measures how well a realization satisfies these four conditions.

The contribution is a well-defined decision function with provable properties, not a manufactured slogan equation. Fields are founded by a precise formal object, semantics, and theorems.

## 4. Action semantics

Governance decides an action before it executes; execution then updates state.

```
                 𝒢(S, α) = Allow
─────────────────────────────────────────────    (E-Allow)
        (S, α)  ⟶  S′ = execute(S, α)

              𝒢(S, α) = Block
─────────────────────────────────────────────    (E-Block)
        (S, α)  ⟶  S       (state unchanged)

           𝒢(S, α) = Escalate(r)
─────────────────────────────────────────────    (E-Escalate)
   (S, α)  ⟶  await(r); resume with human d′
```

`execute(S, α)` updates context and may update delegation state. `Block` leaves state unchanged. `Escalate` suspends the process pending a human decision `d′ ∈ {Allow, Block}`, which then feeds back through E-Allow or E-Block. Escalation is a first-class transition, not an error state.

## 5. Delegation

Delegation makes authority a chain rather than a lookup.

`Δ` is a directed graph whose nodes are actors and whose edges are grants. A grant edge

`g = (from, to, c, scope, depth, τ)`

records that `from` granted capability `c` to `to`, restricted to `scope`, permitted to be re-delegated at most `depth` hops, with optional expiry `τ`.

Operations required by the reference implementation:

- **grant** — add an edge, provided the grantor holds the capability intrinsically or through a valid grant with remaining depth.
- **restrict** — a grant's scope may only narrow the grantor's authority, never widen it.
- **revoke** — remove an edge; all authority derived through it becomes invalid.
- **expire** — a grant past its expiry is treated as absent.

An actor's effective authority for an action is intrinsic authority union authority reachable through valid, unexpired, in-scope grant edges within depth.

The full delegation algebra, including transfer, split, and merge, remains a later theoretical program.

## 6. Rule resolution

When multiple rules apply, the decision must be deterministic.

- **Applicability:** a rule applies when the action capability equals or descends from the rule capability.
- **Combination:** all applicable rules must be satisfied for `Allow`. Any failed block rule yields `Block`. If no block rule fails but an escalation rule fails, the decision is `Escalate`.
- **Conflict:** most-restrictive-wins, with `Block > Escalate > Allow`, and the resolving rule is recorded.

## 7. Axioms

- **GA1 — Conservation of authority.** Authority cannot be created, only held intrinsically or transferred. No operation produces authority that no intrinsic holder had.
- **GA2 — Decision totality and singularity.** Every intended action in every state has exactly one governing decision in `{Allow, Block, Escalate}`.
- **GA3 — Grounded delegation.** Every delegated authority traces through a finite grant chain to intrinsic authority. No grant is self-justifying.
- **GA4 — Revocation dominance.** Once a grant is revoked, no decision may rely on authority derived through it.
- **GA5 — Outcome independence.** A governing decision depends only on state and intended action, never on the result of execution.

## 8. Safety properties and theorems

- **T1 — Authority monotonicity.** No sequence of grant and restrict operations can give an actor effective authority exceeding what an intrinsic holder possessed. Follows from GA1 and GA3.
- **T2 — Safe revocation.** After `revoke(g)`, no subsequent decision grants authority derived through `g`; dependent authority disappears on the next check. Follows from GA4.
- **T3 — Composition preserves parent rules.** A child scope is at least as restrictive as its parent. A child may tighten but never loosen inherited governance.
- **T4 — Conflict determinism.** For every state and action, rule resolution yields exactly one decision independent of rule evaluation order. Follows from GA2.
- **T5 — Block soundness.** A blocked action leaves governance state unchanged, so a rejected action has no observable effect. Follows from GA5 and E-Block.
- **T6 — Decision determinism.** For identical state `S` and action `α`, `𝒢(S, α)` returns exactly one decision with no randomness or order dependence. Follows from GA2 and T4.

These claims refer only to the axioms and definitions, so they apply to any implementation realizing the model.

## 9. Open problems

- **Identity.** If an agent is cloned, what happens to authority, grants, and memory? Is authority attached to an identity or to a role?
- **Intent.** Two observably identical actions may have different intent. Intent is excluded from the core model because it is not directly observable and inferred intent risks violating determinism.
- **Delegation algebra.** A complete algebra for transfer, split, merge, composition, and revocation completeness.
- **Temporal governance.** Rules and authority change over time; the current model decides against one current context.
- **Cross-system governance.** Logical actions may span GitHub, Jira, Slack, AWS, robots, or other trust boundaries that do not share one delegation state.
- **Governance complexity.** Metrics such as approval depth, delegation-graph diameter, rule-resolution cost, and compliance overhead.

## 10. How this document is used

- The **reference implementation** realizes `𝒢`, `Δ`, and the action semantics; its acceptance checks instantiate the safety properties.
- **GovernanceBench** scores implementations against the four conditions of the Runtime Governance Problem.
- Later theory papers extend delegation, complexity, identity, temporal governance, and distributed governance without replacing these foundations.

The contribution of the field is this model. The compiler, policy language, runtime, and benchmark provide evidence that it is implementable and measurable.
