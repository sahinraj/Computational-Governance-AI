"""Adapters that connect GovernanceBench to the reference implementation.

Keeping this bridge outside ``governancebench/`` preserves benchmark
independence: alternative systems can implement the same adapter protocol
without importing or depending on these classes.
"""

from __future__ import annotations

from governance import (
    Action,
    Actor,
    Capability,
    Context,
    Decision,
    DecisionKind,
    DelegationGraph,
    compile_policy,
)
from governancebench import BenchmarkDecision, Scenario, Step


def _policy_source(scenario: Scenario) -> str:
    blocks: list[str] = []
    for rule in scenario.rules:
        lines = [str(rule["id"]), f"  capability: {rule['capability']}"]
        if rule.get("authority_level") is not None:
            lines.append(f"  authority_level: {rule['authority_level']}")
        if rule.get("constraint") is not None:
            lines.append(f"  constraint: {rule['constraint']}")
        if rule.get("forbidden_classes"):
            lines.append(
                "  forbidden_classes: " + ", ".join(rule["forbidden_classes"])
            )
        if rule.get("requires_approval"):
            lines.append(f"  requires_approval: {rule['requires_approval']}")
        if rule.get("parent"):
            lines.append(f"  parent: {rule['parent']}")
        lines.append(f"  on_violation: {rule.get('on_violation', 'block')}")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def _roles(scenario: Scenario) -> set[str]:
    return {
        str(rule["requires_approval"])
        for rule in scenario.rules
        if rule.get("requires_approval")
    }


def _actors(scenario: Scenario) -> dict[str, Actor]:
    return {
        str(item["id"]): Actor(
            id=str(item["id"]),
            authority_level=int(item.get("authority_level", 0)),
            cls=str(item.get("class", item.get("cls", "agent"))),
            capabilities=frozenset(str(value) for value in item.get("capabilities", ())),
        )
        for item in scenario.actors
    }


def _context(step: Step) -> Context:
    return Context(
        budget_used=float(step.context.get("budget_used", 0)),
        prior_approvals=tuple(str(value) for value in step.context.get("prior_approvals", ())),
        now=float(step.context.get("now", 0)),
    )


def _benchmark_decision(decision: Decision) -> BenchmarkDecision:
    return BenchmarkDecision(decision.kind.value, decision.role)


class ReferenceAdapter:
    """Stateful adapter for the compiled reference implementation."""

    name = "reference"

    def __init__(self):
        self.policy = None
        self.actors: dict[str, Actor] = {}
        self.graph: DelegationGraph | None = None
        self.grant_ids: dict[str, str] = {}

    def reset(self, scenario: Scenario) -> None:
        self.policy = compile_policy(
            _policy_source(scenario),
            roles=_roles(scenario),
            default_decision="Block",
        )
        self.actors = _actors(scenario)
        self.graph = DelegationGraph()
        self.grant_ids = {}
        for setup in scenario.setup:
            delegate = setup.get("delegate")
            if not delegate:
                continue
            grant = self.graph.grant(
                self.actors[str(delegate["from"])],
                self.actors[str(delegate["to"])],
                str(delegate["capability"]),
                depth=int(delegate.get("depth", 0)),
                expires_at=delegate.get("expires_at"),
                now=0,
            )
            self.grant_ids[str(delegate.get("id", grant.id))] = grant.id

    def _apply_before(self, step: Step) -> None:
        assert self.graph is not None
        for event in step.before:
            if "revoke" in event:
                grant_id = self.grant_ids.get(str(event["revoke"]), str(event["revoke"]))
                self.graph.revoke(grant_id)

    def decide(self, scenario: Scenario, step: Step) -> BenchmarkDecision:
        assert self.policy is not None and self.graph is not None
        self._apply_before(step)
        action = Action(
            self.actors[step.actor],
            Capability(step.capability),
            dict(step.params),
        )
        decision = self.policy.evaluate(action, _context(step), delegation=self.graph)
        if step.human_decision and decision.kind is DecisionKind.ESCALATE:
            decision = Decision(
                DecisionKind.ALLOW if step.human_decision == "Allow" else DecisionKind.BLOCK,
                reason=f"human override: {step.human_decision}",
                matched_rules=decision.matched_rules,
            )
        return _benchmark_decision(decision)


class StaticBaselineAdapter(ReferenceAdapter):
    """A deliberately static baseline.

    It evaluates the same declarative rules but has no delegation graph,
    ignores revocation events, and freezes context at the first trace step.
    This models a caller check that sees a static actor/request rather than an
    evolving governed process.
    """

    name = "static-baseline"

    def reset(self, scenario: Scenario) -> None:
        super().reset(scenario)
        # The baseline is intentionally permissive for unmatched capability
        # names, matching a static request checker rather than the runtime
        # enforcement artifact.
        self.policy = compile_policy(_policy_source(scenario), roles=_roles(scenario))
        self._initial_context = _context(scenario.trace[0])

    def decide(self, scenario: Scenario, step: Step) -> BenchmarkDecision:
        assert self.policy is not None
        action = Action(
            self.actors[step.actor],
            Capability(step.capability),
            dict(step.params),
        )
        decision = self.policy.evaluate(action, self._initial_context, delegation=None)
        # The baseline does not model a human override as a runtime transition.
        return _benchmark_decision(decision)
