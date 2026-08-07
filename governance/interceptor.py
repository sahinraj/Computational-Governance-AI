"""M6/M8: shadow/enforce interception with a synchronous approval stub."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .compiler import CompiledPolicy
from .model import Action, Context, Decision, DecisionKind


class InterceptorMode(str, Enum):
    SHADOW = "shadow"
    ENFORCE = "enforce"


@dataclass(frozen=True)
class InterceptionResult:
    decision: Decision
    executed: bool
    value: object = None
    initial_decision: Optional[Decision] = None


class ApprovalStub:
    """Deterministic human-approval adapter for tests and integrations."""

    def __init__(self, decisions: Optional[dict[str, bool]] = None, default: bool = False):
        self.decisions = dict(decisions or {})
        self.default = default
        self.requests: list[tuple[str, str, str]] = []

    def request(self, role: str, action: Action, decision: Decision) -> bool:
        self.requests.append((role, action.actor.id, action.capability.name))
        return self.decisions.get(role, self.default)


class Interceptor:
    """Check every intended action and optionally make the result binding."""

    def __init__(
        self,
        policy: CompiledPolicy,
        *,
        mode: InterceptorMode | str = InterceptorMode.SHADOW,
        delegation=None,
        approval_handler: Optional[Callable[[str, Action, Decision], bool]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.policy = policy
        self.mode = InterceptorMode(mode)
        self.delegation = delegation
        self.approval_handler = approval_handler
        self.logger = logger
        self.events: list[dict] = []

    def check(self, action: Action, context: Context) -> Decision:
        decision = self.policy.evaluate(action, context, delegation=self.delegation)
        event = {
            "actor": action.actor.id,
            "capability": action.capability.name,
            "decision": decision.kind.value,
            "role": decision.role,
            "reason": decision.reason,
            "matched_rules": decision.matched_rules,
            "mode": self.mode.value,
        }
        self.events.append(event)
        if self.logger is not None:
            self.logger.info("governance decision", extra={"governance": event})
        return decision

    def execute(
        self,
        action: Action,
        context: Context,
        operation: Callable[[], object],
    ) -> InterceptionResult:
        initial = self.check(action, context)
        decision = initial

        if self.mode is InterceptorMode.SHADOW:
            return InterceptionResult(
                decision=decision,
                initial_decision=initial,
                executed=True,
                value=operation(),
            )

        if decision.kind is DecisionKind.ESCALATE and self.approval_handler is not None:
            approved = self.approval_handler(decision.role, action, decision)
            if approved:
                decision = Decision(
                    DecisionKind.ALLOW,
                    reason=f"approved by {decision.role}",
                    matched_rules=decision.matched_rules,
                )
            else:
                decision = Decision(
                    DecisionKind.BLOCK,
                    reason=f"approval denied by {initial.role}",
                    matched_rules=initial.matched_rules,
                )

        if decision.kind is not DecisionKind.ALLOW:
            return InterceptionResult(
                decision=decision,
                initial_decision=initial,
                executed=False,
            )
        return InterceptionResult(
            decision=decision,
            initial_decision=initial,
            executed=True,
            value=operation(),
        )

    intercept = execute
