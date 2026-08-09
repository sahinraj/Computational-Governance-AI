"""M6/M8: shadow/enforce interception with a synchronous approval stub."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from .approval import ApprovalError, ApprovalManager
from .audit import AuditLog, DecisionEvent
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
    approval_request_id: Optional[str] = None


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
        approval_manager: Optional[ApprovalManager] = None,
        logger: Optional[logging.Logger] = None,
        audit_log: Optional[AuditLog] = None,
        trace_id: str = "default",
    ):
        self.policy = policy
        self.mode = InterceptorMode(mode)
        self.delegation = delegation
        self.approval_handler = approval_handler
        self.approval_manager = approval_manager
        self.logger = logger
        self.audit_log = audit_log or AuditLog()
        self.trace_id = trace_id
        self._next_event_id = self.audit_log.next_sequence(trace_id)
        self.events: list[dict] = []

    def _record(
        self,
        action: Action,
        context: Context,
        decision: Decision,
        *,
        executed: Optional[bool] = None,
        outcome: Optional[str] = None,
    ) -> None:
        event_id = f"{self.trace_id}-{self._next_event_id:04d}"
        self._next_event_id += 1
        audit_event = DecisionEvent.from_decision(
            event_id=event_id,
            trace_id=self.trace_id,
            policy=self.policy,
            action=action,
            context=context,
            decision=decision,
            mode=self.mode.value,
            delegation=self.delegation,
            executed=executed,
            outcome=outcome,
        )
        self.audit_log.append(audit_event)
        event = {
            "actor": action.actor.id,
            "capability": action.capability.name,
            "decision": decision.kind.value,
            "role": decision.role,
            "reason": decision.reason,
            "matched_rules": decision.matched_rules,
            "authority_source": decision.authority_source,
            "authority_path": decision.authority_path,
            "mode": self.mode.value,
            "event_id": audit_event.event_id,
            "trace_id": audit_event.trace_id,
            "executed": executed,
            "outcome": outcome or decision.kind.value,
        }
        self.events.append(event)
        if self.logger is not None:
            self.logger.info("governance decision", extra={"governance": event})

    def _evaluate(self, action: Action, context: Context) -> Decision:
        return self.policy.evaluate(action, context, delegation=self.delegation)

    def check(self, action: Action, context: Context) -> Decision:
        decision = self._evaluate(action, context)
        self._record(action, context, decision)
        return decision

    def record_governance_error(
        self,
        action: Action,
        context: Context,
        reason: str,
        *,
        executed: bool = False,
    ) -> Decision:
        """Record a fail-closed governance error as a blocking decision."""
        decision = Decision(DecisionKind.BLOCK, reason=reason)
        self._record(action, context, decision, executed=executed, outcome=decision.kind.value)
        return decision

    def execute(
        self,
        action: Action,
        context: Context,
        operation: Callable[[], object],
    ) -> InterceptionResult:
        initial = self._evaluate(action, context)
        decision = initial

        if self.mode is InterceptorMode.SHADOW:
            self._record(action, context, initial, executed=True, outcome=decision.kind.value)
            return InterceptionResult(
                decision=decision,
                initial_decision=initial,
                executed=True,
                value=operation(),
            )

        if decision.kind is DecisionKind.ESCALATE and self.approval_manager is not None:
            request = self.approval_manager.request(
                decision,
                self.policy,
                action,
                context,
                delegation=self.delegation,
                now=context.now,
            )
            self._record(action, context, initial, executed=False, outcome=decision.kind.value)
            return InterceptionResult(
                decision=decision,
                initial_decision=initial,
                executed=False,
                approval_request_id=request.id,
            )

        if decision.kind is DecisionKind.ESCALATE and self.approval_handler is not None:
            approved = self.approval_handler(decision.role, action, decision)
            if approved:
                decision = Decision(
                    DecisionKind.ALLOW,
                    reason=f"approved by {decision.role}",
                    matched_rules=decision.matched_rules,
                    authority_source=decision.authority_source,
                    authority_path=decision.authority_path,
                )
            else:
                decision = Decision(
                    DecisionKind.BLOCK,
                    reason=f"approval denied by {initial.role}",
                    matched_rules=initial.matched_rules,
                    authority_source=initial.authority_source,
                    authority_path=initial.authority_path,
                )

        if decision.kind is not DecisionKind.ALLOW:
            self._record(action, context, initial, executed=False, outcome=decision.kind.value)
            return InterceptionResult(
                decision=decision,
                initial_decision=initial,
                executed=False,
            )
        self._record(action, context, initial, executed=True, outcome=decision.kind.value)
        return InterceptionResult(
            decision=decision,
            initial_decision=initial,
            executed=True,
            value=operation(),
        )

    def resume_approved(
        self,
        request_id: str,
        action: Action,
        context: Context,
        operation: Callable[[], object],
    ) -> InterceptionResult:
        """Resume one approved request after rechecking its exact state."""
        if self.mode is InterceptorMode.SHADOW:
            return self.execute(action, context, operation)
        if self.approval_manager is None:
            raise ApprovalError("no approval manager is configured")

        current = self._evaluate(action, context)
        request = self.approval_manager.get(request_id, now=context.now)
        if current.kind is not DecisionKind.ESCALATE or current.role != request.role:
            decision = Decision(
                DecisionKind.BLOCK,
                reason="approval no longer matches the current escalation",
                matched_rules=current.matched_rules,
                authority_source=current.authority_source,
                authority_path=current.authority_path,
            )
            self._record(action, context, current, executed=False, outcome=decision.kind.value)
            return InterceptionResult(
                decision=decision,
                initial_decision=current,
                executed=False,
                approval_request_id=request_id,
            )
        try:
            self.approval_manager.prepare_resume(
                request_id,
                self.policy,
                action,
                context,
                delegation=self.delegation,
                now=context.now,
            )
        except ApprovalError as exc:
            decision = Decision(
                DecisionKind.BLOCK,
                reason=str(exc),
                matched_rules=current.matched_rules,
                authority_source=current.authority_source,
                authority_path=current.authority_path,
            )
            self._record(action, context, current, executed=False, outcome=decision.kind.value)
            return InterceptionResult(
                decision=decision,
                initial_decision=current,
                executed=False,
                approval_request_id=request_id,
            )

        decision = Decision(
            DecisionKind.ALLOW,
            reason=f"approved by {request.role}",
            matched_rules=current.matched_rules,
            authority_source=current.authority_source,
            authority_path=current.authority_path,
        )
        self._record(action, context, current, executed=True, outcome=decision.kind.value)
        return InterceptionResult(
            decision=decision,
            initial_decision=current,
            executed=True,
            value=operation(),
            approval_request_id=request_id,
        )

    intercept = execute
