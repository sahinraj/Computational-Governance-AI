"""Bounded, exact-state human approval requests for enforce mode."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .audit import action_fingerprint, context_fingerprint, policy_fingerprint, state_fingerprint
from .model import Action, Context, Decision, DecisionKind


class ApprovalError(ValueError):
    """Raised when an approval request is invalid, stale, or replayed."""


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """A single-use approval bound to one exact governance state."""

    id: str
    role: str
    action_fingerprint: str
    context_fingerprint: str
    policy_fingerprint: str
    state_fingerprint: str
    matched_rules: tuple[str, ...]
    created_at: float
    expires_at: float
    state: ApprovalState = ApprovalState.PENDING
    consumed: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "role": self.role,
            "action_fingerprint": self.action_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "matched_rules": list(self.matched_rules),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "state": self.state.value,
            "consumed": self.consumed,
        }


class ApprovalManager:
    """In-memory approval lifecycle with fail-closed, single-use semantics."""

    def __init__(self, *, ttl: float = 300.0, request_prefix: str = "approval"):
        if ttl <= 0:
            raise ValueError("approval ttl must be positive")
        if not request_prefix:
            raise ValueError("approval request prefix cannot be empty")
        self.ttl = float(ttl)
        self.request_prefix = request_prefix
        self._next_id = 1
        self._requests: dict[str, ApprovalRequest] = {}

    def request(
        self,
        decision: Decision,
        policy,
        action: Action,
        context: Context,
        *,
        delegation=None,
        now: Optional[float] = None,
        ttl: Optional[float] = None,
    ) -> ApprovalRequest:
        if decision.kind is not DecisionKind.ESCALATE or not decision.role:
            raise ApprovalError("only Escalate decisions can create approval requests")
        effective_ttl = self.ttl if ttl is None else float(ttl)
        if effective_ttl <= 0:
            raise ApprovalError("approval ttl must be positive")
        created_at = context.now if now is None else float(now)
        request_id = f"{self.request_prefix}-{self._next_id:04d}"
        self._next_id += 1
        request = ApprovalRequest(
            id=request_id,
            role=decision.role,
            action_fingerprint=action_fingerprint(action),
            context_fingerprint=context_fingerprint(context),
            policy_fingerprint=policy_fingerprint(policy),
            state_fingerprint=state_fingerprint(policy, delegation),
            matched_rules=decision.matched_rules,
            created_at=created_at,
            expires_at=created_at + effective_ttl,
        )
        self._requests[request_id] = request
        return request

    def _get(self, request_id: str, now: Optional[float] = None) -> ApprovalRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise ApprovalError(f"unknown approval request {request_id}")
        current = request.created_at if now is None else float(now)
        if request.state is ApprovalState.PENDING and current >= request.expires_at:
            request.state = ApprovalState.EXPIRED
        return request

    def get(self, request_id: str, *, now: Optional[float] = None) -> ApprovalRequest:
        return self._get(request_id, now)

    def _check_binding(
        self,
        request: ApprovalRequest,
        policy,
        action: Action,
        context: Context,
        delegation,
    ) -> None:
        mismatches = []
        if request.action_fingerprint != action_fingerprint(action):
            mismatches.append("action")
        if request.context_fingerprint != context_fingerprint(context):
            mismatches.append("context")
        if request.policy_fingerprint != policy_fingerprint(policy):
            mismatches.append("policy")
        if request.state_fingerprint != state_fingerprint(policy, delegation):
            mismatches.append("state")
        if mismatches:
            raise ApprovalError(
                f"approval request {request.id} is bound to changed {', '.join(mismatches)}"
            )

    def approve(
        self,
        request_id: str,
        role: str,
        policy,
        action: Action,
        context: Context,
        *,
        delegation=None,
        now: Optional[float] = None,
    ) -> ApprovalRequest:
        request = self._get(request_id, now)
        if request.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval request {request.id} is {request.state.value}")
        if role != request.role:
            raise ApprovalError(f"approval request {request.id} requires role {request.role}")
        self._check_binding(request, policy, action, context, delegation)
        request.state = ApprovalState.APPROVED
        return request

    def deny(
        self,
        request_id: str,
        role: str,
        *,
        now: Optional[float] = None,
    ) -> ApprovalRequest:
        request = self._get(request_id, now)
        if request.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval request {request.id} is {request.state.value}")
        if role != request.role:
            raise ApprovalError(f"approval request {request.id} requires role {request.role}")
        request.state = ApprovalState.DENIED
        return request

    def prepare_resume(
        self,
        request_id: str,
        policy,
        action: Action,
        context: Context,
        *,
        delegation=None,
        now: Optional[float] = None,
    ) -> ApprovalRequest:
        request = self._get(request_id, now)
        if request.state is not ApprovalState.APPROVED:
            raise ApprovalError(f"approval request {request.id} is {request.state.value}")
        if request.consumed:
            raise ApprovalError(f"approval request {request.id} has already been consumed")
        self._check_binding(request, policy, action, context, delegation)
        request.consumed = True
        return request
