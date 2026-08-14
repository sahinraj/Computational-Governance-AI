"""Bounded, exact-state human approval requests for enforce mode."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from .audit import action_fingerprint, context_fingerprint, policy_fingerprint, state_fingerprint
from .identity import VerifiedIdentity
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
    required_roles: tuple[str, ...] = ()
    threshold: int = 1
    votes: tuple[str, ...] = ()
    state: ApprovalState = ApprovalState.PENDING
    consumed: bool = False
    identity_reference: Optional[str] = None
    vote_identity_references: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict:
        value = {
            "id": self.id,
            "role": self.role,
            "action_fingerprint": self.action_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "matched_rules": list(self.matched_rules),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "required_roles": list(self.required_roles),
            "threshold": self.threshold,
            "votes": list(self.votes),
            "state": self.state.value,
            "consumed": self.consumed,
        }
        if self.identity_reference is not None:
            value["identity_reference"] = self.identity_reference
        if self.vote_identity_references:
            value["vote_identity_references"] = {
                role: reference for role, reference in self.vote_identity_references
            }
        return value


class ApprovalManager:
    """In-memory approval lifecycle with fail-closed, single-use semantics."""

    def __init__(
        self,
        *,
        ttl: float = 300.0,
        request_prefix: str = "approval",
        require_identity: bool = False,
    ):
        if ttl <= 0:
            raise ValueError("approval ttl must be positive")
        if not request_prefix:
            raise ValueError("approval request prefix cannot be empty")
        self.ttl = float(ttl)
        self.request_prefix = request_prefix
        self.require_identity = bool(require_identity)
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
        if self.require_identity and action.identity_reference is None:
            raise ApprovalError("authenticated requester identity is required")
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
            required_roles=decision.approval_roles or (decision.role,),
            threshold=decision.approval_threshold or 1,
            identity_reference=action.identity_reference,
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

    @staticmethod
    def _role_error(request: ApprovalRequest) -> str:
        if len(request.required_roles) == 1:
            return f"approval request {request.id} requires role {request.required_roles[0]}"
        return f"approval request {request.id} requires one of {request.required_roles}"

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
        identity: Any = None,
    ) -> ApprovalRequest:
        request = self._get(request_id, now)
        if request.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval request {request.id} is {request.state.value}")
        if role not in request.required_roles:
            raise ApprovalError(self._role_error(request))
        if role in request.votes:
            raise ApprovalError(f"role {role} has already voted on {request.id}")
        if self.require_identity and identity is None:
            raise ApprovalError("authenticated approver identity is required")
        identity_reference = None
        if identity is not None:
            if not isinstance(identity, VerifiedIdentity):
                raise ApprovalError("approver identity must be provider-verified")
            current = request.created_at if now is None else float(now)
            if not identity.is_valid_at(current):
                raise ApprovalError("authenticated approver identity is expired")
            roles = tuple(getattr(identity, "roles", ()))
            identity_reference = getattr(identity, "identity_reference", None)
            if role not in roles or not identity_reference:
                raise ApprovalError(
                    f"authenticated identity is not authorized for role {role}"
                )
        self._check_binding(request, policy, action, context, delegation)
        request.votes = request.votes + (role,)
        if identity_reference is not None:
            request.vote_identity_references = request.vote_identity_references + (
                (role, identity_reference),
            )
        if len(request.votes) >= request.threshold:
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
        if role not in request.required_roles:
            raise ApprovalError(self._role_error(request))
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

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe snapshot, including terminal and consumed states."""
        return {
            "schema_version": "1.0",
            "ttl": self.ttl,
            "request_prefix": self.request_prefix,
            "require_identity": self.require_identity,
            "next_id": self._next_id,
            "requests": [
                request.to_dict()
                for request in sorted(self._requests.values(), key=lambda item: item.id)
            ],
        }

    to_snapshot = snapshot

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> "ApprovalManager":
        """Restore approval state without silently accepting unknown lifecycle data."""
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != "1.0":
            raise ApprovalError("unsupported or missing approval snapshot version")
        try:
            manager = cls(
                ttl=float(snapshot["ttl"]),
                request_prefix=str(snapshot["request_prefix"]),
                require_identity=bool(snapshot.get("require_identity", False)),
            )
            next_id = snapshot["next_id"]
            requests = snapshot["requests"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ApprovalError("invalid approval snapshot metadata") from exc
        if not isinstance(next_id, int) or isinstance(next_id, bool) or next_id <= 0:
            raise ApprovalError("invalid approval snapshot next id")
        if not isinstance(requests, list):
            raise ApprovalError("invalid approval snapshot requests")
        for item in requests:
            if not isinstance(item, dict):
                raise ApprovalError("invalid approval request snapshot")
            try:
                request = ApprovalRequest(
                    id=str(item["id"]),
                    role=str(item["role"]),
                    action_fingerprint=str(item["action_fingerprint"]),
                    context_fingerprint=str(item["context_fingerprint"]),
                    policy_fingerprint=str(item["policy_fingerprint"]),
                    state_fingerprint=str(item["state_fingerprint"]),
                    matched_rules=tuple(str(rule) for rule in item["matched_rules"]),
                    created_at=float(item["created_at"]),
                    expires_at=float(item["expires_at"]),
                    required_roles=tuple(str(role) for role in item.get("required_roles", ())),
                    threshold=int(item.get("threshold", 1)),
                    votes=tuple(str(role) for role in item.get("votes", ())),
                    state=ApprovalState(str(item["state"])),
                    consumed=bool(item["consumed"]),
                    identity_reference=item.get("identity_reference"),
                    vote_identity_references=tuple(
                        (str(role), str(reference))
                        for role, reference in item.get("vote_identity_references", {}).items()
                    ),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ApprovalError("invalid approval request snapshot fields") from exc
            if request.id in manager._requests:
                raise ApprovalError("approval request ids must be unique")
            if not request.required_roles:
                request.required_roles = (request.role,)
            if not request.id or not request.role or request.expires_at < request.created_at:
                raise ApprovalError("invalid approval request snapshot values")
            if (
                request.threshold < 1
                or request.threshold > len(request.required_roles)
                or len(set(request.votes)) != len(request.votes)
                or not set(request.votes).issubset(request.required_roles)
            ):
                raise ApprovalError("invalid approval quorum snapshot values")
            if request.consumed and request.state is not ApprovalState.APPROVED:
                raise ApprovalError("only approved requests can be consumed")
            if len({role for role, _ in request.vote_identity_references}) != len(
                request.vote_identity_references
            ) or any(role not in request.votes for role, _ in request.vote_identity_references):
                raise ApprovalError("invalid approval identity vote references")
            manager._requests[request.id] = request
        manager._next_id = next_id
        return manager
