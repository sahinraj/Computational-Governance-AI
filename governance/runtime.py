"""Typed tool-boundary adapter for pre-execution governance."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from .identity import IdentityVerifier, VerifiedIdentity
from .interceptor import InterceptionResult, Interceptor, InterceptorMode
from .model import Action, Actor, Capability, Context, Decision, DecisionKind


class RuntimeAdapterError(ValueError):
    """Raised for invalid tool-boundary configuration."""


@dataclass(frozen=True)
class ToolCall:
    """A serializable action envelope presented at a tool boundary."""

    actor: Actor
    capability: Capability | str
    params: Mapping[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    credential: Optional[Mapping[str, Any]] = None

    def __post_init__(self):
        capability = (
            self.capability
            if isinstance(self.capability, Capability)
            else Capability(str(self.capability))
        )
        if not capability.name:
            raise RuntimeAdapterError("tool call capability cannot be empty")
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "params", dict(self.params))
        if self.request_id == "":
            raise RuntimeAdapterError("request_id cannot be empty")
        if self.credential is not None:
            if not isinstance(self.credential, Mapping):
                raise RuntimeAdapterError("identity credential must be an object")
            object.__setattr__(self, "credential", dict(self.credential))

    def to_action(self, identity: Optional[VerifiedIdentity] = None) -> Action:
        return Action(
            self.actor,
            self.capability,
            dict(self.params),
            identity_reference=None if identity is None else identity.identity_reference,
            identity_roles=() if identity is None else identity.roles,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor.id,
            "capability": self.capability.name,
            "params": dict(self.params),
            "request_id": self.request_id,
            "identity_credential_present": self.credential is not None,
        }


class RuntimeAdapter:
    """Single entry point that prevents tool execution before governance."""

    def __init__(
        self,
        interceptor: Interceptor,
        *,
        shadow_error_mode: str = "allow",
        identity_verifier: Optional[IdentityVerifier] = None,
    ):
        if shadow_error_mode not in {"allow", "raise"}:
            raise RuntimeAdapterError("shadow_error_mode must be allow or raise")
        self.interceptor = interceptor
        self.shadow_error_mode = shadow_error_mode
        self.identity_verifier = identity_verifier
        self._completed_request_ids: set[str] = set()

    def _error_result(
        self,
        action: Action,
        context: Context,
        error: Exception,
        *,
        shadow: bool,
        operation: Callable[[], object],
        request_id: Optional[str],
    ) -> InterceptionResult:
        reason = f"governance error: {type(error).__name__}: {error}"
        decision = self.interceptor.record_governance_error(
            action,
            context,
            reason,
            executed=shadow,
        )
        if not shadow:
            return InterceptionResult(decision=decision, initial_decision=decision, executed=False)
        return InterceptionResult(
            decision=decision,
            initial_decision=decision,
            executed=True,
            value=operation(),
            approval_request_id=request_id,
        )

    def invoke(
        self,
        call: ToolCall,
        context: Context,
        operation: Callable[[], object],
    ) -> InterceptionResult:
        """Govern and invoke one tool call; enforce mode is fail-closed."""
        if (
            self.interceptor.mode is InterceptorMode.ENFORCE
            and call.request_id is not None
            and call.request_id in self._completed_request_ids
        ):
            decision = Decision(
                DecisionKind.BLOCK,
                reason=f"duplicate completed request {call.request_id}",
            )
            return InterceptionResult(decision=decision, initial_decision=decision, executed=False)

        try:
            identity = (
                None
                if self.identity_verifier is None
                else self.identity_verifier.verify(
                    call.credential,
                    actor_id=call.actor.id,
                    now=context.now,
                )
            )
        except Exception as error:
            # Identity failures always fail closed, including when the
            # surrounding adapter is in shadow mode. No unverified actor may
            # cross the tool-execution boundary.
            action = call.to_action()
            decision = self.interceptor.record_governance_error(
                action,
                context,
                f"identity verification failed: {type(error).__name__}: {error}",
                executed=False,
            )
            return InterceptionResult(
                decision=decision,
                initial_decision=decision,
                executed=False,
            )

        action = call.to_action(identity)
        shadow = self.interceptor.mode is InterceptorMode.SHADOW
        operation_started = False

        def guarded_operation():
            nonlocal operation_started
            operation_started = True
            return operation()

        try:
            result = self.interceptor.execute(action, context, guarded_operation)
        except Exception as error:
            # Tool failures are not governance failures. The operation may
            # already have run, so preserve its exception and never relabel it
            # as a fail-closed governance block.
            if operation_started:
                raise
            if shadow and self.shadow_error_mode == "raise":
                raise
            result = self._error_result(
                action,
                context,
                error,
                shadow=shadow,
                operation=operation,
                request_id=call.request_id,
            )

        if self.interceptor.mode is InterceptorMode.ENFORCE:
            if result.executed and result.decision.kind is not DecisionKind.ALLOW:
                raise RuntimeAdapterError(
                    "enforce invariant violated: non-Allow result executed"
                )
            if result.executed and call.request_id is not None:
                self._completed_request_ids.add(call.request_id)
        return result
