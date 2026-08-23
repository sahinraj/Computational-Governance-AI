"""Dependency-free versioned service boundary for governed tool calls.

M24 deliberately keeps the transport small: the core service is callable
in-process for tests and local deployments, while the optional HTTP adapter
uses only Python's standard library.  The service owns idempotency and
approval continuation; policy evaluation remains in the existing engine.
"""

from __future__ import annotations

import json
import copy
import threading
import time
from dataclasses import dataclass, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Optional, Protocol
from urllib.parse import urlparse

from .approval import ApprovalError, ApprovalManager, ApprovalRequest
from .audit import fingerprint, policy_fingerprint
from .identity import IdentityError, VerifiedIdentity
from .interceptor import InterceptionResult, InterceptorMode
from .model import Action, Actor, Context, DecisionKind
from .runtime import RuntimeAdapter, ToolCall
from .telemetry import (
    APPROVAL_EXPIRED,
    APPROVAL_REQUESTED,
    APPROVAL_RESUMED,
    APPROVAL_VOTED,
    DECISION_EVALUATED,
    DECISION_REPLAYED,
    EXECUTION_COMPLETED,
    RECOVERY_FAILURE,
    TelemetryCollector,
)


SERVICE_SCHEMA_VERSION = "1.0"


class ServiceError(ValueError):
    """A stable, client-visible service failure."""

    def __init__(self, code: str, message: str, status: int = HTTPStatus.BAD_REQUEST):
        self.code = code
        self.status = int(status)
        super().__init__(message)


@dataclass(frozen=True)
class ServiceResponse:
    status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class DecisionRequest:
    """Versioned request schema for ``POST /v1/decisions``."""

    actor: Actor
    capability: str
    params: Mapping[str, Any]
    idempotency_key: str
    credential: Optional[Mapping[str, Any]] = None
    budget_used: float = 0.0
    prior_approvals: tuple[str, ...] = ()
    correlation_id: Optional[str] = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecisionRequest":
        if not isinstance(value, Mapping):
            raise ServiceError("invalid_request", "request body must be an object")
        allowed = {
            "actor",
            "capability",
            "params",
            "idempotency_key",
            "credential",
            "budget_used",
            "prior_approvals",
            "correlation_id",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ServiceError("invalid_request", f"unknown request fields: {unknown}")
        actor_value = value.get("actor")
        if not isinstance(actor_value, Mapping):
            raise ServiceError("invalid_request", "actor must be an object")
        try:
            actor = Actor(
                id=actor_value["id"],
                authority_level=actor_value["authority_level"],
                cls=actor_value.get("class", "agent"),
                capabilities=frozenset(actor_value.get("capabilities", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ServiceError("invalid_request", "actor has invalid fields") from exc
        if not isinstance(actor.id, str) or not actor.id:
            raise ServiceError("invalid_request", "actor.id must be non-empty")
        capability = value.get("capability")
        key = value.get("idempotency_key")
        params = value.get("params", {})
        if not isinstance(capability, str) or not capability:
            raise ServiceError("invalid_request", "capability must be non-empty")
        if not isinstance(key, str) or not key:
            raise ServiceError("invalid_request", "idempotency_key must be non-empty")
        if not isinstance(params, Mapping):
            raise ServiceError("invalid_request", "params must be an object")
        credential = value.get("credential")
        if credential is not None and not isinstance(credential, Mapping):
            raise ServiceError("invalid_request", "credential must be an object")
        prior = value.get("prior_approvals", ())
        if not isinstance(prior, (list, tuple)) or any(
            not isinstance(role, str) or not role for role in prior
        ):
            raise ServiceError("invalid_request", "prior_approvals must be role names")
        if prior:
            raise ServiceError(
                "invalid_request",
                "prior_approvals are server-managed and cannot be supplied by callers",
            )
        correlation_id = value.get("correlation_id")
        if correlation_id is not None and (
            not isinstance(correlation_id, str) or not correlation_id
        ):
            raise ServiceError("invalid_request", "correlation_id must be a non-empty string")
        try:
            budget_used = float(value.get("budget_used", 0.0))
        except (TypeError, ValueError) as exc:
            raise ServiceError("invalid_request", "budget_used must be numeric") from exc
        return cls(
            actor=actor,
            capability=capability,
            params=copy.deepcopy(dict(params)),
            idempotency_key=key,
            credential=None if credential is None else dict(credential),
            budget_used=budget_used,
            prior_approvals=tuple(prior),
            correlation_id=correlation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "actor": {
                "id": self.actor.id,
                "authority_level": self.actor.authority_level,
                "class": self.actor.cls,
                "capabilities": sorted(self.actor.capabilities),
            },
            "capability": self.capability,
            "params": copy.deepcopy(dict(self.params)),
            "idempotency_key": self.idempotency_key,
            "budget_used": self.budget_used,
            "prior_approvals": list(self.prior_approvals),
        }
        if self.correlation_id is not None:
            value["correlation_id"] = self.correlation_id
        if self.credential is not None:
            value["credential"] = dict(self.credential)
        return value

    def tool_call(self) -> ToolCall:
        return ToolCall(
            actor=self.actor,
            capability=self.capability,
            params=copy.deepcopy(dict(self.params)),
            request_id=self.idempotency_key,
            credential=self.credential,
        )


@dataclass
class _PendingApproval:
    request: DecisionRequest
    action: Action
    context: Context
    handler: Callable[[Mapping[str, Any]], Any]
    correlation_id: str
    decision_id: str


class GovernanceService:
    """Process-local service façade with fail-closed HTTP semantics."""

    def __init__(
        self,
        runtime: RuntimeAdapter,
        *,
        handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]],
        approval_manager: Optional[ApprovalManager] = None,
        actor_registry: Optional[Mapping[str, Actor]] = None,
        telemetry: Optional[TelemetryCollector] = None,
        policy_version: Optional[str] = None,
        clock: Callable[[], float] = time.time,
    ):
        if runtime.interceptor.mode is not InterceptorMode.ENFORCE:
            raise ServiceError("invalid_configuration", "service requires enforce mode")
        if (
            approval_manager is not None
            and approval_manager is not runtime.interceptor.approval_manager
        ):
            raise ServiceError(
                "invalid_configuration",
                "approval manager must be attached to the interceptor",
            )
        self.runtime = runtime
        self.handlers = dict(handlers)
        if runtime.identity_verifier is not None and actor_registry is None:
            raise ServiceError(
                "invalid_configuration",
                "authenticated service requires a trusted actor registry",
            )
        if actor_registry is not None and any(
            not isinstance(actor_id, str)
            or not actor_id
            or not isinstance(actor, Actor)
            or actor_id != actor.id
            for actor_id, actor in actor_registry.items()
        ):
            raise ServiceError(
                "invalid_configuration",
                "actor registry must map non-empty ids to Actor records",
            )
        self.actor_registry = None if actor_registry is None else dict(actor_registry)
        self.approval_manager = approval_manager or runtime.interceptor.approval_manager
        self.telemetry = telemetry or TelemetryCollector()
        self.policy_version = policy_version
        self.clock = clock
        self._lock = threading.RLock()
        self._idempotency: dict[str, tuple[str, ServiceResponse]] = {}
        self._pending: dict[str, _PendingApproval] = {}

    @staticmethod
    def _error(error: ServiceError) -> ServiceResponse:
        return ServiceResponse(
            status=error.status,
            body={
                "schema_version": SERVICE_SCHEMA_VERSION,
                "error": {"code": error.code, "message": str(error)},
            },
        )

    @staticmethod
    def _decision_payload(result: InterceptionResult) -> dict[str, Any]:
        decision = result.decision
        return {
            "kind": decision.kind.value,
            "role": decision.role,
            "reason": decision.reason,
            "matched_rules": list(decision.matched_rules),
            "authority_source": decision.authority_source,
            "authority_path": list(decision.authority_path),
            "approval_roles": list(decision.approval_roles),
            "approval_threshold": decision.approval_threshold,
        }

    @classmethod
    def _result_response(
        cls,
        request_id: str,
        result: InterceptionResult,
        *,
        correlation_id: Optional[str] = None,
        decision_id: Optional[str] = None,
    ) -> ServiceResponse:
        body: dict[str, Any] = {
            "schema_version": SERVICE_SCHEMA_VERSION,
            "request_id": request_id,
            "decision": cls._decision_payload(result),
            "executed": result.executed,
            "approval_request_id": result.approval_request_id,
        }
        if correlation_id is not None:
            body["correlation_id"] = correlation_id
        if decision_id is not None:
            body["decision_id"] = decision_id
        if result.executed:
            try:
                json.dumps(result.value)
            except (TypeError, ValueError) as exc:
                raise ServiceError(
                    "non_serializable_result",
                    "operation result is not JSON serializable",
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                ) from exc
            body["value"] = result.value
        return ServiceResponse(status=HTTPStatus.OK, body=body)

    @staticmethod
    def _with_observability_ids(
        response: ServiceResponse, correlation_id: str, decision_id: str
    ) -> ServiceResponse:
        body = dict(response.body)
        body["correlation_id"] = correlation_id
        body["decision_id"] = decision_id
        return ServiceResponse(status=response.status, body=body)

    def _request_ids(
        self, request: DecisionRequest
    ) -> tuple[DecisionRequest, dict[str, Any], str, str]:
        correlation_id = request.correlation_id or (
            "corr-" + fingerprint({"actor_id": request.actor.id, "key": request.idempotency_key})[:24]
        )
        normalized = replace(request, correlation_id=correlation_id)
        request_value = normalized.to_dict()
        decision_id = "decision-" + fingerprint(request_value)[:24]
        return normalized, request_value, correlation_id, decision_id

    def _emit_decision(
        self,
        *,
        event_name: str,
        correlation_id: str,
        decision_id: str,
        identity_reference: Optional[str] = None,
        approval_reference: Optional[str] = None,
        outcome: Optional[str] = None,
        latency_ms: Optional[float] = None,
        failure_reason: Optional[str] = None,
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.telemetry.emit(
            event_name,
            correlation_id=correlation_id,
            decision_id=decision_id,
            policy_fingerprint=policy_fingerprint(self.runtime.interceptor.policy),
            policy_version=self.policy_version,
            actor_identity_reference=identity_reference,
            approval_reference=approval_reference,
            outcome=outcome,
            latency_ms=latency_ms,
            failure_reason=failure_reason,
            attributes=attributes,
        )

    def _idempotent(self, key: str, request_value: Mapping[str, Any]) -> Optional[ServiceResponse]:
        entry = self._idempotency.get(key)
        if entry is None:
            return None
        request_hash = fingerprint(request_value)
        if entry[0] != request_hash:
            raise ServiceError(
                "idempotency_key_conflict",
                "idempotency key was already used for a different request",
                HTTPStatus.CONFLICT,
            )
        return entry[1]

    def _store_idempotent(
        self,
        key: str,
        request_value: Mapping[str, Any],
        response: ServiceResponse,
    ) -> ServiceResponse:
        self._idempotency[key] = (fingerprint(request_value), response)
        return response

    def _authenticated_identity(
        self,
        *,
        actor_id: Any,
        credential: Any,
        now: float,
    ) -> VerifiedIdentity:
        verifier = self.runtime.identity_verifier
        if verifier is None:
            raise ServiceError(
                "authentication_unavailable",
                "service has no identity verifier configured",
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )
        if not isinstance(actor_id, str) or not actor_id:
            raise ServiceError("authentication_required", "actor_id is required", HTTPStatus.UNAUTHORIZED)
        try:
            return verifier.verify(credential, actor_id=actor_id, now=now)
        except IdentityError as exc:
            raise ServiceError("authentication_failed", str(exc), HTTPStatus.UNAUTHORIZED) from exc

    def _trusted_request(self, request: DecisionRequest) -> DecisionRequest:
        """Replace caller-asserted policy attributes with trusted actor state."""
        if self.actor_registry is None:
            return request
        actor = self.actor_registry.get(request.actor.id)
        if actor is None:
            raise ServiceError(
                "unknown_actor",
                "actor is not registered in trusted service state",
                HTTPStatus.FORBIDDEN,
            )
        return replace(request, actor=actor)

    def _decision(self, value: Mapping[str, Any]) -> ServiceResponse:
        request = self._trusted_request(DecisionRequest.from_dict(value))
        request, request_value, correlation_id, decision_id = self._request_ids(request)
        cached = self._idempotent(request.idempotency_key, request_value)
        if cached is not None:
            self._emit_decision(
                event_name=DECISION_REPLAYED,
                correlation_id=correlation_id,
                decision_id=decision_id,
                outcome=cached.body.get("decision", {}).get("kind"),
                attributes={"request_id": request.idempotency_key},
            )
            return cached
        handler = self.handlers.get(request.capability)
        if handler is None:
            response = self._with_observability_ids(
                self._error(ServiceError("handler_not_found", "no operation handler is registered", HTTPStatus.NOT_FOUND)),
                correlation_id,
                decision_id,
            )
            self._emit_decision(
                event_name=DECISION_EVALUATED,
                correlation_id=correlation_id,
                decision_id=decision_id,
                outcome="handler_not_found",
                failure_reason="handler_not_found",
            )
            return self._store_idempotent(
                request.idempotency_key,
                request_value,
                response,
            )
        now = float(self.clock())
        started = time.monotonic()
        context = Context(
            budget_used=request.budget_used,
            prior_approvals=(),
            now=now,
        )
        identity = None
        if self.runtime.identity_verifier is not None:
            try:
                identity = self.runtime.identity_verifier.verify(
                    request.credential,
                    actor_id=request.actor.id,
                    now=now,
                )
            except IdentityError:
                # RuntimeAdapter records the authentication failure and fails
                # closed; the service converts it to a stable 401 response.
                identity = None
        action = request.tool_call().to_action(identity)
        try:
            result = self.runtime.invoke(
                request.tool_call(),
                context,
                lambda: handler(copy.deepcopy(dict(request.params))),
            )
            response = self._result_response(
                request.idempotency_key,
                result,
                correlation_id=correlation_id,
                decision_id=decision_id,
            )
        except ServiceError as exc:
            response = self._error(exc)
        except Exception:
            # An operation may have started before raising. Cache the failure
            # under the same key so an uncertain retry cannot execute twice.
            response = self._error(
                ServiceError(
                    "operation_failed",
                    "operation failed after governance evaluation",
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            )
        if (
            response.status == HTTPStatus.OK
            and response.body["decision"]["kind"] == DecisionKind.BLOCK.value
            and response.body["decision"]["reason"].startswith("identity verification failed:")
        ):
            response = ServiceResponse(
                status=HTTPStatus.UNAUTHORIZED,
                body={
                    "schema_version": SERVICE_SCHEMA_VERSION,
                    "error": {
                        "code": "authentication_failed",
                        "message": "identity verification failed",
                    },
                },
            )
        if response.status == HTTPStatus.OK and response.body.get("approval_request_id"):
            self._pending[response.body["approval_request_id"]] = _PendingApproval(
                request=request,
                action=action,
                context=context,
                handler=handler,
                correlation_id=correlation_id,
                decision_id=decision_id,
            )
            self._emit_decision(
                event_name=APPROVAL_REQUESTED,
                correlation_id=correlation_id,
                decision_id=decision_id,
                identity_reference=None if identity is None else identity.identity_reference,
                approval_reference=response.body["approval_request_id"],
                outcome="pending",
            )
        response = self._with_observability_ids(response, correlation_id, decision_id)
        decision = response.body.get("decision", {})
        error = response.body.get("error", {})
        self._emit_decision(
            event_name=DECISION_EVALUATED,
            correlation_id=correlation_id,
            decision_id=decision_id,
            identity_reference=None if identity is None else identity.identity_reference,
            outcome=decision.get("kind", error.get("code")),
            latency_ms=(time.monotonic() - started) * 1000,
            failure_reason=error.get("code"),
            attributes={
                "capability": request.capability,
                "executed": response.body.get("executed", False),
                "params_fingerprint": fingerprint(request.params),
            },
        )
        if response.body.get("executed") is not None:
            self._emit_decision(
                event_name=EXECUTION_COMPLETED,
                correlation_id=correlation_id,
                decision_id=decision_id,
                identity_reference=None if identity is None else identity.identity_reference,
                outcome="succeeded" if response.body.get("executed") else "not_executed",
                latency_ms=(time.monotonic() - started) * 1000,
                failure_reason=error.get("code"),
            )
        return self._store_idempotent(request.idempotency_key, request_value, response)

    def _approval(self, request_id: str) -> ServiceResponse:
        if self.approval_manager is None:
            raise ServiceError("approval_unavailable", "approval manager is not configured", HTTPStatus.INTERNAL_SERVER_ERROR)
        try:
            request = self.approval_manager.get(request_id, now=float(self.clock()))
        except ApprovalError as exc:
            raise ServiceError("approval_not_found", str(exc), HTTPStatus.NOT_FOUND) from exc
        if request.state.value == "expired":
            correlation_id = "corr-" + fingerprint({"approval": request_id})[:24]
            self._emit_decision(
                event_name=APPROVAL_EXPIRED,
                correlation_id=correlation_id,
                decision_id="decision-" + fingerprint(request_id)[:24],
                approval_reference=request_id,
                outcome="expired",
            )
        return ServiceResponse(
            status=HTTPStatus.OK,
            body={
                "schema_version": SERVICE_SCHEMA_VERSION,
                "approval": request.to_dict(),
            },
        )

    @staticmethod
    def _vote_value(value: Mapping[str, Any]) -> tuple[str, str, Any, Any, str]:
        allowed = {"decision", "role", "actor_id", "credential", "idempotency_key"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ServiceError("invalid_request", f"unknown vote fields: {unknown}")
        decision = value.get("decision")
        role = value.get("role")
        key = value.get("idempotency_key")
        if decision not in {"approve", "deny"} or not isinstance(role, str) or not role:
            raise ServiceError("invalid_request", "vote decision and role are required")
        if not isinstance(key, str) or not key:
            raise ServiceError("invalid_request", "idempotency_key is required for votes")
        return decision, role, value.get("actor_id"), value.get("credential"), key

    def _vote(self, request_id: str, value: Mapping[str, Any]) -> ServiceResponse:
        if self.approval_manager is None:
            raise ServiceError("approval_unavailable", "approval manager is not configured", HTTPStatus.INTERNAL_SERVER_ERROR)
        decision, role, actor_id, credential, key = self._vote_value(value)
        request_value = {"endpoint": "vote", "request_id": request_id, **dict(value)}
        cached = self._idempotent(key, request_value)
        if cached is not None:
            return cached
        pending = self._pending.get(request_id)
        if pending is None:
            raise ServiceError("approval_not_found", "approval request is not resumable", HTTPStatus.NOT_FOUND)
        identity = self._authenticated_identity(
            actor_id=actor_id,
            credential=credential,
            now=float(self.clock()),
        )
        try:
            if decision == "approve":
                approval = self.approval_manager.approve(
                    request_id,
                    role,
                    self.runtime.interceptor.policy,
                    pending.action,
                    pending.context,
                    delegation=self.runtime.interceptor.delegation,
                    now=float(self.clock()),
                    identity=identity,
                )
            else:
                approval = self.approval_manager.deny(
                    request_id,
                    role,
                    now=float(self.clock()),
                    identity=identity,
                )
        except ApprovalError as exc:
            response = self._error(ServiceError("approval_conflict", str(exc), HTTPStatus.CONFLICT))
        else:
            response = ServiceResponse(
                status=HTTPStatus.OK,
                body={
                    "schema_version": SERVICE_SCHEMA_VERSION,
                    "approval": approval.to_dict(),
                },
            )
        self._emit_decision(
            event_name=APPROVAL_VOTED,
            correlation_id=pending.correlation_id,
            decision_id=pending.decision_id,
            approval_reference=request_id,
            identity_reference=identity.identity_reference,
            outcome=response.body.get("approval", {}).get(
                "state", response.body.get("error", {}).get("code")
            ),
            attributes={"role": role, "vote": decision},
        )
        return self._store_idempotent(key, request_value, response)

    def _resume(self, request_id: str, value: Mapping[str, Any]) -> ServiceResponse:
        if self.approval_manager is None:
            raise ServiceError("approval_unavailable", "approval manager is not configured", HTTPStatus.INTERNAL_SERVER_ERROR)
        allowed = {"actor_id", "credential", "idempotency_key"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ServiceError("invalid_request", f"unknown resume fields: {unknown}")
        key = value.get("idempotency_key")
        if not isinstance(key, str) or not key:
            raise ServiceError("invalid_request", "idempotency_key is required for resume")
        request_value = {"endpoint": "resume", "request_id": request_id, **dict(value)}
        cached = self._idempotent(key, request_value)
        if cached is not None:
            return cached
        pending = self._pending.get(request_id)
        if pending is None:
            raise ServiceError("approval_not_found", "approval request is not resumable", HTTPStatus.NOT_FOUND)
        identity = self._authenticated_identity(
            actor_id=value.get("actor_id"),
            credential=value.get("credential"),
            now=float(self.clock()),
        )
        approval = self.approval_manager.get(request_id, now=float(self.clock()))
        if not set(identity.roles).intersection(approval.required_roles):
            return self._store_idempotent(
                key,
                request_value,
                self._error(ServiceError("authentication_failed", "identity is not an approver", HTTPStatus.FORBIDDEN)),
            )
        try:
            result = self.runtime.interceptor.resume_approved(
                request_id,
                pending.action,
                pending.context,
                lambda: pending.handler(copy.deepcopy(dict(pending.request.params))),
                now=float(self.clock()),
            )
            response = self._result_response(
                key,
                result,
                correlation_id=pending.correlation_id,
                decision_id=pending.decision_id,
            )
        except Exception:
            response = self._error(
                ServiceError(
                    "operation_failed",
                    "operation failed after approval was consumed",
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            )
        response = self._with_observability_ids(
            response, pending.correlation_id, pending.decision_id
        )
        self._emit_decision(
            event_name=APPROVAL_RESUMED,
            correlation_id=pending.correlation_id,
            decision_id=pending.decision_id,
            approval_reference=request_id,
            identity_reference=identity.identity_reference,
            outcome=response.body.get("decision", {}).get("kind", response.body.get("error", {}).get("code")),
        )
        if response.body.get("executed") is not None:
            self._emit_decision(
                event_name=EXECUTION_COMPLETED,
                correlation_id=pending.correlation_id,
                decision_id=pending.decision_id,
                approval_reference=request_id,
                identity_reference=identity.identity_reference,
                outcome="succeeded" if response.body.get("executed") else "not_executed",
            )
        return self._store_idempotent(key, request_value, response)

    def record_recovery_failure(
        self,
        *,
        correlation_id: str,
        decision_id: str,
        reason: str,
    ) -> None:
        """Record a durable recovery failure without affecting enforcement."""
        self._emit_decision(
            event_name=RECOVERY_FAILURE,
            correlation_id=correlation_id,
            decision_id=decision_id,
            outcome="recovery_failed",
            failure_reason=reason,
        )

    def handle(
        self,
        method: str,
        path: str,
        value: Optional[Mapping[str, Any]] = None,
    ) -> ServiceResponse:
        """Handle one protocol request without requiring an HTTP server."""
        with self._lock:
            try:
                parsed = urlparse(path)
                parts = [part for part in parsed.path.split("/") if part]
                if parts[:2] != ["v1", "decisions"] and parts[:2] != ["v1", "approvals"]:
                    raise ServiceError("not_found", "endpoint not found", HTTPStatus.NOT_FOUND)
                if method == "POST" and parts == ["v1", "decisions"]:
                    return self._decision(value or {})
                if len(parts) == 3 and parts[:2] == ["v1", "approvals"] and method == "GET":
                    return self._approval(parts[2])
                if len(parts) == 4 and parts[:2] == ["v1", "approvals"] and method == "POST":
                    if parts[3] == "vote":
                        return self._vote(parts[2], value or {})
                    if parts[3] == "resume":
                        return self._resume(parts[2], value or {})
                raise ServiceError("not_found", "endpoint not found", HTTPStatus.NOT_FOUND)
            except ServiceError as exc:
                return self._error(exc)
            except Exception:
                return self._error(
                    ServiceError(
                        "internal_error",
                        "service failed closed before execution",
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                )


class _GovernanceHandler(BaseHTTPRequestHandler):
    server: "GovernanceHTTPServer"

    def _send(self, response: ServiceResponse) -> None:
        payload = json.dumps(response.body, sort_keys=True).encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                raise ValueError
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ServiceError("invalid_request", "request body must be JSON object") from exc

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self._send(self.server.service.handle("GET", self.path))

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        try:
            value = self._body()
            response = self.server.service.handle("POST", self.path, value)
        except ServiceError as exc:
            response = GovernanceService._error(exc)
        self._send(response)

    def log_message(self, format: str, *args: Any) -> None:
        return


class GovernanceHTTPServer(ThreadingHTTPServer):
    """Local HTTP runner for the M24 service contract."""

    def __init__(self, address: tuple[str, int], service: GovernanceService):
        self.service = service
        super().__init__(address, _GovernanceHandler)


def create_http_server(
    service: GovernanceService,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> GovernanceHTTPServer:
    return GovernanceHTTPServer((host, port), service)


def serve_http(
    service: GovernanceService,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Run the local HTTP service until interrupted."""
    server = create_http_server(service, host=host, port=port)
    try:
        server.serve_forever()
    finally:
        server.server_close()


__all__ = [
    "SERVICE_SCHEMA_VERSION",
    "ServiceError",
    "ServiceResponse",
    "DecisionRequest",
    "GovernanceService",
    "GovernanceHTTPServer",
    "create_http_server",
    "serve_http",
]
