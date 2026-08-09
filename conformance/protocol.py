"""Versioned JSON envelopes for black-box governance integrations.

This module intentionally has no dependency on ``governance`` or
``governancebench``. A third-party implementation can speak these envelopes
without importing this repository's reference classes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


PROTOCOL_VERSION = "1.0"
AUDIT_EVENT_VERSION = "1.0"
DECISIONS = ("Allow", "Block", "Escalate")


class ProtocolError(ValueError):
    """Raised when an envelope is invalid or uses an unsupported version."""


def canonical_json(value: Any) -> str:
    """Serialize a protocol value deterministically for hashes and fixtures."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _version(value: Mapping[str, Any], key: str = "protocol_version") -> str:
    version = str(value.get(key, ""))
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported {key} {version!r}; expected {PROTOCOL_VERSION}")
    return version


def _required(value: Mapping[str, Any], fields: set[str]) -> None:
    missing = sorted(field for field in fields if field not in value)
    if missing:
        raise ProtocolError(f"missing required protocol fields: {missing}")


@dataclass(frozen=True)
class ToolCallEnvelope:
    request_id: str
    actor: Mapping[str, Any]
    capability: str
    params: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, Any] = field(default_factory=dict)
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self):
        if self.protocol_version != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version {self.protocol_version!r}")
        if not self.request_id or not self.capability:
            raise ProtocolError("request_id and capability are required")
        if not self.actor.get("id"):
            raise ProtocolError("actor.id is required")
        object.__setattr__(self, "actor", dict(self.actor))
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "context", dict(self.context))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolCallEnvelope":
        _required(value, {"protocol_version", "request_id", "actor", "capability", "params", "context"})
        version = _version(value)
        return cls(
            request_id=str(value["request_id"]),
            actor=value["actor"],
            capability=str(value["capability"]),
            params=value["params"],
            context=value["context"],
            protocol_version=version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "actor": dict(self.actor),
            "capability": self.capability,
            "params": dict(self.params),
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class DecisionEnvelope:
    decision: str
    role: Optional[str] = None
    reason: str = ""
    matched_rules: tuple[str, ...] = ()
    authority_source: str = ""
    authority_path: tuple[str, ...] = ()
    approval_roles: tuple[str, ...] = ()
    approval_threshold: int = 0
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self):
        if self.protocol_version != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version {self.protocol_version!r}")
        if self.decision not in DECISIONS:
            raise ProtocolError(f"unknown decision {self.decision!r}")
        if self.decision == "Escalate" and not self.role:
            raise ProtocolError("Escalate requires role")
        if self.decision != "Escalate" and self.role:
            raise ProtocolError("role is only valid for Escalate")
        object.__setattr__(self, "matched_rules", tuple(self.matched_rules))
        object.__setattr__(self, "authority_path", tuple(self.authority_path))
        object.__setattr__(self, "approval_roles", tuple(self.approval_roles))
        if self.decision != "Escalate" and (self.approval_roles or self.approval_threshold):
            raise ProtocolError("approval quorum is only valid for Escalate")
        if self.approval_roles and not 1 <= self.approval_threshold <= len(self.approval_roles):
            raise ProtocolError("approval threshold must be within approval role count")
        if not self.approval_roles and self.approval_threshold:
            raise ProtocolError("approval threshold requires approval roles")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DecisionEnvelope":
        _required(value, {"protocol_version", "decision", "role", "reason", "matched_rules"})
        return cls(
            decision=str(value["decision"]),
            role=value["role"],
            reason=str(value["reason"]),
            matched_rules=tuple(str(item) for item in value["matched_rules"]),
            authority_source=str(value.get("authority_source", "")),
            authority_path=tuple(str(item) for item in value.get("authority_path", ())),
            approval_roles=tuple(str(item) for item in value.get("approval_roles", ())),
            approval_threshold=int(value.get("approval_threshold", 0)),
            protocol_version=_version(value),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "decision": self.decision,
            "role": self.role,
            "reason": self.reason,
            "matched_rules": list(self.matched_rules),
            "authority_source": self.authority_source,
            "authority_path": list(self.authority_path),
            "approval_roles": list(self.approval_roles),
            "approval_threshold": self.approval_threshold,
        }


@dataclass(frozen=True)
class AuditEventEnvelope:
    event_id: str
    trace_id: str
    decision: DecisionEnvelope
    policy_fingerprint: str
    state_fingerprint: str
    action_fingerprint: str
    context_fingerprint: str
    actor_id: str
    capability: str
    mode: str
    executed: Optional[bool] = None
    outcome: Optional[str] = None
    event_version: str = AUDIT_EVENT_VERSION

    def __post_init__(self):
        if self.event_version != AUDIT_EVENT_VERSION:
            raise ProtocolError(f"unsupported audit event version {self.event_version!r}")
        if not self.event_id or not self.trace_id:
            raise ProtocolError("event_id and trace_id are required")
        if self.mode not in {"shadow", "enforce"}:
            raise ProtocolError("mode must be shadow or enforce")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuditEventEnvelope":
        _required(value, {
            "event_version", "event_id", "trace_id", "policy_fingerprint",
            "state_fingerprint", "action_fingerprint", "context_fingerprint",
            "actor_id", "capability", "decision", "role", "reason",
            "matched_rules", "mode",
        })
        decision = DecisionEnvelope(
            decision=str(value["decision"]),
            role=value["role"],
            reason=str(value["reason"]),
            matched_rules=tuple(str(item) for item in value["matched_rules"]),
            authority_source=str(value.get("authority_source", "")),
            authority_path=tuple(str(item) for item in value.get("authority_path", ())),
            approval_roles=tuple(str(item) for item in value.get("approval_roles", ())),
            approval_threshold=int(value.get("approval_threshold", 0)),
        )
        return cls(
            event_id=str(value["event_id"]),
            trace_id=str(value["trace_id"]),
            decision=decision,
            policy_fingerprint=str(value["policy_fingerprint"]),
            state_fingerprint=str(value["state_fingerprint"]),
            action_fingerprint=str(value["action_fingerprint"]),
            context_fingerprint=str(value["context_fingerprint"]),
            actor_id=str(value["actor_id"]),
            capability=str(value["capability"]),
            mode=str(value["mode"]),
            executed=value.get("executed"),
            outcome=value.get("outcome"),
            event_version=str(value["event_version"]),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "event_version": self.event_version,
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "policy_fingerprint": self.policy_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "action_fingerprint": self.action_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "actor_id": self.actor_id,
            "capability": self.capability,
            "decision": self.decision.decision,
            "role": self.decision.role,
            "reason": self.decision.reason,
            "matched_rules": list(self.decision.matched_rules),
            "authority_source": self.decision.authority_source,
            "authority_path": list(self.decision.authority_path),
            "approval_roles": list(self.decision.approval_roles),
            "approval_threshold": self.decision.approval_threshold,
            "mode": self.mode,
            "executed": self.executed,
            "outcome": self.outcome,
        }
        return value
