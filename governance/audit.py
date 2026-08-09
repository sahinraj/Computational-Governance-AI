"""Versioned decision events, fingerprints, and deterministic replay."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .model import Action, Context, Decision, DecisionKind


AUDIT_EVENT_VERSION = "1.0"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(value: Any) -> str:
    """Return a stable SHA-256 fingerprint for JSON-compatible state."""
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def policy_fingerprint(policy) -> str:
    """Fingerprint policy semantics without serializing executable callables."""
    rules = []
    for rule in policy.rules:
        predicate = rule.predicate_spec
        rules.append({
            "id": rule.id,
            "capability": rule.capability.name,
            "min_authority": rule.min_authority,
            "disposition": rule.disposition.value,
            "requires_approval": rule.requires_approval,
            "approval_requirement": None if rule.approval_requirement is None else {
                "roles": list(rule.approval_requirement.roles),
                "threshold": rule.approval_requirement.threshold,
            },
            "forbidden_classes": sorted(rule.forbidden_classes),
            "parent_id": rule.parent_id,
            "predicate": None if predicate is None else {
                "field_name": predicate.field_name,
                "operator": predicate.operator,
                "threshold": predicate.threshold,
            },
        })
    return fingerprint({
        "rules": rules,
        "roles": sorted(policy.roles),
        "default_decision": policy.default_decision.value,
    })


def action_fingerprint(action: Action) -> str:
    return fingerprint({
        "actor": {
            "id": action.actor.id,
            "authority_level": action.actor.authority_level,
            "class": action.actor.cls,
            "capabilities": sorted(action.actor.capabilities),
        },
        "capability": action.capability.name,
        "params": action.params,
    })


def context_fingerprint(context: Context) -> str:
    return fingerprint({
        "budget_used": context.budget_used,
        "prior_approvals": list(context.prior_approvals),
        "now": context.now,
    })


def delegation_snapshot(delegation) -> Optional[dict[str, Any]]:
    if delegation is None:
        return None
    return {
        "grants": [
            {
                "id": grant.id,
                "from_actor": grant.from_actor,
                "to_actor": grant.to_actor,
                "capability": grant.capability.name,
                "depth": grant.depth,
                "expires_at": grant.expires_at,
                "parent_grant_id": grant.parent_grant_id,
                "granting_rule_id": grant.granting_rule_id,
            }
            for grant in delegation.grants()
        ],
        "revoked": list(delegation.revoked_grants()),
    }


def state_fingerprint(policy, delegation=None) -> str:
    return fingerprint({
        "policy": policy_fingerprint(policy),
        "delegation": delegation_snapshot(delegation),
    })


@dataclass(frozen=True)
class DecisionEvent:
    """A replayable governance check; parameters are represented by a digest."""

    event_id: str
    trace_id: str
    policy_fingerprint: str
    state_fingerprint: str
    action_fingerprint: str
    context_fingerprint: str
    actor_id: str
    capability: str
    decision: str
    role: Optional[str]
    reason: str
    matched_rules: tuple[str, ...]
    authority_source: str
    authority_path: tuple[str, ...]
    mode: str
    approval_roles: tuple[str, ...] = ()
    approval_threshold: int = 0
    executed: Optional[bool] = None
    outcome: Optional[str] = None
    event_version: str = AUDIT_EVENT_VERSION

    def __post_init__(self):
        if self.decision not in {kind.value for kind in DecisionKind}:
            raise ValueError(f"unknown event decision {self.decision!r}")
        if self.decision == DecisionKind.ESCALATE.value and not self.role:
            raise ValueError("Escalate events require a role")
        if self.decision != DecisionKind.ESCALATE.value and self.role:
            raise ValueError("role is only valid for Escalate events")
        if self.outcome is not None and self.outcome not in {kind.value for kind in DecisionKind}:
            raise ValueError(f"unknown event outcome {self.outcome!r}")

    @classmethod
    def from_decision(
        cls,
        *,
        event_id: str,
        trace_id: str,
        policy,
        action: Action,
        context: Context,
        decision: Decision,
        mode: str,
        delegation=None,
        executed: Optional[bool] = None,
        outcome: Optional[str] = None,
    ) -> "DecisionEvent":
        return cls(
            event_id=event_id,
            trace_id=trace_id,
            policy_fingerprint=policy_fingerprint(policy),
            state_fingerprint=state_fingerprint(policy, delegation),
            action_fingerprint=action_fingerprint(action),
            context_fingerprint=context_fingerprint(context),
            actor_id=action.actor.id,
            capability=action.capability.name,
            decision=decision.kind.value,
            role=decision.role,
            reason=decision.reason,
            matched_rules=decision.matched_rules,
            authority_source=decision.authority_source,
            authority_path=decision.authority_path,
            mode=mode,
            approval_roles=decision.approval_roles,
            approval_threshold=decision.approval_threshold,
            executed=executed,
            outcome=outcome or decision.kind.value,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_version": self.event_version,
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "policy_fingerprint": self.policy_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "action_fingerprint": self.action_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "actor_id": self.actor_id,
            "capability": self.capability,
            "decision": self.decision,
            "role": self.role,
            "reason": self.reason,
            "matched_rules": list(self.matched_rules),
            "authority_source": self.authority_source,
            "authority_path": list(self.authority_path),
            "approval_roles": list(self.approval_roles),
            "approval_threshold": self.approval_threshold,
            "mode": self.mode,
            "executed": self.executed,
            "outcome": self.outcome,
        }

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DecisionEvent":
        required = {
            "event_id", "trace_id", "policy_fingerprint", "state_fingerprint",
            "action_fingerprint", "context_fingerprint", "actor_id", "capability",
            "decision", "reason", "matched_rules", "authority_source",
            "authority_path", "mode",
        }
        missing = sorted(required - set(value))
        if missing:
            raise ValueError(f"audit event missing fields: {missing}")
        return cls(
            event_id=str(value["event_id"]),
            trace_id=str(value["trace_id"]),
            policy_fingerprint=str(value["policy_fingerprint"]),
            state_fingerprint=str(value["state_fingerprint"]),
            action_fingerprint=str(value["action_fingerprint"]),
            context_fingerprint=str(value["context_fingerprint"]),
            actor_id=str(value["actor_id"]),
            capability=str(value["capability"]),
            decision=str(value["decision"]),
            role=value.get("role"),
            reason=str(value["reason"]),
            matched_rules=tuple(str(item) for item in value["matched_rules"]),
            authority_source=str(value["authority_source"]),
            authority_path=tuple(str(item) for item in value["authority_path"]),
            mode=str(value["mode"]),
            approval_roles=tuple(str(item) for item in value.get("approval_roles", ())),
            approval_threshold=int(value.get("approval_threshold", 0)),
            executed=value.get("executed"),
            outcome=value.get("outcome"),
            event_version=str(value.get("event_version", AUDIT_EVENT_VERSION)),
        )


class AuditLog:
    """Append-only in-memory log with deterministic JSONL export."""

    def __init__(self, events: Iterable[DecisionEvent] = ()):
        self._events: list[DecisionEvent] = []
        self._ids: set[str] = set()
        for event in events:
            self.append(event)

    def append(self, event: DecisionEvent) -> None:
        if event.event_id in self._ids:
            raise ValueError(f"duplicate audit event id {event.event_id}")
        self._ids.add(event.event_id)
        self._events.append(event)

    def next_sequence(self, trace_id: str) -> int:
        """Return the next numeric event sequence for a recovered trace."""
        prefix = f"{trace_id}-"
        sequences = []
        for event in self._events:
            if event.trace_id != trace_id or not event.event_id.startswith(prefix):
                continue
            suffix = event.event_id[len(prefix):]
            if suffix.isdigit():
                sequences.append(int(suffix))
        return max(sequences, default=0) + 1

    @property
    def events(self) -> tuple[DecisionEvent, ...]:
        return tuple(self._events)

    def to_jsonl(self) -> str:
        if not self._events:
            return ""
        return "".join(event.to_json() + "\n" for event in self._events)

    def write_jsonl(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl(), encoding="utf-8")

    @classmethod
    def from_jsonl(cls, path: str | Path) -> "AuditLog":
        events = []
        for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(DecisionEvent.from_dict(json.loads(line)))
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid audit event on line {line_no}: {exc}") from exc
        return cls(events)


@dataclass(frozen=True)
class ReplayResult:
    decision: Decision
    drift: tuple[str, ...] = ()

    @property
    def exact(self) -> bool:
        return not self.drift


def replay_event(
    event: DecisionEvent,
    policy,
    action: Action,
    context: Context,
    delegation=None,
) -> ReplayResult:
    """Replay a check and report every policy/state/input mismatch."""
    drift: list[str] = []
    fingerprints = {
        "policy": (event.policy_fingerprint, policy_fingerprint(policy)),
        "state": (event.state_fingerprint, state_fingerprint(policy, delegation)),
        "action": (event.action_fingerprint, action_fingerprint(action)),
        "context": (event.context_fingerprint, context_fingerprint(context)),
    }
    drift.extend(name for name, (expected, actual) in fingerprints.items() if expected != actual)
    decision = policy.evaluate(action, context, delegation=delegation)
    if decision.kind.value != event.decision:
        drift.append("decision")
    if decision.role != event.role:
        drift.append("role")
    if decision.reason != event.reason:
        drift.append("reason")
    if decision.matched_rules != event.matched_rules:
        drift.append("matched_rules")
    if decision.authority_source != event.authority_source:
        drift.append("authority_source")
    if decision.authority_path != event.authority_path:
        drift.append("authority_path")
    return ReplayResult(decision=decision, drift=tuple(dict.fromkeys(drift)))
