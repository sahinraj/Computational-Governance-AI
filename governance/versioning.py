"""M22: stable policy bundles, compatibility checks, diffs, and rollback guards."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .compiler import CompiledPolicy, compile_policy
from .model import DecisionKind


POLICY_BUNDLE_VERSION = "1.0"
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class VersioningError(ValueError):
    """Raised when a policy bundle is invalid, incompatible, or unsafe to activate."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise VersioningError("policy bundle contains non-portable JSON values") from exc


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _version_key(value: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise VersioningError(f"policy version must be stable semver, got {value!r}")
    return tuple(int(part) for part in match.groups())


def _predicate_dict(rule) -> Optional[dict[str, Any]]:
    predicate = rule.predicate_spec
    if predicate is None:
        return None
    return {
        "field_name": predicate.field_name,
        "operator": predicate.operator,
        "threshold": predicate.threshold,
    }


def _rule_dict(rule) -> dict[str, Any]:
    requirement = rule.approval_requirement
    return {
        "id": rule.id,
        "capability": rule.capability.name,
        "min_authority": rule.min_authority,
        "disposition": rule.disposition.value,
        "requires_approval": rule.requires_approval,
        "approval_requirement": None if requirement is None else {
            "roles": list(requirement.roles),
            "threshold": requirement.threshold,
        },
        "forbidden_classes": sorted(rule.forbidden_classes),
        "parent_id": rule.parent_id,
        "predicate": _predicate_dict(rule),
    }


def policy_semantics(policy: CompiledPolicy) -> dict[str, Any]:
    """Return the canonical semantic portion of a compiled policy."""
    return {
        "rules": [_rule_dict(rule) for rule in sorted(policy.rules, key=lambda item: item.id)],
        "roles": sorted(policy.roles),
        "default_decision": policy.default_decision.value,
    }


def _validate_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(provenance, dict):
        raise VersioningError("policy provenance must be an object")
    normalized = {}
    for key, value in provenance.items():
        if not isinstance(key, str):
            raise VersioningError("policy provenance keys must be strings")
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise VersioningError("policy provenance values must be scalar")
        if isinstance(value, float) and not math.isfinite(value):
            raise VersioningError("policy provenance values must be finite")
        normalized[key] = value
    return dict(sorted(normalized.items()))


@dataclass(frozen=True)
class PolicyBundle:
    """Portable policy source plus its stable, semantic identity."""

    policy_id: str
    policy_version: str
    source: str
    semantics: dict[str, Any]
    provenance: dict[str, Any]
    bundle_version: str = POLICY_BUNDLE_VERSION

    def __post_init__(self):
        if self.bundle_version != POLICY_BUNDLE_VERSION:
            raise VersioningError(
                f"unsupported policy bundle version {self.bundle_version!r}"
            )
        if not self.policy_id or not isinstance(self.policy_id, str):
            raise VersioningError("policy_id must be a non-empty string")
        _version_key(self.policy_version)
        if not isinstance(self.source, str) or not self.source.strip():
            raise VersioningError("policy source must be non-empty")
        if not isinstance(self.semantics, dict):
            raise VersioningError("policy semantics must be an object")
        _validate_provenance(self.provenance)

    @property
    def content_hash(self) -> str:
        """Hash semantic policy content, excluding mutable provenance metadata."""
        return _hash({
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "semantics": self.semantics,
        })

    @classmethod
    def from_source(
        cls,
        source: str,
        *,
        policy_id: str,
        policy_version: str,
        roles: Optional[Iterable[str]] = None,
        default_decision: DecisionKind | str = DecisionKind.ALLOW,
        provenance: Optional[dict[str, Any]] = None,
    ) -> "PolicyBundle":
        role_set = None if roles is None else set(roles)
        policy = compile_policy(
            source,
            roles=role_set,
            default_decision=default_decision,
        )
        semantics = policy_semantics(policy)
        if role_set is None:
            referenced_roles = set(policy.roles)
            for rule in policy.rules:
                if rule.requires_approval:
                    referenced_roles.add(rule.requires_approval)
                if rule.approval_requirement is not None:
                    referenced_roles.update(rule.approval_requirement.roles)
            semantics["roles"] = sorted(referenced_roles)
        return cls(
            policy_id=policy_id,
            policy_version=policy_version,
            source=source,
            semantics=semantics,
            provenance=_validate_provenance(provenance or {}),
        )

    @classmethod
    def from_policy(
        cls,
        policy: CompiledPolicy,
        *,
        source: str,
        policy_id: str,
        policy_version: str,
        provenance: Optional[dict[str, Any]] = None,
    ) -> "PolicyBundle":
        """Create a bundle from a compiled policy and its authoritative source."""
        bundle = cls(
            policy_id=policy_id,
            policy_version=policy_version,
            source=source,
            semantics=policy_semantics(policy),
            provenance=_validate_provenance(provenance or {}),
        )
        rebuilt = compile_policy(source, roles=policy.roles, default_decision=policy.default_decision)
        if policy_semantics(rebuilt) != bundle.semantics:
            raise VersioningError("source semantics do not match compiled policy")
        return bundle

    def compile(self) -> CompiledPolicy:
        policy = compile_policy(
            self.source,
            roles=self.semantics.get("roles", ()),
            default_decision=self.semantics.get("default_decision", DecisionKind.ALLOW.value),
        )
        if policy_semantics(policy) != self.semantics:
            raise VersioningError("policy source does not match bundle semantics")
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_version": self.bundle_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "content_hash": self.content_hash,
            "source": self.source,
            "semantics": self.semantics,
            "provenance": dict(self.provenance),
        }

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PolicyBundle":
        if not isinstance(value, dict):
            raise VersioningError("policy bundle must be an object")
        required = {
            "bundle_version", "policy_id", "policy_version", "content_hash",
            "source", "semantics", "provenance",
        }
        missing = sorted(required - set(value))
        if missing:
            raise VersioningError(f"policy bundle missing fields: {missing}")
        for field in ("bundle_version", "policy_id", "policy_version", "content_hash", "source"):
            if not isinstance(value[field], str):
                raise VersioningError(f"policy bundle field {field} must be a string")
        if not isinstance(value["semantics"], dict):
            raise VersioningError("policy bundle semantics must be an object")
        if not isinstance(value["provenance"], dict):
            raise VersioningError("policy bundle provenance must be an object")
        bundle = cls(
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            source=value["source"],
            semantics=value["semantics"],
            provenance=value["provenance"],
            bundle_version=value["bundle_version"],
        )
        if value["content_hash"] != bundle.content_hash:
            raise VersioningError("policy bundle content hash mismatch")
        bundle.compile()
        return bundle

    @classmethod
    def from_json(cls, value: str) -> "PolicyBundle":
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise VersioningError(f"invalid policy bundle JSON: {exc}") from exc
        return cls.from_dict(parsed)

    def diff(self, other: "PolicyBundle") -> dict[str, Any]:
        """Return stable semantic changes between two bundles."""
        if not isinstance(other, PolicyBundle):
            raise VersioningError("policy diff requires another PolicyBundle")
        changes: list[dict[str, Any]] = []
        if self.policy_id != other.policy_id:
            changes.append({"path": "policy_id", "before": self.policy_id, "after": other.policy_id})
        if self.policy_version != other.policy_version:
            changes.append({"path": "policy_version", "before": self.policy_version, "after": other.policy_version})
        before_rules = {rule["id"]: rule for rule in self.semantics["rules"]}
        after_rules = {rule["id"]: rule for rule in other.semantics["rules"]}
        for rule_id in sorted(set(before_rules) | set(after_rules)):
            before = before_rules.get(rule_id)
            after = after_rules.get(rule_id)
            if before is None or after is None:
                changes.append({"path": f"rules.{rule_id}", "before": before, "after": after})
                continue
            for field in sorted(set(before) | set(after)):
                if before.get(field) != after.get(field):
                    changes.append({
                        "path": f"rules.{rule_id}.{field}",
                        "before": before.get(field),
                        "after": after.get(field),
                    })
        for field in ("roles", "default_decision"):
            if self.semantics.get(field) != other.semantics.get(field):
                changes.append({
                    "path": field,
                    "before": self.semantics.get(field),
                    "after": other.semantics.get(field),
                })
        return {
            "policy_id": other.policy_id,
            "from_version": self.policy_version,
            "to_version": other.policy_version,
            "from_hash": self.content_hash,
            "to_hash": other.content_hash,
            "changed": bool(changes),
            "changes": changes,
        }


@dataclass(frozen=True)
class PolicyVersionEvent:
    """Auditable activation or rollback of a policy bundle."""

    event_id: str
    policy_id: str
    event: str
    from_version: Optional[str]
    to_version: str
    content_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "policy_id": self.policy_id,
            "event": self.event,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "content_hash": self.content_hash,
            "reason": self.reason,
        }


class PolicyVersionStore:
    """In-memory lifecycle guard that provides the M22 activation contract."""

    def __init__(self):
        self._bundles: dict[str, dict[str, PolicyBundle]] = {}
        self._active: dict[str, str] = {}
        self._events: list[PolicyVersionEvent] = []
        self._next_event_id = 1

    def register(self, bundle: PolicyBundle) -> None:
        versions = self._bundles.setdefault(bundle.policy_id, {})
        existing = versions.get(bundle.policy_version)
        if existing is not None and existing.content_hash != bundle.content_hash:
            raise VersioningError(
                f"policy version {bundle.policy_id}@{bundle.policy_version} already has different content"
            )
        versions[bundle.policy_version] = bundle

    def activate(
        self,
        bundle: PolicyBundle,
        *,
        reason: str,
        allow_rollback: bool = False,
    ) -> PolicyVersionEvent:
        if not reason.strip():
            raise VersioningError("activation reason is required")
        bundle.compile()
        self.register(bundle)
        previous = self._active.get(bundle.policy_id)
        if previous is not None:
            current_key = _version_key(previous)
            target_key = _version_key(bundle.policy_version)
            if target_key < current_key and not allow_rollback:
                raise VersioningError(
                    f"rollback from {previous} to {bundle.policy_version} requires explicit override"
                )
            if target_key == current_key:
                current = self._bundles[bundle.policy_id][previous]
                if current.content_hash != bundle.content_hash:
                    raise VersioningError("active policy version content cannot be replaced")
                matching = [
                    event for event in self._events
                    if event.policy_id == bundle.policy_id
                    and event.to_version == previous
                ]
                return matching[-1] if matching else self._event(
                    bundle, previous, "activate", reason
                )
        event = self._event(
            bundle,
            previous,
            "rollback" if previous is not None and _version_key(bundle.policy_version) < _version_key(previous) else "activate",
            reason,
        )
        self._active[bundle.policy_id] = bundle.policy_version
        return event

    def rollback(self, policy_id: str, version: str, *, reason: str) -> PolicyVersionEvent:
        bundle = self._bundles.get(policy_id, {}).get(version)
        if bundle is None:
            raise VersioningError(f"unknown policy version {policy_id}@{version}")
        return self.activate(bundle, reason=reason, allow_rollback=True)

    def current(self, policy_id: str) -> PolicyBundle:
        version = self._active.get(policy_id)
        if version is None:
            raise VersioningError(f"no active policy for {policy_id}")
        return self._bundles[policy_id][version]

    def history(self, policy_id: Optional[str] = None) -> tuple[PolicyVersionEvent, ...]:
        if policy_id is None:
            return tuple(self._events)
        return tuple(event for event in self._events if event.policy_id == policy_id)

    def _event(
        self,
        bundle: PolicyBundle,
        previous: Optional[str],
        event_type: str,
        reason: str,
    ) -> PolicyVersionEvent:
        event = PolicyVersionEvent(
            event_id=f"policy-version-{self._next_event_id:04d}",
            policy_id=bundle.policy_id,
            event=event_type,
            from_version=previous,
            to_version=bundle.policy_version,
            content_hash=bundle.content_hash,
            reason=reason,
        )
        self._next_event_id += 1
        self._events.append(event)
        return event
