"""M27 policy lifecycle and controlled rollout primitives.

The lifecycle layer owns operational state around an immutable M22
:class:`PolicyBundle`.  It deliberately does not change policy semantics or
pretend to provide durable multi-worker coordination; the M25 repository
integration remains a separate boundary.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional

from .audit import action_fingerprint, context_fingerprint, policy_fingerprint
from .model import Action, Context, Decision, DecisionKind
from .telemetry import POLICY_LIFECYCLE, TelemetryCollector
from .versioning import PolicyBundle, VersioningError


class PolicyLifecycleError(ValueError):
    """Raised when an operational policy transition is invalid."""


class PolicyLifecycleState(str, Enum):
    DRAFT = "draft"
    VALIDATED = "validated"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


class PolicyExpiryMode(str, Enum):
    FAIL_CLOSED = "fail_closed"
    ESCALATE = "escalate"


def _non_empty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyLifecycleError(f"{field_name} must be a non-empty string")
    return value.strip()


def _finite_time(value: Any, field_name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyLifecycleError(f"{field_name} must be numeric") from exc
    if not math.isfinite(result):
        raise PolicyLifecycleError(f"{field_name} must be finite")
    return result


@dataclass(frozen=True)
class PolicyLifecycleEvent:
    """Append-only operational record for one lifecycle transition."""

    event_id: str
    occurred_at: float
    policy_id: str
    policy_version: str
    event: str
    from_state: PolicyLifecycleState
    to_state: PolicyLifecycleState
    environment: Optional[str]
    actor_id: Optional[str]
    reason: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "event": self.event,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "environment": self.environment,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class PolicyApproval:
    """One distinct human approval vote for a policy/environment pair."""

    approver_id: str
    role: str
    reason: str
    approved_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "approver_id": self.approver_id,
            "role": self.role,
            "reason": self.reason,
            "approved_at": self.approved_at,
        }


@dataclass(frozen=True)
class SimulationCase:
    """A redacted, deterministic input for dry-run and historical replay."""

    case_id: str
    action: Action
    context: Context

    def __post_init__(self) -> None:
        _non_empty(self.case_id, "case_id")


@dataclass(frozen=True)
class DecisionSnapshot:
    """Comparable decision output that never stores raw tool parameters."""

    kind: str
    role: Optional[str]
    reason: str
    matched_rules: tuple[str, ...]
    authority_source: str
    authority_path: tuple[str, ...]
    approval_roles: tuple[str, ...]
    approval_threshold: int

    @classmethod
    def from_decision(cls, decision: Decision) -> "DecisionSnapshot":
        return cls(
            kind=decision.kind.value,
            role=decision.role,
            reason=decision.reason,
            matched_rules=tuple(decision.matched_rules),
            authority_source=decision.authority_source,
            authority_path=tuple(decision.authority_path),
            approval_roles=tuple(decision.approval_roles),
            approval_threshold=decision.approval_threshold,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "role": self.role,
            "reason": self.reason,
            "matched_rules": list(self.matched_rules),
            "authority_source": self.authority_source,
            "authority_path": list(self.authority_path),
            "approval_roles": list(self.approval_roles),
            "approval_threshold": self.approval_threshold,
        }


@dataclass(frozen=True)
class SimulationCaseResult:
    case_id: str
    action_fingerprint: str
    context_fingerprint: str
    candidate: DecisionSnapshot
    baseline: Optional[DecisionSnapshot]
    changed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "action_fingerprint": self.action_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "candidate": self.candidate.to_dict(),
            "baseline": None if self.baseline is None else self.baseline.to_dict(),
            "changed": self.changed,
        }


@dataclass(frozen=True)
class SimulationReport:
    policy_id: str
    candidate_version: str
    baseline_version: Optional[str]
    cases: tuple[SimulationCaseResult, ...]
    generated_at: float

    @property
    def changed_cases(self) -> tuple[SimulationCaseResult, ...]:
        return tuple(case for case in self.cases if case.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "candidate_version": self.candidate_version,
            "baseline_version": self.baseline_version,
            "case_count": len(self.cases),
            "changed_case_count": len(self.changed_cases),
            "cases": [case.to_dict() for case in self.cases],
            "generated_at": self.generated_at,
        }


@dataclass(frozen=True)
class CanaryReport:
    policy_id: str
    candidate_version: str
    environment: str
    sample_rate: float
    max_changed_decisions: int
    simulation: SimulationReport
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "candidate_version": self.candidate_version,
            "environment": self.environment,
            "sample_rate": self.sample_rate,
            "max_changed_decisions": self.max_changed_decisions,
            "sampled_case_count": len(self.simulation.cases),
            "changed_case_count": len(self.simulation.changed_cases),
            "passed": self.passed,
        }


@dataclass(frozen=True)
class PolicyLifecycleRecord:
    """Read-only operational view of a policy version and its evidence."""

    policy_id: str
    policy_version: str
    content_hash: str
    owner: str
    state: PolicyLifecycleState
    environment: Optional[str]
    environment_states: Mapping[str, PolicyLifecycleState]
    expires_at: Optional[float]
    simulation: Optional[SimulationReport]
    canaries: Mapping[str, CanaryReport]
    approvals: Mapping[str, tuple[PolicyApproval, ...]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "content_hash": self.content_hash,
            "owner": self.owner,
            "state": self.state.value,
            "environment": self.environment,
            "environment_states": {
                key: value.value for key, value in sorted(self.environment_states.items())
            },
            "expires_at": self.expires_at,
            "simulation": None if self.simulation is None else self.simulation.to_dict(),
            "canaries": {key: value.to_dict() for key, value in sorted(self.canaries.items())},
            "approvals": {
                key: [vote.to_dict() for vote in value]
                for key, value in sorted(self.approvals.items())
            },
        }


@dataclass
class _LifecycleEntry:
    bundle: PolicyBundle
    owner: str
    expires_at: Optional[float]
    state: PolicyLifecycleState = PolicyLifecycleState.DRAFT
    environment_states: dict[str, PolicyLifecycleState] = field(default_factory=dict)
    simulation: Optional[SimulationReport] = None
    canaries: dict[str, CanaryReport] = field(default_factory=dict)


class PolicyLifecycleManager:
    """Manage auditable policy promotion without mutating policy semantics."""

    def __init__(
        self,
        *,
        production_approval_threshold: int = 2,
        approver_roles: Iterable[str] = (),
        expiry_mode: PolicyExpiryMode | str = PolicyExpiryMode.FAIL_CLOSED,
        telemetry: Optional[TelemetryCollector] = None,
        clock: Callable[[], float] = time.time,
    ):
        if (
            not isinstance(production_approval_threshold, int)
            or isinstance(production_approval_threshold, bool)
            or production_approval_threshold < 1
        ):
            raise PolicyLifecycleError("production approval threshold must be positive")
        try:
            mode = PolicyExpiryMode(expiry_mode)
        except ValueError as exc:
            raise PolicyLifecycleError(f"unsupported expiry mode {expiry_mode!r}") from exc
        roles = frozenset(_non_empty(role, "approver role") for role in approver_roles)
        self.production_approval_threshold = production_approval_threshold
        self.approver_roles = roles
        self.expiry_mode = mode
        self.telemetry = telemetry
        self.clock = clock
        self._entries: dict[tuple[str, str], _LifecycleEntry] = {}
        self._approvals: dict[tuple[str, str, str], list[PolicyApproval]] = {}
        self._active: dict[tuple[str, str], str] = {}
        self._events: list[PolicyLifecycleEvent] = []
        self._next_event_id = 1

    @property
    def events(self) -> tuple[PolicyLifecycleEvent, ...]:
        return tuple(self._events)

    def _entry(self, policy_id: str, version: str) -> _LifecycleEntry:
        key = (_non_empty(policy_id, "policy_id"), _non_empty(version, "policy_version"))
        try:
            return self._entries[key]
        except KeyError as exc:
            raise PolicyLifecycleError(f"unknown policy {key[0]}@{key[1]}") from exc

    def record(
        self,
        policy_id: str,
        version: str,
        *,
        environment: Optional[str] = None,
    ) -> PolicyLifecycleRecord:
        """Return a read-only status view suitable for operators and APIs."""
        policy_id = _non_empty(policy_id, "policy_id")
        version = _non_empty(version, "policy_version")
        if environment is not None:
            environment = _non_empty(environment, "environment")
        entry = self._entry(policy_id, version)
        approvals = {
            environment: tuple(votes)
            for (stored_policy, stored_version, environment), votes in self._approvals.items()
            if stored_policy == policy_id and stored_version == version
        }
        return PolicyLifecycleRecord(
            policy_id=entry.bundle.policy_id,
            policy_version=entry.bundle.policy_version,
            content_hash=entry.bundle.content_hash,
            owner=entry.owner,
            state=entry.environment_states.get(environment, entry.state),
            environment=environment,
            environment_states=dict(entry.environment_states),
            expires_at=entry.expires_at,
            simulation=entry.simulation,
            canaries=dict(entry.canaries),
            approvals=approvals,
        )

    def diff(self, before_version: str, after_version: str, *, policy_id: str) -> dict[str, Any]:
        """Expose M22's semantic diff through the lifecycle boundary."""
        before = self._entry(policy_id, before_version).bundle
        after = self._entry(policy_id, after_version).bundle
        return before.diff(after)

    def _recompute_state(self, entry: _LifecycleEntry) -> None:
        """Derive the aggregate state without hiding active environments."""
        states = tuple(entry.environment_states.values())
        if PolicyLifecycleState.DEPLOYED in states:
            entry.state = PolicyLifecycleState.DEPLOYED
        elif PolicyLifecycleState.EXPIRED in states:
            entry.state = PolicyLifecycleState.EXPIRED
        elif PolicyLifecycleState.ROLLED_BACK in states:
            entry.state = PolicyLifecycleState.ROLLED_BACK
        elif PolicyLifecycleState.SUPERSEDED in states:
            entry.state = PolicyLifecycleState.SUPERSEDED

    def _append_event(
        self,
        entry: _LifecycleEntry,
        *,
        event: str,
        from_state: PolicyLifecycleState,
        to_state: PolicyLifecycleState,
        reason: str,
        environment: Optional[str] = None,
        actor_id: Optional[str] = None,
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> PolicyLifecycleEvent:
        record = PolicyLifecycleEvent(
            event_id=f"policy-lifecycle-{self._next_event_id:04d}",
            occurred_at=_finite_time(self.clock(), "lifecycle clock"),
            policy_id=entry.bundle.policy_id,
            policy_version=entry.bundle.policy_version,
            event=event,
            from_state=from_state,
            to_state=to_state,
            environment=environment,
            actor_id=actor_id,
            reason=_non_empty(reason, "reason"),
            attributes=dict(attributes or {}),
        )
        self._next_event_id += 1
        self._events.append(record)
        if self.telemetry is not None:
            try:
                self.telemetry.emit(
                    POLICY_LIFECYCLE,
                    correlation_id=f"corr-{hashlib.sha256(record.event_id.encode()).hexdigest()[:24]}",
                    decision_id=f"decision-{hashlib.sha256((entry.bundle.policy_id + entry.bundle.policy_version).encode()).hexdigest()[:24]}",
                    policy_fingerprint=entry.bundle.content_hash,
                    policy_version=entry.bundle.policy_version,
                    outcome=to_state.value,
                    failure_reason=None if event != "validation_failed" else "validation_failed",
                    attributes=record.to_dict(),
                )
            except Exception:
                pass
        return record

    def draft(
        self,
        bundle: PolicyBundle,
        *,
        owner: str,
        expires_at: Optional[float] = None,
        reason: str = "policy authored",
    ) -> PolicyLifecycleEvent:
        if not isinstance(bundle, PolicyBundle):
            raise PolicyLifecycleError("draft requires a PolicyBundle")
        owner = _non_empty(owner, "owner")
        deadline = None if expires_at is None else _finite_time(expires_at, "expires_at")
        if deadline is not None and deadline <= _finite_time(self.clock(), "lifecycle clock"):
            raise PolicyLifecycleError("policy expiry must be in the future")
        key = (bundle.policy_id, bundle.policy_version)
        existing = self._entries.get(key)
        if existing is not None:
            if existing.bundle.content_hash != bundle.content_hash:
                raise PolicyLifecycleError(f"policy {key[0]}@{key[1]} already has different content")
            return self._events[-1]
        entry = _LifecycleEntry(bundle=bundle, owner=owner, expires_at=deadline)
        self._entries[key] = entry
        return self._append_event(
            entry,
            event="drafted",
            from_state=PolicyLifecycleState.DRAFT,
            to_state=PolicyLifecycleState.DRAFT,
            reason=reason,
            actor_id=owner,
        )

    def validate(
        self,
        policy_id: str,
        version: str,
        *,
        actor_id: Optional[str] = None,
        reason: str = "policy validation passed",
    ) -> PolicyLifecycleEvent:
        entry = self._entry(policy_id, version)
        if entry.state is not PolicyLifecycleState.DRAFT:
            raise PolicyLifecycleError(f"policy must be draft to validate, got {entry.state.value}")
        try:
            entry.bundle.compile()
        except (VersioningError, ValueError) as exc:
            self._append_event(
                entry,
                event="validation_failed",
                from_state=entry.state,
                to_state=entry.state,
                reason=str(exc),
                actor_id=actor_id,
            )
            raise PolicyLifecycleError(f"policy validation failed: {exc}") from exc
        previous = entry.state
        entry.state = PolicyLifecycleState.VALIDATED
        return self._append_event(
            entry,
            event="validated",
            from_state=previous,
            to_state=entry.state,
            reason=reason,
            actor_id=actor_id,
        )

    @staticmethod
    def _snapshot(policy: PolicyBundle, case: SimulationCase) -> DecisionSnapshot:
        return DecisionSnapshot.from_decision(policy.compile().evaluate(case.action, case.context))

    def _simulation(
        self,
        candidate: PolicyBundle,
        cases: Iterable[SimulationCase],
        *,
        baseline: Optional[PolicyBundle],
    ) -> SimulationReport:
        normalized = tuple(cases)
        if len({case.case_id for case in normalized}) != len(normalized):
            raise PolicyLifecycleError("simulation case IDs must be unique")
        candidate_policy = candidate.compile()
        baseline_policy = None if baseline is None else baseline.compile()
        results = []
        for case in normalized:
            candidate_snapshot = DecisionSnapshot.from_decision(
                candidate_policy.evaluate(case.action, case.context)
            )
            baseline_snapshot = (
                None
                if baseline_policy is None
                else DecisionSnapshot.from_decision(baseline_policy.evaluate(case.action, case.context))
            )
            results.append(
                SimulationCaseResult(
                    case_id=case.case_id,
                    action_fingerprint=action_fingerprint(case.action),
                    context_fingerprint=context_fingerprint(case.context),
                    candidate=candidate_snapshot,
                    baseline=baseline_snapshot,
                    changed=baseline_snapshot is not None and candidate_snapshot != baseline_snapshot,
                )
            )
        return SimulationReport(
            policy_id=candidate.policy_id,
            candidate_version=candidate.policy_version,
            baseline_version=None if baseline is None else baseline.policy_version,
            cases=tuple(results),
            generated_at=_finite_time(self.clock(), "lifecycle clock"),
        )

    def simulate(
        self,
        policy_id: str,
        version: str,
        cases: Iterable[SimulationCase],
        *,
        baseline: Optional[PolicyBundle] = None,
        environment: str = "production",
        actor_id: Optional[str] = None,
        reason: str = "policy dry run",
    ) -> SimulationReport:
        entry = self._entry(policy_id, version)
        if entry.state not in {PolicyLifecycleState.VALIDATED}:
            raise PolicyLifecycleError("policy must be validated before simulation")
        environment = _non_empty(environment, "environment")
        if baseline is None:
            active_version = self._active.get((policy_id, environment))
            if active_version is not None:
                baseline = self._entry(policy_id, active_version).bundle
        report = self._simulation(entry.bundle, cases, baseline=baseline)
        entry.simulation = report
        self._append_event(
            entry,
            event="simulated",
            from_state=entry.state,
            to_state=entry.state,
            reason=reason,
            environment=environment,
            actor_id=actor_id,
            attributes={
                "case_count": len(report.cases),
                "changed_case_count": len(report.changed_cases),
                "baseline_version": report.baseline_version,
            },
        )
        return report

    def canary(
        self,
        policy_id: str,
        version: str,
        cases: Iterable[SimulationCase],
        *,
        baseline: Optional[PolicyBundle] = None,
        environment: str = "production",
        sample_rate: float = 1.0,
        max_changed_decisions: int = 0,
        actor_id: Optional[str] = None,
        reason: str = "policy canary evaluated",
    ) -> CanaryReport:
        entry = self._entry(policy_id, version)
        if entry.state not in {PolicyLifecycleState.VALIDATED, PolicyLifecycleState.APPROVED}:
            raise PolicyLifecycleError("policy must be validated before canary evaluation")
        environment = _non_empty(environment, "environment")
        sample_rate = _finite_time(sample_rate, "sample_rate")
        if sample_rate <= 0 or sample_rate > 1:
            raise PolicyLifecycleError("sample_rate must be greater than 0 and at most 1")
        if not isinstance(max_changed_decisions, int) or isinstance(max_changed_decisions, bool) or max_changed_decisions < 0:
            raise PolicyLifecycleError("max_changed_decisions must be a non-negative integer")
        if baseline is None:
            active_version = self._active.get((policy_id, environment))
            if active_version is None:
                raise PolicyLifecycleError("canary requires an active baseline policy")
            baseline = self._entry(policy_id, active_version).bundle
        sampled = tuple(
            case for case in cases
            if int(hashlib.sha256(case.case_id.encode("utf-8")).hexdigest()[:12], 16) / float(16**12) < sample_rate
        )
        report = CanaryReport(
            policy_id=policy_id,
            candidate_version=version,
            environment=environment,
            sample_rate=sample_rate,
            max_changed_decisions=max_changed_decisions,
            simulation=self._simulation(entry.bundle, sampled, baseline=baseline),
            passed=False,
        )
        report = CanaryReport(
            policy_id=report.policy_id,
            candidate_version=report.candidate_version,
            environment=report.environment,
            sample_rate=report.sample_rate,
            max_changed_decisions=report.max_changed_decisions,
            simulation=report.simulation,
            passed=len(report.simulation.changed_cases) <= max_changed_decisions,
        )
        entry.canaries[environment] = report
        self._append_event(
            entry,
            event="canary_passed" if report.passed else "canary_failed",
            from_state=entry.state,
            to_state=entry.state,
            reason=reason,
            environment=environment,
            actor_id=actor_id,
            attributes=report.to_dict(),
        )
        return report

    def approve(
        self,
        policy_id: str,
        version: str,
        *,
        approver_id: str,
        role: str,
        environment: str = "production",
        reason: str = "policy approved",
    ) -> tuple[PolicyApproval, ...]:
        entry = self._entry(policy_id, version)
        if entry.state not in {
            PolicyLifecycleState.VALIDATED,
            PolicyLifecycleState.APPROVED,
            PolicyLifecycleState.DEPLOYED,
            PolicyLifecycleState.SUPERSEDED,
            PolicyLifecycleState.ROLLED_BACK,
        }:
            raise PolicyLifecycleError("policy must be validated before approval")
        if entry.simulation is None:
            raise PolicyLifecycleError("policy must be simulated before approval")
        approver_id = _non_empty(approver_id, "approver_id")
        role = _non_empty(role, "approver role")
        environment = _non_empty(environment, "environment")
        if self.approver_roles and role not in self.approver_roles:
            raise PolicyLifecycleError(f"approver role {role!r} is not configured")
        key = (policy_id, version, environment)
        votes = self._approvals.setdefault(key, [])
        if any(vote.approver_id == approver_id for vote in votes):
            raise PolicyLifecycleError(f"approver {approver_id!r} already voted")
        if environment == "production" and self.approver_roles and any(
            vote.role == role for vote in votes
        ):
            raise PolicyLifecycleError(f"approver role {role!r} already voted")
        vote = PolicyApproval(approver_id, role, _non_empty(reason, "reason"), _finite_time(self.clock(), "lifecycle clock"))
        votes.append(vote)
        threshold = self.production_approval_threshold if environment == "production" else 1
        previous = entry.state
        if len(votes) >= threshold and entry.state is PolicyLifecycleState.VALIDATED:
            entry.state = PolicyLifecycleState.APPROVED
        self._append_event(
            entry,
            event="approved" if entry.state is PolicyLifecycleState.APPROVED and previous is not entry.state else "approval_recorded",
            from_state=previous,
            to_state=entry.state,
            reason=vote.reason,
            environment=environment,
            actor_id=approver_id,
            attributes={"role": role, "approval_count": len(votes), "approval_threshold": threshold},
        )
        return tuple(votes)

    def _require_production_approval(self, policy_id: str, version: str, environment: str) -> None:
        votes = self._approvals.get((policy_id, version, environment), [])
        threshold = self.production_approval_threshold if environment == "production" else 1
        if len(votes) < threshold:
            raise PolicyLifecycleError(
                f"policy requires {threshold} distinct approvals for {environment}; got {len(votes)}"
            )

    def deploy(
        self,
        policy_id: str,
        version: str,
        *,
        environment: str = "production",
        reason: str = "policy deployed",
        actor_id: Optional[str] = None,
        canary_report: Optional[CanaryReport] = None,
    ) -> PolicyLifecycleEvent:
        entry = self._entry(policy_id, version)
        environment = _non_empty(environment, "environment")
        if entry.state not in {PolicyLifecycleState.APPROVED, PolicyLifecycleState.DEPLOYED, PolicyLifecycleState.SUPERSEDED, PolicyLifecycleState.ROLLED_BACK}:
            raise PolicyLifecycleError("policy must be approved before deployment")
        self._require_production_approval(policy_id, version, environment)
        previous_version = self._active.get((policy_id, environment))
        if environment == "production":
            if previous_version is not None:
                stored_report = entry.canaries.get(environment)
                if canary_report is not None and stored_report != canary_report:
                    raise PolicyLifecycleError("supplied canary evidence is not manager-recorded")
                report = stored_report
                if (
                    report is None
                    or report.policy_id != policy_id
                    or report.candidate_version != version
                    or report.environment != environment
                    or report.simulation.baseline_version != previous_version
                ):
                    raise PolicyLifecycleError("production deployment requires a matching canary report")
                if not report.passed:
                    raise PolicyLifecycleError("production deployment blocked by failed canary")
        active_key = (policy_id, environment)
        if previous_version == version:
            return self._events[-1]
        if previous_version is not None:
            previous = self._entry(policy_id, previous_version)
            previous_state = previous.environment_states.get(environment, previous.state)
            previous.environment_states[environment] = PolicyLifecycleState.SUPERSEDED
            self._recompute_state(previous)
            self._append_event(
                previous,
                event="superseded",
                from_state=previous_state,
                to_state=PolicyLifecycleState.SUPERSEDED,
                reason=f"superseded by {version}: {reason}",
                environment=environment,
                actor_id=actor_id,
            )
        previous_state = entry.environment_states.get(environment, entry.state)
        entry.environment_states[environment] = PolicyLifecycleState.DEPLOYED
        entry.state = PolicyLifecycleState.DEPLOYED
        self._active[active_key] = version
        return self._append_event(
            entry,
            event="deployed",
            from_state=previous_state,
            to_state=entry.state,
            reason=reason,
            environment=environment,
            actor_id=actor_id,
            attributes={"previous_version": previous_version},
        )

    def promote(
        self,
        policy_id: str,
        version: str,
        *,
        from_environment: str,
        to_environment: str,
        reason: str = "policy promoted",
        actor_id: Optional[str] = None,
        canary_report: Optional[CanaryReport] = None,
    ) -> PolicyLifecycleEvent:
        source = self.current(policy_id, from_environment)
        if source.policy_version != version:
            raise PolicyLifecycleError(f"{version} is not active in {from_environment}")
        return self.deploy(
            policy_id,
            version,
            environment=to_environment,
            reason=reason,
            actor_id=actor_id,
            canary_report=canary_report,
        )

    def rollback(
        self,
        policy_id: str,
        *,
        target_version: str,
        environment: str = "production",
        reason: str,
        actor_id: Optional[str] = None,
    ) -> PolicyLifecycleEvent:
        environment = _non_empty(environment, "environment")
        current_version = self._active.get((policy_id, environment))
        if current_version is None:
            raise PolicyLifecycleError(f"no active policy for {policy_id} in {environment}")
        if current_version == target_version:
            raise PolicyLifecycleError("rollback target is already active")
        current = self._entry(policy_id, current_version)
        target = self._entry(policy_id, target_version)
        if target.state is PolicyLifecycleState.EXPIRED:
            raise PolicyLifecycleError("cannot roll back to an expired policy")
        self._require_production_approval(policy_id, target_version, environment)
        current_environment_state = current.environment_states.get(environment, current.state)
        current.environment_states[environment] = PolicyLifecycleState.ROLLED_BACK
        self._recompute_state(current)
        self._active[(policy_id, environment)] = target_version
        self._append_event(
            current,
            event="rolled_back",
            from_state=current_environment_state,
            to_state=PolicyLifecycleState.ROLLED_BACK,
            reason=reason,
            environment=environment,
            actor_id=actor_id,
            attributes={"restored_version": target_version},
        )
        target_previous = target.environment_states.get(environment, target.state)
        target.environment_states[environment] = PolicyLifecycleState.DEPLOYED
        target.state = PolicyLifecycleState.DEPLOYED
        return self._append_event(
            target,
            event="rollback_restored",
            from_state=target_previous,
            to_state=target.state,
            reason=reason,
            environment=environment,
            actor_id=actor_id,
            attributes={"replaced_version": current_version},
        )

    def monitor(self, *, now: Optional[float] = None) -> tuple[PolicyLifecycleEvent, ...]:
        current = _finite_time(self.clock() if now is None else now, "monitor time")
        events = []
        for (policy_id, environment), version in tuple(self._active.items()):
            entry = self._entry(policy_id, version)
            if entry.expires_at is None or current < entry.expires_at:
                continue
            previous = entry.environment_states.get(environment, entry.state)
            entry.environment_states[environment] = PolicyLifecycleState.EXPIRED
            self._recompute_state(entry)
            self._active.pop((policy_id, environment), None)
            events.append(self._append_event(
                entry,
                event="expired",
                from_state=previous,
                to_state=PolicyLifecycleState.EXPIRED,
                reason="policy expiry reached",
                environment=environment,
                attributes={"expires_at": entry.expires_at},
            ))
        return tuple(events)

    def current(self, policy_id: str, environment: str = "production", *, now: Optional[float] = None) -> PolicyBundle:
        self.monitor(now=now)
        version = self._active.get((_non_empty(policy_id, "policy_id"), _non_empty(environment, "environment")))
        if version is None:
            raise PolicyLifecycleError(f"no active, non-expired policy for {policy_id} in {environment}")
        return self._entry(policy_id, version).bundle

    def evaluate(
        self,
        policy_id: str,
        action: Action,
        context: Context,
        *,
        environment: str = "production",
        now: Optional[float] = None,
    ) -> Decision:
        try:
            return self.current(policy_id, environment, now=now).compile().evaluate(action, context)
        except PolicyLifecycleError as exc:
            if self.expiry_mode is PolicyExpiryMode.ESCALATE:
                return Decision(
                    DecisionKind.ESCALATE,
                    role="policy-owner",
                    reason=str(exc),
                )
            return Decision(DecisionKind.BLOCK, reason=str(exc))
