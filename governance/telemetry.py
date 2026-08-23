"""M26 redacted governance telemetry with optional local exporters.

The telemetry boundary is deliberately dependency-free.  Applications may
adapt :class:`TelemetrySink` to OpenTelemetry, but enforcement never depends
on an exporter being available.  The default collector keeps structured local
events and metrics while hashing tool parameters and redacting credentials.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol


TELEMETRY_SCHEMA_VERSION = "1.0"

DECISION_EVALUATED = "governance.decision.evaluated"
DECISION_REPLAYED = "governance.decision.replayed"
EXECUTION_COMPLETED = "governance.execution.completed"
APPROVAL_REQUESTED = "governance.approval.requested"
APPROVAL_VOTED = "governance.approval.voted"
APPROVAL_RESUMED = "governance.approval.resumed"
APPROVAL_EXPIRED = "governance.approval.expired"
RECOVERY_FAILURE = "governance.recovery.failure"


class TelemetryError(ValueError):
    """Raised when telemetry metadata cannot be represented safely."""


def _finite(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryError(f"telemetry {field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise TelemetryError(f"telemetry {field_name} must be finite")
    return result


def _fingerprint(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TelemetryError("telemetry value is not JSON-compatible") from exc
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RedactionPolicy:
    """Default-safe classification rules for structured telemetry values."""

    sensitive_keys: frozenset[str] = field(
        default_factory=lambda: frozenset({
            "authorization",
            "credential",
            "password",
            "private_key",
            "secret",
            "token",
        })
    )
    hashed_keys: frozenset[str] = field(
        default_factory=lambda: frozenset({
            "params",
            "parameters",
            "request_body",
            "tool_call",
            "tool_parameters",
        })
    )
    redacted_value: str = "[REDACTED]"

    def __post_init__(self) -> None:
        if not isinstance(self.redacted_value, str) or not self.redacted_value:
            raise TelemetryError("redacted telemetry value must be a non-empty string")
        if any(not isinstance(key, str) or not key for key in self.sensitive_keys):
            raise TelemetryError("sensitive telemetry keys must be non-empty strings")
        if any(not isinstance(key, str) or not key for key in self.hashed_keys):
            raise TelemetryError("hashed telemetry keys must be non-empty strings")

    def sanitize(self, value: Any, *, key: str | None = None) -> Any:
        """Return JSON-safe data with sensitive fields removed or hashed."""
        normalized = key.lower() if isinstance(key, str) else None
        sensitive = normalized in self.sensitive_keys or (
            normalized is not None
            and any(marker in normalized for marker in (
                "authorization", "credential", "password", "private_key", "secret", "token"
            ))
        )
        if sensitive:
            return self.redacted_value
        if normalized in self.hashed_keys:
            return {"sha256": _fingerprint(value), "classification": "hashed"}
        if isinstance(value, Mapping):
            return {
                str(item_key): self.sanitize(item_value, key=str(item_key))
                for item_key, item_value in sorted(value.items(), key=lambda item: str(item[0]))
            }
        if isinstance(value, (list, tuple)):
            return [self.sanitize(item) for item in value]
        if value is None or isinstance(value, (str, int, bool)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else self.redacted_value
        return self.redacted_value


@dataclass(frozen=True)
class TelemetryEvent:
    """Versioned, redacted event envelope with stable governance fields."""

    event_name: str
    occurred_at: float
    correlation_id: str
    decision_id: str
    policy_fingerprint: str
    policy_version: str | None = None
    actor_identity_reference: str | None = None
    approval_reference: str | None = None
    outcome: str | None = None
    latency_ms: float | None = None
    failure_reason: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    event_version: str = TELEMETRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for field_name in (
            "event_name",
            "correlation_id",
            "decision_id",
            "policy_fingerprint",
        ):
            if not isinstance(getattr(self, field_name), str) or not getattr(self, field_name):
                raise TelemetryError(f"telemetry {field_name} must be non-empty")
        if self.event_version != TELEMETRY_SCHEMA_VERSION:
            raise TelemetryError(f"unsupported telemetry version {self.event_version!r}")
        object.__setattr__(self, "occurred_at", _finite(self.occurred_at, "occurred_at"))
        if self.latency_ms is not None:
            object.__setattr__(self, "latency_ms", _finite(self.latency_ms, "latency_ms"))
        if not isinstance(self.attributes, Mapping):
            raise TelemetryError("telemetry attributes must be an object")

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_version": self.event_version,
            "event_name": self.event_name,
            "occurred_at": self.occurred_at,
            "correlation_id": self.correlation_id,
            "decision_id": self.decision_id,
            "policy_fingerprint": self.policy_fingerprint,
            "policy_version": self.policy_version,
            "actor_identity_reference": self.actor_identity_reference,
            "approval_reference": self.approval_reference,
            "outcome": self.outcome,
            "latency_ms": self.latency_ms,
            "failure_reason": self.failure_reason,
            "attributes": dict(self.attributes),
        }


class TelemetrySink(Protocol):
    """Optional event exporter contract."""

    def emit(self, event: TelemetryEvent) -> None:
        """Export one already-redacted event."""


class InMemoryTelemetrySink:
    """Thread-safe local event and metric store for tests and operators."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: list[TelemetryEvent] = []

    def emit(self, event: TelemetryEvent) -> None:
        with self._lock:
            self._events.append(event)

    def events(self) -> tuple[TelemetryEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            events = tuple(self._events)
        by_name: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        latencies = [event.latency_ms for event in events if event.latency_ms is not None]
        for event in events:
            by_name[event.event_name] = by_name.get(event.event_name, 0) + 1
            if event.outcome is not None:
                outcomes[event.outcome] = outcomes.get(event.outcome, 0) + 1
        return {
            "events_total": len(events),
            "events_by_name": dict(sorted(by_name.items())),
            "outcomes": dict(sorted(outcomes.items())),
            "latency_ms": {
                "count": len(latencies),
                "sum": sum(latencies),
                "max": max(latencies, default=0.0),
            },
        }


class JsonlTelemetrySink:
    """Optional local JSONL exporter suitable for collector/query fixtures."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def emit(self, event: TelemetryEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(payload + "\n")
            handle.flush()

    def load(self) -> tuple[dict[str, Any], ...]:
        if not self.path.exists():
            return ()
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            return tuple(json.loads(line) for line in handle if line.strip())


class TelemetryCollector:
    """Record safe local telemetry and fan out to optional exporters."""

    def __init__(
        self,
        *,
        sinks: Iterable[TelemetrySink] = (),
        redaction: RedactionPolicy | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.redaction = redaction or RedactionPolicy()
        self.clock = clock
        self.memory = InMemoryTelemetrySink()
        self.sinks = tuple(sinks)
        self.export_failures = 0
        self._lock = threading.RLock()

    def emit(
        self,
        event_name: str,
        *,
        correlation_id: str,
        decision_id: str,
        policy_fingerprint: str,
        policy_version: str | None = None,
        actor_identity_reference: str | None = None,
        approval_reference: str | None = None,
        outcome: str | None = None,
        latency_ms: float | None = None,
        failure_reason: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> TelemetryEvent:
        safe_attributes = self.redaction.sanitize(attributes or {})
        event = TelemetryEvent(
            event_name=event_name,
            occurred_at=self.clock(),
            correlation_id=correlation_id,
            decision_id=decision_id,
            policy_fingerprint=policy_fingerprint,
            policy_version=policy_version,
            actor_identity_reference=actor_identity_reference,
            approval_reference=approval_reference,
            outcome=outcome,
            latency_ms=latency_ms,
            failure_reason=failure_reason,
            attributes=safe_attributes,
        )
        self.memory.emit(event)
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:
                # Exporter health must never change governance enforcement.
                with self._lock:
                    self.export_failures += 1
        return event

    def events(self) -> tuple[TelemetryEvent, ...]:
        return self.memory.events()

    def metrics(self) -> dict[str, Any]:
        metrics = self.memory.metrics()
        metrics["export_failures"] = self.export_failures
        return metrics
