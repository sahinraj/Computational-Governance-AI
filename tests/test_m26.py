"""Acceptance tests for M26 redacted decision observability."""

from __future__ import annotations

import json

import pytest

from governance import (
    Actor,
    GovernanceService,
    Interceptor,
    InterceptorMode,
    JsonlTelemetrySink,
    RedactionPolicy,
    RuntimeAdapter,
    ServiceError,
    TelemetryCollector,
    compile_policy,
)


def test_redaction_and_local_export_never_emit_sensitive_values(tmp_path):
    sink = JsonlTelemetrySink(tmp_path / "telemetry.jsonl")
    telemetry = TelemetryCollector(sinks=[sink], clock=lambda: 100.0)
    telemetry.emit(
        "governance.test",
        correlation_id="corr-1",
        decision_id="decision-1",
        policy_fingerprint="policy-hash",
        policy_version="1.0.0",
        attributes={
            "params": {"amount": 10, "secret": "do-not-emit"},
            "credential": {"token": "credential-secret"},
            "api_token": "another-secret",
            "safe": "visible",
        },
    )

    encoded = json.dumps(sink.load())
    assert "do-not-emit" not in encoded
    assert "credential-secret" not in encoded
    assert "another-secret" not in encoded
    assert telemetry.events()[0].attributes["safe"] == "visible"
    assert telemetry.metrics()["events_total"] == 1
    assert telemetry.metrics()["export_failures"] == 0


def test_service_propagates_ids_and_records_allow_block_and_replay_without_params():
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    telemetry = TelemetryCollector(clock=lambda: 100.0)
    calls = []
    service = GovernanceService(
        RuntimeAdapter(Interceptor(policy, mode=InterceptorMode.ENFORCE)),
        actor_registry={"agent-1": Actor("agent-1", 5)},
        handlers={"payment.send": lambda params: calls.append(params) or "sent"},
        telemetry=telemetry,
        policy_version="1.0.0",
        clock=lambda: 100.0,
    )
    request = {
        "actor": {
            "id": "agent-1",
            "authority_level": 999,
            "class": "root",
            "capabilities": ["root.admin"],
        },
        "capability": "payment.send",
        "params": {"secret": "must-not-appear"},
        "idempotency_key": "m26-allow-1",
    }
    first = service.handle("POST", "/v1/decisions", request)
    replay = service.handle("POST", "/v1/decisions", request)

    assert first.status == replay.status == 200
    assert first.body["correlation_id"]
    assert first.body["decision_id"]
    assert first.body == replay.body
    assert calls == [{"secret": "must-not-appear"}]
    names = [event.event_name for event in telemetry.events()]
    assert "governance.decision.evaluated" in names
    assert "governance.execution.completed" in names
    assert "governance.decision.replayed" in names
    for event in telemetry.events():
        assert event.policy_version == "1.0.0"
        assert "must-not-appear" not in json.dumps(event.to_dict())


def test_authenticated_service_rejects_mismatched_registry_keys():
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    runtime = RuntimeAdapter(Interceptor(policy, mode=InterceptorMode.ENFORCE))
    with pytest.raises(ServiceError, match="actor registry"):
        GovernanceService(
            runtime,
            actor_registry={"agent-1": Actor("attacker", 10)},
            handlers={"payment.send": lambda params: None},
        )


def test_custom_redaction_keys_are_supported():
    policy = RedactionPolicy(sensitive_keys=frozenset({"internal_id"}))
    telemetry = TelemetryCollector(redaction=policy)
    event = telemetry.emit(
        "governance.test",
        correlation_id="corr-2",
        decision_id="decision-2",
        policy_fingerprint="policy-hash",
        attributes={"internal_id": "private", "visible": "yes"},
    )
    assert event.attributes == {"internal_id": "[REDACTED]", "visible": "yes"}
