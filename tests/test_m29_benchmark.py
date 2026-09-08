"""Acceptance tests for the M29 realistic-trace benchmark."""

from __future__ import annotations

from evaluation.m29_benchmark import (
    M29_DATASET_VERSION,
    MessageQueueAdapter,
    WebhookGatewayAdapter,
    load_m29_scenarios,
    run_m29,
    validate_report,
)
from governancebench import score_scenarios


def test_m29_corpus_is_versioned_and_covers_required_workflows():
    scenarios = load_m29_scenarios()
    assert len(scenarios) >= 12
    assert sum(len(scenario.trace) for scenario in scenarios) >= 12
    descriptions = " ".join(scenario.description.lower() for scenario in scenarios)
    for keyword in ("deploy", "rollback", "secret", "incident", "infrastructure"):
        assert keyword in descriptions
    assert any(step.context.get("identity_valid") is False for scenario in scenarios for step in scenario.trace)
    assert any(step.context.get("malformed") for scenario in scenarios for step in scenario.trace)
    assert any(step.context.get("external_outcome") == "unknown" for scenario in scenarios for step in scenario.trace)
    assert any(step.context.get("replay") for scenario in scenarios for step in scenario.trace)
    assert any(
        any(delegate.get("expires_at") is not None for delegate in setup for delegate in [setup.get("delegate", {})])
        for scenario in scenarios
        for setup in scenario.setup
    )


def test_each_external_adapter_matches_labels_and_never_executes_non_allow():
    scenarios = load_m29_scenarios()
    for adapter in (WebhookGatewayAdapter(), MessageQueueAdapter()):
        report = score_scenarios(scenarios, adapter)
        assert report.accuracy == 1.0
        assert report.mismatches == []
        assert adapter.summary()["unauthorized_execution_attempts"] == 0
        assert adapter.summary()["executed_operations"] > 0


def test_m29_report_is_deterministic_and_schema_valid():
    first = run_m29()
    second = run_m29()
    assert first == second
    assert first["benchmark_version"] == M29_DATASET_VERSION
    validate_report(first)
    assert {item["name"] for item in first["adapters"]} == {
        "webhook-gateway",
        "message-queue",
    }
    assert first["adapters"][0]["failure_taxonomy"]["identity_failure"] == 1
    assert first["adapters"][0]["failure_taxonomy"]["delegation_expiry"] == 1
    assert first["adapters"][0]["failure_taxonomy"]["replay_attempt"] == 1
    assert first["adapters"][0]["failure_taxonomy"]["external_outcome_unknown"] == 1
