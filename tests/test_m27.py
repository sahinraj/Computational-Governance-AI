"""Acceptance tests for M27 policy lifecycle and controlled rollout."""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from governance import (
    Action,
    Actor,
    Context,
    DecisionKind,
    PolicyBundle,
    PolicyExpiryMode,
    PolicyLifecycleError,
    PolicyLifecycleManager,
    PolicyLifecycleState,
    SimulationCase,
    TelemetryCollector,
    compile_policy,
)


V1 = """
LAW-PAYMENT
  capability: payment.send
  constraint: amount <= 100
  on_violation: block
"""

V2 = """
LAW-PAYMENT
  capability: payment.send
  constraint: amount <= 50
  on_violation: block
"""


def _bundle(source: str, version: str) -> PolicyBundle:
    return PolicyBundle.from_source(source, policy_id="payments", policy_version=version)


def _case(amount: int, case_id: str = "payment-75") -> SimulationCase:
    return SimulationCase(
        case_id,
        Action(Actor("agent-1", 5), compile_policy(V1).rules[0].capability, {"amount": amount}),
        Context(now=100.0),
    )


def _approve(manager: PolicyLifecycleManager, version: str) -> None:
    manager.approve(
        "payments", version, approver_id="security-1", role="SecurityLead"
    )
    manager.approve(
        "payments", version, approver_id="release-1", role="ReleaseManager"
    )


def test_policy_moves_through_auditable_production_rollout_and_rollback():
    now = [100.0]
    telemetry = TelemetryCollector(clock=lambda: now[0])
    manager = PolicyLifecycleManager(
        production_approval_threshold=2,
        approver_roles={"SecurityLead", "ReleaseManager"},
        telemetry=telemetry,
        clock=lambda: now[0],
    )
    v1 = _bundle(V1, "1.0.0")
    v2 = _bundle(V2, "1.1.0")

    manager.draft(v1, owner="policy-owner")
    manager.validate("payments", "1.0.0")
    initial = manager.simulate("payments", "1.0.0", [_case(75)])
    assert initial.baseline_version is None
    _approve(manager, "1.0.0")
    manager.deploy("payments", "1.0.0", reason="initial production activation")
    assert manager.current("payments").policy_version == "1.0.0"
    manager.approve(
        "payments", "1.0.0", approver_id="release-1", role="ReleaseManager",
        environment="staging",
    )
    manager.promote(
        "payments", "1.0.0", from_environment="production",
        to_environment="staging", reason="promote to staging",
    )
    assert manager.current("payments", "staging").policy_version == "1.0.0"

    manager.draft(v2, owner="policy-owner")
    manager.validate("payments", "1.1.0")
    simulation = manager.simulate("payments", "1.1.0", [_case(75)])
    assert simulation.baseline_version == "1.0.0"
    assert [case.case_id for case in simulation.changed_cases] == ["payment-75"]
    canary = manager.canary(
        "payments",
        "1.1.0",
        [_case(75)],
        sample_rate=1.0,
        max_changed_decisions=1,
    )
    assert canary.passed is True
    _approve(manager, "1.1.0")
    manager.deploy("payments", "1.1.0", reason="controlled production rollout")
    assert manager.current("payments").policy_version == "1.1.0"
    assert manager.record("payments", "1.0.0").state is PolicyLifecycleState.SUPERSEDED

    manager.rollback(
        "payments",
        target_version="1.0.0",
        reason="new threshold rejected valid payment traffic",
    )
    assert manager.current("payments").policy_version == "1.0.0"
    assert manager.record("payments", "1.1.0").state is PolicyLifecycleState.ROLLED_BACK
    assert any(
        change["path"].startswith("rules.LAW-PAYMENT.predicate")
        for change in manager.diff("1.0.0", "1.1.0", policy_id="payments")["changes"]
    )
    assert [event.event for event in manager.events].count("deployed") == 3
    assert "rolled_back" in [event.event for event in manager.events]
    assert any(event.event_name == "governance.policy.lifecycle" for event in telemetry.events())


def test_production_deployment_requires_two_distinct_approvals_and_canary():
    manager = PolicyLifecycleManager(
        production_approval_threshold=2,
        approver_roles={"SecurityLead", "ReleaseManager"},
    )
    bundle = _bundle(V1, "1.0.0")
    manager.draft(bundle, owner="policy-owner")
    manager.validate("payments", "1.0.0")
    manager.simulate("payments", "1.0.0", [_case(10)])
    manager.approve(
        "payments", "1.0.0", approver_id="security-1", role="SecurityLead"
    )
    with pytest.raises(PolicyLifecycleError, match="approved"):
        manager.deploy("payments", "1.0.0")


def test_stale_canary_evidence_cannot_authorize_against_a_new_baseline():
    manager = PolicyLifecycleManager(production_approval_threshold=1)
    v1 = _bundle(V1, "1.0.0")
    v2 = _bundle(V2, "1.1.0")
    v3 = _bundle(V1.replace("<= 100", "<= 25"), "1.2.0")
    for bundle in (v1, v2, v3):
        manager.draft(bundle, owner="policy-owner")
        manager.validate("payments", bundle.policy_version)
    manager.simulate("payments", "1.0.0", [_case(10)])
    manager.approve("payments", "1.0.0", approver_id="owner-1", role="Owner")
    manager.deploy("payments", "1.0.0")
    manager.simulate("payments", "1.1.0", [_case(75)])
    canary = manager.canary(
        "payments", "1.1.0", [_case(75)], sample_rate=1.0,
        max_changed_decisions=1,
    )
    manager.approve("payments", "1.1.0", approver_id="owner-1", role="Owner")
    manager.deploy("payments", "1.1.0", canary_report=canary)
    manager.simulate("payments", "1.2.0", [_case(10)])
    manager.approve("payments", "1.2.0", approver_id="owner-1", role="Owner")
    with pytest.raises(PolicyLifecycleError, match="matching canary"):
        manager.deploy("payments", "1.2.0", canary_report=canary)


def test_invalid_policy_cannot_be_validated_or_deployed():
    manager = PolicyLifecycleManager()
    valid = _bundle(V1, "1.0.0")
    invalid = replace(valid, source="not a policy")
    manager.draft(invalid, owner="policy-owner")
    with pytest.raises(PolicyLifecycleError, match="validation failed"):
        manager.validate("payments", "1.0.0")
    assert manager.record("payments", "1.0.0").state is PolicyLifecycleState.DRAFT
    with pytest.raises(PolicyLifecycleError, match="approved"):
        manager.deploy("payments", "1.0.0")


def test_expiry_is_visible_and_fails_closed_or_escalates():
    now = [100.0]
    manager = PolicyLifecycleManager(
        production_approval_threshold=1,
        clock=lambda: now[0],
    )
    bundle = _bundle(V1, "1.0.0")
    manager.draft(bundle, owner="policy-owner", expires_at=101.0)
    manager.validate("payments", "1.0.0")
    manager.simulate("payments", "1.0.0", [_case(10)])
    manager.approve(
        "payments", "1.0.0", approver_id="owner-1", role="Owner"
    )
    manager.deploy("payments", "1.0.0")
    now[0] = 101.0
    expired = manager.monitor()
    assert len(expired) == 1
    assert expired[0].to_state is PolicyLifecycleState.EXPIRED
    decision = manager.evaluate(
        "payments", _case(10).action, _case(10).context, now=101.0
    )
    assert decision.kind is DecisionKind.BLOCK

    escalating = PolicyLifecycleManager(
        production_approval_threshold=1,
        expiry_mode=PolicyExpiryMode.ESCALATE,
        clock=lambda: now[0],
    )
    escalating.draft(_bundle(V1, "2.0.0"), owner="policy-owner", expires_at=102.0)
    escalating.validate("payments", "2.0.0")
    escalating.simulate("payments", "2.0.0", [_case(10)])
    escalating.approve(
        "payments", "2.0.0", approver_id="owner-1", role="Owner"
    )
    escalating.deploy("payments", "2.0.0")
    decision = escalating.evaluate(
        "payments", _case(10).action, _case(10).context, now=102.0
    )
    assert decision.kind is DecisionKind.ESCALATE


def test_policy_rollout_cli_executes_auditable_initial_deployment(tmp_path, capsys):
    policy_path = tmp_path / "payments.law"
    policy_path.write_text(V1, encoding="utf-8")
    from governance.cli import main

    assert main([
        "policy-rollout",
        str(policy_path),
        "--policy-id", "payments",
        "--policy-version", "1.0.0",
        "--owner", "policy-owner",
        "--approver", "security-1:SecurityLead",
        "--approver", "release-1:ReleaseManager",
        "--actor-id", "agent-1",
        "--capability", "payment.send",
        "--actor-capability", "payment.send",
        "--params", '{"amount": 10}',
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["record"]["state"] == "deployed"
    assert payload["events"][-1]["event"] == "deployed"
