"""Acceptance tests for M30 threat-model and red-team evidence."""

from __future__ import annotations

import json

import pytest

from evaluation.m30_red_team import _CASES, main, run_m30, validate_report
from governance import (
    Action,
    Actor,
    ApprovalError,
    ApprovalManager,
    Capability,
    Context,
    IdentityVerifier,
    SignedTestIdentityProvider,
    compile_policy,
)


def test_m30_red_team_report_is_exact_and_covers_required_threats():
    first = run_m30()
    second = run_m30()

    assert first == second
    assert first["exact"] is True
    assert first["failed"] == 0
    assert first["case_count"] == len(_CASES)
    assert {case["case_id"] for case in first["cases"]} == {
        "M30-REPLAY",
        "M30-IDENTITY",
        "M30-DOWNGRADE",
        "M30-STALE-APPROVAL",
        "M30-COLLUSION",
        "M30-CONFUSED-DEPUTY",
        "M30-RECOVERY",
    }
    validate_report(first)


def test_m30_cli_writes_machine_readable_evidence(tmp_path, capsys):
    output = tmp_path / "m30.json"
    assert main(["--output", str(output), "--check"]) == 0
    printed = json.loads(capsys.readouterr().out)
    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert printed == persisted
    assert persisted["milestone"] == "M30"
    assert persisted["exact"] is True


def test_secure_quorum_snapshot_rejects_reused_identity_reference():
    provider = SignedTestIdentityProvider(
        {"key-v1": b"m30-snapshot-secret"},
        trust_domain="prod.example",
        issuer="fixture-issuer",
    )
    verifier = IdentityVerifier(
        provider,
        trust_domain="prod.example",
        role_mapping={
            "requester": "Requester",
            "approver": "ReleaseManager",
            "security": "SecurityLead",
        },
    )
    requester = verifier.verify(
        provider.issue(
            "agent-1", ["requester"], now=100, ttl=60, key_id="key-v1"
        ),
        actor_id="agent-1",
        now=100,
    )
    approver = verifier.verify(
        provider.issue(
            "approver-1", ["approver"], now=100, ttl=60, key_id="key-v1"
        ),
        actor_id="approver-1",
        now=100,
    )
    policy = compile_policy(
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  approval_policy: quorum 2 of ReleaseManager, SecurityLead\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager", "SecurityLead"},
    )
    action = Action(
        Actor("agent-1", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
        identity_reference=requester.identity_reference,
        identity_roles=requester.roles,
    )
    context = Context(now=100)
    manager = ApprovalManager(require_identity=True)
    request = manager.request(policy.evaluate(action, context), policy, action, context, now=100)
    manager.approve(
        request.id, "ReleaseManager", policy, action, context,
        identity=approver, now=100,
    )
    snapshot = manager.snapshot()
    snapshot["requests"][0]["votes"] = ["ReleaseManager", "SecurityLead"]
    snapshot["requests"][0]["state"] = "approved"
    snapshot["requests"][0]["vote_identity_references"] = {
        "ReleaseManager": approver.identity_reference,
        "SecurityLead": approver.identity_reference,
    }
    with pytest.raises(ApprovalError, match="reuse an approver identity"):
        ApprovalManager.from_snapshot(snapshot)
