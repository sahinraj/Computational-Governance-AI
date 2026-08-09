"""Acceptance tests for M21's end-to-end integration surface."""

import json
import re
from pathlib import Path

from governance import (
    Action,
    Actor,
    ApprovalManager,
    AtomicJsonStore,
    AuditLog,
    Capability,
    Context,
    DelegationGraph,
    Interceptor,
    JsonlAuditStore,
    compile_policy,
    replay_event,
)


def test_phase3_end_to_end_persistence_quorum_and_replay(tmp_path):
    policy = compile_policy(
        """
LAW-E2E
  capability: deploy.production
  approval_policy: quorum 2 of ReleaseManager, SecurityLead, FinanceLead
  on_violation: escalate
""",
        roles={"ReleaseManager", "SecurityLead", "FinanceLead"},
    )
    admin = Actor("admin", 5, capabilities={"deploy.production"})
    worker = Actor("worker", 5)
    graph = DelegationGraph()
    graph.grant(admin, worker, "deploy.production", depth=0)
    graph_store = AtomicJsonStore(tmp_path / "state" / "delegation.json")
    graph_store.save(graph.snapshot())
    recovered_graph = DelegationGraph.from_snapshot(graph_store.load())
    assert recovered_graph.has_authority(worker, "deploy.production")

    action = Action(worker, Capability("deploy.production"), {"service": "payments"})
    context = Context(now=10)
    approval = ApprovalManager(ttl=30, request_prefix="e2e")
    audit = AuditLog()
    interceptor = Interceptor(
        policy,
        mode="enforce",
        delegation=recovered_graph,
        approval_manager=approval,
        audit_log=audit,
        trace_id="phase3",
    )
    pending = interceptor.execute(action, context, lambda: "deployed")
    approval.approve(pending.approval_request_id, "ReleaseManager", policy, action, context, delegation=recovered_graph, now=10)
    approval_store = AtomicJsonStore(tmp_path / "state" / "approvals.json")
    approval_store.save(approval.snapshot())
    recovered_approval = ApprovalManager.from_snapshot(approval_store.load())
    recovered_approval.approve(pending.approval_request_id, "SecurityLead", policy, action, context, delegation=recovered_graph, now=10)
    interceptor.approval_manager = recovered_approval
    resumed = interceptor.resume_approved(
        pending.approval_request_id, action, context, lambda: "deployed"
    )
    assert resumed.executed is True

    audit_store = JsonlAuditStore(tmp_path / "audit" / "events.jsonl")
    for event in audit.events:
        audit_store.append(event)
    recovered_audit = audit_store.load()
    assert [event.event_id for event in recovered_audit.events] == [
        "phase3-0001", "phase3-0002"
    ]
    replay = replay_event(recovered_audit.events[0], policy, action, context, recovered_graph)
    assert replay.exact


def test_cli_validate_and_assurance_commands(tmp_path, capsys):
    from governance.cli import main

    policy_path = tmp_path / "policy.law"
    policy_path.write_text("LAW-1\n  capability: payment.send\n", encoding="utf-8")
    assert main(["validate-policy", str(policy_path)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main([
        "tool-call", "--policy", str(policy_path), "--actor-id", "agent",
        "--authority-level", "5", "--actor-capability", "payment.send",
        "--capability", "payment.send",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "Allow"

    audit_path = tmp_path / "events.jsonl"
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    log = AuditLog()
    action = Action(
        Actor("agent", 5, capabilities={"payment.send"}), Capability("payment.send")
    )
    Interceptor(policy, audit_log=log, trace_id="cli").check(action, Context())
    JsonlAuditStore(audit_path).append(log.events[0])
    assert main([
        "audit-replay", "--policy", str(policy_path), "--audit", str(audit_path),
        "--event-id", "cli-0001", "--actor-id", "agent", "--authority-level", "5",
        "--actor-capability", "payment.send", "--capability", "payment.send",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["exact"] is True
    assert main(["assurance", "--traces", "2", "--seed", "7"]) == 0
    assert json.loads(capsys.readouterr().out)["exact"] is True


def test_release_metadata_is_v030():
    text = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'^version = "0\.3\.0"$', text, re.MULTILINE)
