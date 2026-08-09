"""Acceptance tests for M18 durable state and crash-safe recovery."""

import json

import pytest

from governance import (
    Action,
    Actor,
    ApprovalManager,
    ApprovalState,
    AtomicJsonStore,
    AuditLog,
    Capability,
    Context,
    DelegationGraph,
    Interceptor,
    JsonlAuditStore,
    StoreError,
    compile_policy,
)


def _approval_policy():
    return compile_policy(
        """
LAW-APPROVAL
  capability: deploy.production
  requires_approval: ReleaseManager
  on_violation: escalate
""",
        roles={"ReleaseManager"},
    )


def _approval_action():
    actor = Actor("release-agent", 5, capabilities={"deploy.production"})
    return Action(actor, Capability("deploy.production"), {"service": "payments"})


def test_delegation_snapshot_restores_authority_and_revocation(tmp_path):
    admin = Actor("admin", 5, capabilities={"github.write"})
    worker = Actor("worker", 2)
    graph = DelegationGraph()
    grant = graph.grant(admin, worker, "github.write", depth=1, expires_at=100)
    store = AtomicJsonStore(tmp_path / "delegation.json")
    store.save(graph.snapshot())

    restored = DelegationGraph.from_snapshot(store.load())
    assert restored.authority_proof(worker, "github.write", now=10).path == (grant.id,)
    assert restored.has_authority(worker, "github.write", now=99)
    restored.revoke(grant.id)
    store.save(restored.snapshot())
    revoked = DelegationGraph.from_snapshot(store.load())
    assert not revoked.has_authority(worker, "github.write", now=10)
    assert revoked._next_id == graph._next_id


def test_approval_snapshot_preserves_single_use_terminal_state(tmp_path):
    policy = _approval_policy()
    action = _approval_action()
    context = Context(now=10)
    manager = ApprovalManager(ttl=30, request_prefix="req")
    request = manager.request(
        policy.evaluate(action, context), policy, action, context, now=10
    )
    manager.approve(request.id, "ReleaseManager", policy, action, context, now=10)
    manager.prepare_resume(request.id, policy, action, context, now=10)
    store = AtomicJsonStore(tmp_path / "approvals.json")
    store.save(manager.snapshot())

    restored = ApprovalManager.from_snapshot(store.load())
    recovered = restored.get(request.id, now=10)
    assert recovered.state is ApprovalState.APPROVED
    assert recovered.consumed is True
    with pytest.raises(ValueError, match="consumed"):
        restored.prepare_resume(request.id, policy, action, context, now=10)


def test_audit_jsonl_recovery_continues_trace_sequence(tmp_path):
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    action = Action(
        Actor("agent", 5, capabilities={"payment.send"}),
        Capability("payment.send"),
    )
    context = Context(now=1)
    log = AuditLog()
    first = Interceptor(policy, audit_log=log, trace_id="trace-7")
    first.check(action, context)
    store = JsonlAuditStore(tmp_path / "audit.jsonl")
    store.append(log.events[0])

    recovered_log = store.load()
    second = Interceptor(policy, audit_log=recovered_log, trace_id="trace-7")
    second.check(action, context)
    assert [event.event_id for event in recovered_log.events] == [
        "trace-7-0001", "trace-7-0002"
    ]
    assert len(store.load().events) == 1


def test_corrupt_or_incompatible_snapshots_fail_closed(tmp_path):
    path = tmp_path / "state.json"
    store = AtomicJsonStore(path)
    store.save({"safe": True})
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(StoreError, match="could not read"):
        store.load()

    path.write_text(
        json.dumps({"store_version": "9.0", "payload": {"safe": True}}),
        encoding="utf-8",
    )
    with pytest.raises(StoreError, match="unsupported store version"):
        store.load()


def test_delegation_snapshot_rejects_unknown_parent_and_revocation():
    base = {
        "schema_version": "1.0",
        "intrinsic": {},
        "grants": [{
            "id": "G-0001",
            "from_actor": "admin",
            "to_actor": "worker",
            "capability": "github.write",
            "depth": 0,
            "parent_grant_id": "G-9999",
        }],
        "revoked": ["G-9999"],
        "next_id": 2,
    }
    with pytest.raises(ValueError, match="revoked grant"):
        DelegationGraph.from_snapshot(base)
