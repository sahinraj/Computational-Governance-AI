"""Acceptance tests for M25 transactional durable storage."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading

import pytest

from governance import (
    Action,
    Actor,
    Capability,
    ConcurrencyError,
    Context,
    DecisionEvent,
    Interceptor,
    SQLiteGovernanceStore,
    StoreError,
    compile_policy,
)


def _event(event_id: str, trace_id: str, *, now: float = 100.0) -> DecisionEvent:
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    action = Action(Actor("agent-1", 5), Capability("payment.send"))
    interceptor = Interceptor(policy, trace_id=trace_id)
    interceptor.check(action, Context(now=now))
    event = interceptor.audit_log.events[0]
    return DecisionEvent(
        event_id=event_id,
        trace_id=event.trace_id,
        policy_fingerprint=event.policy_fingerprint,
        state_fingerprint=event.state_fingerprint,
        action_fingerprint=event.action_fingerprint,
        context_fingerprint=event.context_fingerprint,
        actor_id=event.actor_id,
        capability=event.capability,
        decision=event.decision,
        role=event.role,
        reason=event.reason,
        matched_rules=event.matched_rules,
        authority_source=event.authority_source,
        authority_path=event.authority_path,
        mode=event.mode,
        executed=event.executed,
        outcome=event.outcome,
    )


def test_state_revisions_and_stale_writes_are_fail_closed(tmp_path: Path):
    store = SQLiteGovernanceStore(tmp_path / "governance.db")
    created = store.save_policy("payments", "1.0.0", {"content_hash": "abc"})
    updated = store.save_policy(
        "payments",
        "1.1.0",
        {"content_hash": "def"},
        expected_revision=created.revision,
    )
    assert updated.revision == 2
    assert store.load_policy("payments").payload["policy_version"] == "1.1.0"
    with pytest.raises(ConcurrencyError, match="stale"):
        store.save_policy(
            "payments",
            "9.0.0",
            {"content_hash": "bad"},
            expected_revision=created.revision,
        )
    assert store.load_policy("payments").revision == 2
    store.close()


def test_concurrent_compare_and_swap_accepts_one_writer(tmp_path: Path):
    store = SQLiteGovernanceStore(tmp_path / "concurrent.db")
    first = store.save_approvals("primary", {"state": "pending"})
    barrier = threading.Barrier(2)

    def write(value: str):
        barrier.wait()
        try:
            return store.save_approvals(
                "primary", {"state": value}, expected_revision=first.revision
            ).revision
        except ConcurrencyError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(write, ("approved", "denied")))
    assert sorted(results, key=str) == [2, "conflict"]
    assert store.load_approvals("primary").revision == 2


def test_audit_sequences_are_monotonic_and_duplicate_payloads_are_idempotent(tmp_path: Path):
    store = SQLiteGovernanceStore(tmp_path / "audit.db")
    events = [_event(f"evt-{index}", f"trace-{index}") for index in range(1, 9)]

    with ThreadPoolExecutor(max_workers=4) as executor:
        stored = list(executor.map(lambda item: store.append_audit(item, created_at=100), events))
    sequences = sorted(item.sequence for item in stored)
    assert sequences == list(range(1, 9))
    assert store.latest_audit_sequence() == 8
    duplicate = store.append_audit(events[0], created_at=100)
    assert duplicate.sequence == stored[0].sequence
    conflicting = DecisionEvent(
        event_id=events[0].event_id,
        trace_id="different-trace",
        policy_fingerprint=events[0].policy_fingerprint,
        state_fingerprint=events[0].state_fingerprint,
        action_fingerprint=events[0].action_fingerprint,
        context_fingerprint=events[0].context_fingerprint,
        actor_id=events[0].actor_id,
        capability=events[0].capability,
        decision=events[0].decision,
        role=events[0].role,
        reason="tampered",
        matched_rules=events[0].matched_rules,
        authority_source=events[0].authority_source,
        authority_path=events[0].authority_path,
        mode=events[0].mode,
    )
    with pytest.raises(StoreError, match="duplicate audit event conflict"):
        store.append_audit(conflicting, created_at=100)


def test_idempotency_and_execution_claims_survive_restart(tmp_path: Path):
    path = tmp_path / "restart.db"
    store = SQLiteGovernanceStore(path)
    reserved = store.begin_idempotency("decisions", "req-1", "hash-1")
    assert reserved.status == "in_progress"
    completed = store.complete_idempotency(
        "decisions",
        "req-1",
        "hash-1",
        response_status=200,
        response={"executed": True},
    )
    claim = store.claim_execution("decisions", "req-1", "claim-1")
    assert claim.status == "claimed"
    finished = store.complete_execution(
        "decisions", "req-1", "claim-1", status="succeeded", outcome={"ok": True}
    )
    store.close()

    restored = SQLiteGovernanceStore(path)
    assert restored.load_idempotency("decisions", "req-1") == completed
    assert restored.claim_execution("decisions", "req-1", "claim-1") == finished
    with pytest.raises(ConcurrencyError, match="execution claim"):
        restored.claim_execution("decisions", "req-1", "claim-2")


def test_backup_restore_retention_and_failpoint_recovery(tmp_path: Path):
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    restored_path = tmp_path / "restored.db"
    store = SQLiteGovernanceStore(source_path)
    original = store.save_grants("global", {"grants": [], "revoked": []})
    old = _event("old", "trace-old")
    current = _event("current", "trace-current")
    store.append_audit(old, created_at=10)
    store.append_audit(current, created_at=20)
    store.backup(backup_path)
    restored = SQLiteGovernanceStore.restore(backup_path, restored_path)
    assert restored.load_grants("global") == original
    assert [item.event.event_id for item in restored.load_audit()] == ["old", "current"]
    assert restored.purge_audit(before=20) == 1
    assert [item.event.event_id for item in restored.load_audit()] == ["current"]

    def crash(point: str):
        if point == "before_commit":
            raise RuntimeError("injected crash")

    crashing = SQLiteGovernanceStore(source_path, failpoint=crash)
    with pytest.raises(StoreError, match="durable transaction failed"):
        crashing.save_grants("global", {"grants": ["lost"]}, expected_revision=original.revision)
    assert crashing.load_grants("global") == original

