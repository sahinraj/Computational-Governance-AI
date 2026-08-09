"""Acceptance tests for M14 audit events and deterministic replay."""

import json

import pytest

from governance import (
    Action,
    Actor,
    AuditLog,
    Capability,
    Context,
    DecisionEvent,
    DelegationGraph,
    Interceptor,
    replay_event,
)


def _policy(source):
    from governance import compile_policy

    return compile_policy(source)


def test_audit_event_is_versioned_redacted_and_round_trips(tmp_path):
    policy = _policy("LAW-1\n  capability: payment.send\n  constraint: amount <= 100\n")
    action = Action(
        Actor("finance", 5, capabilities={"payment.send"}),
        Capability("payment.send"),
        {"amount": 50, "card_number": "secret"},
    )
    log = AuditLog()
    interceptor = Interceptor(policy, audit_log=log, trace_id="trace-7")
    interceptor.check(action, Context(now=3))

    event = log.events[0]
    payload = event.to_dict()
    assert payload["event_version"] == "1.0"
    assert payload["trace_id"] == "trace-7"
    assert "card_number" not in json.dumps(payload)
    assert "amount" not in json.dumps(payload)
    path = tmp_path / "events.jsonl"
    log.write_jsonl(path)
    restored = AuditLog.from_jsonl(path)
    assert restored.events == (DecisionEvent.from_dict(payload),)


def test_shadow_and_enforce_emit_same_semantic_check_fields():
    policy = _policy("LAW-1\n  capability: payment.send\n  authority_level: >= 6\n")
    action = Action(Actor("agent", 5), Capability("payment.send"), {"amount": 10})
    context = Context()
    shadow_log = AuditLog()
    enforce_log = AuditLog()
    Interceptor(policy, mode="shadow", audit_log=shadow_log).check(action, context)
    Interceptor(policy, mode="enforce", audit_log=enforce_log).check(action, context)
    shadow = shadow_log.events[0]
    enforce = enforce_log.events[0]
    assert shadow.decision == enforce.decision == "Block"
    assert shadow.reason == enforce.reason
    assert shadow.matched_rules == enforce.matched_rules
    assert shadow.action_fingerprint == enforce.action_fingerprint
    assert shadow.context_fingerprint == enforce.context_fingerprint
    assert shadow.mode != enforce.mode


def test_replay_detects_context_policy_and_delegation_drift():
    policy = _policy("LAW-1\n  capability: github.write\n")
    admin = Actor("admin", 5, capabilities={"github.write"})
    worker = Actor("worker", 1)
    graph = DelegationGraph()
    graph.grant(admin, worker, "github.write", depth=0)
    action = Action(worker, Capability("github.write"), {"repo": "core"})
    context = Context(now=1)
    log = AuditLog()
    Interceptor(policy, delegation=graph, audit_log=log).check(action, context)
    event = log.events[0]

    assert replay_event(event, policy, action, context, graph).exact is True
    changed_context = replay_event(event, policy, action, Context(now=2), graph)
    assert changed_context.exact is False
    assert "context" in changed_context.drift

    changed_policy = _policy("LAW-1\n  capability: github.write\n  authority_level: >= 6\n")
    policy_result = replay_event(event, changed_policy, action, context, graph)
    assert policy_result.exact is False
    assert "policy" in policy_result.drift
    graph.revoke(graph.grants()[0])
    delegation_result = replay_event(event, policy, action, context, graph)
    assert delegation_result.exact is False
    assert "state" in delegation_result.drift


def test_audit_log_rejects_duplicate_event_ids():
    event = DecisionEvent(
        event_id="event-1",
        trace_id="trace-1",
        policy_fingerprint="p",
        state_fingerprint="s",
        action_fingerprint="a",
        context_fingerprint="c",
        actor_id="agent",
        capability="payment.send",
        decision="Allow",
        role=None,
        reason="ok",
        matched_rules=(),
        authority_source="",
        authority_path=(),
        mode="enforce",
    )
    log = AuditLog([event])
    with pytest.raises(ValueError, match="duplicate audit event id"):
        log.append(event)
