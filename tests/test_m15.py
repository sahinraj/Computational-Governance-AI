"""Acceptance tests for M15 bounded human approval lifecycle."""

import pytest

from governance import (
    Action,
    Actor,
    ApprovalError,
    ApprovalManager,
    ApprovalState,
    Capability,
    Context,
    DecisionKind,
    Interceptor,
    compile_policy,
)


def _policy():
    return compile_policy(
        """
LAW-APPROVAL
  capability: deploy.production
  requires_approval: ReleaseManager
  on_violation: escalate
""",
        roles={"ReleaseManager"},
    )


def _action():
    return Action(
        Actor("release-agent", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
        {"service": "payments"},
    )


def test_async_approval_pauses_then_resumes_once():
    policy = _policy()
    action = _action()
    context = Context(now=10)
    manager = ApprovalManager(ttl=30, request_prefix="req")
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)
    calls = []

    pending = interceptor.execute(action, context, lambda: calls.append("called"))
    assert pending.decision.kind is DecisionKind.ESCALATE
    assert pending.executed is False
    assert pending.approval_request_id == "req-0001"
    assert calls == []
    assert manager.get("req-0001").state is ApprovalState.PENDING

    manager.approve("req-0001", "ReleaseManager", policy, action, context, now=10)
    resumed = interceptor.resume_approved(
        "req-0001", action, context, lambda: calls.append("called") or "deployed"
    )
    assert resumed.decision.kind is DecisionKind.ALLOW
    assert resumed.executed is True
    assert resumed.value == "deployed"
    assert calls == ["called"]
    assert manager.get("req-0001").consumed is True

    replay = interceptor.resume_approved("req-0001", action, context, lambda: calls.append("replay"))
    assert replay.decision.kind is DecisionKind.BLOCK
    assert replay.executed is False
    assert calls == ["called"]


def test_denial_and_expiry_are_fail_closed():
    policy = _policy()
    action = _action()
    manager = ApprovalManager(ttl=5)
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)

    denied = interceptor.execute(action, Context(now=0), lambda: pytest.fail("denied operation"))
    manager.deny(denied.approval_request_id, "ReleaseManager", now=0)
    denied_result = interceptor.resume_approved(
        denied.approval_request_id, action, Context(now=0), lambda: pytest.fail("denied operation")
    )
    assert denied_result.decision.kind is DecisionKind.BLOCK
    assert manager.get(denied.approval_request_id).state is ApprovalState.DENIED

    expired = interceptor.execute(action, Context(now=10), lambda: pytest.fail("expired operation"))
    with pytest.raises(ApprovalError, match="expired"):
        manager.approve(expired.approval_request_id, "ReleaseManager", policy, action, Context(now=15), now=15)
    expired_result = interceptor.resume_approved(
        expired.approval_request_id, action, Context(now=15), lambda: pytest.fail("expired operation")
    )
    assert expired_result.decision.kind is DecisionKind.BLOCK
    assert manager.get(expired.approval_request_id).state is ApprovalState.EXPIRED


def test_approval_cannot_cross_action_context_policy_or_role():
    policy = _policy()
    action = _action()
    context = Context(now=1)
    manager = ApprovalManager(ttl=30)
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)
    pending = interceptor.execute(action, context, lambda: "never")

    with pytest.raises(ApprovalError, match="requires role"):
        manager.approve(pending.approval_request_id, "SecurityLead", policy, action, context, now=1)
    with pytest.raises(ApprovalError, match="changed action"):
        manager.approve(
            pending.approval_request_id,
            "ReleaseManager",
            policy,
            Action(action.actor, action.capability, {"service": "other"}),
            context,
            now=1,
        )
    with pytest.raises(ApprovalError, match="changed context"):
        manager.approve(
            pending.approval_request_id,
            "ReleaseManager",
            policy,
            action,
            Context(now=2),
            now=2,
        )


def test_shadow_mode_never_waits_for_approval_manager():
    policy = _policy()
    manager = ApprovalManager()
    calls = []
    result = Interceptor(policy, mode="shadow", approval_manager=manager).execute(
        _action(), Context(), lambda: calls.append("called") or "observed"
    )
    assert result.decision.kind is DecisionKind.ESCALATE
    assert result.executed is True
    assert result.value == "observed"
    assert calls == ["called"]
