"""Acceptance tests for M20 distinct-reviewer approval quorums."""

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
    ParseError,
    compile_policy,
    parse_laws,
)


ROLES = {"ReleaseManager", "SecurityLead", "FinanceLead"}


def _policy():
    return compile_policy(
        """
LAW-QUORUM
  capability: deploy.production
  authority_level: >= 4
  approval_policy: quorum 2 of ReleaseManager, SecurityLead, FinanceLead
  on_violation: escalate
""",
        roles=ROLES,
    )


def _action():
    return Action(
        Actor("release-agent", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
        {"service": "payments"},
    )


def test_quorum_requires_two_distinct_named_roles_and_resumes_once():
    policy = _policy()
    action = _action()
    context = Context(now=10)
    manager = ApprovalManager(ttl=30, request_prefix="quorum")
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)
    calls = []

    pending = interceptor.execute(action, context, lambda: calls.append("run") or "ok")
    assert pending.decision.kind is DecisionKind.ESCALATE
    assert pending.decision.role == "quorum(2/3)"
    request = manager.get(pending.approval_request_id)
    assert request.required_roles == (
        "ReleaseManager", "SecurityLead", "FinanceLead"
    )
    assert request.threshold == 2
    assert request.state is ApprovalState.PENDING
    assert calls == []

    manager.approve(pending.approval_request_id, "ReleaseManager", policy, action, context, now=10)
    assert manager.get(pending.approval_request_id).state is ApprovalState.PENDING
    with pytest.raises(ApprovalError, match="already voted"):
        manager.approve(pending.approval_request_id, "ReleaseManager", policy, action, context, now=10)
    manager.approve(pending.approval_request_id, "SecurityLead", policy, action, context, now=10)
    assert manager.get(pending.approval_request_id).state is ApprovalState.APPROVED

    resumed = interceptor.resume_approved(
        pending.approval_request_id, action, context, lambda: calls.append("run") or "ok"
    )
    assert resumed.decision.kind is DecisionKind.ALLOW
    assert resumed.value == "ok"
    replay = interceptor.resume_approved(
        pending.approval_request_id, action, context, lambda: calls.append("replay")
    )
    assert replay.decision.kind is DecisionKind.BLOCK
    assert calls == ["run"]


def test_quorum_votes_are_bound_and_reviewer_set_is_closed():
    policy = _policy()
    action = _action()
    context = Context(now=1)
    manager = ApprovalManager()
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)
    pending = interceptor.execute(action, context, lambda: "never")

    with pytest.raises(ApprovalError, match="one of"):
        manager.approve(pending.approval_request_id, "UnknownRole", policy, action, context, now=1)
    changed = Action(action.actor, action.capability, {"service": "other"})
    with pytest.raises(ApprovalError, match="changed action"):
        manager.approve(pending.approval_request_id, "ReleaseManager", policy, changed, context, now=1)
    manager.approve(pending.approval_request_id, "ReleaseManager", policy, action, context, now=1)
    manager.approve(pending.approval_request_id, "FinanceLead", policy, action, context, now=1)


def test_quorum_denial_and_expiry_fail_closed():
    policy = _policy()
    action = _action()
    context = Context(now=0)
    manager = ApprovalManager(ttl=1)
    interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)

    denied = interceptor.execute(action, context, lambda: pytest.fail("denied operation"))
    manager.deny(denied.approval_request_id, "SecurityLead", now=0)
    assert manager.get(denied.approval_request_id).state is ApprovalState.DENIED
    denied_result = interceptor.resume_approved(
        denied.approval_request_id, action, context, lambda: pytest.fail("denied operation")
    )
    assert denied_result.decision.kind is DecisionKind.BLOCK

    expired = interceptor.execute(action, Context(now=2), lambda: pytest.fail("expired operation"))
    with pytest.raises(ApprovalError, match="expired"):
        manager.approve(expired.approval_request_id, "ReleaseManager", policy, action, Context(now=3), now=3)
    assert manager.get(expired.approval_request_id, now=3).state is ApprovalState.EXPIRED


def test_quorum_parser_rejects_invalid_policies():
    with pytest.raises(ParseError, match="approval_policy"):
        parse_laws("LAW-1\n  capability: deploy\n  approval_policy: ReleaseManager\n")
    with pytest.raises(ParseError, match="threshold"):
        parse_laws(
            "LAW-1\n  capability: deploy\n  approval_policy: quorum 3 of ReleaseManager, SecurityLead\n"
        )
    with pytest.raises(ParseError, match="mutually exclusive"):
        parse_laws(
            "LAW-1\n  capability: deploy\n  requires_approval: ReleaseManager\n"
            "  approval_policy: quorum 1 of SecurityLead\n"
        )
