"""Acceptance tests for milestones M4 through M8."""

import logging

import pytest

from governance import (
    Action,
    Actor,
    ApprovalStub,
    Capability,
    CompileError,
    Context,
    DecisionKind,
    DelegationError,
    DelegationGraph,
    InheritanceError,
    Interceptor,
    InterceptorMode,
    compile_policy,
    evaluate_rules,
    inherit_rules,
    parse_laws,
)


def _policy(source, *, roles=None):
    return compile_policy(source, roles=roles)


def _action(capability="payment.send", **params):
    return Action(Actor("agent", 5), Capability(capability), params)


# M4 — composition and inheritance

def test_composition_all_pass_and_no_applicable_rule_allow():
    rules = parse_laws("LAW-1\n  capability: payment.send\n  authority_level: >= 3\n")
    assert evaluate_rules(rules, _action(), Context()).kind is DecisionKind.ALLOW
    assert evaluate_rules(rules, _action("deploy.production"), Context()).kind is DecisionKind.ALLOW


def test_block_wins_over_escalate_and_order_does_not_matter():
    source = """
LAW-A
  capability: payment
  constraint: amount <= 100
  on_violation: escalate
  requires_approval: FinanceLead
LAW-B
  capability: payment.send
  constraint: amount <= 50
  on_violation: block
"""
    rules = parse_laws(source)
    action = _action(amount=150)
    first = evaluate_rules(rules, action, Context())
    second = evaluate_rules(tuple(reversed(rules)), action, Context())
    assert first.kind is DecisionKind.BLOCK
    assert second == first
    assert first.matched_rules == ("LAW-A", "LAW-B")


def test_escalation_is_first_class_and_names_role():
    rules = parse_laws("""
LAW-1
  capability: payment.send
  constraint: amount <= 100
  requires_approval: FinanceLead
  on_violation: escalate
""")
    decision = evaluate_rules(rules, _action(amount=101), Context())
    assert decision.kind is DecisionKind.ESCALATE
    assert decision.role == "FinanceLead"


def test_inheritance_retains_parent_and_allows_tightening():
    parent = parse_laws("""
LAW-P
  capability: payment
  authority_level: >= 3
  constraint: amount <= 100
  on_violation: block
""")
    child = parse_laws("""
LAW-C
  parent: LAW-P
  capability: payment.send
  authority_level: >= 4
  constraint: amount <= 50
  on_violation: block
""")
    combined = inherit_rules(parent, child)
    decision = evaluate_rules(combined, _action(amount=75), Context())
    assert decision.kind is DecisionKind.BLOCK
    assert decision.matched_rules == ("LAW-C", "LAW-P")


def test_inheritance_rejects_attempted_loosening():
    parent = parse_laws("LAW-P\n  capability: payment\n  authority_level: >= 3\n")
    weaker = parse_laws("""
LAW-C
  parent: LAW-P
  capability: payment.send
  authority_level: >= 2
""")
    with pytest.raises(InheritanceError, match="lowers authority"):
        inherit_rules(parent, weaker)


# M5 — compiler and validation

def test_compiler_rejects_contradictory_rules_with_named_reason():
    with pytest.raises(CompileError, match="contradictory_rules"):
        _policy("""
LAW-A
  capability: payment.send
  constraint: amount <= 100
  on_violation: block
LAW-B
  capability: payment.send
  constraint: amount <= 100
  on_violation: escalate
""")


def test_compiler_rejects_dangling_approval_role():
    with pytest.raises(CompileError, match="dangling_role"):
        _policy("""
LAW-1
  capability: deploy.production
  requires_approval: Reviewer
  on_violation: escalate
""", roles={"FinanceLead"})


def test_compiler_emits_deterministic_policy_artifact():
    policy = _policy("LAW-1\n  capability: payment.send\n")
    assert len(policy.rules) == 1
    assert policy.evaluate(_action(), Context()).kind is DecisionKind.ALLOW


def test_compiler_supports_explicit_default_deny():
    policy = _policy("LAW-1\n  capability: payment.send\n", roles=None)
    strict = compile_policy("LAW-1\n  capability: payment.send\n", default_decision="Block")
    action = _action("unclassified.action")
    assert policy.evaluate(action, Context()).kind is DecisionKind.ALLOW
    assert strict.evaluate(action, Context()).kind is DecisionKind.BLOCK


def test_compiler_validates_parent_links_in_one_source():
    policy = _policy("""
LAW-P
  capability: payment
  authority_level: >= 3
LAW-C
  parent: LAW-P
  capability: payment.send
  authority_level: >= 4
""")
    assert [rule.id for rule in policy.rules] == ["LAW-P", "LAW-C"]


def test_compiler_rejects_missing_parent():
    with pytest.raises(CompileError, match="dangling_parent"):
        _policy("""
LAW-C
  parent: LAW-MISSING
  capability: payment.send
""")


# M6 — interceptor and shadow mode

def test_shadow_mode_logs_and_executes_blocked_action(caplog):
    policy = _policy("""
LAW-1
  capability: payment.send
  authority_level: >= 6
  on_violation: block
""")
    interceptor = Interceptor(policy, mode=InterceptorMode.SHADOW, logger=logging.getLogger("test"))
    with caplog.at_level(logging.INFO):
        result = interceptor.execute(_action(), Context(), lambda: "executed")
    assert result.decision.kind is DecisionKind.BLOCK
    assert result.executed is True
    assert result.value == "executed"
    assert interceptor.events[0]["decision"] == "Block"
    assert "governance decision" in caplog.text


def test_enforce_mode_blocks_before_operation():
    policy = _policy("LAW-1\n  capability: payment.send\n  authority_level: >= 6\n")
    calls = []
    result = Interceptor(policy, mode="enforce").execute(
        _action(), Context(), lambda: calls.append("called")
    )
    assert result.executed is False
    assert calls == []


# M7 — delegation graph

def test_delegation_grant_revoke_and_derived_authority():
    admin = Actor("admin", 5, capabilities={"github.write"})
    worker = Actor("worker", 2)
    child = Actor("child", 1)
    graph = DelegationGraph()
    grant = graph.grant(admin, worker, "github.write", depth=1)
    child_grant = graph.grant(worker, child, "github.write", depth=0)
    assert child_grant.parent_grant_id == grant.id
    assert graph.has_authority(child, "github.write") is True
    graph.revoke(grant)
    assert graph.has_authority(worker, "github.write") is False
    assert graph.has_authority(child, "github.write") is False


def test_delegation_rejects_excess_depth_and_expiry():
    admin = Actor("admin", 5, capabilities={"github.write"})
    worker = Actor("worker", 2)
    graph = DelegationGraph()
    with pytest.raises(DelegationError, match="does not hold valid authority"):
        # No parent delegation exists for worker yet.
        graph.grant(worker, "child", "github.write", depth=0)
    grant = graph.grant(admin, worker, "github.write", depth=0, expires_at=10)
    assert graph.has_authority(worker, "github.write", now=9) is True
    assert graph.has_authority(worker, "github.write", now=10) is False
    assert grant.id in graph.expire(10)


def test_delegation_rejects_actor_cycles():
    admin = Actor("admin", 5, capabilities={"github.write"})
    first = Actor("first", 3)
    second = Actor("second", 3)
    graph = DelegationGraph()
    graph.grant(admin, first, "github.write", depth=2)
    graph.grant(first, second, "github.write", depth=1)
    with pytest.raises(DelegationError, match="cycle"):
        graph.grant(second, first, "github.write", depth=0)


# M8 — enforce mode and escalation

def test_enforce_mode_approval_allows_and_resumes_operation():
    policy = _policy("""
LAW-1
  capability: deploy.production
  requires_approval: ReleaseManager
  on_violation: escalate
""", roles={"ReleaseManager"})
    approval = ApprovalStub({"ReleaseManager": True})
    result = Interceptor(
        policy,
        mode=InterceptorMode.ENFORCE,
        approval_handler=approval.request,
    ).execute(
        Action(Actor("agent", 5), Capability("deploy.production")),
        Context(),
        lambda: "deployed",
    )
    assert result.initial_decision.kind is DecisionKind.ESCALATE
    assert result.decision.kind is DecisionKind.ALLOW
    assert result.executed is True
    assert result.value == "deployed"
    assert approval.requests == [("ReleaseManager", "agent", "deploy.production")]


def test_enforce_mode_denied_escalation_does_not_execute():
    policy = _policy("""
LAW-1
  capability: deploy.production
  requires_approval: ReleaseManager
  on_violation: escalate
""", roles={"ReleaseManager"})
    result = Interceptor(
        policy,
        mode="enforce",
        approval_handler=ApprovalStub({"ReleaseManager": False}).request,
    ).execute(
        Action(Actor("agent", 5), Capability("deploy.production")),
        Context(),
        lambda: pytest.fail("operation should not execute"),
    )
    assert result.decision.kind is DecisionKind.BLOCK
    assert result.executed is False
