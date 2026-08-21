"""Regression tests for merged-PR review findings remediated after audit."""

from __future__ import annotations

import math

import pytest

from governance import (
    Action,
    Actor,
    ApprovalError,
    ApprovalManager,
    Capability,
    ConcurrencyError,
    Context,
    DelegationError,
    DelegationGraph,
    DecisionKind,
    Interceptor,
    ParseError,
    PolicyBundle,
    SQLiteGovernanceStore,
    VersioningError,
    compile_policy,
    parse_laws,
    state_fingerprint,
)


def _approval_setup(ttl: float = 1.0):
    policy = compile_policy(
        "LAW-APPROVAL\n"
        "  capability: deploy.production\n"
        "  approval_policy: quorum 2 of ReleaseManager, SecurityLead\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager", "SecurityLead"},
    )
    action = Action(
        Actor("agent", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
    )
    context = Context(now=0)
    manager = ApprovalManager(ttl=ttl)
    pending = Interceptor(policy, mode="enforce", approval_manager=manager).execute(
        action, context, lambda: "never"
    )
    return policy, action, context, manager, pending.approval_request_id


def test_approved_requests_expire_before_resume_and_snapshot_quorum_is_consistent():
    policy, action, context, manager, request_id = _approval_setup()
    manager.approve(request_id, "ReleaseManager", policy, action, context, now=0)
    manager.approve(request_id, "SecurityLead", policy, action, context, now=0)
    with pytest.raises(ApprovalError, match="expired"):
        manager.prepare_resume(request_id, policy, action, context, now=2)

    snapshot = manager.snapshot()
    snapshot["requests"][0]["votes"] = []
    snapshot["requests"][0]["state"] = "approved"
    with pytest.raises(ApprovalError, match="threshold"):
        ApprovalManager.from_snapshot(snapshot)


def test_delegation_rejects_empty_scope_bad_parent_and_counter_collision():
    graph = DelegationGraph(intrinsic={"admin": {"github.write"}})
    with pytest.raises(DelegationError, match="scope cannot be empty"):
        graph.grant("admin", "worker", "github.write", scope="")

    invalid = {
        "schema_version": "1.0",
        "intrinsic": {"admin": ["github.write"]},
        "grants": [{
            "id": "G-0001",
            "from_actor": "not-other",
            "to_actor": "worker",
            "capability": "github.write",
            "depth": 0,
            "parent_grant_id": "G-0002",
        }, {
            "id": "G-0002",
            "from_actor": "admin",
            "to_actor": "other",
            "capability": "github.write",
            "depth": 1,
        }],
        "revoked": [],
        "next_id": 3,
    }
    with pytest.raises(DelegationError, match="grant parent must belong"):
        DelegationGraph.from_snapshot(invalid)

    collision = dict(invalid)
    collision["grants"] = [dict(invalid["grants"][1])]
    collision["next_id"] = 2
    with pytest.raises(DelegationError, match="collide"):
        DelegationGraph.from_snapshot(collision)


def test_intrinsic_registration_changes_state_binding_and_parser_is_order_independent():
    policy = compile_policy("LAW-1\n  capability: github.write\n")
    graph = DelegationGraph(intrinsic={"admin": {"github.write"}})
    before = state_fingerprint(policy, graph)
    graph.register_intrinsic("admin", "github.admin")
    assert state_fingerprint(policy, graph) != before

    with pytest.raises(ParseError, match="mutually exclusive"):
        parse_laws(
            "LAW-1\n  capability: deploy\n"
            "  approval_policy: quorum 1 of ReleaseManager\n"
            "  requires_approval: SecurityLead\n"
        )


def test_policy_bundles_infer_roles_validate_types_and_reject_nonfinite_values():
    source = (
        "LAW-1\n  capability: deploy\n"
        "  requires_approval: ReleaseManager\n"
    )
    bundle = PolicyBundle.from_source(
        source, policy_id="deploy", policy_version="1.0.0"
    )
    assert bundle.compile().rules[0].requires_approval == "ReleaseManager"
    assert PolicyBundle.from_json(bundle.to_json()).to_dict() == bundle.to_dict()

    payload = bundle.to_dict()
    payload["policy_version"] = 1
    with pytest.raises(VersioningError, match="must be a string"):
        PolicyBundle.from_dict(payload)
    with pytest.raises(VersioningError, match="finite"):
        PolicyBundle.from_source(
            "LAW-1\n  capability: deploy\n",
            policy_id="deploy",
            policy_version="1.0.0",
            provenance={"score": math.nan},
        )


def test_durable_claims_are_explicit_and_terminal_results_are_immutable(tmp_path):
    store = SQLiteGovernanceStore(tmp_path / "review.db")
    first = store.begin_idempotency("decisions", "r1", "h1")
    second = store.begin_idempotency("decisions", "r1", "h1")
    assert first.acquired is True
    assert second.acquired is False
    completed = store.complete_idempotency(
        "decisions", "r1", "h1", response_status=200, response={"ok": True}
    )
    assert store.complete_idempotency(
        "decisions", "r1", "h1", response_status=200, response={"ok": True}
    ) == completed
    with pytest.raises(ConcurrencyError, match="completed idempotency"):
        store.complete_idempotency(
            "decisions", "r1", "h1", response_status=500, response={"ok": False}
        )

    claim = store.claim_execution("decisions", "r1", "c1")
    assert claim.acquired is True
    done = store.complete_execution(
        "decisions", "r1", "c1", status="succeeded", outcome={"remote_id": "x"}
    )
    assert store.complete_execution(
        "decisions", "r1", "c1", status="succeeded", outcome={"remote_id": "x"}
    ) == done
    with pytest.raises(ConcurrencyError, match="completed execution"):
        store.complete_execution(
            "decisions", "r1", "c1", status="failed", outcome={"remote_id": "x"}
        )
    store.close()
