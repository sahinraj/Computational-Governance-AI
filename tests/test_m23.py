"""Acceptance tests for M23 authenticated workload and actor identity."""

import json
from pathlib import Path

import pytest

from governance import (
    ApprovalError,
    ApprovalManager,
    AuditLog,
    DelegationGraph,
    IdentityError,
    IdentityVerifier,
    Interceptor,
    JsonlAuditStore,
    RuntimeAdapter,
    SignedTestIdentityProvider,
    ToolCall,
    VerifiedIdentity,
    compile_policy,
    replay_event,
)
from governance.model import Actor, Capability, Context, DecisionKind, Action


TRUST_DOMAIN = "prod.example"


def _provider(key_id="key-v1", secret=b"m23-test-secret"):
    return SignedTestIdentityProvider(
        {key_id: secret},
        trust_domain=TRUST_DOMAIN,
        issuer="fixture-issuer",
    )


def _verifier(provider):
    return IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={"release-operator": "ReleaseManager"},
    )


def _credential(provider, *, subject="agent-1", now=10.0, key_id="key-v1", **kwargs):
    return provider.issue(
        subject,
        ["release-operator"],
        now=now,
        ttl=30,
        key_id=key_id,
        **kwargs,
    )


def test_authenticated_runtime_allows_valid_identity_and_records_reference():
    provider = _provider()
    verifier = _verifier(provider)
    credential = _credential(provider)
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    interceptor = Interceptor(policy, mode="enforce")
    adapter = RuntimeAdapter(interceptor, identity_verifier=verifier)
    calls = []

    result = adapter.invoke(
        ToolCall(Actor("agent-1", 5), "payment.send", credential=credential),
        Context(now=10),
        lambda: calls.append("executed") or "ok",
    )

    assert result.decision.kind is DecisionKind.ALLOW
    assert result.executed is True
    assert calls == ["executed"]
    identity = verifier.verify(credential, actor_id="agent-1", now=10)
    event = interceptor.audit_log.events[0]
    assert event.identity_reference == identity.identity_reference
    assert event.identity_roles == ("ReleaseManager",)
    assert "m23-test-secret" not in event.to_json()


def test_checked_in_signed_fixture_verifies():
    fixture = json.loads(
        (Path(__file__).parent / "fixtures" / "m23-credentials.json").read_text(
            encoding="utf-8"
        )
    )
    provider = SignedTestIdentityProvider(
        {"fixture-v1": b"m23-fixture-secret"},
        trust_domain=fixture["trust_domain"],
        issuer=fixture["issuer"],
    )
    identity = provider.verify(fixture["credential"], now=100)
    assert identity.subject == "agent-fixture"
    assert identity.roles == ("release-operator",)


def test_unauthenticated_expired_wrong_domain_and_impersonated_calls_fail_closed():
    provider = _provider()
    verifier = _verifier(provider)
    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    calls = []

    def invoke(call, now):
        return RuntimeAdapter(
            Interceptor(policy, mode="enforce"),
            identity_verifier=verifier,
        ).invoke(call, Context(now=now), lambda: calls.append("executed"))

    missing = invoke(ToolCall(Actor("agent-1", 5), "payment.send"), 10)
    assert missing.decision.kind is DecisionKind.BLOCK

    expired = _credential(provider, now=0)
    expired_result = invoke(
        ToolCall(Actor("agent-1", 5), "payment.send", credential=expired),
        31,
    )
    assert expired_result.decision.kind is DecisionKind.BLOCK

    wrong_domain = _credential(provider, trust_domain="other.example")
    wrong_domain_result = invoke(
        ToolCall(Actor("agent-1", 5), "payment.send", credential=wrong_domain),
        10,
    )
    assert wrong_domain_result.decision.kind is DecisionKind.BLOCK

    impersonated = _credential(provider, subject="different-agent")
    impersonated_result = invoke(
        ToolCall(Actor("agent-1", 5), "payment.send", credential=impersonated),
        10,
    )
    assert impersonated_result.decision.kind is DecisionKind.BLOCK
    assert calls == []


def test_forged_credentials_and_unmapped_roles_are_rejected():
    provider = _provider()
    verifier = _verifier(provider)
    forged = _credential(provider)
    forged["subject"] = "admin"
    with pytest.raises(IdentityError, match="signature"):
        verifier.verify(forged, actor_id="admin", now=10)

    unmapped = provider.issue(
        "agent-1",
        ["unmapped"],
        now=10,
        ttl=30,
        key_id="key-v1",
    )
    with pytest.raises(IdentityError, match="unmapped roles"):
        verifier.verify(unmapped, actor_id="agent-1", now=10)


def test_verified_identity_binds_delegation_proofs_and_approval_roles():
    provider = _provider()
    identity = _verifier(provider).verify(
        _credential(provider), actor_id="agent-1", now=10
    )
    graph = DelegationGraph(intrinsic={"agent-1": {"payment.send"}})
    proof = graph.authority_proof(
        "agent-1",
        "payment.send",
        identity_reference=identity.identity_reference,
    )
    assert proof.allowed is True
    assert proof.identity_reference == identity.identity_reference

    policy = compile_policy(
        "LAW-APPROVAL\n"
        "  capability: payment.send\n"
        "  requires_approval: ReleaseManager\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager"},
    )
    action = Action(
        Actor("agent-1", 5),
        Capability("payment.send"),
        identity_reference=identity.identity_reference,
        identity_roles=identity.roles,
    )
    context = Context(now=10)
    decision = policy.evaluate(action, context, delegation=graph)
    manager = ApprovalManager(require_identity=True)
    request = manager.request(decision, policy, action, context, delegation=graph, now=10)
    assert request.identity_reference == identity.identity_reference
    with pytest.raises(ApprovalError, match="provider-verified"):
        manager.approve(
            request.id,
            "ReleaseManager",
            policy,
            action,
            context,
            delegation=graph,
            identity=VerifiedIdentity(
                trust_domain=TRUST_DOMAIN,
                subject="agent-2",
                roles=("OtherRole",),
                expires_at=40,
                issuer="fixture-issuer",
                credential_reference="other",
            ),
            now=10,
        )

    class ForgedIdentity(VerifiedIdentity):
        @property
        def is_provider_verified(self):
            return True

    forged_subclass = ForgedIdentity(
        trust_domain=TRUST_DOMAIN,
        subject="attacker",
        roles=("ReleaseManager",),
        expires_at=40,
        issuer="fixture-issuer",
        credential_reference="forged-subclass",
        issued_at=0,
    )
    with pytest.raises(ApprovalError, match="provider-verified"):
        manager.approve(
            request.id,
            "ReleaseManager",
            policy,
            action,
            context,
            delegation=graph,
            identity=forged_subclass,
            now=10,
        )
    approved = manager.approve(
        request.id,
        "ReleaseManager",
        policy,
        action,
        context,
        delegation=graph,
        identity=identity,
        now=10,
    )
    assert approved.state.value == "approved"
    assert approved.vote_identity_references == (
        ("ReleaseManager", identity.identity_reference),
    )
    restored = ApprovalManager.from_snapshot(manager.snapshot())
    restored_request = restored.get(request.id, now=10)
    assert restored.require_identity is True
    assert restored_request.identity_reference == identity.identity_reference
    assert restored_request.vote_identity_references == approved.vote_identity_references


def test_approval_rejects_forged_identity_and_requires_authenticated_denial():
    provider = _provider()
    verifier = _verifier(provider)
    identity = verifier.verify(_credential(provider), actor_id="agent-1", now=10)
    policy = compile_policy(
        "LAW-APPROVAL\n"
        "  capability: payment.send\n"
        "  requires_approval: ReleaseManager\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager"},
    )
    action = Action(
        Actor("agent-1", 5),
        Capability("payment.send"),
        identity_reference=identity.identity_reference,
        identity_roles=identity.roles,
    )
    context = Context(now=10)
    graph = DelegationGraph(intrinsic={"agent-1": {"payment.send"}})
    decision = policy.evaluate(action, context, delegation=graph)

    forged = VerifiedIdentity(
        trust_domain=TRUST_DOMAIN,
        subject="attacker",
        roles=("ReleaseManager",),
        expires_at=40,
        issuer="fixture-issuer",
        credential_reference="forged",
        issued_at=0,
    )
    manager = ApprovalManager(require_identity=True)
    request = manager.request(decision, policy, action, context, delegation=graph, now=10)
    with pytest.raises(ApprovalError, match="provider-verified"):
        manager.approve(
            request.id,
            "ReleaseManager",
            policy,
            action,
            context,
            delegation=graph,
            identity=forged,
            now=10,
        )
    with pytest.raises(ApprovalError, match="authenticated approver identity is required"):
        manager.deny(request.id, "ReleaseManager", now=10)
    wrong_role_identity = IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={"release-operator": "OtherRole"},
    ).verify(
        provider.issue(
            "agent-2", ["release-operator"], now=10, ttl=30, key_id="key-v1"
        ),
        actor_id="agent-2",
        now=10,
    )
    with pytest.raises(ApprovalError, match="authorized for role"):
        manager.deny(
            request.id,
            "ReleaseManager",
            identity=wrong_role_identity,
            now=10,
        )

    denied = manager.deny(
        request.id,
        "ReleaseManager",
        identity=identity,
        now=10,
    )
    assert denied.state.value == "denied"
    assert denied.denial_identity_reference == identity.identity_reference
    restored = ApprovalManager.from_snapshot(manager.snapshot())
    assert restored.get(request.id, now=10).denial_identity_reference == identity.identity_reference


def test_identity_rotation_and_audit_restart_preserve_historical_binding(tmp_path):
    old_provider = _provider()
    new_provider = _provider("key-v2", b"rotated-secret")
    old = _verifier(old_provider).verify(
        _credential(old_provider, credential_reference="credential-v1"),
        actor_id="agent-1",
        now=10,
    )
    rotated = _verifier(new_provider).verify(
        _credential(
            new_provider,
            key_id="key-v2",
            credential_reference="credential-v2",
        ),
        actor_id="agent-1",
        now=10,
    )
    assert old.identity_reference == rotated.identity_reference
    assert VerifiedIdentity.from_dict(old.to_dict()) == old

    policy = compile_policy("LAW-1\n  capability: payment.send\n")
    context = Context(now=10)
    action = Action(
        Actor("agent-1", 5),
        Capability("payment.send"),
        identity_reference=old.identity_reference,
        identity_roles=old.roles,
    )
    log = AuditLog()
    Interceptor(policy, mode="enforce", audit_log=log, trace_id="m23").check(
        action, context
    )
    path = tmp_path / "audit.jsonl"
    JsonlAuditStore(path).append(log.events[0])
    recovered = JsonlAuditStore(path).load()
    rotated_action = Action(
        Actor("agent-1", 5),
        Capability("payment.send"),
        identity_reference=rotated.identity_reference,
        identity_roles=rotated.roles,
    )
    replay = replay_event(recovered.events[0], policy, rotated_action, context)
    assert replay.exact is True
    assert json.loads(recovered.events[0].to_json())["identity_reference"] == old.identity_reference
