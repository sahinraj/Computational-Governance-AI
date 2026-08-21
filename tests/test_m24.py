"""Acceptance tests for the M24 service boundary and client SDK."""

from __future__ import annotations

import threading

import pytest

from governance import (
    Actor,
    ApprovalManager,
    Capability,
    DecisionRequest,
    GovernanceClient,
    GovernanceService,
    IdentityVerifier,
    InProcessTransport,
    Interceptor,
    InterceptorMode,
    RuntimeAdapter,
    ServiceClientError,
    SignedTestIdentityProvider,
    create_http_server,
    compile_policy,
)
from governance.sdk import HTTPTransport


TRUST_DOMAIN = "prod.example"


def _provider():
    return SignedTestIdentityProvider(
        {"key-v1": b"m24-test-secret"},
        trust_domain=TRUST_DOMAIN,
        issuer="fixture-issuer",
    )


def _verifier(provider):
    return IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={"release-operator": "ReleaseManager"},
    )


def _credential(provider, *, subject="agent-1", now=100.0):
    return provider.issue(
        subject,
        ["release-operator"],
        now=now,
        ttl=60,
        key_id="key-v1",
    )


def _service(calls, *, clock=None):
    provider = _provider()
    verifier = _verifier(provider)
    policy = compile_policy(
        "LAW-PAYMENT\n"
        "  capability: payment.send\n"
        "  constraint: amount <= 100\n"
        "  on_violation: block\n"
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  constraint: approved == true\n"
        "  requires_approval: ReleaseManager\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager"},
    )
    manager = ApprovalManager(require_identity=True)
    interceptor = Interceptor(
        policy,
        mode=InterceptorMode.ENFORCE,
        approval_manager=manager,
    )
    runtime = RuntimeAdapter(interceptor, identity_verifier=verifier)
    return (
        GovernanceService(
            runtime,
            approval_manager=manager,
            handlers={
                "payment.send": lambda params: calls.append(("payment.send", dict(params))) or "sent",
                "deploy.production": lambda params: calls.append(("deploy.production", dict(params))) or "deployed",
            },
            clock=clock or (lambda: 100.0),
        ),
        provider,
    )


def _payment_request(provider, key, *, amount=10):
    return DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="payment.send",
        params={"amount": amount},
        idempotency_key=key,
        credential=_credential(provider),
    )


def test_allow_executes_once_and_duplicate_idempotency_is_safe():
    calls = []
    service, provider = _service(calls)
    client = GovernanceClient(InProcessTransport(service))
    request = _payment_request(provider, "payment-1")

    first = client.decide(request)
    second = client.decide(request)

    assert first["decision"]["kind"] == "Allow"
    assert first["executed"] is True
    assert second == first
    assert calls == [("payment.send", {"amount": 10})]


def test_block_and_authentication_failure_never_execute():
    calls = []
    service, provider = _service(calls)
    client = GovernanceClient(InProcessTransport(service))

    blocked = client.decide(_payment_request(provider, "payment-blocked", amount=150))
    assert blocked["decision"]["kind"] == "Block"
    assert blocked["executed"] is False

    missing = _payment_request(provider, "payment-missing")
    missing = DecisionRequest(
        actor=missing.actor,
        capability=missing.capability,
        params=missing.params,
        idempotency_key=missing.idempotency_key,
    )
    with pytest.raises(ServiceClientError) as error:
        client.decide(missing)
    assert error.value.code == "authentication_failed"
    assert calls == []


def test_approval_vote_and_resume_are_authenticated_and_single_use():
    calls = []
    service, provider = _service(calls)
    client = GovernanceClient(InProcessTransport(service))
    requester = DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="deploy.production",
        params={"approved": False},
        idempotency_key="deploy-1",
        credential=_credential(provider),
    )

    initial = client.decide(requester)
    approval_id = initial["approval_request_id"]
    assert initial["decision"]["kind"] == "Escalate"
    assert initial["executed"] is False
    assert client.get_approval(approval_id)["approval"]["state"] == "pending"

    approver_credential = _credential(provider, subject="approver-1")
    voted = client.vote(
        approval_id,
        {
            "decision": "approve",
            "role": "ReleaseManager",
            "actor_id": "approver-1",
            "credential": approver_credential,
            "idempotency_key": "vote-1",
        },
    )
    assert voted["approval"]["state"] == "approved"
    resumed = client.resume(
        approval_id,
        {
            "actor_id": "approver-1",
            "credential": approver_credential,
            "idempotency_key": "resume-1",
        },
    )
    assert resumed["decision"]["kind"] == "Allow"
    assert resumed["executed"] is True
    assert calls == [("deploy.production", {"approved": False})]

    assert client.resume(
        approval_id,
        {
            "actor_id": "approver-1",
            "credential": approver_credential,
            "idempotency_key": "resume-1",
        },
    ) == resumed
    replay = client.resume(
        approval_id,
        {
            "actor_id": "approver-1",
            "credential": approver_credential,
            "idempotency_key": "resume-2",
        },
    )
    assert replay["decision"]["kind"] == "Block"
    assert replay["executed"] is False
    assert calls == [("deploy.production", {"approved": False})]


def test_unauthorized_vote_is_rejected_and_schema_is_strict():
    calls = []
    service, provider = _service(calls)
    client = GovernanceClient(InProcessTransport(service))
    request = DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="deploy.production",
        params={"approved": False},
        idempotency_key="deploy-2",
        credential=_credential(provider),
    )
    approval_id = client.decide(request)["approval_request_id"]
    with pytest.raises(ServiceClientError) as error:
        client.vote(
            approval_id,
            {
                "decision": "approve",
                "role": "ReleaseManager",
                "actor_id": "approver-1",
                "credential": _credential(provider, subject="approver-1"),
                "idempotency_key": "vote-2",
                "unexpected": True,
            },
        )
    assert error.value.code == "invalid_request"
    assert client.get_approval(approval_id)["approval"]["state"] == "pending"


def test_operation_failure_is_cached_for_safe_uncertain_retry():
    calls = []
    service, provider = _service(calls)

    def failing_handler(params):
        calls.append(dict(params))
        raise RuntimeError("downstream unavailable")

    service.handlers["payment.send"] = failing_handler
    client = GovernanceClient(InProcessTransport(service))
    request = _payment_request(provider, "payment-failure")
    with pytest.raises(ServiceClientError) as first:
        client.decide(request)
    with pytest.raises(ServiceClientError) as second:
        client.decide(request)
    assert first.value.code == second.value.code == "operation_failed"
    assert calls == [{"amount": 10}]


def test_http_transport_round_trips_the_same_contract():
    calls = []
    service, provider = _service(calls)
    server = create_http_server(service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GovernanceClient(
            HTTPTransport(f"http://{server.server_address[0]}:{server.server_address[1]}")
        )
        response = client.decide(_payment_request(provider, "http-1"))
        assert response["schema_version"] == "1.0"
        assert response["decision"]["kind"] == "Allow"
        assert calls == [("payment.send", {"amount": 10})]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
