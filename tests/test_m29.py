"""Acceptance tests for the M24/M25 durable service integration."""

from __future__ import annotations

import threading

from governance import (
    Actor,
    ApprovalManager,
    DecisionRequest,
    DurableGovernanceService,
    IdentityVerifier,
    InProcessTransport,
    Interceptor,
    InterceptorMode,
    RuntimeAdapter,
    SQLiteGovernanceStore,
    SignedTestIdentityProvider,
    GovernanceClient,
    compile_policy,
)


TRUST_DOMAIN = "prod.example"


def _provider() -> SignedTestIdentityProvider:
    return SignedTestIdentityProvider(
        {"key-v1": b"m29-test-secret"},
        trust_domain=TRUST_DOMAIN,
        issuer="fixture-issuer",
    )


def _credential(provider, *, subject="agent-1", now=100.0):
    return provider.issue(subject, ["release-operator"], now=now, ttl=60, key_id="key-v1")


def _service(path, calls, *, provider, handler=None):
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
    verifier = IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={"release-operator": "ReleaseManager"},
    )
    interceptor = Interceptor(policy, mode=InterceptorMode.ENFORCE, approval_manager=manager)
    runtime = RuntimeAdapter(interceptor, identity_verifier=verifier)
    operation = handler or (lambda params: calls.append(dict(params)) or "sent")
    return DurableGovernanceService(
        runtime,
        repository=SQLiteGovernanceStore(path),
        approval_manager=manager,
        actor_registry={
            "agent-1": Actor(
                "agent-1", 5, capabilities={"payment.send", "deploy.production"}
            )
        },
        handlers={"payment.send": operation, "deploy.production": operation},
        clock=lambda: 100.0,
    )


def _payment(provider, key, *, amount=10):
    return DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="payment.send",
        params={"amount": amount},
        idempotency_key=key,
        credential=_credential(provider),
    )


def _deployment(provider, key):
    return DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="deploy.production",
        params={"approved": False},
        idempotency_key=key,
        credential=_credential(provider),
    )


def test_decision_result_survives_restart_and_does_not_reexecute(tmp_path):
    path = tmp_path / "service.db"
    provider = _provider()
    first_calls = []
    first = _service(path, first_calls, provider=provider)
    request = _payment(provider, "payment-restart")
    response = GovernanceClient(InProcessTransport(first)).decide(request)
    first.repository.close()

    second_calls = []
    second = _service(path, second_calls, provider=provider)
    replay = GovernanceClient(InProcessTransport(second)).decide(request)
    assert replay == response
    assert first_calls == [{"amount": 10}]
    assert second_calls == []
    second.repository.close()


def test_concurrent_workers_have_one_execution_owner(tmp_path):
    path = tmp_path / "concurrent.db"
    provider = _provider()
    started = threading.Event()
    release = threading.Event()
    calls = []

    def handler(params):
        calls.append(dict(params))
        started.set()
        release.wait(timeout=5)
        return "sent"

    first = _service(path, calls, provider=provider, handler=handler)
    second = _service(path, calls, provider=provider, handler=handler)
    request = _payment(provider, "payment-concurrent")
    result = {}

    def run_first():
        result["first"] = first.handle("POST", "/v1/decisions", request.to_dict())

    worker = threading.Thread(target=run_first)
    worker.start()
    assert started.wait(timeout=5)
    other = second.handle("POST", "/v1/decisions", request.to_dict())
    release.set()
    worker.join(timeout=5)
    assert result["first"].status == 200
    assert other.status == 409
    assert other.body["error"]["code"] == "request_in_progress"
    assert calls == [{"amount": 10}]
    first.repository.close()
    second.repository.close()


def test_approval_votes_and_resume_survive_restart_without_credentials_on_disk(tmp_path):
    path = tmp_path / "approval.db"
    provider = _provider()
    calls = []
    first = _service(path, calls, provider=provider)
    client = GovernanceClient(InProcessTransport(first))
    initial = client.decide(_deployment(provider, "deploy-restart"))
    approval_id = initial["approval_request_id"]
    assert client.get_approval(approval_id)["approval"]["state"] == "pending"
    first.repository.close()

    raw = path.read_bytes()
    assert b"m29-test-secret" not in raw
    second = _service(path, calls, provider=provider)
    second_client = GovernanceClient(InProcessTransport(second))
    approver = _credential(provider, subject="approver-1")
    voted = second_client.vote(
        approval_id,
        {
            "decision": "approve",
            "role": "ReleaseManager",
            "actor_id": "approver-1",
            "credential": approver,
            "idempotency_key": "vote-restart",
        },
    )
    assert voted["approval"]["state"] == "approved"
    second.repository.close()

    third = _service(path, calls, provider=provider)
    resumed = GovernanceClient(InProcessTransport(third)).resume(
        approval_id,
        {
            "actor_id": "approver-1",
            "credential": approver,
            "idempotency_key": "resume-restart",
        },
    )
    assert resumed["decision"]["kind"] == "Allow"
    assert resumed["executed"] is True
    assert calls == [{"approved": False}]
    third.repository.close()


def test_handler_failure_is_durable_unknown_and_never_retried(tmp_path):
    path = tmp_path / "unknown.db"
    provider = _provider()
    calls = []

    def failing(params):
        calls.append(dict(params))
        raise RuntimeError("external system disconnected")

    first = _service(path, calls, provider=provider, handler=failing)
    request = _payment(provider, "payment-unknown")
    response = GovernanceClient(InProcessTransport(first)).transport.request(
        "POST", "/v1/decisions", request.to_dict()
    )
    assert response.status == 500
    assert response.body["error"]["code"] == "operation_uncertain"
    claim = first.repository.load_execution("execution", "payment-unknown")
    assert claim.status == "unknown"
    first.repository.close()

    second_calls = []
    second = _service(path, second_calls, provider=provider, handler=failing)
    replay = GovernanceClient(InProcessTransport(second)).transport.request(
        "POST", "/v1/decisions", request.to_dict()
    )
    assert replay.status == 500
    assert replay.body["error"]["code"] == "operation_uncertain"
    assert calls == [{"amount": 10}]
    assert second_calls == []
    second.repository.close()
