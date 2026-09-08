"""M30 deterministic threat-model and red-team evidence runner.

The suite exercises the reference trust boundary with bounded attack cases.
It intentionally uses local test providers and SQLite fixtures; it does not
claim vendor integration, exhaustive fuzzing, or production readiness.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Mapping, Optional

from governance import (
    Action,
    Actor,
    ApprovalError,
    ApprovalManager,
    Capability,
    Context,
    DecisionRequest,
    DurableGovernanceService,
    GovernanceService,
    IdentityVerifier,
    Interceptor,
    InterceptorMode,
    PolicyBundle,
    PolicyVersionStore,
    RuntimeAdapter,
    SQLiteGovernanceStore,
    SignedTestIdentityProvider,
    VersioningError,
    compile_policy,
)


M30_SCHEMA_VERSION = "1.0"
M30_REPORT_PATH = Path("reports/m30-red-team.json")
TRUST_DOMAIN = "prod.example"


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    threat: str
    control: str
    passed: bool
    evidence: Mapping[str, Any]
    failure: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "threat": self.threat,
            "control": self.control,
            "passed": self.passed,
            "evidence": dict(self.evidence),
            "failure": self.failure,
        }


def _provider() -> SignedTestIdentityProvider:
    return SignedTestIdentityProvider(
        {"key-v1": b"m30-test-secret"},
        trust_domain=TRUST_DOMAIN,
        issuer="fixture-issuer",
    )


def _credential(
    provider: SignedTestIdentityProvider,
    *,
    subject: str = "agent-1",
    roles: tuple[str, ...] = ("release-operator",),
    now: float = 100.0,
):
    return provider.issue(
        subject,
        list(roles),
        now=now,
        ttl=60,
        key_id="key-v1",
    )


def _service(
    calls: list[dict[str, Any]],
    *,
    provider: Optional[SignedTestIdentityProvider] = None,
    repository: Optional[SQLiteGovernanceStore] = None,
    policy_source: Optional[str] = None,
    handler: Optional[Callable[[Mapping[str, Any]], Any]] = None,
):
    provider = provider or _provider()
    policy = compile_policy(
        policy_source
        or (
            "LAW-PAYMENT\n"
            "  capability: payment.send\n"
            "  constraint: amount <= 100\n"
            "  on_violation: block\n"
        ),
        roles={"ReleaseManager"},
    )
    manager = ApprovalManager(require_identity=True)
    verifier = IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={"release-operator": "ReleaseManager"},
    )
    interceptor = Interceptor(
        policy,
        mode=InterceptorMode.ENFORCE,
        approval_manager=manager,
    )
    runtime = RuntimeAdapter(interceptor, identity_verifier=verifier)
    operation = handler or (lambda params: calls.append(dict(params)) or "ok")
    service_type = DurableGovernanceService if repository is not None else GovernanceService
    return service_type(
        runtime,
        repository=repository,
        approval_manager=manager,
        actor_registry={
            "agent-1": Actor(
                "agent-1", 5, capabilities={"payment.send", "deploy.production"}
            ),
        },
        handlers={"payment.send": operation, "deploy.production": operation},
        clock=lambda: 100.0,
    ), provider


def _request(provider, key: str, *, credential=None, amount: int = 10) -> DecisionRequest:
    return DecisionRequest(
        actor=Actor("agent-1", 5),
        capability="payment.send",
        params={"amount": amount},
        idempotency_key=key,
        credential=_credential(provider) if credential is None else credential,
    )


def _replay_case() -> Mapping[str, Any]:
    calls: list[dict[str, Any]] = []
    service, provider = _service(calls)
    request = _request(provider, "m30-replay")
    first = service.handle("POST", "/v1/decisions", request.to_dict())
    second = service.handle("POST", "/v1/decisions", request.to_dict())
    assert first.status == second.status == 200
    assert first.body == second.body
    assert first.body["executed"] is True
    assert calls == [{"amount": 10}]
    return {"response_replayed": True, "execution_count": len(calls)}


def _identity_substitution_case() -> Mapping[str, Any]:
    calls: list[dict[str, Any]] = []
    service, provider = _service(calls)
    forged_subject = _credential(provider, subject="attacker")
    response = service.handle(
        "POST", "/v1/decisions", _request(
            provider, "m30-identity-substitution", credential=forged_subject
        ).to_dict()
    )
    assert response.status == 401
    assert response.body["error"]["code"] == "authentication_failed"
    assert calls == []
    return {"status": response.status, "execution_count": len(calls)}


def _policy_downgrade_case() -> Mapping[str, Any]:
    source = "LAW-1\n  capability: deploy.production\n  on_violation: block\n"
    stricter = (
        "LAW-1\n"
        "  capability: deploy.production\n"
        "  authority_level: >= 9\n"
        "  on_violation: block\n"
    )
    old = PolicyBundle.from_source(source, policy_id="deploy", policy_version="1.0.0")
    current = PolicyBundle.from_source(
        stricter, policy_id="deploy", policy_version="2.0.0"
    )
    store = PolicyVersionStore()
    store.activate(current, reason="activate stricter policy")
    try:
        store.activate(old, reason="unapproved downgrade")
    except VersioningError as exc:
        downgrade_error = str(exc)
    else:
        raise AssertionError("policy downgrade was accepted without explicit override")

    tampered = current.to_dict()
    tampered["source"] = source
    try:
        PolicyBundle.from_dict(tampered)
    except VersioningError as exc:
        tamper_error = str(exc)
    else:
        raise AssertionError("tampered policy bundle was accepted")
    return {"downgrade_rejected": True, "tamper_rejected": True,
            "errors": [downgrade_error, tamper_error]}


def _stale_approval_case() -> Mapping[str, Any]:
    original = compile_policy(
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  requires_approval: ReleaseManager\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager"},
    )
    changed = compile_policy(
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  requires_approval: SecurityLead\n"
        "  on_violation: escalate\n",
        roles={"SecurityLead"},
    )
    action = Action(
        Actor("agent-1", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
    )
    context = Context(now=100.0)
    manager = ApprovalManager()
    pending = Interceptor(
        original, mode=InterceptorMode.ENFORCE, approval_manager=manager
    ).execute(action, context, lambda: "must not execute")
    assert pending.approval_request_id is not None
    manager.approve(
        pending.approval_request_id, "ReleaseManager", original, action, context,
        now=100.0,
    )
    try:
        manager.prepare_resume(
            pending.approval_request_id, changed, action, context, now=100.0
        )
    except ApprovalError as exc:
        return {"stale_approval_rejected": True, "error": str(exc)}
    raise AssertionError("stale approval was accepted for changed policy")


def _approval_collusion_case() -> Mapping[str, Any]:
    provider = _provider()
    verifier = IdentityVerifier(
        provider,
        trust_domain=TRUST_DOMAIN,
        role_mapping={
            "requester": "Requester",
            "release-approver": "ReleaseManager",
            "security-approver": "SecurityLead",
        },
    )
    requester = verifier.verify(
        _credential(provider, roles=("requester",)), actor_id="agent-1", now=100.0
    )
    colluder = verifier.verify(
        _credential(
            provider,
            subject="colluder",
            roles=("release-approver", "security-approver"),
        ),
        actor_id="colluder",
        now=100.0,
    )
    independent = verifier.verify(
        _credential(
            provider, subject="security-1", roles=("security-approver",)
        ),
        actor_id="security-1",
        now=100.0,
    )
    policy = compile_policy(
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  approval_policy: quorum 2 of ReleaseManager, SecurityLead\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager", "SecurityLead"},
    )
    action = Action(
        Actor("agent-1", 5, capabilities={"deploy.production"}),
        Capability("deploy.production"),
        identity_reference=requester.identity_reference,
        identity_roles=requester.roles,
    )
    context = Context(now=100.0)
    manager = ApprovalManager(require_identity=True)
    request = manager.request(policy.evaluate(action, context), policy, action, context, now=100.0)
    manager.approve(
        request.id, "ReleaseManager", policy, action, context,
        identity=colluder, now=100.0,
    )
    try:
        manager.approve(
            request.id, "SecurityLead", policy, action, context,
            identity=colluder, now=100.0,
        )
    except ApprovalError as exc:
        collusion_error = str(exc)
    else:
        raise AssertionError("one verified identity satisfied multiple quorum roles")
    manager.approve(
        request.id, "SecurityLead", policy, action, context,
        identity=independent, now=100.0,
    )
    assert manager.get(request.id).state.value == "approved"
    return {
        "same_identity_second_vote_rejected": True,
        "independent_second_vote_accepted": True,
        "error": collusion_error,
    }


def _confused_deputy_case() -> Mapping[str, Any]:
    calls: list[dict[str, Any]] = []
    service, provider = _service(
        calls,
        policy_source=(
            "LAW-ADMIN\n"
            "  capability: deploy.production\n"
            "  authority_level: >= 9\n"
            "  on_violation: block\n"
        ),
    )
    request = _request(provider, "m30-confused-deputy")
    forged_actor = dict(request.to_dict())
    forged_actor["actor"] = {
        "id": "agent-1",
        "authority_level": 99,
        "class": "admin",
        "capabilities": ["deploy.production"],
    }
    forged_actor["capability"] = "deploy.production"
    forged_actor["params"] = {}
    response = service.handle("POST", "/v1/decisions", forged_actor)
    assert response.status == 200
    assert response.body["decision"]["kind"] == "Block"
    assert response.body["executed"] is False
    assert calls == []
    return {"caller_claim_ignored": True, "decision": response.body["decision"]["kind"],
            "execution_count": len(calls)}


def _recovery_case() -> Mapping[str, Any]:
    with TemporaryDirectory(prefix="m30-recovery-") as directory:
        path = Path(directory) / "governance.db"
        calls: list[dict[str, Any]] = []

        def failing(params: Mapping[str, Any]):
            calls.append(dict(params))
            raise RuntimeError("downstream unavailable")

        first_store = SQLiteGovernanceStore(path)
        first, provider = _service(calls, repository=first_store, handler=failing)
        request = _request(provider, "m30-recovery")
        first_response = first.handle("POST", "/v1/decisions", request.to_dict())
        first_store.close()
        second_calls: list[dict[str, Any]] = []
        second_store = SQLiteGovernanceStore(path)
        second, _ = _service(second_calls, repository=second_store, handler=failing)
        second_response = second.handle("POST", "/v1/decisions", request.to_dict())
        claim = second_store.load_execution("service:execution:decision", "m30-recovery")
        second_store.close()
    assert first_response.status == second_response.status == 500
    assert first_response.body["error"]["code"] == "operation_uncertain"
    assert second_response.body == first_response.body
    assert claim.status == "unknown"
    assert calls == [{"amount": 10}]
    assert second_calls == []
    return {"uncertain_outcome_preserved": True, "execution_count": len(calls),
            "recovered_claim_status": claim.status}


_CASES: tuple[tuple[str, str, str, Callable[[], Mapping[str, Any]]], ...] = (
    ("M30-REPLAY", "replay and duplicate execution", "durable idempotency and single execution", _replay_case),
    ("M30-IDENTITY", "identity substitution", "verified subject binding before execution", _identity_substitution_case),
    ("M30-DOWNGRADE", "policy downgrade and bundle tampering", "monotonic activation and content hashes", _policy_downgrade_case),
    ("M30-STALE-APPROVAL", "stale approval reuse", "approval binding to policy/action/context/state", _stale_approval_case),
    ("M30-COLLUSION", "approval collusion", "distinct verified approver identities for quorum", _approval_collusion_case),
    ("M30-CONFUSED-DEPUTY", "confused deputy capability crossing", "trusted actor registry over caller claims", _confused_deputy_case),
    ("M30-RECOVERY", "restart and uncertain-outcome recovery", "durable claim state and no unsafe retry", _recovery_case),
)


def run_m30() -> dict[str, Any]:
    """Run all bounded M30 cases and return a deterministic report."""
    results: list[CaseResult] = []
    for case_id, threat, control, runner in _CASES:
        try:
            evidence = runner()
        except Exception as exc:
            results.append(
                CaseResult(
                    case_id, threat, control, False, {},
                    f"{type(exc).__name__}: {exc}",
                )
            )
        else:
            results.append(CaseResult(case_id, threat, control, True, evidence))
    failures = [item for item in results if not item.passed]
    taxonomy: dict[str, int] = {}
    for item in results:
        key = "passed" if item.passed else "failed"
        taxonomy[key] = taxonomy.get(key, 0) + 1
    return {
        "schema_version": M30_SCHEMA_VERSION,
        "milestone": "M30",
        "case_count": len(results),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "exact": not failures,
        "failure_taxonomy": taxonomy,
        "cases": [item.to_dict() for item in results],
    }


def validate_report(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != M30_SCHEMA_VERSION:
        raise ValueError("unsupported M30 report schema")
    if report.get("milestone") != "M30":
        raise ValueError("report milestone must be M30")
    expected = {item[0] for item in _CASES}
    cases = report.get("cases", [])
    if report.get("case_count") != len(expected) or {item.get("case_id") for item in cases} != expected:
        raise ValueError("M30 report does not contain the complete threat corpus")
    if report.get("failed") != 0 or report.get("exact") is not True:
        raise ValueError("M30 red-team cases did not all pass")
    if any(not item.get("passed") or item.get("failure") for item in cases):
        raise ValueError("M30 report contains a failed case")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=M30_REPORT_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = run_m30()
    if args.check:
        validate_report(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
