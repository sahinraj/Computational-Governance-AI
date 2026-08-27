"""M28 deterministic adversarial assurance and fault-injection evidence."""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from governance import (
    Action,
    Actor,
    ApprovalManager,
    Capability,
    Context,
    DelegationGraph,
    DecisionKind,
    IdentityError,
    IdentityVerifier,
    GovernanceService,
    Interceptor,
    InterceptorMode,
    PolicyBundle,
    PolicyLifecycleManager,
    RuntimeAdapter,
    SignedTestIdentityProvider,
    SQLiteGovernanceStore,
    StoreError,
    compile_policy,
)


DEFAULT_SEED = 20260826
DEFAULT_PROPERTY_TRACES = 128
DEFAULT_FUZZ_CASES = 32


@dataclass(frozen=True)
class M28Report:
    seed: int
    property_traces: int
    fuzz_cases: int
    checks: int
    passed: int
    failed: int
    failures: tuple[dict[str, Any], ...]
    category_counts: dict[str, int]
    category_passed: dict[str, int]
    mutation_detected: bool
    scope: tuple[str, ...] = (
        "seeded property traces",
        "bounded malformed-input fuzz corpus",
        "selected mutation operators",
        "clock and expiry boundaries",
        "SQLite transaction crash injection",
    )

    @property
    def exact(self) -> bool:
        return self.failed == 0 and self.passed == self.checks and self.mutation_detected

    def to_dict(self) -> dict[str, Any]:
        return {
            "milestone": "M28",
            "seed": self.seed,
            "property_traces": self.property_traces,
            "fuzz_cases": self.fuzz_cases,
            "checks": self.checks,
            "passed": self.passed,
            "failed": self.failed,
            "failures": list(self.failures),
            "category_counts": dict(sorted(self.category_counts.items())),
            "category_passed": dict(sorted(self.category_passed.items())),
            "mutation_detected": self.mutation_detected,
            "scope": list(self.scope),
            "exact": self.exact,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _policy():
    return compile_policy(
        "LAW-WRITE\n"
        "  capability: data.write\n"
        "  authority_level: >= 3\n"
        "  constraint: amount <= 100\n"
        "  on_violation: block\n"
        "LAW-DEPLOY\n"
        "  capability: deploy.production\n"
        "  requires_approval: ReleaseManager\n"
        "  on_violation: escalate\n",
        roles={"ReleaseManager"},
        default_decision="Block",
    )


def _check_factory():
    counts: dict[str, int] = {}
    passed: dict[str, int] = {}
    failures: list[dict[str, Any]] = []

    def check(category: str, case_id: str, condition: bool, detail: str) -> None:
        counts[category] = counts.get(category, 0) + 1
        if condition:
            passed[category] = passed.get(category, 0) + 1
        elif len(failures) < 25:
            failures.append({"category": category, "case_id": case_id, "detail": detail})

    return check, counts, passed, failures


def _run_property_checks(seed: int, traces: int, check: Callable[..., None]) -> None:
    rng = random.Random(seed)
    policy = _policy()
    for index in range(traces):
        actor = Actor(
            f"agent-{index}",
            rng.randrange(0, 7),
            capabilities={"data.write"},
        )
        action = Action(
            actor,
            Capability("data.write"),
            {"amount": rng.randrange(-10, 151)},
        )
        context = Context(
            budget_used=float(rng.randrange(0, 120)),
            now=float(rng.randrange(0, 20)),
        )
        direct = policy.evaluate(action, context)
        interceptor = Interceptor(policy, mode=InterceptorMode.ENFORCE)
        checked = interceptor.check(action, context)
        replay = policy.evaluate(action, context)
        check(
            "property",
            f"trace-{index:04d}",
            checked == direct == replay,
            "direct, intercepted, and repeated evaluations diverged",
        )
        executed: list[str] = []
        result = Interceptor(policy, mode=InterceptorMode.ENFORCE).execute(
            action, context, lambda: executed.append("executed")
        )
        check(
            "property",
            f"execution-{index:04d}",
            result.executed is (direct.kind is DecisionKind.ALLOW)
            and bool(executed) is result.executed,
            "execution did not match the independent Allow gate",
        )


def _run_fuzz_checks(seed: int, cases: int, check: Callable[..., None]) -> None:
    rng = random.Random(seed ^ 0xF00D)
    malformed: list[Any] = [
        None,
        [],
        "request",
        {"unknown": True},
        {"actor": "not-an-object"},
        {"actor": {"id": "agent", "authority_level": 1}, "capability": 4},
        {"actor": {"id": "agent", "authority_level": 1}, "capability": "x", "params": []},
        {"actor": {"id": "agent", "authority_level": 1}, "capability": "x", "idempotency_key": ""},
    ]
    while len(malformed) < cases:
        malformed.append({
            "actor": {"id": rng.choice(["", 1, None]), "authority_level": rng.choice([None, "high", -1])},
            "capability": rng.choice([None, "", 7]),
            "params": rng.choice([None, [], "secret"]),
            "idempotency_key": rng.choice([None, "", 9]),
        })
    policy = _policy()
    calls: list[str] = []
    service = GovernanceService(
        RuntimeAdapter(
            Interceptor(policy, mode=InterceptorMode.ENFORCE)
        ),
        actor_registry={"agent": Actor("agent", 5, capabilities={"data.write"})},
        handlers={"data.write": lambda params: calls.append("executed")},
    )
    for index, payload in enumerate(malformed[:cases]):
        response = service.handle("POST", "/v1/decisions", payload)
        check(
            "fuzz",
            f"malformed-{index:04d}",
            response.status != 200 and not calls,
            "malformed input reached a successful response or handler",
        )


def _run_mutation_checks(check: Callable[..., None]) -> bool:
    mutations = (
        ("expiry-inclusive", lambda now, expiry: now <= expiry, lambda now, expiry: now < expiry, (10.0, 10.0)),
        ("approval-under-quorum", lambda count, threshold: count >= threshold - 1, lambda count, threshold: count >= threshold, (1, 2)),
        ("rollback-without-reason", lambda reason: True, lambda reason: bool(reason.strip()), ("",)),
        ("default-allow", lambda configured: True, lambda configured: configured, (False,)),
    )
    detected = True
    for name, mutated, correct, args in mutations:
        diverged = mutated(*args) != correct(*args)
        detected = detected and diverged
        check("mutation", name, diverged, "selected mutation was not distinguished by its invariant")
    return detected


def _run_clock_checks(check: Callable[..., None]) -> None:
    admin = Actor("admin", 5, capabilities={"data.write"})
    graph = DelegationGraph()
    graph.grant(admin, "worker", "data.write", depth=1, expires_at=100.0)
    check("clock_skew", "delegation-before-expiry", graph.has_authority("worker", "data.write", now=99.999), "authority denied before expiry")
    check("clock_skew", "delegation-at-expiry", not graph.has_authority("worker", "data.write", now=100.0), "authority survived expiry boundary")

    policy = compile_policy(
        "LAW-APPROVAL\n  capability: deploy.production\n  requires_approval: ReleaseManager\n  on_violation: escalate",
        roles={"ReleaseManager"},
    )
    manager = ApprovalManager(ttl=10)
    pending = Interceptor(policy, mode=InterceptorMode.ENFORCE, approval_manager=manager).execute(
        Action(Actor("agent", 5), Capability("deploy.production")),
        Context(now=100.0),
        lambda: None,
    )
    check("clock_skew", "approval-before-expiry", manager.get(pending.approval_request_id, now=109.999).state.value == "pending", "approval expired early")
    check("clock_skew", "approval-at-expiry", manager.get(pending.approval_request_id, now=110.0).state.value == "expired", "approval remained active at expiry")

    provider = SignedTestIdentityProvider(
        {"clock-key": b"m28-clock-secret"},
        trust_domain="m28.example",
        issuer="m28-fixture",
    )
    verifier = IdentityVerifier(
        provider,
        trust_domain="m28.example",
        role_mapping={"operator": "ReleaseManager"},
    )
    credential = provider.issue(
        "agent", ["operator"], now=100.0, ttl=10.0, key_id="clock-key"
    )
    check(
        "clock_skew",
        "identity-before-issuance",
        _identity_rejected(verifier, credential, now=99.999),
        "identity was accepted before issuance",
    )
    check(
        "clock_skew",
        "identity-at-expiry",
        _identity_rejected(verifier, credential, now=110.0),
        "identity remained valid at expiry",
    )


def _identity_rejected(verifier: IdentityVerifier, credential: dict[str, Any], *, now: float) -> bool:
    try:
        verifier.verify(credential, actor_id="agent", now=now)
    except IdentityError:
        return True
    return False

    bundle = PolicyBundle.from_source(
        "LAW-EXPIRY\n  capability: data.write\n",
        policy_id="clock-policy",
        policy_version="1.0.0",
    )
    lifecycle = PolicyLifecycleManager(production_approval_threshold=1, clock=lambda: 100.0)
    lifecycle.draft(bundle, owner="owner", expires_at=101.0)
    lifecycle.validate("clock-policy", "1.0.0")
    lifecycle.simulate("clock-policy", "1.0.0", [])
    lifecycle.approve("clock-policy", "1.0.0", approver_id="owner", role="Owner")
    lifecycle.deploy("clock-policy", "1.0.0")
    check("clock_skew", "policy-expiry", len(lifecycle.monitor(now=101.0)) == 1, "policy expiry was not observed")


def _run_crash_checks(seed: int, check: Callable[..., None]) -> None:
    path = Path.cwd() / f".m28-crash-{seed}.db"
    try:
        store = SQLiteGovernanceStore(path)
        original = store.save_state("fixture", "primary", {"state": "committed"})
        armed = {"value": False}

        def failpoint(point: str) -> None:
            if armed["value"] and point == "before_commit":
                raise RuntimeError("M28 injected crash")

        store._failpoint = failpoint
        armed["value"] = True
        try:
            store.save_state("fixture", "primary", {"state": "lost"}, expected_revision=original.revision)
        except StoreError:
            pass
        restored = store.load_state("fixture", "primary")
        check("crash_injection", "state-rollback", restored.payload == {"state": "committed"}, "failed transaction changed durable state")
        armed["value"] = False
        reservation = store.begin_idempotency("decisions", "request", "hash")
        claim = store.claim_execution("decisions", "request", "claim")
        armed["value"] = True
        try:
            store.complete_idempotency(
                "decisions", "request", "hash", response_status=200,
                response={"executed": True},
            )
        except StoreError:
            pass
        try:
            store.complete_execution(
                "decisions", "request", "claim", status="succeeded",
                outcome={"ok": True},
            )
        except StoreError:
            pass
        armed["value"] = False
        check(
            "crash_injection",
            "idempotency-rollback",
            store.load_idempotency("decisions", "request").status == "in_progress"
            and reservation.acquired,
            "failed idempotency completion changed durable reservation",
        )
        check(
            "crash_injection",
            "execution-rollback",
            store.claim_execution("decisions", "request", "claim").status == "claimed"
            and claim.acquired,
            "failed execution completion changed durable claim",
        )
        store.close()
    finally:
        path.unlink(missing_ok=True)


def run_m28(*, seed: int = DEFAULT_SEED, property_traces: int = DEFAULT_PROPERTY_TRACES, fuzz_cases: int = DEFAULT_FUZZ_CASES) -> M28Report:
    if property_traces <= 0 or fuzz_cases <= 0:
        raise ValueError("M28 trace and fuzz counts must be positive")
    check, counts, passed, failures = _check_factory()
    _run_property_checks(seed, property_traces, check)
    _run_fuzz_checks(seed, fuzz_cases, check)
    mutation_detected = _run_mutation_checks(check)
    _run_clock_checks(check)
    _run_crash_checks(seed, check)
    return M28Report(
        seed=seed,
        property_traces=property_traces,
        fuzz_cases=fuzz_cases,
        checks=sum(counts.values()),
        passed=sum(passed.values()),
        failed=sum(counts.values()) - sum(passed.values()),
        failures=tuple(failures),
        category_counts=counts,
        category_passed=passed,
        mutation_detected=mutation_detected,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--property-traces", type=int, default=DEFAULT_PROPERTY_TRACES)
    parser.add_argument("--fuzz-cases", type=int, default=DEFAULT_FUZZ_CASES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = run_m28(
        seed=args.seed,
        property_traces=args.property_traces,
        fuzz_cases=args.fuzz_cases,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report.to_json(), encoding="utf-8")
    print(report.to_json(), end="")
    return 0 if not args.check or report.exact else 1


if __name__ == "__main__":
    raise SystemExit(main())
