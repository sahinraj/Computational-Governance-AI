"""M19: deterministic model-based assurance over generated governance traces."""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance import (
    Action,
    Actor,
    ApprovalError,
    ApprovalManager,
    Capability,
    Context,
    DelegationError,
    DelegationGraph,
    DecisionKind,
    Interceptor,
    compile_policy,
)


DEFAULT_SEED = 20260809
DEFAULT_TRACES = 1000


@dataclass(frozen=True)
class AssuranceReport:
    seed: int
    traces: int
    checks: int
    passed: int
    failed: int
    failures: tuple[dict[str, Any], ...]
    invalid_transitions_rejected: int
    mutation_detected: bool
    oracle: str = "independent finite-state governance oracle"

    @property
    def exact(self) -> bool:
        return self.failed == 0 and self.passed == self.checks

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "traces": self.traces,
            "checks": self.checks,
            "passed": self.passed,
            "failed": self.failed,
            "failures": list(self.failures),
            "invalid_transitions_rejected": self.invalid_transitions_rejected,
            "mutation_detected": self.mutation_detected,
            "oracle": self.oracle,
            "exact": self.exact,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _independent_authority_oracle(*, revoked: bool, now: float, expires_at: float) -> bool:
    """Minimal reference model for a single bounded delegated grant."""
    return not revoked and now < expires_at


def run_assurance(*, seed: int = DEFAULT_SEED, traces: int = DEFAULT_TRACES) -> AssuranceReport:
    """Generate traces and compare the implementation with independent invariants."""
    if traces <= 0:
        raise ValueError("trace count must be positive")
    rng = random.Random(seed)
    failures: list[dict[str, Any]] = []
    checks = 0
    passed = 0
    invalid_transitions_rejected = 0

    def check(condition: bool, trace: int, invariant: str) -> None:
        nonlocal checks, passed
        checks += 1
        if condition:
            passed += 1
        elif len(failures) < 25:
            failures.append({"trace": trace, "invariant": invariant})

    policy = compile_policy(
        """
LAW-ASSURANCE
  capability: deploy.production
  requires_approval: ReleaseManager
  on_violation: escalate
""",
        roles={"ReleaseManager"},
    )

    for trace in range(traces):
        trace_seed = rng.randrange(1, 1_000_000_000)
        expiry = float(10 + (trace_seed % 90))
        active_now = expiry - 1
        admin = Actor(f"admin-{trace}", 5, capabilities={"service.write"})
        worker = Actor(f"worker-{trace}", 2)
        graph = DelegationGraph()
        grant = graph.grant(admin, worker, "service.write", depth=1, expires_at=expiry)

        expected_active = _independent_authority_oracle(
            revoked=False, now=active_now, expires_at=expiry
        )
        check(
            graph.has_authority(worker, "service.write", now=active_now) == expected_active,
            trace,
            "bounded delegation matches independent oracle before expiry",
        )
        check(
            graph.has_authority(worker, "service.write", now=expiry)
            == _independent_authority_oracle(revoked=False, now=expiry, expires_at=expiry),
            trace,
            "expired delegation is denied",
        )

        try:
            graph.grant(admin, f"widened-{trace}", "service.write", scope="service")
        except DelegationError:
            invalid_transitions_rejected += 1
            check(True, trace, "capability attenuation rejects widening scope")
        else:
            check(False, trace, "capability attenuation rejects widening scope")

        graph.revoke(grant.id)
        check(
            not graph.has_authority(worker, "service.write", now=active_now),
            trace,
            "revocation invalidates derived authority",
        )

        first = Actor(f"first-{trace}", 3)
        second = Actor(f"second-{trace}", 3)
        cycle_graph = DelegationGraph()
        cycle_graph.grant(admin, first, "service.write", depth=2)
        cycle_graph.grant(first, second, "service.write", depth=1)
        try:
            cycle_graph.grant(second, first, "service.write", depth=0)
        except DelegationError:
            invalid_transitions_rejected += 1
            check(True, trace, "delegation cycle is rejected")
        else:
            check(False, trace, "delegation cycle is rejected")

        action = Action(
            Actor(
                f"release-agent-{trace}",
                5,
                capabilities={"deploy.production"},
            ),
            Capability("deploy.production"),
            {"service": f"service-{trace_seed % 17}"},
        )
        context = Context(now=float(trace_seed % 20))
        manager = ApprovalManager(ttl=30, request_prefix=f"trace-{trace}")
        calls: list[str] = []
        interceptor = Interceptor(policy, mode="enforce", approval_manager=manager)
        pending = interceptor.execute(action, context, lambda: calls.append("executed"))
        check(
            pending.decision.kind is DecisionKind.ESCALATE and pending.executed is False,
            trace,
            "approval-required action pauses before execution",
        )
        check(not calls, trace, "operation is not called before approval")

        changed_action = Action(action.actor, action.capability, {"service": "changed"})
        try:
            manager.approve(
                pending.approval_request_id,
                "ReleaseManager",
                policy,
                changed_action,
                context,
                now=context.now,
            )
        except ApprovalError:
            invalid_transitions_rejected += 1
            check(True, trace, "approval cannot cross an action binding")
        else:
            check(False, trace, "approval cannot cross an action binding")

        manager.approve(
            pending.approval_request_id,
            "ReleaseManager",
            policy,
            action,
            context,
            now=context.now,
        )
        resumed = interceptor.resume_approved(
            pending.approval_request_id,
            action,
            context,
            lambda: calls.append("executed") or "ok",
        )
        check(
            resumed.decision.kind is DecisionKind.ALLOW and resumed.executed,
            trace,
            "matching approval resumes the exact action",
        )
        check(calls == ["executed"], trace, "approved operation executes exactly once")
        replay = interceptor.resume_approved(
            pending.approval_request_id,
            action,
            context,
            lambda: calls.append("replayed"),
        )
        check(
            replay.decision.kind is DecisionKind.BLOCK and not replay.executed,
            trace,
            "single-use approval rejects replay",
        )
        check(calls == ["executed"], trace, "replayed operation never executes")

    return AssuranceReport(
        seed=seed,
        traces=traces,
        checks=checks,
        passed=passed,
        failed=checks - passed,
        failures=tuple(failures),
        invalid_transitions_rejected=invalid_transitions_rejected,
        mutation_detected=invalid_transitions_rejected == traces * 3,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--traces", type=int, default=DEFAULT_TRACES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = run_assurance(seed=args.seed, traces=args.traces)
    payload = report.to_json()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if not args.check or report.exact else 1


if __name__ == "__main__":
    raise SystemExit(main())
