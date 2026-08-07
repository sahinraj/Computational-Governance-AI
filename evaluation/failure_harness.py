"""M11 failure-taxonomy injection and containment harness."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from governance import (
    Action,
    Actor,
    Capability,
    Context,
    DelegationError,
    DelegationGraph,
    Interceptor,
    InterceptorMode,
    compile_policy,
)


@dataclass(frozen=True)
class FailureOutcome:
    case_id: str
    category: str
    detected: bool
    contained: bool
    decision: str
    executed: bool
    log: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _authority_leakage() -> FailureOutcome:
    policy = compile_policy(
        "LAW-FAIL-001\n  capability: github.write\n  authority_level: >= 2\n  on_violation: block",
        default_decision="Block",
    )
    actor = Actor("untrusted", 2)
    result = Interceptor(
        policy,
        mode=InterceptorMode.ENFORCE,
        delegation=DelegationGraph(),
    ).execute(
        Action(actor, Capability("github.write")),
        Context(),
        lambda: "should-not-run",
    )
    return FailureOutcome(
        case_id="FAIL-001",
        category="authority_leakage",
        detected=result.decision.kind.value == "Block",
        contained=not result.executed,
        decision=result.decision.kind.value,
        executed=result.executed,
        log=(result.decision.reason,),
    )


def _delegation_loop() -> FailureOutcome:
    admin = Actor("admin", 5, capabilities={"github.write"})
    first = Actor("first", 3)
    second = Actor("second", 3)
    graph = DelegationGraph()
    logs: list[str] = []
    graph.grant(admin, first, "github.write", depth=2)
    graph.grant(first, second, "github.write", depth=1)
    try:
        graph.grant(second, first, "github.write", depth=0)
    except DelegationError as exc:
        logs.append(str(exc))
        return FailureOutcome(
            case_id="FAIL-002",
            category="delegation_loops",
            detected=True,
            contained=True,
            decision="Block",
            executed=False,
            log=tuple(logs),
        )
    return FailureOutcome(
        case_id="FAIL-002",
        category="delegation_loops",
        detected=False,
        contained=False,
        decision="Allow",
        executed=True,
        log=("delegation cycle was not rejected",),
    )


def _escalation_deadlock() -> FailureOutcome:
    policy = compile_policy(
        "LAW-FAIL-003\n  capability: deploy.production\n  requires_approval: ReleaseManager\n  on_violation: escalate",
        roles={"ReleaseManager"},
        default_decision="Block",
    )
    actor = Actor("release-agent", 5, capabilities={"deploy.production"})
    result = Interceptor(policy, mode=InterceptorMode.ENFORCE).execute(
        Action(actor, Capability("deploy.production")),
        Context(),
        lambda: "should-not-run",
    )
    return FailureOutcome(
        case_id="FAIL-003",
        category="escalation_deadlock",
        detected=result.decision.kind.value == "Escalate",
        contained=not result.executed,
        decision=result.decision.kind.value,
        executed=result.executed,
        log=(result.decision.reason, "no approval handler; execution suspended"),
    )


def _capability_taxonomy_gap() -> FailureOutcome:
    policy = compile_policy(
        "LAW-FAIL-004\n  capability: github.write\n  on_violation: block",
        default_decision="Block",
    )
    actor = Actor("agent", 5, capabilities={"github.write"})
    result = Interceptor(policy, mode=InterceptorMode.ENFORCE).execute(
        Action(actor, Capability("github_write")),
        Context(),
        lambda: "should-not-run",
    )
    return FailureOutcome(
        case_id="FAIL-004",
        category="capability_taxonomy_gaps",
        detected=result.decision.kind.value == "Block",
        contained=not result.executed,
        decision=result.decision.kind.value,
        executed=result.executed,
        log=(result.decision.reason,),
    )


CASES: tuple[Callable[[], FailureOutcome], ...] = (
    _authority_leakage,
    _delegation_loop,
    _escalation_deadlock,
    _capability_taxonomy_gap,
)


def run_failure_harness() -> tuple[FailureOutcome, ...]:
    return tuple(case() for case in CASES)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/failure-taxonomy.json"),
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outcomes = run_failure_harness()
    payload = {"cases": [outcome.to_dict() for outcome in outcomes]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.check and not all(outcome.detected and outcome.contained for outcome in outcomes):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
