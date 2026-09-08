"""M29 realistic-trace benchmark and dependency-free external adapter harness."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Optional

from governance.audit import fingerprint
from governancebench import BenchmarkDecision, Scenario, Step, load_scenarios, score_scenarios

from .reference import ReferenceAdapter


M29_DATASET_VERSION = "0.3"
M29_SCHEMA_VERSION = "1.0"
M29_DATASET_PATH = Path(__file__).parent.parent / "governancebench" / "data" / "m29_scenarios.json"


def load_m29_scenarios(path: Optional[str | Path] = None) -> tuple[Scenario, ...]:
    """Load and validate the versioned realistic-trace corpus."""
    return load_scenarios(path or M29_DATASET_PATH)


class _ExternalAdapterBase:
    """Shared enforcement probe for two deliberately different host contracts."""

    name = "external-base"

    def __init__(self):
        self.reference = ReferenceAdapter()
        self._seen_request_ids: set[str] = set()
        self.execution_events: list[dict[str, Any]] = []
        self.failure_taxonomy: dict[str, int] = {}
        self.unauthorized_execution_attempts = 0
        self._all_execution_events: list[dict[str, Any]] = []
        self._all_failure_taxonomy: dict[str, int] = {}
        self._all_unauthorized_execution_attempts = 0

    def reset(self, scenario: Scenario) -> None:
        self.reference.reset(scenario)
        self._seen_request_ids = set()
        self.execution_events = []
        self.failure_taxonomy = {}
        self.unauthorized_execution_attempts = 0

    def _dispatch(self, scenario: Scenario, step: Step) -> BenchmarkDecision:
        raise NotImplementedError

    def _failure_class(self, scenario: Scenario, step: Step, decision: BenchmarkDecision) -> str:
        context = step.context
        if context.get("malformed"):
            return "malformed_input"
        if context.get("identity_valid") is False:
            return "identity_failure"
        if context.get("replay"):
            return "replay_attempt"
        now = float(context.get("now", 0))
        if any(
            delegate.get("expires_at") is not None
            and now >= float(delegate["expires_at"])
            for setup in scenario.setup
            for delegate in [setup.get("delegate", {})]
        ):
            return "delegation_expiry"
        if context.get("external_outcome") == "unknown":
            return "external_outcome_unknown"
        if decision.kind == "Escalate":
            return "approval_required"
        if decision.kind == "Block":
            return "policy_block"
        return "allowed_execution"

    def _record_execution(self, scenario: Scenario, step: Step, decision: BenchmarkDecision) -> None:
        if decision.kind != "Allow":
            return
        request_id = step.context.get("request_id", f"{scenario.id}:{step.index}")
        outcome = str(step.context.get("external_outcome", "succeeded"))
        self.execution_events.append({
            "scenario": scenario.id,
            "step": step.index,
            "request_id": str(request_id),
            "outcome": outcome,
        })

    def decide(self, scenario: Scenario, step: Step) -> Mapping[str, Any]:
        context = step.context
        request_id = context.get("request_id")
        request_key = None if request_id is None else str(request_id)
        if context.get("malformed"):
            decision = BenchmarkDecision("Block")
        elif context.get("identity_valid") is False:
            decision = BenchmarkDecision("Block")
        elif context.get("replay") and request_key in self._seen_request_ids:
            decision = BenchmarkDecision("Block")
        else:
            decision = self._dispatch(scenario, step)
        if request_key is not None:
            self._seen_request_ids.add(request_key)

        if decision.kind != "Allow" and context.get("external_outcome") == "unknown":
            self.unauthorized_execution_attempts += 1
            self._all_unauthorized_execution_attempts += 1
        execution_count = len(self.execution_events)
        self._record_execution(scenario, step, decision)
        failure_class = self._failure_class(scenario, step, decision)
        self.failure_taxonomy[failure_class] = self.failure_taxonomy.get(failure_class, 0) + 1
        self._all_failure_taxonomy[failure_class] = (
            self._all_failure_taxonomy.get(failure_class, 0) + 1
        )
        if len(self.execution_events) > execution_count:
            self._all_execution_events.append(self.execution_events[-1])
        return {"kind": decision.kind, "role": decision.role}

    def summary(self) -> dict[str, Any]:
        outcomes = {}
        for event in self._all_execution_events:
            outcomes[event["outcome"]] = outcomes.get(event["outcome"], 0) + 1
        return {
            "name": self.name,
            "executed_operations": len(self._all_execution_events),
            "execution_outcomes": dict(sorted(outcomes.items())),
            "unauthorized_execution_attempts": self._all_unauthorized_execution_attempts,
            "failure_taxonomy": dict(sorted(self._all_failure_taxonomy.items())),
        }


class WebhookGatewayAdapter(_ExternalAdapterBase):
    """Adapter for a JSON webhook gateway with an explicit envelope contract."""

    name = "webhook-gateway"

    def _dispatch(self, scenario: Scenario, step: Step) -> BenchmarkDecision:
        envelope = {
            "version": "1",
            "event": "tool.request",
            "payload": step.to_dict(),
        }
        received = json.loads(json.dumps(envelope, sort_keys=True))
        forwarded = Step.from_dict(received["payload"], step.index)
        return self.reference.decide(scenario, forwarded)


class MessageQueueAdapter(_ExternalAdapterBase):
    """Adapter for a serialized message-bus contract with typed payloads."""

    name = "message-queue"

    def _dispatch(self, scenario: Scenario, step: Step) -> BenchmarkDecision:
        message = {
            "schema": "governance.tool-call.v1",
            "message_id": f"{scenario.id}:{step.index}",
            "payload": step.to_dict(),
        }
        received = json.loads(json.dumps(message, sort_keys=True))
        if received.get("schema") != "governance.tool-call.v1":
            raise ValueError("unsupported message schema")
        forwarded = Step.from_dict(received["payload"], step.index)
        return self.reference.decide(scenario, forwarded)


def _policy_fingerprint(scenario: Scenario) -> str:
    return fingerprint({"constraints": [dict(rule) for rule in scenario.rules]})


def run_m29(scenarios: Optional[tuple[Scenario, ...]] = None) -> dict[str, Any]:
    """Run both external adapters and return a deterministic evidence report."""
    corpus = load_m29_scenarios() if scenarios is None else tuple(scenarios)
    if len(corpus) < 12:
        raise ValueError("M29 requires at least 12 realistic scenarios")
    adapters = [WebhookGatewayAdapter(), MessageQueueAdapter()]
    systems = []
    for adapter in adapters:
        score = score_scenarios(corpus, adapter, system=adapter.name)
        summary = adapter.summary()
        systems.append({
            "name": adapter.name,
            "total_steps": score.total_steps,
            "exact_matches": score.exact_matches,
            "accuracy": score.accuracy,
            "executed_operations": summary["executed_operations"],
            "execution_outcomes": summary["execution_outcomes"],
            "unauthorized_execution_attempts": summary["unauthorized_execution_attempts"],
            "failure_taxonomy": summary["failure_taxonomy"],
            "mismatches": score.mismatches,
        })
    return {
        "schema_version": M29_SCHEMA_VERSION,
        "benchmark_version": M29_DATASET_VERSION,
        "dataset": {
            "path": "governancebench/data/m29_scenarios.json",
            "scenario_count": len(corpus),
            "trace_step_count": sum(len(scenario.trace) for scenario in corpus),
            "categories": sorted({scenario.category for scenario in corpus}),
            "policy_fingerprints": {
                scenario.id: _policy_fingerprint(scenario)
                for scenario in corpus
            },
        },
        "adapters": systems,
    }


def validate_report(report: Mapping[str, Any]) -> None:
    if report.get("schema_version") != M29_SCHEMA_VERSION:
        raise ValueError("unsupported M29 report schema")
    dataset = report.get("dataset", {})
    if dataset.get("scenario_count", 0) < 12 or dataset.get("trace_step_count", 0) < 12:
        raise ValueError("M29 report does not contain the required corpus")
    adapters = report.get("adapters", [])
    if {item.get("name") for item in adapters} != {"webhook-gateway", "message-queue"}:
        raise ValueError("M29 report must contain both external adapters")
    for item in adapters:
        if item.get("accuracy") != 1.0:
            raise ValueError(f"{item.get('name')} did not match the M29 labels exactly")
        if item.get("unauthorized_execution_attempts") != 0:
            raise ValueError(f"{item.get('name')} crossed the governance boundary")
        if item.get("mismatches"):
            raise ValueError(f"{item.get('name')} has benchmark mismatches")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path("reports/m29-benchmark.json")
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = run_m29()
    if args.check:
        validate_report(report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
