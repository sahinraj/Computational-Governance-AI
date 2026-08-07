"""GovernanceBench's runtime-agnostic scenario schema and loader.

This module deliberately imports only the Python standard library. A system
under test supplies an adapter that consumes :class:`Scenario` and returns
abstract ``Allow``, ``Block``, or ``Escalate`` decisions. The benchmark never
imports the reference implementation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


CATEGORIES = (
    "authority_violations",
    "budget_violations",
    "approval_chain_violations",
    "delegation_misuse",
    "escalation_handling",
    "policy_conflicts",
    "runtime_context_change",
    "revocation_correctness",
    "multi_agent_attacks",
    "human_override",
)
DECISIONS = ("Allow", "Block", "Escalate")
HUMAN_DECISIONS = ("Allow", "Block")


class SchemaError(ValueError):
    """Raised when a benchmark scenario is malformed."""


def _copy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return dict(value)


@dataclass(frozen=True)
class Step:
    actor: str
    capability: str
    params: Mapping[str, Any]
    context: Mapping[str, Any]
    expected: str
    tests: str
    expected_role: Optional[str] = None
    before: tuple[Mapping[str, Any], ...] = ()
    human_decision: Optional[str] = None
    index: int = 0

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], index: int) -> "Step":
        return cls(
            actor=str(value.get("actor", "")),
            capability=str(value.get("action", {}).get("capability", value.get("capability", ""))),
            params=_copy_mapping(value.get("action", {}).get("params", value.get("params", {}))),
            context=_copy_mapping(value.get("context", {})),
            expected=str(value.get("expected", "")),
            tests=str(value.get("tests", "")),
            expected_role=value.get("expected_role"),
            before=tuple(_copy_mapping(item) for item in value.get("before", ())),
            human_decision=value.get("human_decision"),
            index=int(value.get("step", index)),
        )

    def validate(self, actor_ids: set[str], rule_ids: set[str]) -> None:
        if not self.actor or self.actor not in actor_ids:
            raise SchemaError(f"step {self.index}: unknown actor {self.actor!r}")
        if not self.capability:
            raise SchemaError(f"step {self.index}: missing capability")
        if self.expected not in DECISIONS:
            raise SchemaError(
                f"step {self.index}: expected must be one of {DECISIONS}, got {self.expected!r}"
            )
        if not self.tests or self.tests not in rule_ids:
            raise SchemaError(f"step {self.index}: tests unknown rule {self.tests!r}")
        if self.expected == "Escalate" and not self.expected_role:
            raise SchemaError(f"step {self.index}: Escalate requires expected_role")
        if self.expected != "Escalate" and self.expected_role:
            raise SchemaError(f"step {self.index}: expected_role only applies to Escalate")
        if self.human_decision not in (None, *HUMAN_DECISIONS):
            raise SchemaError(
                f"step {self.index}: human_decision must be Allow or Block"
            )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "step": self.index,
            "actor": self.actor,
            "action": {"capability": self.capability, "params": dict(self.params)},
            "context": dict(self.context),
            "expected": self.expected,
            "tests": self.tests,
        }
        if self.expected_role:
            value["expected_role"] = self.expected_role
        if self.before:
            value["before"] = [dict(item) for item in self.before]
        if self.human_decision:
            value["human_decision"] = self.human_decision
        return value


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    description: str
    rules: tuple[Mapping[str, Any], ...]
    actors: tuple[Mapping[str, Any], ...]
    setup: tuple[Mapping[str, Any], ...] = ()
    trace: tuple[Step, ...] = ()
    scoring: str = "exact_decision_match"
    schema_version: str = "1.0"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Scenario":
        trace = tuple(
            Step.from_dict(item, index)
            for index, item in enumerate(value.get("trace", ()), start=1)
        )
        scenario = cls(
            id=str(value.get("id", "")),
            category=str(value.get("category", "")),
            description=str(value.get("description", "")),
            rules=tuple(_copy_mapping(item) for item in value.get("constraints", value.get("rules", ()))),
            actors=tuple(_copy_mapping(item) for item in value.get("actors", ())),
            setup=tuple(_copy_mapping(item) for item in value.get("setup", ())),
            trace=trace,
            scoring=str(value.get("scoring", "exact_decision_match")),
            schema_version=str(value.get("schema_version", "1.0")),
        )
        scenario.validate()
        return scenario

    def validate(self) -> None:
        if not self.id:
            raise SchemaError("scenario is missing id")
        if self.category not in CATEGORIES:
            raise SchemaError(f"{self.id}: unknown category {self.category!r}")
        if self.scoring != "exact_decision_match":
            raise SchemaError(f"{self.id}: unsupported scoring rule {self.scoring!r}")
        rule_ids = [str(rule.get("id", "")) for rule in self.rules]
        if not all(rule_ids) or len(set(rule_ids)) != len(rule_ids):
            raise SchemaError(f"{self.id}: rule ids must be present and unique")
        actor_ids = [str(actor.get("id", "")) for actor in self.actors]
        if not all(actor_ids) or len(set(actor_ids)) != len(actor_ids):
            raise SchemaError(f"{self.id}: actor ids must be present and unique")
        if not self.trace:
            raise SchemaError(f"{self.id}: trace cannot be empty")
        for step in self.trace:
            step.validate(set(actor_ids), set(rule_ids))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "category": self.category,
            "description": self.description,
            "constraints": [dict(rule) for rule in self.rules],
            "actors": [dict(actor) for actor in self.actors],
            "setup": [dict(item) for item in self.setup],
            "trace": [step.to_dict() for step in self.trace],
            "scoring": self.scoring,
        }


def validate_dataset(scenarios: Iterable[Scenario]) -> tuple[Scenario, ...]:
    scenarios = tuple(scenarios)
    ids = [scenario.id for scenario in scenarios]
    if len(set(ids)) != len(ids):
        raise SchemaError("scenario ids must be unique")
    categories = {scenario.category for scenario in scenarios}
    missing = set(CATEGORIES) - categories
    if missing:
        raise SchemaError(f"dataset is missing categories: {sorted(missing)}")
    for scenario in scenarios:
        scenario.validate()
    return scenarios


def load_scenarios(path: Optional[str | Path] = None) -> tuple[Scenario, ...]:
    dataset_path = Path(path) if path is not None else Path(__file__).parent / "data" / "scenarios.json"
    with dataset_path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise SchemaError("dataset root must be a JSON list")
    return validate_dataset(Scenario.from_dict(item) for item in raw)


DATASET = load_scenarios()
GB_0001 = next(scenario for scenario in DATASET if scenario.id == "GB-0001")
