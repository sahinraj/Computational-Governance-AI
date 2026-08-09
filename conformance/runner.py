"""Black-box conformance runner for protocol-speaking governance systems."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from .protocol import DecisionEnvelope, ProtocolError, ToolCallEnvelope


class ConformanceAdapter(Protocol):
    def decide(self, tool_call: Mapping[str, Any]) -> Mapping[str, Any] | DecisionEnvelope:
        """Return a protocol Decision envelope for one tool call."""


@dataclass(frozen=True)
class ConformanceCase:
    case_id: str
    tool_call: ToolCallEnvelope
    expected: DecisionEnvelope

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConformanceCase":
        case_id = str(value.get("case_id", ""))
        if not case_id:
            raise ProtocolError("conformance case_id is required")
        return cls(
            case_id=case_id,
            tool_call=ToolCallEnvelope.from_dict(value["tool_call"]),
            expected=DecisionEnvelope.from_dict(value["expected"]),
        )


@dataclass
class ConformanceReport:
    adapter: str
    total: int = 0
    exact_matches: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.exact_matches / self.total if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "total": self.total,
            "exact_matches": self.exact_matches,
            "accuracy": self.accuracy,
            "failures": list(self.failures),
        }


def load_cases(path: str | Path | None = None) -> tuple[ConformanceCase, ...]:
    fixture_path = Path(path) if path is not None else Path(__file__).parent / "fixtures" / "cases.json"
    raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ProtocolError("conformance fixture root must be a list")
    cases = tuple(ConformanceCase.from_dict(item) for item in raw)
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)):
        raise ProtocolError("conformance case ids must be unique")
    return cases


def run_conformance(cases: tuple[ConformanceCase, ...], adapter: ConformanceAdapter) -> ConformanceReport:
    report = ConformanceReport(adapter=getattr(adapter, "name", adapter.__class__.__name__))
    for case in cases:
        report.total += 1
        try:
            actual_value = adapter.decide(case.tool_call.to_dict())
            actual = (
                actual_value
                if isinstance(actual_value, DecisionEnvelope)
                else DecisionEnvelope.from_dict(actual_value)
            )
            expected = case.expected.to_dict()
            received = actual.to_dict()
            # Reasons are explanatory and can vary across implementations;
            # decision kind, role, matched rules, and provenance are normative.
            keys = (
                "decision", "role", "matched_rules", "authority_source", "authority_path",
                "approval_roles", "approval_threshold",
            )
            if all(received[key] == expected[key] for key in keys):
                report.exact_matches += 1
            else:
                report.failures.append({"case_id": case.case_id, "expected": expected, "actual": received})
        except Exception as exc:  # adapters must not crash the whole corpus
            report.failures.append({"case_id": case.case_id, "error": f"{type(exc).__name__}: {exc}"})
    return report


class TranscriptAdapter:
    """Minimal implementation-independent fixture adapter."""

    name = "transcript-fixture"

    def __init__(self, cases: tuple[ConformanceCase, ...]):
        self._decisions = {
            case.tool_call.request_id: case.expected.to_dict() for case in cases
        }

    def decide(self, tool_call: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            return self._decisions[str(tool_call["request_id"])]
        except KeyError as exc:
            raise ProtocolError(f"unknown transcript request {tool_call.get('request_id')!r}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    cases = load_cases(args.fixture)
    report = run_conformance(cases, TranscriptAdapter(cases))
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if not args.check or report.accuracy == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
