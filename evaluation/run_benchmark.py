"""Run GovernanceBench against the reference and static baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from governancebench import load_scenarios, score_scenarios

from .reference import ReferenceAdapter, StaticBaselineAdapter


def run_evaluation() -> dict[str, Any]:
    scenarios = load_scenarios()
    reference = score_scenarios(scenarios, ReferenceAdapter())
    baseline = score_scenarios(scenarios, StaticBaselineAdapter())
    return {
        "dataset": {
            "scenario_count": len(scenarios),
            "categories": sorted({scenario.category for scenario in scenarios}),
        },
        "systems": [reference.to_dict(), baseline.to_dict()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/governancebench.json"),
        help="JSON report path (default: reports/governancebench.json)",
    )
    parser.add_argument("--check", action="store_true", help="fail if the reference is not perfect")
    args = parser.parse_args()
    report = run_evaluation()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.check:
        reference = report["systems"][0]
        if reference["accuracy"] != 1.0:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
