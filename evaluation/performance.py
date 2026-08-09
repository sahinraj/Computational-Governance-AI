"""Reproducible local decision-overhead measurement."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

from governance import Action, Actor, Capability, Context, compile_policy


def measure(iterations: int = 1000) -> dict:
    policy = compile_policy(
        "LAW-1\n  capability: payment.send\n  constraint: amount <= 100\n"
    )
    action = Action(
        Actor("benchmark-agent", 5, capabilities={"payment.send"}),
        Capability("payment.send"),
        {"amount": 50},
    )
    context = Context()
    samples = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        policy.evaluate(action, context)
        samples.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "iterations": iterations,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "mean_ms": sum(samples) / len(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--output", type=Path, default=Path("reports/performance.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.iterations <= 0:
        parser.error("--iterations must be positive")
    report = measure(args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not args.check or report["mean_ms"] < 100 else 1


if __name__ == "__main__":
    raise SystemExit(main())
