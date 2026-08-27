"""Acceptance tests for M28 adversarial assurance evidence."""

from __future__ import annotations

import json

from evaluation.m28_assurance import run_m28


def test_m28_seeded_report_is_exact_and_covers_all_adversarial_categories():
    first = run_m28(seed=20260826, property_traces=16, fuzz_cases=12)
    second = run_m28(seed=20260826, property_traces=16, fuzz_cases=12)

    assert first.exact is True
    assert first.to_dict() == second.to_dict()
    assert first.failed == 0
    assert first.mutation_detected is True
    assert set(first.category_counts) == {
        "property",
        "fuzz",
        "mutation",
        "clock_skew",
        "crash_injection",
    }


def test_m28_cli_writes_machine_readable_evidence(tmp_path, capsys):
    from evaluation.m28_assurance import main

    output = tmp_path / "m28.json"
    assert main([
        "--seed", "7",
        "--property-traces", "4",
        "--fuzz-cases", "8",
        "--output", str(output),
        "--check",
    ]) == 0
    printed = json.loads(capsys.readouterr().out)
    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert printed == persisted
    assert persisted["milestone"] == "M28"
    assert persisted["exact"] is True
