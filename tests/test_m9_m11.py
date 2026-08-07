"""Acceptance tests for GovernanceBench, evaluation, and failure containment."""

from governancebench import CATEGORIES, load_scenarios, score_scenarios
from evaluation.failure_harness import run_failure_harness
from evaluation.reference import ReferenceAdapter, StaticBaselineAdapter


def test_m9_dataset_loads_all_categories_and_round_trips():
    scenarios = load_scenarios()
    assert len(scenarios) == 10
    assert {scenario.category for scenario in scenarios} == set(CATEGORIES)
    assert all(step.tests for scenario in scenarios for step in scenario.trace)
    assert all(step.expected for scenario in scenarios for step in scenario.trace)
    assert all(scenario.to_dict()["id"] == scenario.id for scenario in scenarios)


def test_m10_reference_beats_static_baseline_on_dynamic_categories():
    scenarios = load_scenarios()
    reference = score_scenarios(scenarios, ReferenceAdapter())
    baseline = score_scenarios(scenarios, StaticBaselineAdapter())
    assert reference.accuracy == 1.0
    assert reference.escalation_accuracy == 1.0
    assert baseline.accuracy < reference.accuracy
    for category in (
        "delegation_misuse",
        "runtime_context_change",
        "revocation_correctness",
        "multi_agent_attacks",
    ):
        assert reference.categories[category].accuracy == 1.0
        assert baseline.categories[category].accuracy < 1.0


def test_m11_each_failure_has_logged_containment():
    outcomes = run_failure_harness()
    assert {outcome.category for outcome in outcomes} == {
        "authority_leakage",
        "delegation_loops",
        "escalation_deadlock",
        "capability_taxonomy_gaps",
    }
    assert all(outcome.detected for outcome in outcomes)
    assert all(outcome.contained for outcome in outcomes)
    assert all(outcome.log for outcome in outcomes)
