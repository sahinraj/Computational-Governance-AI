"""Acceptance tests for M19 deterministic model-based assurance."""

from evaluation.model_assurance import DEFAULT_SEED, run_assurance


def test_fixed_seed_assurance_covers_one_thousand_traces_exactly():
    report = run_assurance(seed=DEFAULT_SEED, traces=1000)
    assert report.exact
    assert report.traces == 1000
    assert report.failed == 0
    assert report.mutation_detected
    assert report.invalid_transitions_rejected == 3000


def test_assurance_report_is_reproducible_for_same_seed():
    first = run_assurance(seed=41, traces=12).to_dict()
    second = run_assurance(seed=41, traces=12).to_dict()
    assert first == second
