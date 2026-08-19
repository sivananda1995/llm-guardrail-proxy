"""Precision at prevalence, and the resolution floor that decides what a corpus can support."""

from __future__ import annotations

import pytest

from guardrail.evaluate import (
    BLOCK_PRECISION_FLOOR,
    PREVALENCES,
    Rates,
    ci_hint,
    justify,
    rates,
    sweep,
)


def make(tp=9, fn=1, fp=2, tn=98) -> Rates:
    return Rates(detector="d", true_positives=tp, false_negatives=fn,
                 false_positives=fp, true_negatives=tn)


def test_rates_counts_what_it_was_given():
    measured = rates("d", attacks=[True, True, False], benign=[False, True])
    assert measured.true_positives == 2
    assert measured.false_negatives == 1
    assert measured.false_positives == 1
    assert measured.true_negatives == 1


def test_tpr_and_fpr_are_ratios_of_their_own_population():
    measured = make(tp=9, fn=1, fp=2, tn=98)
    assert measured.tpr == pytest.approx(0.9)
    assert measured.fpr == pytest.approx(0.02)


def test_an_empty_population_gives_zero_rather_than_dividing():
    empty = Rates(detector="d", true_positives=0, false_negatives=0,
                  false_positives=0, true_negatives=0)
    assert empty.tpr == 0.0
    assert empty.fpr == 0.0
    assert empty.precision_at(0.5) == 0.0


def test_precision_is_high_at_high_prevalence():
    assert make().precision_at(0.5) > 0.9


def test_precision_collapses_at_low_prevalence_with_the_same_detector():
    measured = make()
    assert measured.precision_at(0.5) > 0.9
    assert measured.precision_at(0.0001) < 0.01


def test_the_alarm_ratio_is_the_inverse_of_precision():
    measured = make()
    assert measured.alarms_per_true_positive(0.01) == pytest.approx(
        1 / measured.precision_at(0.01))


def test_a_detector_that_never_fires_has_an_infinite_alarm_ratio():
    silent = Rates(detector="d", true_positives=0, false_negatives=10,
                   false_positives=0, true_negatives=10)
    assert silent.alarms_per_true_positive(0.5) == float("inf")


def test_the_smallest_measurable_rate_is_one_over_the_population():
    assert make(fp=0, tn=20).smallest_measurable_fpr == pytest.approx(1 / 20)


def test_a_measured_zero_resolves_to_one_over_the_population():
    measured = make(fp=0, tn=34)
    assert measured.fpr == 0.0
    assert measured.resolved_fpr == pytest.approx(1 / 34)


def test_a_measured_rate_above_the_floor_is_used_as_measured():
    measured = make(fp=5, tn=15)
    assert measured.resolved_fpr == pytest.approx(measured.fpr)


def test_resolved_precision_is_never_more_optimistic_than_measured():
    measured = make(fp=0, tn=34)
    for prevalence in PREVALENCES:
        assert measured.precision_at(prevalence, resolved=True) <= measured.precision_at(prevalence)


def test_a_measured_zero_still_cannot_support_a_block_at_low_prevalence():
    """The number that changes the argument, asserted as a number."""
    measured = make(tp=4, fn=0, fp=0, tn=34)
    assert measured.precision_at(0.0004) == 1.0
    assert measured.precision_at(0.0004, resolved=True) < 0.02


def test_the_needed_sample_size_is_reported_and_is_large():
    measured = make(tp=4, fn=0, fp=0, tn=34)
    needed = measured.benign_needed_for(0.0004)
    assert needed > 2000
    assert needed > measured.benign


def test_the_needed_sample_size_falls_as_prevalence_rises():
    measured = make(tp=4, fn=0, fp=0, tn=34)
    assert measured.benign_needed_for(0.1) < measured.benign_needed_for(0.001)


def test_a_detector_with_no_true_positives_needs_no_sample_size_computed():
    silent = Rates(detector="d", true_positives=0, false_negatives=4,
                   false_positives=0, true_negatives=10)
    assert silent.benign_needed_for(0.001) == 0


def test_a_sample_size_of_the_needed_number_would_support_the_block():
    measured = make(tp=4, fn=0, fp=0, tn=34)
    needed = measured.benign_needed_for(0.0004)
    larger = Rates(detector="d", true_positives=4, false_negatives=0,
                   false_positives=0, true_negatives=needed)
    assert larger.precision_at(0.0004, resolved=True) >= BLOCK_PRECISION_FLOOR


# --------------------------------------------------------------------------- intervals

def test_a_wilson_interval_of_zero_over_twenty_does_not_reach_zero_width():
    low, high = ci_hint(0, 20)
    assert low == 0.0
    assert high > 0.1


def test_a_wilson_interval_narrows_with_more_samples():
    narrow = ci_hint(0, 2000)
    wide = ci_hint(0, 20)
    assert narrow[1] < wide[1]


def test_a_wilson_interval_stays_inside_zero_and_one():
    for successes, trials in ((0, 1), (1, 1), (5, 10), (0, 10000)):
        low, high = ci_hint(successes, trials)
        assert 0.0 <= low <= high <= 1.0


def test_no_trials_gives_the_widest_possible_interval():
    assert ci_hint(0, 0) == (0.0, 1.0)


# --------------------------------------------------------------------------- verdicts

def test_a_non_blocking_action_is_justified_whatever_the_precision():
    verdict = justify("d", "flag", make(fp=5, tn=15), 0.0001)
    assert verdict.justified is True
    assert "does not refuse" in verdict.reason


def test_a_block_with_no_labelled_attack_is_unjustified():
    silent = Rates(detector="d", true_positives=0, false_negatives=0,
                   false_positives=0, true_negatives=20)
    verdict = justify("d", "block", silent, 0.5)
    assert verdict.justified is False
    assert "unmeasured" in verdict.reason


def test_a_block_at_high_prevalence_is_justified():
    verdict = justify("d", "block", make(tp=20, fn=0, fp=0, tn=200), 0.5)
    assert verdict.justified is True
    assert "floor" in verdict.reason


def test_a_block_at_low_prevalence_on_a_small_corpus_is_unjustified():
    verdict = justify("d", "block", make(tp=4, fn=0, fp=0, tn=34), 0.0004)
    assert verdict.justified is False
    assert "2499" in verdict.reason
    assert verdict.benign_needed == 2499
    assert verdict.benign_measured == 34


def test_the_verdict_payload_carries_both_precisions():
    payload = justify("d", "block", make(tp=4, fn=0, fp=0, tn=34), 0.0004).to_json()
    assert payload["precision"] == 1.0
    assert payload["resolved_precision"] < 0.02


def test_an_infinite_alarm_ratio_serialises_as_null():
    silent = Rates(detector="d", true_positives=0, false_negatives=1,
                   false_positives=0, true_negatives=10)
    payload = justify("d", "flag", silent, 0.5).to_json()
    assert payload["alarms_per_true_positive"] is None


def test_the_block_floor_is_a_coin_flip():
    assert BLOCK_PRECISION_FLOOR == 0.5


# --------------------------------------------------------------------------- the published table

def test_the_sweep_covers_every_detector_and_prevalence():
    table = sweep([make(), Rates(detector="e", true_positives=1, false_negatives=0,
                                 false_positives=0, true_negatives=9)])
    assert [row["detector"] for row in table] == ["d", "e"]
    for row in table:
        assert set(row["precision"]) == {str(p) for p in PREVALENCES}


def test_precision_falls_monotonically_as_prevalence_falls():
    row = sweep([make()])[0]
    values = [row["precision"][str(p)] for p in sorted(PREVALENCES, reverse=True)]
    assert values == sorted(values, reverse=True)


def test_the_rates_payload_never_omits_the_resolution_floor():
    payload = make(fp=0, tn=34).to_json()
    assert payload["smallest_measurable_fpr"] > 0
    assert payload["resolved_fpr"] > 0
    assert payload["benign_needed_for_block"]
