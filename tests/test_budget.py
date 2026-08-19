"""Running detectors under a budget, and the decision that has no safe answer."""

from __future__ import annotations

import time

import pytest

from guardrail.budget import ADVERSARIAL_MULTIPLE, DetectorRun, Spend, availability, spend, timed
from guardrail.errors import GuardrailUnavailable
from guardrail.policy import FAIL_CLOSED, FAIL_OPEN, PROMPT, RESPONSE


def test_a_fast_detector_answers_within_budget():
    result, run = timed(lambda: ("a", "b"), "fast", budget_ms=50)
    assert result == ("a", "b")
    assert run.answered is True
    assert run.findings == 2
    assert run.over_budget is False


def test_a_detector_that_raises_becomes_an_unavailability():
    def explode():
        raise ValueError("no")

    with pytest.raises(GuardrailUnavailable) as caught:
        timed(explode, "broken", budget_ms=50)
    assert caught.value.detector == "broken"
    assert "ValueError" in caught.value.reason


def test_a_detector_that_exceeds_its_budget_becomes_an_unavailability():
    with pytest.raises(GuardrailUnavailable) as caught:
        timed(lambda: time.sleep(0.02), "slow", budget_ms=1)
    assert "budget" in caught.value.reason
    assert caught.value.elapsed_ms > 1


def test_a_large_overrun_is_reported_as_adversarial():
    with pytest.raises(GuardrailUnavailable) as caught:
        timed(lambda: time.sleep(0.05), "slow", budget_ms=1)
    assert caught.value.looks_adversarial is True


def test_a_run_result_without_a_length_reports_no_findings():
    _, run = timed(object, "opaque", budget_ms=50)
    assert run.findings == 0


def test_the_adversarial_multiple_is_above_ordinary_variance():
    assert ADVERSARIAL_MULTIPLE >= 2.0


def test_a_run_payload_carries_the_budget_it_was_measured_against():
    run = DetectorRun(name="d", elapsed_ms=1.0, budget_ms=2.0, answered=True)
    assert run.to_json()["budget_ms"] == 2.0


# --------------------------------------------------------------------------- spending a side

def test_every_detector_for_a_side_runs(policy):
    findings, record = spend(policy, PROMPT, lambda detector: [detector.name])
    assert sorted(findings) == sorted(d.name for d in policy.for_side(PROMPT))
    assert record.unavailable == ()
    assert record.unchecked is False


def test_the_total_is_the_sum_of_the_runs(policy):
    _, record = spend(policy, PROMPT, lambda detector: [])
    assert record.total_ms == pytest.approx(sum(run.elapsed_ms for run in record.runs), abs=1e-3)


def test_failing_open_continues_past_a_broken_detector(policy):
    def work(detector):
        if detector.name == "secret_pattern":
            raise RuntimeError("boom")
        return [detector.name]

    findings, record = spend(policy, RESPONSE, work)
    assert "secret_pattern" in record.unavailable
    assert record.failed_open is True
    assert record.failed_closed is False
    assert findings, "the other detectors still ran"
    assert record.unchecked is True


def test_failing_closed_stops_at_the_first_broken_detector(policy):
    def work(detector):
        raise RuntimeError("boom")

    findings, record = spend(policy, PROMPT, work)
    assert record.failed_closed is True
    assert record.failed_open is False
    assert findings == []
    assert record.unchecked is False, "a closed failure did not let anything through"


def test_a_side_with_no_failure_reports_nothing_unchecked(policy):
    _, record = spend(policy, RESPONSE, lambda detector: [])
    assert record.unchecked is False
    assert record.failed_open is False


def test_the_answered_set_excludes_the_detector_that_failed(policy):
    def work(detector):
        if detector.name == "pii_email":
            raise RuntimeError("boom")
        return []

    _, record = spend(policy, RESPONSE, work)
    assert "pii_email" not in record.answered
    assert "pii_card" in record.answered


def test_the_spend_payload_names_the_side_and_the_unchecked_flag(policy):
    _, record = spend(policy, PROMPT, lambda detector: [])
    payload = record.to_json()
    assert payload["side"] == PROMPT
    assert payload["went_through_unchecked"] is False


def test_an_empty_spend_reports_zero_rather_than_dividing():
    record = Spend(side=PROMPT)
    assert record.total_ms == 0
    assert record.answered == ()
    assert record.adversarial == ()


# --------------------------------------------------------------------------- availability

def test_failing_closed_multiplies_availability():
    result = availability(0.999, 0.999, fail_open=False)
    assert result["combined_availability"] < 0.999
    assert result["coverage"] == 1.0
    assert result["uncovered_minutes_per_month"] == 0.0


def test_failing_open_keeps_availability_and_spends_coverage():
    result = availability(0.999, 0.999, fail_open=True)
    assert result["combined_availability"] == 0.999
    assert result["coverage"] == 0.999
    assert result["uncovered_minutes_per_month"] > 0


def test_failing_closed_doubles_the_downtime_of_two_equal_nines():
    closed = availability(0.999, 0.999, fail_open=False)
    open_ = availability(0.999, 0.999, fail_open=True)
    assert closed["downtime_minutes_per_month"] == pytest.approx(
        open_["downtime_minutes_per_month"] * 2, rel=0.01)


def test_a_perfect_guardrail_costs_nothing_either_way():
    closed = availability(0.999, 1.0, fail_open=False)
    open_ = availability(0.999, 1.0, fail_open=True)
    assert closed["combined_availability"] == open_["combined_availability"]


def test_the_shipped_policy_fails_closed_on_the_prompt_and_open_on_the_response(policy):
    assert policy.budget.mode_for(PROMPT) == FAIL_CLOSED
    assert policy.budget.mode_for(RESPONSE) == FAIL_OPEN
