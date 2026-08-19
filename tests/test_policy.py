"""The loader, which is the only thing standing between a typo and a guardrail that does nothing."""

from __future__ import annotations

import pytest

from guardrail.errors import PolicyError
from guardrail.policy import (
    BLOCK,
    FAIL_CLOSED,
    FAIL_OPEN,
    FLAG,
    PROMPT,
    REDACT,
    RESPONSE,
    DetectorPolicy,
    load,
)

MINIMAL = """
version: 1
route: t
description: a route
prevalence: 0.0
detectors:
  injection_override:
    action: flag
    where: [prompt]
    budget_ms: 5
stream:
  lookback_chars: 32
budget:
  total_ms: 45
  on_unavailable:
    prompt: closed
    response: open
response:
  refusal: "no"
"""


def test_the_shipped_policy_loads(policy):
    assert policy.route == "support-assistant"
    assert policy.prevalence == 0.0004
    assert len(policy.detectors) == 7


def test_the_shipped_policy_holds_back_more_than_the_longest_key(policy):
    assert policy.stream.lookback_chars >= 20


def test_detectors_are_ordered_cheapest_first(policy):
    budgets = [detector.budget_ms for detector in policy.for_side(RESPONSE)]
    assert budgets == sorted(budgets)


def test_for_side_returns_only_that_side(policy):
    assert all(detector.applies_to(PROMPT) for detector in policy.for_side(PROMPT))
    assert all(detector.applies_to(RESPONSE) for detector in policy.for_side(RESPONSE))


def test_a_detector_on_both_sides_appears_in_both(policy):
    assert "secret_pattern" in [d.name for d in policy.for_side(PROMPT)]
    assert "secret_pattern" in [d.name for d in policy.for_side(RESPONSE)]


def test_stream_unsafe_detectors_are_named(policy):
    assert policy.stream_unsafe() == ("system_prompt_echo",)


def test_the_fail_mode_differs_per_side(policy):
    assert policy.budget.mode_for(PROMPT) == FAIL_CLOSED
    assert policy.budget.mode_for(RESPONSE) == FAIL_OPEN


def test_an_unknown_side_defaults_to_failing_closed(policy):
    assert policy.budget.mode_for("sideways") == FAIL_CLOSED


def test_detector_budgets_fit_inside_the_total(policy):
    assert sum(d.budget_ms for d in policy.detectors.values()) <= policy.budget.total_ms


def test_a_minimal_policy_loads(write_policy):
    loaded = write_policy(MINIMAL)
    assert loaded.route == "t"


def test_a_missing_file_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        load(tmp_path / "absent.yaml")


def test_an_unknown_detector_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("injection_override:", "telepathy:"))
    assert "telepathy" in str(caught.value)


def test_an_unknown_action_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("action: flag", "action: ponder"))


def test_a_detector_with_no_side_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("where: [prompt]", "where: []"))
    assert "never run" in str(caught.value)


def test_an_unknown_side_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("where: [prompt]", "where: [sideways]"))


def test_redacting_a_prompt_is_refused(write_policy):
    """Redacting an input changes the question without telling anyone who asked it."""
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("action: flag", "action: redact"))
    assert "redact" in str(caught.value).lower()


def test_budgets_that_exceed_the_total_are_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("total_ms: 45", "total_ms: 2"))
    assert "budget" in str(caught.value).lower()


def test_an_unknown_failure_mode_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("prompt: closed", "prompt: maybe"))
    assert "third option" in str(caught.value)


def test_a_missing_failure_mode_for_a_side_defaults_rather_than_failing(write_policy):
    loaded = write_policy(MINIMAL.replace("    prompt: closed\n", ""))
    assert loaded.budget.mode_for(PROMPT) == FAIL_CLOSED


def test_explaining_refusals_on_a_live_route_is_refused(write_policy):
    body = MINIMAL.replace("prevalence: 0.0", "prevalence: 0.01").replace(
        'refusal: "no"', 'refusal: "no"\n  explain: true')
    with pytest.raises(PolicyError) as caught:
        write_policy(body)
    assert "oracle" in str(caught.value).lower()


def test_explaining_refusals_is_allowed_when_prevalence_is_zero(write_policy):
    loaded = write_policy(MINIMAL.replace('refusal: "no"', 'refusal: "no"\n  explain: true'))
    assert loaded.response.explain is True


def test_an_unknown_reads_form_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("action: flag", "action: flag\n    reads: tea-leaves"))


def test_an_unknown_confidence_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("action: flag", "action: flag\n    min_confidence: vibes"))


def test_a_negative_lookback_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("lookback_chars: 32", "lookback_chars: -1"))


def test_a_prevalence_outside_zero_to_one_is_refused(write_policy):
    with pytest.raises(PolicyError):
        write_policy(MINIMAL.replace("prevalence: 0.0", "prevalence: 4"))


# --------------------------------------------------------------------------- confidence degrading

@pytest.mark.parametrize(("minimum", "confidence", "expected"), [
    ("high", "high", BLOCK),
    ("high", "medium", FLAG),
    ("high", "low", FLAG),
    ("medium", "medium", BLOCK),
    ("medium", "low", FLAG),
    ("low", "low", BLOCK),
])
def test_an_action_degrades_below_its_minimum_confidence(minimum, confidence, expected):
    detector = DetectorPolicy(name="d", action=BLOCK, where=(PROMPT,), budget_ms=1,
                              min_confidence=minimum)
    assert detector.action_for(confidence) == expected


def test_a_redacting_detector_also_degrades_to_flag():
    detector = DetectorPolicy(name="d", action=REDACT, where=(RESPONSE,), budget_ms=1,
                              min_confidence="high")
    assert detector.action_for("low") == FLAG


def test_the_shipped_secret_detector_only_blocks_at_high_confidence(policy):
    detector = policy.detectors["secret_pattern"]
    assert detector.action_for("high") == BLOCK
    assert detector.action_for("low") == FLAG


def test_the_shipped_secret_detector_reads_the_text_as_sent(policy):
    assert policy.detectors["secret_pattern"].reads == "raw"


def test_blocks_is_true_only_for_blocking_detectors(policy):
    assert policy.detectors["secret_pattern"].blocks is True
    assert policy.detectors["injection_override"].blocks is False


def test_the_policy_payload_round_trips_the_decisions(policy):
    payload = policy.to_json()
    assert payload["route"] == policy.route
    assert payload["stream"]["lookback_chars"] == policy.stream.lookback_chars
    assert payload["budget"]["on_unavailable"][RESPONSE] == FAIL_OPEN


def test_invalid_yaml_is_a_policy_error(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("route: [unclosed\n")
    with pytest.raises(PolicyError) as caught:
        load(path)
    assert "not valid YAML" in str(caught.value)


def test_a_policy_with_no_route_is_refused(tmp_path):
    path = tmp_path / "no-route.yaml"
    path.write_text("detectors:\n  pii_email:\n    action: redact\n    where: [response]\n"
                    "    budget_ms: 1\n")
    with pytest.raises(PolicyError) as caught:
        load(path)
    assert "route" in str(caught.value)


def test_a_policy_with_no_detectors_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("""detectors:
  injection_override:
    action: flag
    where: [prompt]
    budget_ms: 5
""", "detectors: {}\n"))
    assert "no detectors" in str(caught.value)


def test_a_detector_with_no_budget_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("    budget_ms: 5\n", ""))
    assert "budget_ms" in str(caught.value)


def test_a_zero_budget_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("budget_ms: 5", "budget_ms: 0"))
    assert "budget" in str(caught.value)


def test_an_unknown_side_in_the_failure_modes_is_refused(write_policy):
    with pytest.raises(PolicyError) as caught:
        write_policy(MINIMAL.replace("    prompt: closed", "    sideways: closed"))
    assert "sideways" in str(caught.value)
