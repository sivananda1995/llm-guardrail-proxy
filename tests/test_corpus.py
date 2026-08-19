"""The corpus, run through the real proxy, one test per case.

Parametrised by slug so a failure names the case rather than a count, and every assertion is against
what the case *declares*, so changing the expected behaviour means editing the corpus rather than
editing the test that guards it.
"""

from __future__ import annotations

import pytest

import attacks
from attacks.scenarios import ATTACK, BENIGN, EVASION


@pytest.fixture(scope="module")
def results():
    return {case.slug: (case, transaction) for case, transaction in attacks.run_all()}


@pytest.mark.parametrize("slug", [case.slug for case in attacks.CASES])
def test_every_case_is_refused_or_allowed_as_declared(slug, results):
    case, transaction = results[slug]
    assert (not transaction.allowed) == case.expect_blocked, case.note


@pytest.mark.parametrize("slug", [case.slug for case in attacks.CASES if case.expect_redacted])
def test_every_case_that_should_be_redacted_is(slug, results):
    _, transaction = results[slug]
    assert transaction.response is not None
    assert transaction.response.redactions >= 1


@pytest.mark.parametrize("slug", [case.slug for case in attacks.CASES if case.expect_detectors])
def test_every_declared_detector_fires_on_its_case(slug, results):
    case, transaction = results[slug]
    fired = {finding.detector for finding in transaction.findings}
    assert set(case.expect_detectors) <= fired, case.note


@pytest.mark.parametrize("slug", [case.slug for case in attacks.of_kind(BENIGN)])
def test_no_benign_case_is_refused(slug, results):
    _, transaction = results[slug]
    assert transaction.allowed is True


@pytest.mark.parametrize("slug", [case.slug for case in attacks.of_kind(BENIGN)])
def test_no_benign_case_leaks(slug, results):
    _, transaction = results[slug]
    assert transaction.leaked_chars == 0


@pytest.mark.parametrize("slug", [case.slug for case in attacks.CASES])
def test_no_case_leaks_at_the_shipped_lookback(slug, results):
    """The lookback the policy ships with is large enough that nothing in the corpus escapes."""
    _, transaction = results[slug]
    assert transaction.leaked_chars == 0


@pytest.mark.parametrize("slug", [case.slug for case in attacks.CASES])
def test_no_case_exits_non_zero(slug, results):
    _, transaction = results[slug]
    assert transaction.exit_code == 0


@pytest.mark.parametrize("slug", [case.slug for case in attacks.of_kind(EVASION)])
def test_every_evasion_declares_whether_canonicalisation_defeats_it(slug):
    case = attacks.case(slug)
    assert case.defeated_by_canonicalisation is not None


@pytest.mark.parametrize("slug", [
    case.slug for case in attacks.of_kind(EVASION) if case.defeated_by_canonicalisation])
def test_an_evasion_that_canonicalisation_defeats_is_caught(slug, results):
    _, transaction = results[slug]
    assert transaction.allowed is False


def test_the_set_of_surviving_evasions_is_exactly_what_is_declared():
    """The number that would otherwise grow quietly.

    Asserted as an exact set rather than a count, because a new surviving evasion and a fixed one
    cancel out in a count and this is the one figure in the repository nobody wants to grow.
    """
    survived = tuple(
        case.slug for case in attacks.of_kind(EVASION)
        if case.defeated_by_canonicalisation is False)
    assert survived == attacks.KNOWN_SURVIVING_EVASIONS


def test_a_surviving_evasion_really_does_survive(results):
    for slug in attacks.KNOWN_SURVIVING_EVASIONS:
        _, transaction = results[slug]
        assert transaction.allowed is True, f"{slug} is declared as surviving but was caught"


def test_the_corpus_has_enough_benign_traffic_to_measure_a_false_positive_rate():
    assert len(attacks.of_kind(BENIGN)) >= 10


def test_the_corpus_covers_both_sides_of_the_proxy():
    prompt_side = [case for case in attacks.of_kind(ATTACK) if case.expect_detectors]
    response_side = [case for case in attacks.of_kind(ATTACK) if not case.expect_detectors]
    assert prompt_side and response_side


def test_every_case_names_a_completion_that_exists():
    from guardrail.upstream import COMPLETIONS
    for case in attacks.CASES:
        assert case.completion in COMPLETIONS


def test_every_case_has_a_note_explaining_why_it_is_in_the_corpus():
    for case in attacks.CASES:
        assert case.note, case.slug


def test_slugs_are_unique():
    slugs = [case.slug for case in attacks.CASES]
    assert len(slugs) == len(set(slugs))


def test_the_summary_counts_match_the_corpus():
    summary = attacks.summary()
    assert summary["cases"] == len(attacks.CASES)
    assert summary["benign"] + summary["attacks"] + summary["evasions"] == summary["cases"]


def test_looking_up_an_unknown_case_names_the_known_ones():
    with pytest.raises(KeyError) as caught:
        attacks.case("nope")
    assert "plain_question" in str(caught.value)


def test_the_case_payload_reports_the_prompt_length_and_not_the_prompt():
    case = attacks.case("secret_in_prompt")
    payload = case.to_json()
    assert payload["prompt_chars"] == len(case.prompt)
    assert "AKIA" not in str(payload)


# --------------------------------------------------------------------------- measured rates

def test_every_detector_has_a_measurement():
    measured = attacks.measure()
    assert set(measured) == set(attacks.load_policy().detectors)


def test_every_detector_catches_what_it_is_labelled_for():
    for name, rates in attacks.measure().items():
        assert rates.tpr == 1.0, f"{name} missed a labelled positive"


def test_gating_at_min_confidence_removes_every_false_positive():
    for name, rates in attacks.measure().items():
        assert rates.fpr == 0.0, f"{name} fired on benign traffic at its action confidence"


def test_the_same_detector_has_a_false_positive_rate_as_a_signal():
    """What `min_confidence` buys, as a number rather than as a paragraph."""
    signal = attacks.measure(at_action_confidence=False)["secret_pattern"]
    gate = attacks.measure()["secret_pattern"]
    assert signal.fpr > 0.1
    assert gate.fpr == 0.0
    assert signal.false_positives == 5


def test_a_measured_zero_is_reported_with_its_resolution():
    gate = attacks.measure()["secret_pattern"]
    assert gate.fpr == 0.0
    assert gate.resolved_fpr == pytest.approx(1 / gate.benign)


def test_the_corpus_cannot_support_a_block_at_the_declared_prevalence():
    """The uncomfortable headline, asserted so it cannot be quietly dropped from the report."""
    from guardrail.proxy import posture
    policy = attacks.load_policy()
    stand = posture(policy, attacks.measure(policy))
    blocking = {name for name, detector in policy.detectors.items() if detector.blocks}
    assert set(stand["unjustified"]) == blocking
