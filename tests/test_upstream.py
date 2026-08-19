"""The fixture, and the determinism the whole suite depends on."""

from __future__ import annotations

import pytest

from guardrail.detect import ECHO_MIN_SPAN, REGISTRY
from guardrail.upstream import (
    COMPLETIONS,
    DEFAULT_CHUNK,
    SYSTEM_PROMPT,
    Completion,
    Upstream,
    completion,
)


def test_streaming_yields_the_whole_text():
    source = Upstream()
    assert "".join(source.stream("hello there, this is a response")) == \
        "hello there, this is a response"


def test_the_same_seed_gives_the_same_chunk_boundaries():
    first = list(Upstream(seed=7).stream("a longer response to chunk up"))
    second = list(Upstream(seed=7).stream("a longer response to chunk up"))
    assert first == second


def test_a_different_seed_gives_different_boundaries():
    first = list(Upstream(seed=1).stream("a longer response to chunk up" * 3))
    second = list(Upstream(seed=2).stream("a longer response to chunk up" * 3))
    assert first != second


def test_successive_calls_on_one_source_differ():
    """Seeded per call, so a test's result does not depend on how many ran before it."""
    source = Upstream(seed=3)
    text = "a longer response to chunk up" * 3
    assert list(source.stream(text)) != list(source.stream(text))


def test_chunks_are_near_the_declared_size():
    source = Upstream(chunk_size=DEFAULT_CHUNK, jitter=3)
    sizes = [len(chunk) for chunk in source.stream("x" * 400)]
    assert all(1 <= size <= DEFAULT_CHUNK + 3 for size in sizes)


def test_no_jitter_gives_a_fixed_size():
    source = Upstream(chunk_size=5, jitter=0)
    sizes = [len(chunk) for chunk in source.stream("x" * 20)]
    assert sizes == [5, 5, 5, 5]


def test_an_empty_response_yields_nothing():
    assert list(Upstream().stream("")) == []


def test_a_completion_object_streams_its_text():
    source = Upstream()
    assert "".join(source.stream(COMPLETIONS["clean_answer"])) == COMPLETIONS["clean_answer"].text


def test_the_source_accounts_for_what_it_emitted():
    source = Upstream()
    text = "a response of some length to account for"
    list(source.stream(text))
    assert source.chars_emitted == len(text)
    assert source.chunks_emitted > 1
    assert source.calls == 1


def test_the_source_payload_names_what_it_is_not():
    payload = Upstream().to_json()
    assert "not a model" in payload["note"]


def test_completion_lookup_names_the_known_ones():
    with pytest.raises(KeyError) as caught:
        completion("nope")
    assert "clean_answer" in str(caught.value)


def test_a_raw_string_can_be_streamed_without_a_completion():
    assert "".join(Upstream().stream("plain string")) == "plain string"


@pytest.mark.parametrize("name", sorted(COMPLETIONS))
def test_every_completion_declares_a_kind_and_a_note(name):
    entry = COMPLETIONS[name]
    assert entry.kind
    assert entry.note


@pytest.mark.parametrize("name", sorted(COMPLETIONS))
def test_every_expected_detector_is_implemented(name):
    for detector in COMPLETIONS[name].expect_detectors:
        assert detector in REGISTRY


@pytest.mark.parametrize("name", sorted(COMPLETIONS))
def test_a_clean_completion_expects_nothing_and_a_leaking_one_expects_something(name):
    entry = COMPLETIONS[name]
    if entry.kind == "clean":
        assert entry.expect_detectors == ()
    else:
        assert entry.expect_detectors


def test_the_system_prompt_is_long_enough_for_the_echo_detector():
    assert len(SYSTEM_PROMPT) > ECHO_MIN_SPAN * 2


def test_the_system_prompt_contains_something_worth_leaking():
    assert "NW-ESC-4417" in SYSTEM_PROMPT


def test_a_completion_reports_its_length_and_never_its_text_in_the_payload():
    entry = Completion(text="a secret answer", kind="clean")
    payload = entry.to_json()
    assert payload["chars"] == len("a secret answer")
    assert "a secret answer" not in str(payload)


def test_the_corpus_has_both_early_and_late_leaks():
    early = COMPLETIONS["leaks_key_early"].text
    late = COMPLETIONS["leaks_key_late"].text
    assert early.index("AKIA") < 5
    assert late.index("AKIA") > len(late) // 2


def test_the_near_miss_completion_is_not_luhn_valid():
    from guardrail.detect import pii_card
    assert pii_card(COMPLETIONS["near_miss_order"].text) == ()
