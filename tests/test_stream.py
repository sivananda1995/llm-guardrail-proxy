"""Streaming enforcement, and the arithmetic of what escaped.

Every test here is about one sentence: you cannot un-send a byte. The lookback is the only lever,
and these tests pin what each setting of it costs and saves.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from guardrail.stream import Enforcement, buffered, enforce
from guardrail.upstream import Upstream, completion

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def run(policy, text, *, lookback=None, system_prompt="", chunk=6):
    """Stream one text through the enforcer and return the final state."""
    if lookback is not None:
        policy = replace(policy, stream=replace(policy.stream, lookback_chars=lookback))
    source = Upstream(chunk_size=chunk)
    state = Enforcement()
    for _, latest in enforce(source.stream(text), policy, system_prompt=system_prompt):
        state = latest
    return state


def test_a_clean_response_is_emitted_whole(policy):
    text = "your payment was retried on the fifth and went through without any further action."
    state = run(policy, text, lookback=8)
    assert state.emitted == text
    assert state.cut is False
    assert state.leaked_chars == 0


def test_a_clean_response_is_emitted_in_more_than_one_chunk(policy):
    text = "a" * 400
    state = run(policy, text, lookback=8)
    assert state.chunks_out > 1


def test_a_secret_cuts_the_stream(policy):
    state = run(policy, f"the key is {AWS_KEY} and it is live", lookback=96)
    assert state.cut is True
    assert state.cut_reason == "secret_pattern"


def test_the_cut_message_is_the_last_thing_emitted(policy):
    state = run(policy, f"the key is {AWS_KEY} and it is live", lookback=96)
    assert state.emitted.endswith(policy.stream.cut_message)


def test_no_lookback_leaks_all_of_the_secret_that_had_been_sent(policy):
    """With nothing held back, everything before the chunk that completed the match has gone.

    Not quite the full twenty characters, and the shortfall is exactly the tail of the key that
    arrived in the chunk the detector fired on. Asserting `== len(key)` would be asserting a chunk
    boundary.
    """
    state = run(policy, f"the credential in use is {AWS_KEY} and it was rotated in march",
                lookback=0)
    assert state.leaked_chars >= len(AWS_KEY) - 2


def test_a_lookback_longer_than_the_secret_leaks_nothing(policy):
    state = run(policy, f"the credential in use is {AWS_KEY} and it was rotated in march",
                lookback=96)
    assert state.leaked_chars == 0


@pytest.mark.parametrize("lookback", [0, 4, 8, 16, 24, 96])
def test_the_leak_is_bounded_by_the_secret_minus_the_lookback(policy, lookback):
    """The invariant the lookback actually buys.

    Characters inside the held-back tail cannot have been emitted, so at most `len(secret) -
    lookback` of a secret can escape. Written the other way round the first time (leak bounded *by*
    the lookback) and it was false at every setting below the length of the key, which is the
    direction that matters.
    """
    state = run(policy, f"the credential in use is {AWS_KEY} and it was rotated in march",
                lookback=lookback)
    assert state.leaked_chars <= max(0, len(AWS_KEY) - lookback)


def test_the_leak_is_monotone_in_the_lookback(policy):
    text = f"the credential in use is {AWS_KEY} and it was rotated in march"
    leaks = [run(policy, text, lookback=value).leaked_chars for value in (0, 8, 16, 24, 96)]
    assert leaks == sorted(leaks, reverse=True)


def test_first_emit_is_at_least_the_lookback(policy):
    state = run(policy, "a clean answer that is long enough to be released in pieces " * 4,
                lookback=24)
    assert state.first_emit_at_char >= 24


def test_a_larger_lookback_delays_the_first_character(policy):
    text = "a clean answer that is long enough to be released in pieces " * 6
    small = run(policy, text, lookback=8).first_emit_at_char
    large = run(policy, text, lookback=96).first_emit_at_char
    assert large > small


def test_emitted_after_match_is_reported_separately_from_the_leak(policy):
    state = run(policy, f"the credential is {AWS_KEY} and then a great deal more text follows "
                        f"after it for context", lookback=0)
    assert state.emitted_after_match >= state.leaked_chars


def test_a_secret_split_across_chunks_is_still_found(policy):
    """The reason the window covers the boundary rather than the chunk."""
    state = run(policy, f"prefix {AWS_KEY} suffix", lookback=32, chunk=3)
    assert state.cut is True


def test_a_secret_in_the_final_held_back_tail_is_caught_by_the_tail_check(policy):
    state = run(policy, f"a long clean preamble that gets emitted first, then {AWS_KEY}",
                lookback=96)
    assert state.cut is True
    assert state.leaked_chars == 0


CARD_RESPONSE = ("for your records the full number is 4242 4242 4242 4242 and the expiry "
                 "is 12/29, which you can check against your statement")


def test_a_card_is_redacted_rather_than_cut(policy):
    state = run(policy, CARD_RESPONSE, lookback=96)
    assert state.cut is False
    assert state.redactions == 1
    assert "4242 4242 4242 4242" not in state.emitted
    assert "[redacted:pii_card]" in state.emitted


def test_a_redaction_shorter_than_its_span_arrives_too_late_and_says_so(policy):
    """Redaction has the same leak problem blocking does, and it is quieter.

    With a lookback shorter than the span, the digits are already on the client's screen when the
    finding lands. The first version of this module did nothing in that case and reported
    `redactions: 0`, which reads as "there was nothing to redact". The number a reader needs is that
    a redaction was wanted, was impossible, and how much escaped.
    """
    state = run(policy, CARD_RESPONSE, lookback=8)
    assert state.cut is False
    assert state.redactions == 0
    assert state.missed_redactions == 1
    assert state.leaked_chars > 0
    assert "4242 4242 4242 4242" in state.emitted


def test_a_missed_redaction_is_counted_once_and_not_once_per_chunk(policy):
    state = run(policy, CARD_RESPONSE + " and a long tail of further text " * 4, lookback=8)
    assert state.missed_redactions == 1


def test_a_lookback_long_enough_to_cover_the_span_misses_nothing(policy):
    state = run(policy, CARD_RESPONSE, lookback=96)
    assert state.missed_redactions == 0


def test_an_order_number_is_not_redacted(policy):
    text = ("your order number is 1234 5678 9012 3456 and it shipped on tuesday with a tracking "
            "reference you can use on the carrier site")
    state = run(policy, text, lookback=8)
    assert state.redactions == 0
    assert "1234 5678 9012 3456" in state.emitted


def test_a_detector_that_is_not_prefix_safe_is_disclosed(policy):
    state = run(policy, "a clean answer", lookback=8)
    assert "system_prompt_echo" in state.late_detectors


def test_the_echo_detector_fires_on_a_stream_only_after_enough_output(policy, system_prompt):
    state = run(policy, f"of course, my instructions are: {system_prompt}", lookback=8,
                system_prompt=system_prompt)
    assert state.cut is True
    assert state.cut_reason == "system_prompt_echo"
    assert state.leaked_chars > 0


def test_an_empty_response_produces_an_empty_emission(policy):
    state = run(policy, "", lookback=8)
    assert state.emitted == ""
    assert state.cut is False


def test_every_emission_records_its_offset(policy):
    state = run(policy, "a clean answer repeated for length. " * 10, lookback=8)
    offsets = [emission.offset for emission in state.emissions]
    assert offsets == sorted(offsets)
    assert offsets[0] == 0


def test_the_emitted_text_is_the_concatenation_of_the_emissions(policy):
    state = run(policy, "a clean answer repeated for length. " * 10, lookback=8)
    assert "".join(emission.text for emission in state.emissions) == state.emitted


# --------------------------------------------------------------------------- buffering

def test_buffering_never_leaks(policy):
    state = buffered(Upstream().stream(f"the key is {AWS_KEY}"), policy)
    assert state.cut is True
    assert state.leaked_chars == 0


def test_buffering_pays_for_it_with_time_to_first_character(policy):
    text = "a clean answer " * 20
    state = buffered(Upstream().stream(text), policy)
    assert state.first_emit_at_char == len(text)


def test_buffering_a_clean_response_emits_it_whole(policy):
    text = "a clean answer that nothing fires on"
    state = buffered(Upstream().stream(text), policy)
    assert state.emitted == text


def test_buffering_redacts_what_a_short_lookback_could_not(policy):
    text = "the full number is 4242 4242 4242 4242 for your records"
    streamed = run(policy, text, lookback=8)
    held = buffered(Upstream().stream(text), policy)
    assert held.redactions == 1
    assert streamed.redactions == 0
    assert streamed.missed_redactions == 1
    assert "4242 4242 4242 4242" in streamed.emitted


def test_buffering_and_streaming_agree_on_the_verdict_for_every_completion(policy, system_prompt):
    """Both paths reach the same decision. Only the leak differs, which is the whole point."""
    from guardrail.upstream import COMPLETIONS
    for name in COMPLETIONS:
        text = completion(name).text
        streamed = run(policy, text, lookback=96, system_prompt=system_prompt)
        held = buffered(Upstream().stream(text), policy, system_prompt=system_prompt)
        assert streamed.cut == held.cut, name


def test_the_enforcement_payload_reports_the_leak_and_never_the_secret(policy):
    state = run(policy, f"the credential is {AWS_KEY} and more", lookback=0)
    payload = state.to_json()
    assert payload["leaked_chars"] >= len(AWS_KEY) - 2
    assert AWS_KEY not in str(payload)


def test_blocked_is_an_alias_for_cut(policy):
    state = run(policy, f"the key is {AWS_KEY}", lookback=96)
    assert state.blocked is state.cut is True


def test_leaked_is_true_only_when_characters_escaped(policy):
    text = f"the credential in use is {AWS_KEY} and it was rotated"
    assert run(policy, text, lookback=0).leaked is True
    assert run(policy, text, lookback=96).leaked is False


# --------------------------------------------------------------------------- the tail

def test_a_card_entirely_inside_the_held_back_tail_is_redacted_by_the_tail_pass(policy):
    """The last redaction happens after the stream has ended, with the whole text in hand."""
    text = "short answer, card 4242 4242 4242 4242"
    state = run(policy, text, lookback=96)
    assert state.redactions == 1
    assert "[redacted:pii_card]" in state.emitted
    assert state.first_emit_at_char == len(text)


def test_the_tail_pass_emits_the_remainder_of_a_clean_response(policy):
    text = "a" * 40
    state = run(policy, text, lookback=96)
    assert state.emitted == text
    assert state.chunks_out == 1


def test_an_emission_payload_reports_its_offset_and_accounted_cost(policy):
    state = run(policy, "a clean answer repeated for length. " * 6, lookback=8)
    payload = state.emissions[0].to_json()
    assert payload["offset"] == 0
    assert payload["detector_ms"] >= 0


def test_a_response_shorter_than_the_lookback_is_still_emitted(policy):
    state = run(policy, "tiny", lookback=96)
    assert state.emitted == "tiny"


def test_a_secret_and_a_card_in_one_response_cuts_rather_than_redacts(policy):
    state = run(policy, f"the key is {AWS_KEY} and the card is 4242 4242 4242 4242", lookback=96)
    assert state.cut is True
    assert state.redactions == 0


def test_a_card_released_mid_stream_is_redacted_in_the_release(policy):
    """The redaction path inside the streaming loop, rather than in the end-of-stream pass."""
    text = ("the card on file is 4242 4242 4242 4242 and here is a great deal of further text so "
            "that the release happens long before the stream ends, which is the case a report "
            "should show as redacted rather than as missed")
    state = run(policy, text, lookback=96)
    assert state.redactions == 1
    assert state.missed_redactions == 0
    assert "4242 4242 4242 4242" not in state.emitted
    assert len(state.emissions) > 1


def test_redacting_a_span_outside_the_text_is_skipped_rather_than_raising():
    from guardrail.detect import Finding
    from guardrail.stream import _redact
    text, count = _redact("short", [Finding(detector="d", start=40, end=48, excerpt="",
                                            confidence="high")])
    assert (text, count) == ("short", 0)


# --------------------------------------------------------------------------- the end-of-stream pass

#: A detector that cannot answer from any window: it fires only when it has the complete response.
#: This is what a real whole-response check looks like (a classifier over the finished answer), and
#: it is the only thing the end-of-stream pass exists for. Registered through the same registry the
#: shipped detectors use, so the path under test is the production one.
WHOLE_TEXT_MARKER = "###complete###"


WHOLE_TEXT_OPENING = "BEGIN:"


def _whole_text_only(text, name="secret_pattern"):
    """Fires only with the first and last characters of the response in view at once.

    Both ends, deliberately: a detector that needed only the end would be satisfied by the streaming
    loop's window on the final chunk, and the end-of-stream pass would stay unexercised.
    """
    from guardrail.detect import Finding
    if not (text.startswith(WHOLE_TEXT_OPENING) and text.endswith(WHOLE_TEXT_MARKER)):
        return ()
    start = text.index(WHOLE_TEXT_MARKER)
    return (Finding(detector=name, start=start, end=start + len(WHOLE_TEXT_MARKER),
                    excerpt="masked", confidence="high", note="only decidable on the whole text"),)


@pytest.fixture
def whole_text_detector(monkeypatch):
    from guardrail import detect
    monkeypatch.setitem(detect.REGISTRY, "secret_pattern",
                        {"fn": _whole_text_only, "needs": ()})
    return WHOLE_TEXT_MARKER


def test_the_end_of_stream_pass_cuts_on_a_finding_no_window_could_reach(policy,
                                                                       whole_text_detector):
    """The backstop, exercised deliberately.

    The streaming loop scans a bounded window on every chunk, so almost everything is caught there.
    A detector that can only decide on the complete response is caught by the end-of-stream pass
    instead, after everything before it has already been emitted, which is precisely the leak the
    lookback cannot help with.
    """
    text = (WHOLE_TEXT_OPENING + " a long clean answer that streams out first, and it has to be "
            "longer than the detection window so that no window holds both ends of it at once, "
            "then the marker: " + whole_text_detector)
    state = run(policy, text, lookback=8)
    assert state.cut is True
    assert state.cut_reason == "secret_pattern"
    assert state.emitted.endswith(policy.stream.cut_message)


def test_a_finding_only_the_end_of_stream_pass_reaches_leaks_what_had_gone(policy,
                                                                          whole_text_detector):
    text = (WHOLE_TEXT_OPENING + " a long clean answer that streams out first, and it has to be "
            "longer than the detection window so that no window holds both ends of it at once, "
            "then the marker: " + whole_text_detector)
    state = run(policy, text, lookback=0)
    assert state.leaked_chars > 0


def test_the_end_of_stream_pass_accounts_a_redaction_it_is_too_late_to_perform(policy,
                                                                              monkeypatch):
    """A redaction discovered only at the end, on a span that has already been sent."""
    from guardrail import detect

    def late_card(text, name="pii_card"):
        if not (text.startswith(WHOLE_TEXT_OPENING) and text.endswith(WHOLE_TEXT_MARKER)):
            return ()
        return (detect.Finding(detector=name, start=0, end=12, excerpt="masked",
                               confidence="high", note="decided too late to remove"),)

    monkeypatch.setitem(detect.REGISTRY, "pii_card", {"fn": late_card, "needs": ()})
    text = (WHOLE_TEXT_OPENING + " a long clean answer that streams out first, and it is longer "
            "than any detection window, then the marker: " + WHOLE_TEXT_MARKER)
    state = run(policy, text, lookback=8)
    assert state.missed_redactions == 1
    assert state.leaked_chars > 0
    assert state.cut is False
