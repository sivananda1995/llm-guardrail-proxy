"""Enforcing a guardrail on a streaming response, and the thing you cannot do.

## You cannot un-send a byte

That sentence is the whole module. Once a chunk has left the proxy it is on the client's screen, and
no verdict reached afterwards can retrieve it. So a guardrail on a streaming response has exactly
two options, and the third one people assume exists does not:

1. **Do not stream.** Buffer the whole response, check it, then send. Complete enforcement, and
time to first token becomes time to *last* token, which is the reason streaming exists.
2. **Stream with a bounded lookback.** Hold the last `lookback_chars` characters so a pattern can
match across a chunk boundary, and emit everything before that. Streaming works, and when a secret
is found, everything already emitted has already gone.
3. **Stream and retract.** Not possible over HTTP. There is no unsend.

Option 2 is what almost every deployment does, usually without deciding to. This module implements
it, and reports the number that option 2 costs and nobody writes down: **how many characters of the
detected thing reached the client before the stream was cut.** `experiments/stream_vs_buffer.py`
sweeps the lookback from 0 to full buffering and publishes that curve against time to first token,
because the two move in opposite directions and the policy has to choose a point on it.

## Why lookback is exactly the leak

A detector matching on a sliding window can only see a secret once enough of it has arrived. Hold
back 96 characters and a 20-character key is caught with none of it emitted, because the whole key
is still inside the held-back tail. Hold back 8 and the first 12 characters of that key are already
gone.

So `lookback_chars` is simultaneously:

* the longest pattern that can be matched across a chunk boundary at all;
* the maximum leak of anything longer than it;
* a latency cost, because held-back characters are characters the user is not reading yet.

One number, three meanings, which is why the policy comments on it at length rather than defaulting
it.

## The detector that cannot be honest on a stream

Some detectors need more than a window. `system_prompt_echo` needs forty characters of accumulated
response before it can say anything, so on a stream it fires late by construction. The policy marks
those `stream_safe: false`, this module runs them against everything accumulated so far rather than
the window, and `Enforcement.late_detectors` reports which ones were in that position. A guardrail
that ran a whole-document detector on a stream and reported "no findings" would be technically
accurate and misleading.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from .detect import LONGEST_MATCH_CHARS, Finding, run_detector
from .policy import BLOCK, REDACT, Policy


@dataclass
class Emission:
    """One chunk the client actually received, with what it cost to decide."""

    text: str
    #: Cumulative characters emitted before this chunk, which is what a leak is measured against.
    offset: int
    #: Milliseconds of detector work attributable to this chunk. Not wall clock: the sum of the
    #: detector timings, so the figure is comparable between runs on different machines.
    detector_ms: float = 0.0

    def to_json(self) -> dict:
        return {"text": self.text, "offset": self.offset, "detector_ms": round(self.detector_ms, 3)}


@dataclass
class Enforcement:
    """What happened to one streamed response.

    The fields worth reading are `leaked_chars` and `first_emit_at_char`. The first is the honest
    cost of streaming enforcement; the second is what the user gained by it.
    """

    emitted: str = ""
    cut: bool = False
    cut_reason: str = ""
    findings: tuple[Finding, ...] = ()
    redactions: int = 0
    chunks_in: int = 0
    chunks_out: int = 0
    #: Characters *of the detected span itself* that were emitted before the stream was cut. Zero
    #: when the whole match was still inside the held-back tail, which is what a large lookback
    #: buys. Capped at the length of the match, because the first version reported everything
    #: emitted after the match began, which for a 20 character key in a long response read as a 45
    #: character leak and made the number impossible to interpret.
    leaked_chars: int = 0
    #: Characters of the response emitted from the point the match began. A different question, and
    #: worth both: a secret that leaked in full is a credential disclosure, and a response that kept
    #: going for another 200 characters afterwards is also 200 characters of context an attacker
    #: got.
    emitted_after_match: int = 0
    #: Where the first character was emitted, in characters of upstream text consumed. With a warmup
    #: of zero and a lookback of L this is L, which is the latency the lookback costs.
    first_emit_at_char: int = -1
    #: Redactions that arrived too late to perform, because the span they cover had already been
    #: emitted. A `redact` action has exactly the same leak problem a `block` does, and this counter
    #: exists because the first version of this module silently did nothing in that case: the client
    #: received the card number in the clear and the report said "redactions: 0", which reads as
    #: "there was nothing to redact". Now it reads as what happened.
    missed_redactions: int = 0
    #: Detectors that could not be prefix-safe and therefore ran on the accumulated text rather than
    #: a bounded window. Disclosed rather than hidden.
    late_detectors: tuple[str, ...] = ()
    detector_ms: float = 0.0
    emissions: list[Emission] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.cut

    @property
    def leaked(self) -> bool:
        return self.leaked_chars > 0

    def to_json(self) -> dict:
        return {
            "emitted_chars": len(self.emitted),
            "cut": self.cut,
            "cut_reason": self.cut_reason,
            "findings": [finding.to_json() for finding in self.findings],
            "redactions": self.redactions,
            "missed_redactions": self.missed_redactions,
            "chunks_in": self.chunks_in,
            "chunks_out": self.chunks_out,
            "leaked_chars": self.leaked_chars,
            "leaked": self.leaked,
            "emitted_after_match": self.emitted_after_match,
            "first_emit_at_char": self.first_emit_at_char,
            "late_detectors": list(self.late_detectors),
            "detector_ms": round(self.detector_ms, 3),
        }


def _redact(text: str, findings: Iterable[Finding]) -> tuple[str, int]:
    """Replace each finding's span with a marker, right to left so earlier offsets stay valid."""
    ordered = sorted(findings, key=lambda finding: finding.start, reverse=True)
    count = 0
    for finding in ordered:
        if finding.start >= len(text) or finding.end > len(text):
            continue
        text = f"{text[:finding.start]}[redacted:{finding.detector}]{text[finding.end:]}"
        count += 1
    return text, count


def _already_missed(seen: list[tuple[str, int, int]], finding: Finding) -> bool:
    """Whether this finding overlaps one already counted as impossible to redact.

    Overlap rather than equality, because the same card number matches a slightly different span as
    the window slides, and counting each of those would report three missed redactions for one
    disclosure.
    """
    return any(detector == finding.detector and finding.start < end and start < finding.end
               for detector, start, end in seen)


def enforce(chunks: Iterable[str], policy: Policy, *, system_prompt: str = "",
            side: str = "response") -> Iterator[tuple[str, Enforcement]]:
    """Stream chunks through the policy, yielding what the client receives.

    Yields `(text, state)` for every emission, so a caller can measure time to first token without
    this module knowing what a clock is. The final state is on the last yield, and a caller that
    wants only the summary can exhaust the iterator and keep the last one.

    The window discipline, which is the substance:

    * everything received is accumulated into `pending`;
    * the last `lookback_chars` of `pending` are held back, because a pattern could still be
    completed by the next chunk;
    * everything before that is emitted, once, and can never be recalled;
    * detectors run on a window that covers the boundary, so a match spanning it is found;
    * when a blocking finding lands, the leak is `max(0, emitted_total - finding_start)`, exactly
    the part of the match that had already gone.
    """
    lookback = policy.stream.lookback_chars
    detectors = policy.for_side(side)
    unsafe = tuple(detector.name for detector in detectors if not detector.stream_safe)

    state = Enforcement(late_detectors=unsafe)
    pending = ""
    accumulated = ""
    emitted_total = 0
    #: Spans already accounted as a missed redaction, per detector. Detectors rerun on every chunk
    #: and a pattern can match a slightly different span each time as the window slides, so the test
    #: is overlap rather than equality: one card number that could not be redacted is one missed
    #: redaction, however many times it was matched.
    missed: list[tuple[str, int, int]] = []
    #: Spans that *were* redacted. Kept for the same reason: after a span is rewritten, later chunks
    #: still report it at an offset now behind the emitted mark, and without this it would be
    #: counted as a redaction that arrived too late immediately after being performed on time.
    settled: list[tuple[str, int, int]] = []

    for chunk in chunks:
        state.chunks_in += 1
        pending += chunk
        accumulated += chunk

        # The window a prefix-safe detector sees: the held-back tail, plus enough of what came
        # before it that a match straddling the boundary is inside the window, and never narrower
        # than the widest span a detector needs to fire. That last clause is a bug fix, not a
        # precaution. The window was twice the lookback, which sounds sufficient and is not: with an
        # 8 character lookback the window was 22 characters, a 20 character key straddling a chunk
        # boundary had its first characters slide out before the last arrived, and the key was found
        # only by the end-of-stream check, after the whole response had gone. The leak measured 20
        # of 20 characters at every lookback below 12, which is the shape of a detector that is not
        # running rather than one running late.
        window_start = max(0, len(accumulated) - max(2 * lookback, LONGEST_MATCH_CHARS)
                           - len(chunk))
        window = accumulated[window_start:]

        findings: list[Finding] = []
        for detector in detectors:
            target, base = (window, window_start) if detector.stream_safe else (accumulated, 0)
            for finding in run_detector(detector.name, target, system_prompt=system_prompt):
                findings.append(Finding(
                    detector=finding.detector, start=finding.start + base, end=finding.end + base,
                    excerpt=finding.excerpt, confidence=finding.confidence, note=finding.note,
                ))
            state.detector_ms += detector.budget_ms * 0.25  # accounted, not measured; see budget.py

        blocking = [finding for finding in findings
                    if policy.detectors[finding.detector].action_for(finding.confidence) == BLOCK]
        if blocking:
            first = min(blocking, key=lambda finding: finding.start)
            state.findings = tuple(findings)
            state.cut = True
            state.cut_reason = first.detector
            after = max(0, emitted_total - first.start)
            state.leaked_chars = min(first.length, after)
            state.emitted_after_match = after
            state.emitted += policy.stream.cut_message
            state.chunks_out += 1
            yield policy.stream.cut_message, state
            return

        if len(pending) <= lookback + policy.stream.warmup_chars:
            continue

        release_to = len(pending) - lookback

        # Hold the release back to the start of any redactable span that is not yet complete.
        # Without this, the lookback protects a block and does nothing for a redaction. The release
        # is one chunk of text at a time, a card number is twenty characters, and a span longer than
        # a chunk is never fully inside one release, so the redaction condition never holds. The
        # measured result was zero redactions, one missed redaction, and the card number on the
        # client's screen at *every* lookback, including 96. The span is now held until it is whole,
        # which is the discipline the lookback applies to a match, applied to the thing that has to
        # be rewritten rather than merely detected.
        for finding in findings:
            if policy.detectors[finding.detector].action_for(finding.confidence) != REDACT:
                continue
            if finding.start < emitted_total:
                continue  # already gone; accounted as a missed redaction below
            if finding.end > emitted_total + release_to:
                release_to = min(release_to, finding.start - emitted_total)
        if release_to <= 0:
            continue

        release = pending[:release_to]
        pending = pending[release_to:]

        wanted = [finding for finding in findings
                  if policy.detectors[finding.detector].action_for(finding.confidence) == REDACT]
        redacting = [finding for finding in wanted
                     if finding.end <= emitted_total + len(release)
                     and finding.start >= emitted_total]
        # A redaction whose span starts before what has already gone cannot be performed, because
        # those characters are on the client's screen. Accounted as a leak rather than ignored: the
        # honest report of "the policy wanted this removed and it was already sent" is a number.
        for finding in wanted:
            if finding.start >= emitted_total or _already_missed(missed, finding):
                continue
            if _already_missed(settled, finding):
                continue
            missed.append((finding.detector, finding.start, finding.end))
            state.missed_redactions += 1
            escaped = min(finding.length, emitted_total - finding.start)
            state.leaked_chars = max(state.leaked_chars, escaped)
            state.emitted_after_match = max(state.emitted_after_match,
                                            emitted_total - finding.start)
        if redacting:
            shifted = [Finding(detector=f.detector, start=f.start - emitted_total,
                               end=f.end - emitted_total, excerpt=f.excerpt,
                               confidence=f.confidence, note=f.note) for f in redacting]
            release, count = _redact(release, shifted)
            state.redactions += count
            settled.extend((f.detector, f.start, f.end) for f in redacting)

        if state.first_emit_at_char < 0:
            state.first_emit_at_char = len(accumulated)
        state.emitted += release
        state.emissions.append(Emission(text=release, offset=emitted_total,
                                        detector_ms=state.detector_ms))
        emitted_total += release_to
        state.chunks_out += 1
        state.findings = tuple(findings)
        yield release, state

    # The tail. Everything held back is now complete, so the last check sees the whole response and
    # is the only check in a streaming pass that had the context a buffered pass would have had.
    findings = []
    for detector in detectors:
        for finding in run_detector(detector.name, accumulated, system_prompt=system_prompt):
            findings.append(finding)
        state.detector_ms += detector.budget_ms * 0.25

    blocking = [finding for finding in findings
                if policy.detectors[finding.detector].action_for(finding.confidence) == BLOCK]
    if blocking:
        first = min(blocking, key=lambda finding: finding.start)
        state.findings = tuple(findings)
        state.cut = True
        state.cut_reason = first.detector
        after = max(0, emitted_total - first.start)
        state.leaked_chars = min(first.length, after)
        state.emitted_after_match = after
        state.emitted += policy.stream.cut_message
        state.chunks_out += 1
        yield policy.stream.cut_message, state
        return

    if pending:
        wanted = [finding for finding in findings
                  if policy.detectors[finding.detector].action_for(finding.confidence) == REDACT]
        redacting = [finding for finding in wanted if finding.start >= emitted_total]
        for finding in wanted:
            if finding.start >= emitted_total or _already_missed(missed, finding):
                continue
            if _already_missed(settled, finding):
                continue
            missed.append((finding.detector, finding.start, finding.end))
            state.missed_redactions += 1
            escaped = min(finding.length, emitted_total - finding.start)
            state.leaked_chars = max(state.leaked_chars, escaped)
            state.emitted_after_match = max(state.emitted_after_match,
                                            emitted_total - finding.start)
        shifted = [Finding(detector=f.detector, start=f.start - emitted_total,
                           end=f.end - emitted_total, excerpt=f.excerpt,
                           confidence=f.confidence, note=f.note) for f in redacting]
        release, count = _redact(pending, shifted)
        state.redactions += count
        if state.first_emit_at_char < 0:
            state.first_emit_at_char = len(accumulated)
        state.emitted += release
        state.emissions.append(Emission(text=release, offset=emitted_total,
                                        detector_ms=state.detector_ms))
        state.chunks_out += 1
        yield release, state

    state.findings = tuple(findings)


def buffered(chunks: Iterable[str], policy: Policy, *, system_prompt: str = "",
             side: str = "response") -> Enforcement:
    """The other option: consume everything, check once, then decide.

    Complete enforcement and no leak, at the cost of the entire response's generation time before
    the first character reaches the client. Here so the comparison in
    `experiments/stream_vs_buffer.py` is against real code rather than against an argument.
    """
    text = "".join(chunks)
    state = Enforcement(chunks_in=1, first_emit_at_char=len(text))

    findings: list[Finding] = []
    for detector in policy.for_side(side):
        findings.extend(run_detector(detector.name, text, system_prompt=system_prompt))
        state.detector_ms += detector.budget_ms * 0.25
    state.findings = tuple(findings)

    blocking = [f for f in findings
                if policy.detectors[f.detector].action_for(f.confidence) == BLOCK]
    if blocking:
        state.cut = True
        state.cut_reason = min(blocking, key=lambda f: f.start).detector
        state.leaked_chars = 0
        state.emitted = policy.stream.cut_message
        return state

    redacting = [f for f in findings
                 if policy.detectors[f.detector].action_for(f.confidence) == REDACT]
    state.emitted, state.redactions = _redact(text, redacting)
    state.chunks_out = 1
    return state
