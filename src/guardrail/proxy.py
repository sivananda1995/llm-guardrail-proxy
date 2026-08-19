"""The request path: normalise, check the prompt, stream the response, check that too.

The order is the design, and each step is where it is because of what the step before it
establishes.

1. **Normalise first.** Every detector reads the canonical text, so guardrail and model cannot
disagree about what the request said. A detector that ran on the raw string would be checking a
different document from the one the model answers.
2. **Check the prompt, under budget.** A blocking finding here saves the model call, the only
part of this pipeline that costs real money.
3. **Stream the response through the enforcer.** With the policy's lookback, so a pattern can match
across a chunk boundary, and with an honest account of what was already emitted when a block fired.
4. **Check the output independently of the input.** A response echoing the system prompt is a leak
whether or not the request looked like an attack. Trusting the output because the input passed is
how an indirect injection, arriving through a retrieved document rather than the prompt, gets a
clean run.

## What the result says that a guardrail usually does not

`Transaction.unchecked_sides` and `Transaction.leaked_chars`. The first is which sides went through
with a detector's verdict missing, because the policy failed open; the second is how much of a
detected secret reached the client before the stream was cut. Both are the awkward numbers, both are
in the payload and in every renderer, and a guardrail that reported "allowed, no findings" without
disclosing that a detector timed out would be claiming something it did not establish.

## The refusal is constant

Whatever fired, the client gets the same bytes. A refusal that named the detector would be a
labelled oracle: probe until the message changes and the boundary is readable off the difference.
The detector name goes to the log, which is a different audience with different trust.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass, replace

from .budget import Spend, availability, spend
from .detect import Finding, run_detector
from .evaluate import Rates, justify
from .normalise import Normalised, canonical
from .policy import BLOCK, PROMPT, RESPONSE, DetectorPolicy, Policy
from .stream import Enforcement, buffered, enforce
from .upstream import SYSTEM_PROMPT, Completion, Upstream

#: Nominal availabilities for the arithmetic in the report. Declared here rather than measured,
#: because this repository has no production telemetry, and labelled as an assumption everywhere it
#: appears.
ASSUMED_MODEL_AVAILABILITY = 0.999
ASSUMED_GUARDRAIL_AVAILABILITY = 0.999


@dataclass
class Transaction:
    """One request through the proxy, with everything it established and everything it did not."""

    prompt: str
    normalised: Normalised
    allowed: bool
    prompt_findings: tuple[Finding, ...] = ()
    prompt_spend: Spend | None = None
    response: Enforcement | None = None
    response_text: str = ""
    refused_at: str = ""
    refusal_reason: str = ""
    elapsed_ms: float = 0.0
    streamed: bool = True

    @property
    def findings(self) -> tuple[Finding, ...]:
        return (*self.prompt_findings, *(self.response.findings if self.response else ()))

    @property
    def unchecked_sides(self) -> tuple[str, ...]:
        """Sides that went through with a verdict missing, which a report must never omit."""
        sides = []
        if self.prompt_spend and self.prompt_spend.unchecked:
            sides.append(PROMPT)
        return tuple(sides)

    @property
    def leaked_chars(self) -> int:
        return self.response.leaked_chars if self.response else 0

    @property
    def verdict(self) -> str:
        # The leak is tested *before* the refusal, and the order is the whole point. A stream that
        # was cut after part of a secret had gone is a refusal from the policy's point of view and a
        # disclosure from the client's, and the first version reported it as "refused" with an exit
        # code of zero: the guardrail leaked a credential and called it a success.
        if self.leaked_chars:
            return "leaked"
        if not self.allowed:
            return "refused"
        # There is no separate "cut" verdict, and there was one until it turned out to be
        # unreachable: a cut stream sets `allowed=False`, so it is a refusal that happened on the
        # output side, which `refused_at` already says. A verdict nothing can produce is worse than
        # a missing one: a reader looks for it in the report and concludes it never happens.
        if self.response and self.response.redactions:
            return "redacted"
        if self.unchecked_sides:
            return "allowed_unchecked"
        return "allowed"

    @property
    def exit_code(self) -> int:
        """0 when the guardrail did its job, 1 when something got through it.

        `leaked` and `allowed_unchecked` are failures of the guardrail rather than of the request,
        and they exit non-zero for that reason: a run where a secret partly escaped or a detector
        never answered is not a clean run, however the request was labelled.
        """
        return 1 if self.verdict in ("leaked", "allowed_unchecked") else 0

    def to_json(self) -> dict:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "streamed": self.streamed,
            "refused_at": self.refused_at,
            "refusal_reason": self.refusal_reason,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "normalisation": self.normalised.to_json(),
            "prompt_findings": [finding.to_json() for finding in self.prompt_findings],
            "prompt_spend": self.prompt_spend.to_json() if self.prompt_spend else None,
            "response": self.response.to_json() if self.response else None,
            "response_chars": len(self.response_text),
            "unchecked_sides": list(self.unchecked_sides),
            "leaked_chars": self.leaked_chars,
            "caveats": self.caveats(),
        }

    def caveats(self) -> list[str]:
        """What this run did not establish. Printed by every renderer.

        A guardrail's caveats are load-bearing in a way most tools' are not: "allowed" from a proxy
        whose output-side detector timed out is a different claim from "allowed", and only one of
        them is true.
        """
        notes = ["the upstream is a deterministic token stream generator, not a model"]
        if self.unchecked_sides:
            notes.append(
                f"{', '.join(self.unchecked_sides)} went through unchecked because a detector "
                "did not answer and the policy fails open on that side")
        if self.response and self.response.late_detectors:
            notes.append(
                f"{', '.join(self.response.late_detectors)} cannot be enforced on a stream from a "
                "bounded window, so it could only fire after enough output had accumulated")
        if self.leaked_chars:
            notes.append(
                f"{self.leaked_chars} character(s) of the detected span reached the client "
                "before the stream was cut, and cannot be recalled")
        return notes


def detector_findings(detector: DetectorPolicy, normalised: Normalised, *,
                      system_prompt: str = "") -> list[Finding]:
    """One detector over one normalised text, reading the form it declares it needs.

    The form matters and is not a detail. A detector that declares `raw` reads the text as sent,
    because its patterns are case sensitive; one that declares `canonical` reads the folded form,
    because its patterns are about meaning. Decoded base64 segments go to every detector regardless,
    because a payload that arrived encoded is not in either form until it is decoded.

    Public, and used by the rate measurement in `attacks/` as well as by the request path, because a
    false positive rate measured through a different code path from the one that serves traffic is a
    rate for a detector nobody deployed.
    """
    forms = {
        "canonical": (normalised.text,),
        "raw": (normalised.original,),
        "both": (normalised.text, normalised.original),
    }[detector.reads]
    found: list[Finding] = []
    for form in (*forms, *normalised.decoded):
        found.extend(run_detector(detector.name, form, system_prompt=system_prompt,
                                  decoded=normalised.decoded))
    return found


def _scan(normalised: Normalised, policy: Policy, side: str, *,
          system_prompt: str = "") -> tuple[list[Finding], Spend]:
    """Every detector for one side, under its budget, with the accounting."""
    return spend(policy, side,
                 lambda detector: detector_findings(detector, normalised,
                                                    system_prompt=system_prompt))


def handle(prompt: str, completion: Completion | str, policy: Policy, *,
           upstream: Upstream | None = None, system_prompt: str = SYSTEM_PROMPT,
           stream_response: bool = True) -> Transaction:
    """One request, end to end.

    `stream_response=False` buffers instead, which is the other half of the comparison in
    `experiments/stream_vs_buffer.py`. It is a parameter rather than a separate function because the
    point is that the same policy produces different enforcement depending on it, and a caller
    should have to choose.
    """
    started = time.perf_counter()
    source = upstream or Upstream()
    normalised = canonical(prompt)

    # The prompt side. Detectors read the canonical text plus anything decoded out of it, so an
    # encoded payload is scanned without the decoded bytes being spliced into what the model is
    # asked.
    prompt_findings, prompt_spend = _scan(normalised, policy, PROMPT, system_prompt=system_prompt)
    if prompt_spend.failed_closed:
        return Transaction(
            prompt=prompt, normalised=normalised, allowed=False,
            prompt_findings=tuple(prompt_findings), prompt_spend=prompt_spend,
            refused_at=PROMPT, refusal_reason="guardrail unavailable and the policy fails closed",
            elapsed_ms=(time.perf_counter() - started) * 1000.0, streamed=stream_response,
        )

    blocking = [finding for finding in prompt_findings
                if policy.detectors[finding.detector].action_for(finding.confidence) == BLOCK]
    if blocking:
        return Transaction(
            prompt=prompt, normalised=normalised, allowed=False,
            prompt_findings=tuple(prompt_findings), prompt_spend=prompt_spend,
            refused_at=PROMPT, refusal_reason=min(blocking, key=lambda f: f.start).detector,
            elapsed_ms=(time.perf_counter() - started) * 1000.0, streamed=stream_response,
        )

    # The response side, checked independently of the input. An indirect injection arriving through
    # a retrieved document never touched the prompt, so a clean prompt establishes nothing about the
    # output.
    chunks = source.stream(completion)
    if stream_response:
        state = Enforcement()
        # The enforcer yields `(text, state)` per emission and the state accumulates, so the last
        # one is the summary. Exhausted rather than collected: a caller that wanted the chunks would
        # iterate it itself, and holding them here would defeat the point of streaming.
        for _, latest in enforce(chunks, policy, system_prompt=system_prompt, side=RESPONSE):
            state = latest
    else:
        state = buffered(chunks, policy, system_prompt=system_prompt, side=RESPONSE)

    return Transaction(
        prompt=prompt, normalised=normalised, allowed=not state.cut,
        prompt_findings=tuple(prompt_findings), prompt_spend=prompt_spend,
        response=state, response_text=state.emitted,
        refused_at=RESPONSE if state.cut else "",
        refusal_reason=state.cut_reason,
        elapsed_ms=(time.perf_counter() - started) * 1000.0, streamed=stream_response,
    )


def leak_curve(policy: Policy, completion: Completion | str,
               lookbacks: Iterable[int] = (0, 8, 16, 24, 96), *,
               system_prompt: str = SYSTEM_PROMPT, include_buffered: bool = True,
               seed: int = 20260818) -> list[dict]:
    """The flagship measurement: what each lookback costs and what it saves, on one response.

    For each lookback, the same completion is streamed through the same policy with only
    `stream.lookback_chars` changed, and three numbers come out:

    * `leaked_chars`, how much of the detected span reached the client before the cut;
    * `emitted_after_match`, how much output followed the start of the match, which is a different
      question and also an attacker's gain;
    * `first_emit_at_char`, how many characters of upstream text were consumed before the client saw
      anything, which is the latency the lookback costs.

    The buffered row is appended with `lookback: None` because it is not a point on the same axis:
    it is the other option, with a leak of zero and a first emit at the end of the response.

    A fresh `Upstream` per row, seeded identically, so chunk boundaries are the same across the
    sweep and the only thing that varies is the lookback. Without that, the curve would be measuring
    the jitter.
    """
    rows: list[dict] = []
    for lookback in lookbacks:
        variant = replace(policy, stream=replace(policy.stream, lookback_chars=lookback))
        source = Upstream(seed=seed)
        state = Enforcement()
        for _, latest in enforce(source.stream(completion), variant,
                                 system_prompt=system_prompt, side=RESPONSE):
            state = latest
        rows.append({
            "lookback": lookback,
            "leaked_chars": state.leaked_chars,
            "emitted_after_match": state.emitted_after_match,
            # None rather than a sentinel or a zero: a lookback large enough that the whole response
            # was still held back when the block fired means the client never saw a character, and
            # reporting that as "first emit at character 0" says the opposite of what happened.
            "first_emit_at_char": (state.first_emit_at_char
                                   if state.first_emit_at_char >= 0 else None),
            "cut": state.cut,
            "emitted_chars": len(state.emitted),
            "detectors": sorted({finding.detector for finding in state.findings}),
        })

    if include_buffered:
        source = Upstream(seed=seed)
        state = buffered(source.stream(completion), policy, system_prompt=system_prompt,
                         side=RESPONSE)
        upstream_chars = source.chars_emitted
        rows.append({
            "lookback": None,
            "leaked_chars": state.leaked_chars,
            "emitted_after_match": state.emitted_after_match,
            "first_emit_at_char": upstream_chars,
            "cut": state.cut,
            "emitted_chars": len(state.emitted),
            "detectors": sorted({finding.detector for finding in state.findings}),
        })
    return rows


def client_sees(transaction: Transaction, policy: Policy) -> str:
    """The bytes the client receives, which is constant for every refusal.

    The whole point of routing every refusal through one function: an attacker who can tell "blocked
    for a secret" from "blocked for injection" has a labelled oracle. `policy.response.explain` can
    turn the detector name back on, and the loader refuses that on any route with a non-zero
    declared prevalence.
    """
    if transaction.allowed:
        return transaction.response_text
    if policy.response.explain:
        return f"{policy.response.refusal} [{transaction.refusal_reason}]"
    return policy.response.refusal


def posture(policy: Policy, measured: dict[str, Rates]) -> dict:
    """A policy's own report card: is each action justified at the declared prevalence, and what
    does the fail mode cost.

    This is the part a review reads before a deployment rather than after an incident. Every
    blocking detector is checked against its measured precision at the route's declared prevalence,
    and both fail modes are priced in availability, so the two decisions the policy makes silently
    are on one page.
    """
    verdicts = []
    for name, detector in sorted(policy.detectors.items()):
        rates = measured.get(name)
        if rates is None:
            verdicts.append({
                "detector": name, "action": detector.action, "justified": False,
                "reason": "no measured rates: nothing in the corpus exercises this detector",
            })
            continue
        verdicts.append(justify(name, detector.action, rates, policy.prevalence).to_json())

    return {
        "route": policy.route,
        "prevalence": policy.prevalence,
        "verdicts": verdicts,
        "unjustified": [entry["detector"] for entry in verdicts if not entry["justified"]],
        "availability": {
            side: availability(ASSUMED_MODEL_AVAILABILITY, ASSUMED_GUARDRAIL_AVAILABILITY,
                              fail_open=policy.budget.mode_for(side) == "open")
            for side in (PROMPT, RESPONSE)
        },
        "availability_note": (
            f"model {ASSUMED_MODEL_AVAILABILITY} and guardrail "
            f"{ASSUMED_GUARDRAIL_AVAILABILITY} are assumptions declared in proxy.py, not "
            "measurements; this repository has no production telemetry"),
        "stream_unsafe_detectors": list(policy.stream_unsafe()),
        "lookback_chars": policy.stream.lookback_chars,
    }


__all__ = ["Transaction", "client_sees", "detector_findings", "handle", "leak_curve",
           "posture"]
