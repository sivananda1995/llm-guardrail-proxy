"""Running detectors under a timeout, and the decision that has no safe answer.

## The decision

A detector can fail. It can raise, and it can exceed its budget. The proxy then has to do one of
exactly two things, and both are wrong:

* **fail closed**: the request fails. A guardrail outage is a product outage, so the guardrail's
availability multiplies into the product's. Two nines of guardrail in series with three nines of
model gives you two nines.
* **fail open**: the request proceeds unchecked. The guardrail is optional in precisely the moments
something can cause it to fail, and an attacker who can make it slow has switched it off.

There is no third option, and the reason this module exists rather than a `try` block in the proxy
is that the choice has to be *stated per side*, *measured*, and *reported in the response* rather
than made by whichever exception handler ran.

## Why fail-open is an attack surface and not just a trade-off

`experiments/redos_fail_open.py` demonstrates it end to end against a pattern nobody would flag in
review. The obvious first implementation of this repository's own exfiltration detector is

    r"(\\w+\\s?)+\\bsystem prompt\\b"

which is how you would write "any run of words followed by 'system prompt'". It backtracks
catastrophically: **24 characters of input take 2.3 seconds**, against a detector budget of 8 ms. So
an attacker sends 30 characters, the detector blows its budget, the route fails open, and the
request the detector existed to stop goes through unchecked. The payload does not have to look like
an attack, because it is not attacking the model.

The defence is not a longer timeout. It is that detectors must be linear time by construction, which
`tests/test_detect.py` asserts with a wall-clock bound against adversarial inputs, and the timeout
is the backstop rather than the plan.

## Accounted milliseconds, not wall clock

The timings this module reports are measured with `perf_counter`, and the *budget* comparisons use
them, because a timeout has to be real. Everything published as a headline figure is a ratio or a
count, never an absolute duration, because absolute durations move between machines and a receipt
that cannot be reproduced is not a receipt. `experiments/latency_budget.py` reports the best of
several repeats and the spread, for the same reason.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .errors import GuardrailUnavailable
from .policy import FAIL_OPEN, DetectorPolicy, Policy

#: A detector that exceeds its budget by this multiple is not merely slow. Ordinary variance is tens
#: of per cent; a factor of five is a different algorithm running, which in practice means
#: backtracking on crafted input. Reported so a fail-open event can be told apart from a busy
#: machine.
ADVERSARIAL_MULTIPLE = 5.0


@dataclass
class DetectorRun:
    """One detector's attempt: what it cost, and whether it answered."""

    name: str
    elapsed_ms: float
    budget_ms: float
    answered: bool
    findings: int = 0
    error: str = ""

    @property
    def over_budget(self) -> bool:
        return self.elapsed_ms > self.budget_ms

    @property
    def looks_adversarial(self) -> bool:
        return self.elapsed_ms > self.budget_ms * ADVERSARIAL_MULTIPLE

    def to_json(self) -> dict:
        return {"name": self.name, "elapsed_ms": round(self.elapsed_ms, 3),
                "budget_ms": self.budget_ms, "answered": self.answered,
                "findings": self.findings, "over_budget": self.over_budget,
                "looks_adversarial": self.looks_adversarial, "error": self.error}


@dataclass
class Spend:
    """What one side of one request cost the guardrail, and how it ended."""

    side: str
    runs: list[DetectorRun] = field(default_factory=list)
    #: Detectors that did not answer. The set that decides whether the fail mode was exercised.
    unavailable: tuple[str, ...] = ()
    failed_open: bool = False
    failed_closed: bool = False

    @property
    def total_ms(self) -> float:
        return round(sum(run.elapsed_ms for run in self.runs), 3)

    @property
    def answered(self) -> tuple[str, ...]:
        return tuple(run.name for run in self.runs if run.answered)

    @property
    def adversarial(self) -> tuple[str, ...]:
        return tuple(run.name for run in self.runs if run.looks_adversarial)

    @property
    def unchecked(self) -> bool:
        """Whether this side went through with a detector's verdict missing.

        The field a report must never omit. A response that says "no findings" after a detector
        failed open is claiming something it did not establish.
        """
        return self.failed_open and bool(self.unavailable)

    def to_json(self) -> dict:
        return {
            "side": self.side,
            "total_ms": self.total_ms,
            "detectors_run": len(self.runs),
            "answered": list(self.answered),
            "unavailable": list(self.unavailable),
            "failed_open": self.failed_open,
            "failed_closed": self.failed_closed,
            "went_through_unchecked": self.unchecked,
            "looks_adversarial": list(self.adversarial),
            "runs": [run.to_json() for run in self.runs],
        }


def timed(work: Callable[[], object], name: str, budget_ms: float) -> tuple[object, DetectorRun]:
    """Run one detector, time it, and convert a budget overrun into an unavailability.

    The timeout is checked *after* the call rather than interrupting it, and that is a real
    limitation stated rather than hidden: Python cannot pre-empt a regex engine mid-match without a
    separate process or the third-party `regex` module's own timeout. So this measures the overrun
    and reports it, and the actual defence against a slow detector is that detectors are linear
    time, verified by test.

    What this does buy: the overrun is *visible*, the fail mode is exercised deliberately, and the
    response records that a detector did not answer. A `try` block around the call would have given
    the same protection against exceptions and none of that.
    """
    started = time.perf_counter()
    try:
        result = work()
    except Exception as exc:  # a detector is untrusted code running on untrusted input
        elapsed = (time.perf_counter() - started) * 1000.0
        raise GuardrailUnavailable(name, f"{type(exc).__name__}: {exc}", elapsed) from exc
    elapsed = (time.perf_counter() - started) * 1000.0
    run = DetectorRun(name=name, elapsed_ms=elapsed, budget_ms=budget_ms, answered=True,
                      findings=len(result) if hasattr(result, "__len__") else 0)
    if run.over_budget:
        raise GuardrailUnavailable(
            name, f"exceeded its {budget_ms} ms budget", elapsed,
            looks_adversarial=run.looks_adversarial,
        )
    return result, run


def spend(policy: Policy, side: str,
          work: Callable[[DetectorPolicy], object]) -> tuple[list, Spend]:
    """Run every detector for a side under its budget, applying the policy's failure mode.

    Returns the findings that were actually produced, plus the accounting. A caller that ignores the
    second value is a caller that will report "no findings" for a request nobody checked, which is
    why the signature makes it awkward to drop.
    """
    record = Spend(side=side)
    findings: list = []
    unavailable: list[str] = []
    mode = policy.budget.mode_for(side)

    for detector in policy.for_side(side):
        try:
            produced, run = timed(lambda d=detector: work(d), detector.name, detector.budget_ms)
        except GuardrailUnavailable as exc:
            record.runs.append(DetectorRun(
                name=detector.name, elapsed_ms=exc.elapsed_ms, budget_ms=detector.budget_ms,
                answered=False, error=exc.reason,
            ))
            unavailable.append(detector.name)
            if mode != FAIL_OPEN:
                record.unavailable = tuple(unavailable)
                record.failed_closed = True
                return findings, record
            continue
        record.runs.append(run)
        findings.extend(produced)

    record.unavailable = tuple(unavailable)
    record.failed_open = bool(unavailable) and mode == FAIL_OPEN
    return findings, record


def availability(model_nines: float, guardrail_nines: float, fail_open: bool) -> dict:
    """The arithmetic the fail mode decides, which is usually left as an intuition.

    In series and failing closed, availabilities multiply: a 99.9% model behind a 99.9% guardrail is
    99.8%, so adding the guardrail *doubled* the expected downtime. Failing open, the product's
    availability is the model's, and what degrades instead is coverage: the guardrail is absent for
    exactly its own downtime, which is the window an attacker wants to cause.

    Returned as a dictionary rather than printed, because the point is to put both columns next to
    each other in the report and let the policy own the choice.
    """
    combined = model_nines if fail_open else model_nines * guardrail_nines
    return {
        "model_availability": model_nines,
        "guardrail_availability": guardrail_nines,
        "fail_open": fail_open,
        "combined_availability": round(combined, 6),
        "downtime_minutes_per_month": round((1 - combined) * 30 * 24 * 60, 2),
        "coverage": round(guardrail_nines if fail_open else 1.0, 6),
        "uncovered_minutes_per_month": round(
            (1 - guardrail_nines) * 30 * 24 * 60 if fail_open else 0.0, 2),
        "note": ("failing open keeps the model's availability and spends the guardrail's downtime "
                 "as coverage; failing closed keeps coverage at one and multiplies the downtime"),
    }
