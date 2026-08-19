"""Measuring a detector, and the arithmetic that decides whether its verdict is worth acting on.

## The number that is never quoted

Guardrail accuracy is quoted as a true positive rate: "catches 95% of injections". Sometimes a false
positive rate comes with it. Neither answers the question an on-call engineer has, which is: **when
this fires, how often is it right?**

That is precision, and precision depends on prevalence far more than on the detector:

    precision = TPR * p / (TPR * p + FPR * (1 - p))

At 50% prevalence, a detector at 95% TPR and 2% FPR is 98% precise, which sounds like a working
system. At one attack in ten thousand requests, the same detector is **0.47%** precise: 211 false
alarms for every true one. Nothing about the detector changed.

This is not a subtle point and it is routinely skipped, because the fix is uncomfortable. You cannot
get to usable precision at low prevalence by improving the detector: reaching 50% precision at p =
0.0001 needs a false positive rate near one in a million, which no text heuristic achieves. What you
can change is **what a positive costs**. A detector at 0.47% precision is useless as a blocking gate
and perfectly good as a signal that annotates a request, feeds a rate limiter, or raises the
priority of a review queue.

So this module computes precision at prevalence, and the report prints it next to the action the
policy chose, because "block" on a 0.47%-precise detector is a decision somebody should have to look
at.

## Rates are measured, not assumed

`rates()` runs a detector over a labelled corpus and counts. Nothing here takes a TPR as a
parameter, because a detector's real rates on the traffic it will see are the only ones that matter,
and a figure quoted from a paper is a figure about somebody else's corpus.

The corpus is small, which bounds the resolution: with 20 benign samples the smallest measurable
false positive rate other than zero is 5%. `rates()` reports the sample size next to every rate and
`ci_hint()` gives the width of the interval, so a zero is legible as "none in 20" rather than as
"never".
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

#: Prevalences the sweep reports. Chosen to span the range a real route sits in: a red-team corpus
#: is near 0.5, an internal tool maybe 0.01, and a public consumer endpoint is somewhere below
#: 0.001.
PREVALENCES = (0.5, 0.1, 0.01, 0.001, 0.0001)

#: Precision below which a blocking action is refusing more legitimate requests than attacks. Half
#: is the honest place to draw it: at 50% precision a block is a coin flip on whether the user did
#: anything wrong, and below it the guardrail is doing more damage than the attacks it stops.
BLOCK_PRECISION_FLOOR = 0.5


@dataclass(frozen=True)
class Rates:
    """One detector's measured behaviour on a labelled corpus."""

    detector: str
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int

    @property
    def attacks(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def benign(self) -> int:
        return self.false_positives + self.true_negatives

    @property
    def tpr(self) -> float:
        return self.true_positives / self.attacks if self.attacks else 0.0

    @property
    def fpr(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0

    @property
    def smallest_measurable_fpr(self) -> float:
        """The resolution floor. A zero false positive rate over 20 samples means "fewer than one in
        20", not "never", and a report that prints 0.0% without this number is overclaiming.
        """
        return 1.0 / self.benign if self.benign else 1.0

    @property
    def resolved_fpr(self) -> float:
        """The largest false positive rate this corpus cannot rule out.

        `max(measured, 1/benign)`. A detector that fired on none of 34 benign samples has a measured
        rate of zero and a *supportable* rate of one in 34, and the difference decides arguments: at
        a prevalence of 0.0004, zero gives a precision of 100% and one in 34 gives 1.3%. Quoting
        the first is how a guardrail comes to have a blocking action justified by a number the
        corpus was never large enough to produce.
        """
        return max(self.fpr, self.smallest_measurable_fpr)

    def precision_at(self, prevalence: float, *, resolved: bool = False) -> float:
        """Precision if this detector ran on traffic with the given attack share.

        `resolved=True` uses `resolved_fpr` instead of the measured rate, which is the version any
        claim about a blocking action has to survive.
        """
        hits = self.tpr * prevalence
        rate = self.resolved_fpr if resolved else self.fpr
        alarms = hits + rate * (1.0 - prevalence)
        return hits / alarms if alarms else 0.0

    def benign_needed_for(self, prevalence: float,
                          floor: float = BLOCK_PRECISION_FLOOR) -> int:
        """Clean samples, with no false positive among them, needed to support a blocking action.

        Inverts the precision identity for the false positive rate that would put precision exactly
        at the floor, then reports the sample size whose resolution reaches it. This is the number
        that makes the base-rate argument actionable rather than discouraging: it converts "your
        corpus is too small" into "you need this many, and you have that many".
        """
        if self.tpr <= 0.0 or prevalence <= 0.0 or floor >= 1.0:
            return 0
        permitted = self.tpr * prevalence * (1.0 - floor) / (floor * (1.0 - prevalence))
        return math.ceil(1.0 / permitted) if permitted > 0 else 0

    def alarms_per_true_positive(self, prevalence: float) -> float:
        precision = self.precision_at(prevalence)
        return (1.0 / precision) if precision else float("inf")

    def to_json(self) -> dict:
        return {
            "detector": self.detector,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "attacks": self.attacks,
            "benign": self.benign,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "smallest_measurable_fpr": round(self.smallest_measurable_fpr, 4),
            "resolved_fpr": round(self.resolved_fpr, 4),
            "precision_at": {str(p): round(self.precision_at(p), 6) for p in PREVALENCES},
            "precision_at_resolved": {str(p): round(self.precision_at(p, resolved=True), 6)
                                      for p in PREVALENCES},
            "benign_needed_for_block": {str(p): self.benign_needed_for(p) for p in PREVALENCES},
            "alarms_per_true_positive": {
                str(p): (None if math.isinf(self.alarms_per_true_positive(p))
                         else round(self.alarms_per_true_positive(p), 1))
                for p in PREVALENCES
            },
        }


def rates(detector: str, attacks: Iterable[bool], benign: Iterable[bool]) -> Rates:
    """Count a detector's outcomes. `attacks` and `benign` are "did it fire" per labelled sample."""
    attack_results = list(attacks)
    benign_results = list(benign)
    return Rates(
        detector=detector,
        true_positives=sum(1 for fired in attack_results if fired),
        false_negatives=sum(1 for fired in attack_results if not fired),
        false_positives=sum(1 for fired in benign_results if fired),
        true_negatives=sum(1 for fired in benign_results if not fired),
    )


def ci_hint(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """A Wilson interval, so a rate measured on 20 samples is not read as a rate measured on 20,000.

    Wilson rather than the normal approximation because the interesting cases here are proportions
    at or near zero, where the normal approximation gives a lower bound below zero and reads as
    certainty.
    """
    if trials == 0:
        return (0.0, 1.0)
    phat = successes / trials
    denominator = 1 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
    spread = margin / denominator
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass(frozen=True)
class Verdict:
    """Whether a detector's measured rates justify the action a policy gave it."""

    detector: str
    action: str
    prevalence: float
    precision: float
    #: Precision computed against `Rates.resolved_fpr` rather than the measured rate. The number a
    #: blocking action is actually defended with.
    resolved_precision: float
    alarms_per_true_positive: float
    #: Clean samples needed, with no false positive among them, to support this action at this
    #: prevalence. Zero when the action does not refuse anything.
    benign_needed: int
    benign_measured: int
    justified: bool
    reason: str

    def to_json(self) -> dict:
        return {
            "detector": self.detector, "action": self.action, "prevalence": self.prevalence,
            "precision": round(self.precision, 6),
            "resolved_precision": round(self.resolved_precision, 6),
            "alarms_per_true_positive": (None if math.isinf(self.alarms_per_true_positive)
                                         else round(self.alarms_per_true_positive, 1)),
            "benign_needed": self.benign_needed, "benign_measured": self.benign_measured,
            "justified": self.justified, "reason": self.reason,
        }


def justify(detector: str, action: str, measured: Rates, prevalence: float) -> Verdict:
    """Whether the policy's action is defensible at the rates this corpus can support.

    This is the check that turns the base-rate argument into something a build can fail on, and it
    deliberately uses `resolved_fpr` rather than the measured false positive rate. A detector that
    fired on none of 34 benign samples has a measured precision of 100% at any prevalence, and a
    check written against that number would approve every blocking action in this repository. The
    resolved rate asks the question a reviewer would: what is the worst false positive rate
    consistent with what was actually observed, and does the action survive it?

    The consequence is uncomfortable and is the point. On this corpus, at a declared prevalence of
    0.0004, no blocking detector is justified, and the verdict says how many clean samples it
    would take. That is the honest state of a guardrail measured on 38 samples, and a report that
    concealed it would be the thing this repository was written to argue with.
    """
    precision = measured.precision_at(prevalence)
    resolved = measured.precision_at(prevalence, resolved=True)
    ratio = measured.alarms_per_true_positive(prevalence)
    needed = measured.benign_needed_for(prevalence) if action == "block" else 0

    if action != "block":
        return Verdict(detector, action, prevalence, precision, resolved, ratio, 0,
                       measured.benign, True,
                       f"{action} does not refuse a request, so precision bounds the noise in "
                       "a log rather than the harm to a user")
    if measured.attacks == 0:
        return Verdict(detector, action, prevalence, precision, resolved, ratio, needed,
                       measured.benign, False,
                       "no labelled attack exercises this detector, so its true positive rate is "
                       "unmeasured and a blocking action rests on nothing")
    if resolved >= BLOCK_PRECISION_FLOOR:
        return Verdict(detector, action, prevalence, precision, resolved, ratio, needed,
                       measured.benign, True,
                       f"precision {resolved:.1%} at prevalence {prevalence:g} is above the "
                       f"{BLOCK_PRECISION_FLOOR:.0%} floor even at the worst false positive rate "
                       f"this corpus can support, {measured.resolved_fpr:.3f}")
    return Verdict(
        detector, action, prevalence, precision, resolved, ratio, needed, measured.benign, False,
        f"the corpus cannot support a block: {measured.benign} benign samples resolve no finer "
        f"than a false positive rate of {measured.resolved_fpr:.3f}, which caps precision at "
        f"{resolved:.2%} at prevalence {prevalence:g}. Supporting it needs {needed} clean samples "
        f"with no false positive among them",
    )


def sweep(measured: Sequence[Rates], prevalences: Sequence[float] = PREVALENCES) -> list[dict]:
    """Precision for every detector at every prevalence, for the published table."""
    return [
        {
            "detector": entry.detector,
            "tpr": round(entry.tpr, 4),
            "fpr": round(entry.fpr, 4),
            "precision": {str(p): round(entry.precision_at(p), 6) for p in prevalences},
        }
        for entry in measured
    ]
