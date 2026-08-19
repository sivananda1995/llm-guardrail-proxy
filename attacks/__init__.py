"""The corpus this repository is judged against, and the one function that runs a case.

`run_case` is here rather than duplicated in the CLI, the tests and the experiments, because a tool
whose examples come from one harness and whose tests come from another has two behaviours and the
published one is the one nobody checks.
"""

from __future__ import annotations

from guardrail import policy as policy_module
from guardrail import proxy, upstream
from guardrail.evaluate import Rates, rates
from guardrail.normalise import canonical
from guardrail.policy import PROMPT, RESPONSE

from .scenarios import (
    ATTACK,
    BENIGN,
    CASES,
    CASES_BY_SLUG,
    EVASION,
    KNOWN_SURVIVING_EVASIONS,
    POLICY_PATH,
    Case,
    case,
    of_kind,
    summary,
)

__all__ = [
    "ATTACK", "BENIGN", "CASES", "CASES_BY_SLUG", "EVASION", "KNOWN_SURVIVING_EVASIONS",
    "POLICY_PATH", "Case", "case", "load_policy", "measure", "of_kind", "run_all", "run_case",
    "summary",
]


def load_policy(path: str = POLICY_PATH):
    return policy_module.load(path)


def run_case(slug: str, policy=None, *, stream_response: bool = True,
             upstream_source: upstream.Upstream | None = None) -> tuple[Case, proxy.Transaction]:
    """One corpus case through the real proxy, with the real policy."""
    entry = case(slug)
    policy = policy or load_policy()
    return entry, proxy.handle(
        entry.prompt, upstream.completion(entry.completion), policy,
        upstream=upstream_source or upstream.Upstream(),
        stream_response=stream_response,
    )


def measure(policy=None, *, at_action_confidence: bool = True) -> dict[str, Rates]:
    """Every detector's true and false positive rate, measured on this corpus.

    Two labelled populations per detector, one per side, because a detector that runs on both sides
    sees different traffic on each. On the prompt side the samples are the corpus prompts and the
    label is whether the case declares this detector should fire; on the response side they are the
    scripted completions and the label is `Completion.expect_detectors`.

    Measured through `proxy.detector_findings`, the same call the request path makes. A rate
    measured through a shortcut is a rate for a detector nobody deployed, and this is exactly where
    that mistake would be invisible: the numbers would look fine either way.

    ## Two rates, and which one belongs next to an action

    `at_action_confidence=True` counts a sample as positive only when the finding is confident
    enough for the detector's declared action to apply. That is the rate a `block` has to be
    defended with, because a finding below `min_confidence` degrades to `flag` and never refuses
    anything.

    False gives the other rate: any finding at all, which is what the detector produces as a
    signal.
    The gap between the two is what `min_confidence` buys, and on this corpus it is the difference
    between a false positive rate of 14.7% and one of zero for the same detector, because five
    benign samples carry a high-entropy run: a git hash, a tracking reference, and base64 payloads.
    Both are published, because quoting only the flattering one is the move this repository argues
    with.

    The populations are small, deliberately visibly so. `Rates.smallest_measurable_fpr` is the
    resolution floor and every renderer prints it next to the rate, so a zero reads as "none in
    twenty" rather than as "never".
    """
    policy = policy or load_policy()
    system_prompt = upstream.SYSTEM_PROMPT
    measured: dict[str, Rates] = {}

    for name, detector in policy.detectors.items():
        def fired(text: str, detector=detector) -> bool:
            found = proxy.detector_findings(detector, canonical(text), system_prompt=system_prompt)
            if not at_action_confidence:
                return bool(found)
            return any(detector.action_for(finding.confidence) == detector.action
                       for finding in found)

        fired_on_attacks: list[bool] = []
        fired_on_benign: list[bool] = []

        if detector.applies_to(PROMPT):
            for entry in CASES:
                expected = name in entry.expect_detectors
                (fired_on_attacks if expected else fired_on_benign).append(fired(entry.prompt))

        if detector.applies_to(RESPONSE):
            for completion in upstream.COMPLETIONS.values():
                expected = name in completion.expect_detectors
                (fired_on_attacks if expected else fired_on_benign).append(fired(completion.text))

        measured[name] = rates(name, fired_on_attacks, fired_on_benign)
    return measured


def run_all(policy=None, *, stream_response: bool = True) -> list[tuple[Case, proxy.Transaction]]:
    """The whole corpus through the real proxy, in declaration order."""
    policy = policy or load_policy()
    source = upstream.Upstream()
    return [run_case(entry.slug, policy, stream_response=stream_response, upstream_source=source)
            for entry in CASES]
