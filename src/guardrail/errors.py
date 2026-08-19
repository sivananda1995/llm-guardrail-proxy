"""One exception family, so the proxy can map failures to exit codes without catching Exception.

The distinction the exit codes rest on, and the reason this file exists at all: a `PolicyError`
means this tool was invoked wrongly and nothing about the request has been established either way,
while a `GuardrailUnavailable` means the guardrail itself failed and the proxy now has to make the
decision this whole repository is about. Collapsing those two into one exception is how a guardrail
ends up failing open because its configuration file had a typo.
"""

from __future__ import annotations


class GuardrailError(Exception):
    """Base for everything this package raises on purpose."""


class PolicyError(GuardrailError):
    """The policy is missing, malformed, or internally inconsistent."""


class GuardrailUnavailable(GuardrailError):
    """A detector could not produce a verdict: it timed out, or it raised.

    Carries the elapsed milliseconds because the fail-open decision depends on them, and carries
    whether the failure looked adversarial, because a detector that times out on one crafted input
    and nothing else is being attacked rather than being slow.
    """

    def __init__(self, detector: str, reason: str, elapsed_ms: float,
                 looks_adversarial: bool = False) -> None:
        super().__init__(
            f"{detector} could not produce a verdict after {elapsed_ms:.1f} ms: {reason}")
        self.detector = detector
        self.reason = reason
        self.elapsed_ms = elapsed_ms
        self.looks_adversarial = looks_adversarial


class StreamError(GuardrailError):
    """The upstream stream ended in a state the enforcer cannot describe honestly."""
