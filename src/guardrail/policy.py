"""The policy: every decision the proxy makes, declared in one reviewed file.

A guardrail has four settings that decide whether it is worth having, and in most deployments all
four are implicit:

* **the action** per detector, which is the only one anybody configures;
* **what happens when the guardrail itself fails**, which is usually whatever the exception handler
happened to do;
* **how much of a streaming response is held back**, which is the same number as how much of a
detected secret reaches the client before the stream is cut;
* **the assumed prevalence**, without which "this detector is 99% accurate" says nothing about
how often it will be right in production.

All four are loaded from YAML and validated here. The loader refuses a policy whose detector budgets
exceed the total, because a budget nobody enforces is a comment, and refuses a route that explains
its refusals to untrusted users, because a refusal that names the detector is a labelled oracle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detect import REGISTRY
from .errors import PolicyError

BLOCK = "block"
REDACT = "redact"
FLAG = "flag"
ACTIONS = (BLOCK, REDACT, FLAG)

#: Confidence levels a detector can report, weakest first. A detector that reports at more than one
#: confidence needs the policy to say what each one does, because otherwise the weaker signal
#: inherits the stronger action and the detector's false positive rate becomes that of its noisiest
#: component. This was not theoretical: the secret detector reports documented key shapes at `high`
#: and high-entropy runs at `low`, and with one action for the whole detector a git hash in a
#: support answer blocked the response.
CONFIDENCE = ("low", "medium", "high")

#: Which form of the text a detector reads. There is no single canonical form that serves every
#: detector, because canonicalisation is lossy and different detectors depend on different parts of
#: what it discards. Case folding is the clearest case: an injection pattern needs it, because
#: `IGNORE` and `ignore` are the same instruction, and a secret shape is destroyed by it, because
#: `AKIAIOSFODNN7EXAMPLE` case-folded no longer matches `AKIA[0-9A-Z]{16}` and is no longer a key.
#: The first version of this proxy fed every detector the canonical text and silently stopped
#: detecting credentials in prompts.
READS = ("canonical", "raw", "both")

PROMPT = "prompt"
RESPONSE = "response"
SIDES = (PROMPT, RESPONSE)

FAIL_CLOSED = "closed"
FAIL_OPEN = "open"
FAILURE_MODES = (FAIL_CLOSED, FAIL_OPEN)


@dataclass(frozen=True)
class DetectorPolicy:
    """What one detector is for, what it costs, and whether it can run on a stream."""

    name: str
    action: str
    where: tuple[str, ...]
    budget_ms: float
    #: Whether a verdict can be reached from a bounded window of text. A detector that needs the
    #: whole response cannot be enforced on a stream without buffering it, and saying so is the
    #: difference between a guardrail that works on streams and one that appears to.
    stream_safe: bool = True
    #: The weakest confidence at which this detector's declared action applies. A finding below it
    #: degrades to `flag`: it is still reported and it does not refuse a request. Defaults to `high`
    #: for a blocking detector, because a block is the action where being wrong is expensive.
    min_confidence: str = "high"
    #: Which form of the text this detector reads: the canonical form, the text as sent, or both.
    #: See `READS`. A detector whose patterns are case sensitive must not read the canonical form.
    reads: str = "canonical"

    def action_for(self, confidence: str) -> str:
        """The action for a finding at a given confidence.

        Degrading rather than dropping. A low-confidence finding on a blocking detector is still
        worth logging, and dropping it would hide the fact that the detector nearly fired.
        """
        if CONFIDENCE.index(confidence) < CONFIDENCE.index(self.min_confidence):
            return FLAG
        return self.action

    @property
    def blocks(self) -> bool:
        return self.action == BLOCK

    def applies_to(self, side: str) -> bool:
        return side in self.where

    def to_json(self) -> dict:
        return {"name": self.name, "action": self.action, "where": list(self.where),
                "budget_ms": self.budget_ms, "stream_safe": self.stream_safe,
                "min_confidence": self.min_confidence, "reads": self.reads}


@dataclass(frozen=True)
class StreamPolicy:
    """How the enforcer treats a streaming response."""

    #: Characters held back so a pattern can match across a chunk boundary, and equivalently the
    #: maximum number of characters of a detected secret that reach the client first.
    lookback_chars: int = 96
    warmup_chars: int = 0
    cut_message: str = "\n\n[response withheld]"

    def to_json(self) -> dict:
        return {"lookback_chars": self.lookback_chars, "warmup_chars": self.warmup_chars,
                "cut_message": self.cut_message}


@dataclass(frozen=True)
class BudgetPolicy:
    """The guardrail's share of the request, and what happens when it is exceeded."""

    total_ms: float = 45.0
    #: Per side, because the right answer differs per side. Failing closed on the input costs a
    #: request; failing closed on the output costs a request that already consumed a model call.
    on_unavailable: dict[str, str] = field(default_factory=lambda: {PROMPT: FAIL_CLOSED,
                                                                    RESPONSE: FAIL_OPEN})

    def mode_for(self, side: str) -> str:
        return self.on_unavailable.get(side, FAIL_CLOSED)

    def to_json(self) -> dict:
        return {"total_ms": self.total_ms, "on_unavailable": dict(self.on_unavailable)}


@dataclass(frozen=True)
class ResponsePolicy:
    """What a refused request receives."""

    refusal: str = "I can't help with that request."
    #: Whether the refusal names the detector that fired. True is useful in development and is an
    #: oracle in production, so the loader refuses it on a route with a non-zero prevalence.
    explain: bool = False

    def to_json(self) -> dict:
        return {"refusal": self.refusal, "explain": self.explain}


@dataclass(frozen=True)
class Policy:
    """One route's policy, whole."""

    route: str
    description: str
    prevalence: float
    detectors: dict[str, DetectorPolicy]
    stream: StreamPolicy
    budget: BudgetPolicy
    response: ResponsePolicy
    version: int = 1

    def for_side(self, side: str) -> tuple[DetectorPolicy, ...]:
        """Detectors for one side, in a fixed order so the cost accounting is reproducible.

        Ordered cheapest first. Not an optimisation: a detector that blocks makes the ones after it
        irrelevant, so running the cheap ones first is what keeps the median request cheap while
        leaving the worst case unchanged.
        """
        return tuple(sorted(
            (detector for detector in self.detectors.values() if detector.applies_to(side)),
            key=lambda detector: (detector.budget_ms, detector.name),
        ))

    def stream_unsafe(self, side: str = RESPONSE) -> tuple[str, ...]:
        """Detectors that cannot be enforced on a stream, which the report has to disclose."""
        return tuple(detector.name for detector in self.for_side(side) if not detector.stream_safe)

    @property
    def declared_budget_ms(self) -> float:
        return round(sum(detector.budget_ms for detector in self.detectors.values()), 3)

    def to_json(self) -> dict:
        return {
            "route": self.route,
            "version": self.version,
            "prevalence": self.prevalence,
            "detectors": {name: detector.to_json()
                          for name, detector in sorted(self.detectors.items())},
            "declared_budget_ms": self.declared_budget_ms,
            "stream": self.stream.to_json(),
            "budget": self.budget.to_json(),
            "response": self.response.to_json(),
            "stream_unsafe_detectors": list(self.stream_unsafe()),
        }


def _detector(name: str, payload: dict) -> DetectorPolicy:
    # A policy that names a detector nothing implements is the failure this check exists for: the
    # detector never runs, no error is raised, and the route looks protected. Checked here rather
    # than at request time, because "your policy references a detector that does not exist" is a
    # startup message and a KeyError from inside the request path is an incident.
    if name not in REGISTRY:
        raise PolicyError(f"detector {name!r} is not implemented; known detectors are "
                          f"{', '.join(sorted(REGISTRY))}")
    for key in ("action", "where", "budget_ms"):
        if key not in payload:
            raise PolicyError(f"detector {name!r} does not declare {key}")
    action = str(payload["action"])
    if action not in ACTIONS:
        raise PolicyError(f"detector {name!r} declares action {action!r}, not one of "
                          f"{', '.join(ACTIONS)}")
    where = tuple(payload["where"])
    unknown = [side for side in where if side not in SIDES]
    if unknown:
        raise PolicyError(f"detector {name!r} applies to {', '.join(unknown)}, not one of "
                          f"{', '.join(SIDES)}")
    if not where:
        raise PolicyError(f"detector {name!r} applies to no side, so it would never run")
    if action == REDACT and PROMPT in where:
        raise PolicyError(
            f"detector {name!r} redacts on the prompt side. Redacting a prompt changes what "
            "the model is asked without telling anyone, which produces an answer to a question "
            "the user did not ask. Block it or flag it."
        )
    budget = float(payload["budget_ms"])
    if budget <= 0:
        raise PolicyError(f"detector {name!r} declares a budget of {budget} ms")
    confidence = str(payload.get("min_confidence", "high" if action == BLOCK else "low"))
    if confidence not in CONFIDENCE:
        raise PolicyError(f"detector {name!r} declares min_confidence {confidence!r}, not one of "
                          f"{', '.join(CONFIDENCE)}")
    reads = str(payload.get("reads", "canonical"))
    if reads not in READS:
        raise PolicyError(f"detector {name!r} declares reads {reads!r}, not one of "
                          f"{', '.join(READS)}")
    return DetectorPolicy(name=name, action=action, where=where, budget_ms=budget,
                          stream_safe=bool(payload.get("stream_safe", True)),
                          min_confidence=confidence, reads=reads)


def load(path: str | Path) -> Policy:
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"no policy at {path}")
    try:
        document = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path} is not valid YAML: {exc}") from exc

    for key in ("route", "detectors"):
        if key not in document:
            raise PolicyError(f"{path} does not declare {key}")

    detectors = {name: _detector(name, payload or {})
                 for name, payload in (document["detectors"] or {}).items()}
    if not detectors:
        raise PolicyError(f"{path} declares no detectors")

    stream_payload = document.get("stream") or {}
    lookback = int(stream_payload.get("lookback_chars", 96))
    if lookback < 0:
        raise PolicyError(f"lookback_chars is {lookback}; it is a number of characters")

    budget_payload = document.get("budget") or {}
    modes = dict(budget_payload.get("on_unavailable") or {})
    for side, mode in modes.items():
        if side not in SIDES:
            raise PolicyError(f"on_unavailable names side {side!r}, not one of {', '.join(SIDES)}")
        if mode not in FAILURE_MODES:
            raise PolicyError(
                f"on_unavailable.{side} is {mode!r}, not one of {', '.join(FAILURE_MODES)}. "
                "There is no third option and leaving it unset is choosing one by accident."
            )
    budget = BudgetPolicy(total_ms=float(budget_payload.get("total_ms", 45.0)),
                          on_unavailable=modes or {PROMPT: FAIL_CLOSED, RESPONSE: FAIL_OPEN})

    response_payload = document.get("response") or {}
    response = ResponsePolicy(
        refusal=str(response_payload.get("refusal", "I can't help with that request.")),
        explain=bool(response_payload.get("explain", False)),
    )

    prevalence = float(document.get("prevalence", 0.0))
    if not 0.0 <= prevalence <= 1.0:
        raise PolicyError(f"prevalence {prevalence} is not a share between 0 and 1")

    policy = Policy(
        route=str(document["route"]),
        description=str(document.get("description", "")).strip(),
        prevalence=prevalence,
        detectors=detectors,
        stream=StreamPolicy(lookback_chars=lookback,
                            warmup_chars=int(stream_payload.get("warmup_chars", 0)),
                            cut_message=str(stream_payload.get("cut_message",
                                                               "\n\n[response withheld]"))),
        budget=budget,
        response=response,
        version=int(document.get("version", 1)),
    )

    if policy.declared_budget_ms > policy.budget.total_ms:
        raise PolicyError(
            f"the detector budgets sum to {policy.declared_budget_ms} ms and the total is "
            f"{policy.budget.total_ms} ms. A budget that is not enforced is a comment, so this is "
            "refused rather than warned about."
        )
    if policy.response.explain and prevalence > 0:
        raise PolicyError(
            "response.explain is true on a route with a declared attack prevalence. A refusal that "
            "names the detector that fired is a labelled oracle: an attacker probes until the "
            "message "
            "changes and reads the boundary off the difference."
        )
    return policy
