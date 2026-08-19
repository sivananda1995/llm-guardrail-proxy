"""The detectors, and the property that matters more than their accuracy: linear time.

## Why linear time is the first requirement

A detector runs on attacker-controlled input, in the request path, under a timeout, and the policy
says what happens when it exceeds that timeout. So a detector whose running time an attacker can
inflate is a detector an attacker can switch off, and on a route that fails open that is the whole
guardrail.

This is not hypothetical, and finding a real example took more care than expected, which is itself
the lesson. The first candidate written for this repository was

    r"(ignore\\s+)+(previous|all)\\s+instructions"

which has the shape everybody points at, a quantifier inside a repeated group, and does **not**
blow up: `\\s+` and `ignore` cannot both match the same character, so there is no ambiguity for the
engine to explore. A pattern is not dangerous because it looks dangerous.

The pattern that does blow up is the obvious way to write "any run of words followed by a phrase":

    r"(\\w+\\s?)+\\bsystem prompt\\b"

Here `\\w+` and the optional `\\s?` genuinely overlap, so a run of word characters with no match at
the end can be split an exponential number of ways. `NAIVE_EXFILTRATION` below is that pattern,
`redos_curve()` measures it, and the shape is unambiguous: microseconds at 12 characters, about 9 ms
at 16, about 150 ms at 20, and around 2.5 seconds at 24 characters of input, against a detector
budget of 8 ms. Twenty-four characters. Not a megabyte, not a crafted Unicode payload: a short
string of letters that no reviewer would look at twice.

So every pattern here is checked by `tests/test_detect.py` against adversarial inputs with a hard
wall clock assertion, and the patterns are written without nested quantifiers. That is a
*structural* property, verified, rather than a claim about how the patterns look.

## Why structure and entropy rather than word lists

A secret detector built from a list of vendor prefixes finds the secrets whose vendors it knows
about. The two signals that generalise are **shape** (an issuer publishes the format, and it is
checkable) and **entropy** (a 32-character run with 4.6 bits per character is not English). Both are
here, and they say different things: a shape match is a confident finding and an entropy match is a
warning, because entropy alone also fires on a git hash, a UUID and a minified asset name.

## What a detector returns, and what it deliberately does not

A `Finding` carries a span. Not the matched text: the span. A guardrail that logs the secret it
found has copied the secret into the log pipeline, which is usually less protected than the thing it
came from, and this is the most common way a redaction feature becomes a disclosure.
`Finding.excerpt` exists for reports and is masked at construction.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

#: Shannon entropy per character above which a run of base64-ish characters is worth reporting, and
#: a threshold whose honest description is less flattering than the usual one. It is measured only
#: on runs of `ENTROPY_MIN_RUN` characters with no whitespace, which is why ordinary prose never
#: reaches it: English at this length is around 3.8 bits per character, well above the threshold,
#: and would fire constantly if the run pattern allowed spaces. Among runs that do qualify, the
#: separation is real but not clean. Base64 measures about 4.6 bits, a 40 character git hash 3.96, a
#: long snake_case identifier 3.88 and a hyphenated slug 4.14. Every one of those is above 3.6. That
#: is not a threshold to block on, and the design does not: entropy findings are reported at `low`
#: confidence, the policy's `min_confidence: high` degrades them to `flag`, and `attacks.measure()`
#: publishes both rates. As a signal this detector has a false positive rate of 14.7% on the corpus;
#: as a gate it has zero. The threshold is a triage boundary, not a verdict.
ENTROPY_BITS = 3.6
#: Shortest run worth measuring entropy on. Below this, entropy is noise: "Xk9" is high entropy and
#: is three characters of a word.
ENTROPY_MIN_RUN = 24


#: The widest span a prefix-safe detector needs in view to fire at all, and therefore the smallest
#: window a streaming enforcer can scan without losing detections outright. This is not the same
#: number as the lookback, and conflating them was a bug. The lookback decides how much of a match
#: can be *held back*; the window decides whether the match can be *seen*. With a window of twice
#: the lookback, a policy with an 8 character lookback could never see a 20 character key at all: by
#: the time the key was complete its first characters had slid out of the window, and the key was
#: caught only by the end-of-stream check, after the whole thing had gone. 64 covers every shipped
#: pattern's minimum match with headroom: a 19 digit card with separators is 37 characters, the
#: longest documented key shape is 45, and an entropy run fires at 24. A pattern whose *minimum*
#: match exceeds this would need the constant raised, which is why it is named here rather than
#: written as a literal in the enforcer.
LONGEST_MATCH_CHARS = 64


def shannon(text: str) -> float:
    """Bits per character. Zero for an empty string rather than an exception: a detector that
    raises on empty input is a detector that raises on the first chunk of a stream.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def luhn(digits: str) -> bool:
    """The Luhn check. A sixteen-digit run that fails it is an order number, not a card."""
    numbers = [int(character) for character in digits if character.isdigit()]
    if len(numbers) < 12:
        return False
    total, parity = 0, len(numbers) % 2
    for index, digit in enumerate(numbers):
        value = digit
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


@dataclass(frozen=True)
class Finding:
    """One thing a detector found, located rather than quoted."""

    detector: str
    start: int
    end: int
    #: A masked excerpt for the report. Masked at construction rather than at render time, so a
    #: payload cannot reach a log through a code path that forgot to mask.
    excerpt: str
    confidence: str = "high"
    note: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_json(self) -> dict:
        return {"detector": self.detector, "start": self.start, "end": self.end,
                "length": self.length, "excerpt": self.excerpt, "confidence": self.confidence,
                "note": self.note}


def mask(text: str, keep: int = 4) -> str:
    """A recognisable but useless excerpt: the first few characters and a length.

    `keep` is small on purpose. Four characters of an API key identify the vendor and the
    environment, which is what somebody reading a report needs, and are not enough to use.
    """
    if len(text) <= keep:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * min(len(text) - keep, 12)} ({len(text)} chars)"


# --------------------------------------------------------------------------- patterns Every pattern
# below is written without a nested quantifier. Where a repetition is genuinely needed inside a
# group, the inner element is a single character class with a bounded count, which cannot backtrack
# exponentially. `tests/test_detect.py` times each of these against an adversarial input.

#: Documented shapes. Each is a vendor's published format, so a match is a confident finding.
SECRET_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)

#: High-entropy runs. Reported at low confidence, because a git hash matches this too.
ENTROPY_RUN = re.compile(rf"[A-Za-z0-9+/=_\-]{{{ENTROPY_MIN_RUN},}}")

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
CARD_RUN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

#: The override family: telling the model to disregard what it was told. Written as alternations of
#: fixed strings with single bounded gaps, never as a repeated group.
OVERRIDE = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\bignore\s{1,4}(?:all\s{1,4}|any\s{1,4}|the\s{1,4})?(?:previous|prior|above|earlier)"
    r"\s{1,4}(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)\b",
    r"\bdisregard\s{1,4}(?:all\s{1,4}|any\s{1,4}|the\s{1,4})?(?:previous|prior|above|earlier)\b",
    r"\bforget\s{1,4}(?:everything|all)\s{1,4}(?:you|that|above)\b",
    r"\byou\s{1,4}are\s{1,4}(?:now|actually)\s{1,4}(?:a|an|in)\b",
    r"\bnew\s{1,4}(?:instructions|system\s{1,4}prompt|rules)\s{0,4}:",
    r"\b(?:developer|debug|god|admin)\s{1,4}mode\s{1,4}(?:on|enabled|activated)\b",
))

#: The exfiltration family: making the model disclose its own instructions. Narrower than the
#: override family and with a much lower false-positive rate, which is why the policy blocks on it.
EXFILTRATION = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\b(?:repeat|print|show|reveal|output|display|echo)\s{1,4}(?:me\s{1,4})?"
    r"(?:your|the)\s{1,4}(?:system\s{1,4})?(?:prompt|instructions|rules|directive)\b",
    r"\bwhat\s{1,4}(?:were|are)\s{1,4}your\s{1,4}(?:original\s{1,4})?instructions\b",
    r"\brepeat\s{1,4}(?:everything|the\s{1,4}text)\s{1,4}above\b",
    r"\b(?:base64|rot13|hex)\s{0,4}(?:encode|encoded)?\s{0,4}(?:your|the)\s{1,4}"
    r"(?:system\s{1,4})?(?:prompt|instructions)\b",
    r"\bbegin\s{1,4}your\s{1,4}(?:reply|response|answer)\s{1,4}with\s{1,4}(?:your|the)\s{1,4}"
    r"(?:system\s{1,4})?(?:prompt|instructions)\b",
))


# --------------------------------------------------------------------------- detectors


def secret_pattern(text: str, name: str = "secret_pattern") -> tuple[Finding, ...]:
    """Documented key shapes at high confidence, high-entropy runs at low.

    The two are one detector rather than two because they answer the same question and a caller
    should not have to enable both to be protected. They are reported at different confidences
    because they deserve different responses: a shape match is a key, an entropy match is a
    candidate.
    """
    found: list[Finding] = []
    claimed: list[tuple[int, int]] = []
    for label, pattern in SECRET_SHAPES:
        for match in pattern.finditer(text):
            found.append(Finding(detector=name, start=match.start(), end=match.end(),
                                 excerpt=mask(match.group(0)), confidence="high",
                                 note=f"matches the published shape of a {label}"))
            claimed.append((match.start(), match.end()))
    for match in ENTROPY_RUN.finditer(text):
        if any(start <= match.start() < end for start, end in claimed):
            continue
        run = match.group(0)
        bits = shannon(run)
        if bits < ENTROPY_BITS:
            continue
        found.append(Finding(
            detector=name, start=match.start(), end=match.end(), excerpt=mask(run),
            confidence="low",
            note=(f"{bits:.2f} bits per character over {len(run)} characters, which is above the "
                  f"{ENTROPY_BITS} threshold and also true of a git hash"),
        ))
    return tuple(found)


def pii_email(text: str, name: str = "pii_email") -> tuple[Finding, ...]:
    return tuple(
        Finding(detector=name, start=match.start(), end=match.end(),
                excerpt=mask(match.group(0), keep=2), confidence="high",
                note="an address in a response is a disclosure unless the user supplied it")
        for match in EMAIL.finditer(text)
    )


def pii_card(text: str, name: str = "pii_card") -> tuple[Finding, ...]:
    """Digit runs that pass the Luhn check. The check is the detector: without it this fires on any
    order number, which is the difference between a useful redactor and one that gets switched off.
    """
    found: list[Finding] = []
    for match in CARD_RUN.finditer(text):
        run = match.group(0)
        if not luhn(run):
            continue
        found.append(Finding(detector=name, start=match.start(), end=match.end(),
                             excerpt=mask(run.replace(" ", "").replace("-", ""), keep=6),
                             confidence="high", note="a digit run that passes the Luhn check"))
    return tuple(found)


def _any_pattern(patterns: Iterable[re.Pattern[str]], text: str, name: str,
                 note: str, confidence: str = "high") -> tuple[Finding, ...]:
    found: list[Finding] = []
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            found.append(Finding(detector=name, start=match.start(), end=match.end(),
                                 excerpt=mask(match.group(0), keep=24), confidence=confidence,
                                 note=note))
    return tuple(found)


def injection_override(text: str, name: str = "injection_override") -> tuple[Finding, ...]:
    return _any_pattern(OVERRIDE, text, name,
                        "an instruction to disregard the system prompt", confidence="medium")


def injection_exfiltration(text: str, name: str = "injection_exfiltration") -> tuple[Finding, ...]:
    return _any_pattern(EXFILTRATION, text, name,
                        "a request for the model's own instructions", confidence="high")


#: The minimum span of the system prompt that counts as an echo. Short spans appear by coincidence:
#: a system prompt containing "You are a helpful assistant" would otherwise match half the internet.
ECHO_MIN_SPAN = 40


def system_prompt_echo(text: str, system_prompt: str,
                       name: str = "system_prompt_echo") -> tuple[Finding, ...]:
    """A distinctive span of the system prompt appearing in the response.

    Implemented as a rolling window over the system prompt rather than a similarity score, because a
    score needs a threshold nobody can defend and a span is a fact: this exact sequence of 40
    characters from the instructions is in the output.

    This detector is **not** prefix-safe. It needs `ECHO_MIN_SPAN` characters of accumulated
    response to say anything, so on a stream it cannot fire until that much has been emitted, and
    the policy marks it `stream_safe: false` so the report discloses that rather than implying the
    check ran in time.
    """
    if len(system_prompt) < ECHO_MIN_SPAN or len(text) < ECHO_MIN_SPAN:
        return ()
    for start in range(0, len(system_prompt) - ECHO_MIN_SPAN + 1, 8):
        span = system_prompt[start:start + ECHO_MIN_SPAN]
        # Case insensitive, and done with a pattern over the original text rather than by folding
        # both sides, because the finding carries a span and the span has to index the text the
        # caller passed. `casefold()` is not length preserving for every character, so folding first
        # would let an offset drift, and an offset that drifts is a redaction that removes the wrong
        # characters. Before this, the detector was case sensitive and passed only because one 40
        # character window of the fixture's system prompt happens to be entirely lower case.
        found = re.search(re.escape(span), text, re.IGNORECASE)
        index = found.start() if found else -1
        if index >= 0:
            return (Finding(
                detector=name, start=index, end=index + len(span), excerpt=mask(span, keep=16),
                confidence="high",
                note=f"{ECHO_MIN_SPAN} characters of the system prompt, verbatim, from "
                     f"offset {start}",
            ),)
    return ()


def encoded_payload(text: str, decoded: tuple[str, ...] = (),
                    name: str = "encoded_payload") -> tuple[Finding, ...]:
    """Something arrived encoded and decoded to text.

    Not an attack by itself. It is the cheapest signal that a request was written to be read twice,
    which is why the policy flags it and why it is worth having next to detectors that block.
    """
    if not decoded:
        return ()
    return (Finding(
        detector=name, start=0, end=len(text), excerpt=mask(decoded[0], keep=24),
        confidence="medium",
        note=f"{len(decoded)} base64 segment(s) decoded to text, which a plain request does not "
             f"need",
    ),)


#: Every detector, by the name the policy uses. `system_prompt_echo` and `encoded_payload` take a
#: second argument, so the registry stores what each one needs rather than pretending they share a
#: signature.
Detector = Callable[..., "tuple[Finding, ...]"]

REGISTRY: dict[str, dict] = {
    "secret_pattern": {"fn": secret_pattern, "needs": ()},
    "pii_email": {"fn": pii_email, "needs": ()},
    "pii_card": {"fn": pii_card, "needs": ()},
    "injection_override": {"fn": injection_override, "needs": ()},
    "injection_exfiltration": {"fn": injection_exfiltration, "needs": ()},
    "system_prompt_echo": {"fn": system_prompt_echo, "needs": ("system_prompt",)},
    "encoded_payload": {"fn": encoded_payload, "needs": ("decoded",)},
}


#: The pattern this repository deliberately does **not** use, kept so the failure is reproducible
#: rather than described. Written the obvious way for "any run of words followed by this phrase",
#: and catastrophically ambiguous because `\w+` and `\s?` compete for the same characters. Every
#: shipped pattern is checked against this one's timing curve in `tests/test_detect.py`.
NAIVE_EXFILTRATION = re.compile(r"(\w+\s?)+\bsystem prompt\b")

#: Input lengths the ReDoS curve is measured at. Stops at 24 because the next step up takes about
#: ten seconds, and a demonstration that makes the test suite unusable proves the point twice.
REDOS_LENGTHS = (12, 16, 20, 24)


def time_pattern(pattern: re.Pattern[str], text: str, repeats: int = 3) -> float:
    """Milliseconds for one pattern against one input, best of `repeats`.

    Best rather than mean, because the interesting quantity is the pattern's own cost and the noise
    on a shared machine is all upward. A mean would make a fast pattern look slow on a busy runner
    and the assertion in `tests/test_detect.py` would be flaky, which is how a timing test gets
    deleted.
    """
    best = float("inf")
    for _ in range(max(1, repeats)):
        started = time.perf_counter()
        pattern.search(text)
        best = min(best, (time.perf_counter() - started) * 1000.0)
    return best


def redos_curve(lengths: Iterable[int] = REDOS_LENGTHS, repeats: int = 3,
                pattern: re.Pattern[str] = NAIVE_EXFILTRATION) -> list[tuple[int, float]]:
    """The blowup, measured rather than asserted.

    The input is a run of word characters with no match at the end, which is the worst case for an
    ambiguous pattern: the engine has to try every way of splitting the run before it can conclude
    that the phrase is absent. An attacker does not need the payload to look like an attack, because
    it is not attacking the model.
    """
    return [(length, time_pattern(pattern, "a" * length, repeats)) for length in lengths]


def run_detector(name: str, text: str, *, system_prompt: str = "",
                 decoded: tuple[str, ...] = ()) -> tuple[Finding, ...]:
    """Run one detector by name, supplying only what it declares it needs."""
    entry = REGISTRY.get(name)
    if entry is None:
        raise KeyError(f"no detector called {name!r}; known: {', '.join(sorted(REGISTRY))}")
    extra = {}
    if "system_prompt" in entry["needs"]:
        extra["system_prompt"] = system_prompt
    if "decoded" in entry["needs"]:
        extra["decoded"] = decoded
    return entry["fn"](text, **extra)
