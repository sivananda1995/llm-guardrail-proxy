# ADR-003: there is no third option

**Status:** accepted
**Date:** 2026-08-19

## Context

A detector can fail. It can raise, and it can exceed its budget. The proxy then does one of exactly two
things, and both are wrong:

* **fail closed**: the request fails. A guardrail outage is a product outage, so the guardrail's
  availability multiplies into the product's.
* **fail open**: the request proceeds unchecked. The guardrail is now absent in precisely the moments
  something is able to make it fail.

Most proxies have this behaviour by accident, which means it is whatever the nearest exception handler
happened to do, and it is usually fail-open because that is what a bare `try` around a detector call
produces.

## Decision

The failure mode is declared **per side** in the policy, the arithmetic for both is printed in the
report, and a request that went through unchecked says so in its own payload.

```yaml
budget:
  total_ms: 45
  on_unavailable:
    prompt: closed
    response: open
```

The loader refuses an unknown mode with a message that says there is no third option and that leaving
it unset is choosing one by accident. `Spend.unchecked` is true when a side both failed open and had a
detector that did not answer; `Transaction.verdict` becomes `allowed_unchecked`, which exits non-zero.

The split is asymmetric on purpose. Failing closed on the prompt costs a request that has not consumed
a model call yet. Failing closed on the response throws away an answer that has already been paid for,
and on this route the output side is checked for disclosure rather than for abuse.

## Consequences

The arithmetic, at a declared 99.9% for both the model and the guardrail:

| side | mode | combined availability | downtime per month | uncovered per month |
| --- | --- | --- | --- | --- |
| prompt | closed | 0.9980 | 86.36 minutes | 0 |
| response | open | 0.9990 | 43.2 minutes | 43.2 minutes |

Failing closed doubles the expected downtime. Failing open keeps the model's availability and spends
the guardrail's downtime as coverage instead: 43.2 minutes a month uncovered, which is the window an
attacker wants to cause.

And they can cause it, cheaply, without touching the model. `experiments/redos_fail_open.py`
demonstrates it end to end:

1. A pattern written the obvious way for "any run of words followed by a phrase",
   `(\w+\s?)+\bsystem prompt\b`, is catastrophically ambiguous.
2. A run of twenty-four letters takes seconds rather than milliseconds, against a 7 ms budget: about 6
   orders of magnitude more than any shipped pattern on the same input, and over budget from 16
   characters of input.
3. The detector never answers.
4. Failing open, the verdict is `allowed_unchecked`, exit code 1. Failing closed, the verdict is
   `refused`, and so is everybody else's request.

The payload does not have to look like an attack, because it is not attacking the model.

Worth noting what did *not* blow up: the first candidate written for this repository was
`(ignore\s+)+(previous|all)\s+instructions`, which has the shape everybody points at and is fine,
because `\s+` and `ignore` cannot both match the same character. A pattern is not dangerous because it
looks dangerous, which is why the check is a measurement rather than a review.

The real defence is therefore **not** the timeout. It is that detectors are linear time by
construction, asserted in `tests/test_detect.py` with a wall clock bound against adversarial inputs and
a ratio against the naive pattern. The timeout is the backstop.

The timeout itself has a stated limitation: it is checked after the call rather than interrupting it,
because Python cannot pre-empt a regex engine mid-match without a separate process. What the budget
buys is that the overrun is *visible*, the fail mode is exercised deliberately, and the response records
that a detector did not answer.

## Alternatives considered

**One global failure mode.** Simpler and wrong in one direction or the other for one of the two sides.

**Fail closed everywhere and accept the availability cost.** Defensible on a high-prevalence internal
route. The report prints the arithmetic for both columns so that choice can be made with the number in
front of it.

**Run detectors in a subprocess with a hard kill.** Buys a real interrupt and costs a process per
request. Worth it for a detector that cannot be made linear time; the shipped ones can.

**A longer timeout.** Moves the crossing point and does not remove it. Exponential beats any constant.

## What would change our mind

A detector that cannot be linear time and has to be deployed anyway, for example a model-based
classifier with a network call. Then the subprocess or a circuit breaker becomes necessary, and the
availability arithmetic in this ADR is the input to that design rather than an argument against it.
