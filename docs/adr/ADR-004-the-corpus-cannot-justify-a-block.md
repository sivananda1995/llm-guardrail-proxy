# ADR-004: the corpus cannot justify a block

**Status:** accepted
**Date:** 2026-08-19

## Context

Guardrail accuracy is quoted as a true positive rate, sometimes with a false positive rate beside it.
Neither answers the question an on-call engineer has, which is: **when this fires, how often is it
right?**

That is precision, and precision depends on prevalence far more than on the detector:

```
precision = TPR * p / (TPR * p + FPR * (1 - p))
```

At 50% prevalence a detector at 95% TPR and 2% FPR is 98% precise, which sounds like a working system.
At one attack in ten thousand requests the same detector is 0.47% precise: 211 false alarms for every
true one, with nothing about the detector changed.

This route declares `prevalence: 0.0004`. So every blocking action on it has to be defended at that
prevalence, not at the prevalence of a red-team corpus.

There is a second problem, and it is the one that decides the argument. Measured on this repository's
corpus, every detector has a false positive rate of **zero**. Precision computed from zero is 100% at
any prevalence, and a check written against that number approves every blocking action in the
repository. But a rate of zero over 34 samples is not zero. It is "below one in 34".

## Decision

Three decisions, and the third is the uncomfortable one.

**Measure every detector twice.** Once as a **gate**, counting only findings confident enough for the
declared action to apply, and once as a **signal**, counting any finding at all. Both are published.
`min_confidence` is what separates them, and the gap is large: `secret_pattern` has a false positive
rate of 14.7% as a signal, because 5 benign samples contain a high-entropy run that is not a secret (a
git hash, a tracking reference, base64 payloads), and 0.000 as a gate, because those all report at low
confidence and the policy degrades them to `flag`.

**Defend an action against the rate the corpus can support, not the rate it measured.**
`Rates.resolved_fpr` is `max(measured, 1 / benign)`. At 34 benign samples that is 0.029, and the
resolved precision of `secret_pattern` at this route's prevalence is **1.34%**, not 100%.

**Report unsupported actions rather than passing them.** `justify()` compares resolved precision
against a 50% floor, which is the honest place to draw it: at 50% a block is a coin flip on whether the
user did anything wrong. On this corpus, at this prevalence, **3 of 3 blocking actions are
unsupported**, and each verdict says what it would take to support one: about 2,499 clean samples with
no false positive among them. The corpus has 34.

## Consequences

`guard posture` prints three red rows, and `guard posture --strict` exits 1. That is the honest state of
a guardrail measured on 38 labelled samples.

`--strict` is deliberately **not** wired into CI. Wiring it in would mean either deleting the check or
weakening the floor within a week, and both are worse than a red number in a report that somebody reads.
What CI does run is `guard corpus`, which fails when behaviour stops matching what the corpus declares:
a claim the evidence actually supports.

The arithmetic also settles a policy question that would otherwise be a matter of taste.
`injection_override` (the "ignore all previous instructions" family) is set to `flag`, not `block`, and
the reason is not generosity: it is a broad family, its findings are medium confidence, and at 0.0004
prevalence a block there refuses far more legitimate requests than attacks. `injection_exfiltration` is
narrower and blocks. Same file, same author, different actions, because the numbers differ.

And it explains a real bug this framework caught. Before `min_confidence` existed, one action covered a
detector's confident and speculative halves, and a 32 character git hash in a support answer blocked
the response. The fix was not a better entropy threshold. It was that a detector reporting at two
confidences needs the policy to say what each one does.

## Alternatives considered

**Quote the measured zero.** Every action passes, the report is green, and the first false positive in
production is a surprise. This is what a guardrail vendor's datasheet looks like.

**Lower the floor until the actions pass.** Rewriting the question until the answer is yes.

**Raise the prevalence until precision improves.** Same move, one layer down: prevalence is a property
of the traffic, and inflating it to justify a block is how a policy becomes fiction. The sweep prints
precision at five prevalences so a reader can substitute their own and see what it costs.

**Collect 2,500 clean samples.** The correct answer, and out of scope for a repository that has to run
offline. Naming the number is what makes it actionable instead of discouraging.

## What would change our mind

Production traffic. A measured prevalence and 2,500 labelled benign requests would move every number in
this ADR, and the framework is built so that swapping the corpus is the only change needed: nothing here
takes a rate as a parameter.
