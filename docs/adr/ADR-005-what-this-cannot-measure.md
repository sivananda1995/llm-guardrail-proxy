# ADR-005: what this cannot measure

**Status:** accepted
**Date:** 2026-08-19

## Context

This repository runs fully offline. There is no API key, no network call, and no model. The upstream is
`guardrail.upstream.Upstream`, a deterministic token stream generator that yields scripted completions
in jittered chunks.

That is a real limitation, and the temptation is to describe it as "a mock for testing" and move on.
This ADR states it plainly instead, because the difference between what this measures and what it does
not is the difference between a receipt and a claim.

## Decision

State the boundary, and keep every published claim on the right side of it.

**What is measured, and would be identical against a real model.** Every claim in this repository is a
claim about the *proxy*, and each is determined by the byte stream and the policy rather than by what
produced the bytes:

* how much of a detected secret escapes at a given lookback, and what that lookback costs in latency;
* what precision a detector's measured rates deliver at a declared prevalence, and how large a corpus
  would have to be to support a blocking action;
* what happens when a detector exceeds its budget, and what an attacker gains by causing that;
* which evasions survive canonicalisation, and which step of the pipeline each one depends on;
* that a refusal is byte-identical whatever fired, so a probe returns one bit rather than a label.

A real model produces a different stream. The enforcement arithmetic on any given stream is the same.

**What is not measured, at all.** Whether a prompt-injection detector catches the injections that
actually work on a particular model. That is a claim about models, it requires the model, and this
repository does not make it. Nothing here should be read as "this policy stops prompt injection". What
it says is "this policy, on this traffic, has these rates, and here is what those rates buy at your
prevalence".

Also not measured:

* **Prevalence.** `0.0004` is declared in the policy, not observed. Every precision figure moves with
  it, which is why the sweep prints five prevalences instead of one.
* **Availability.** The 99.9% figures for the model and the guardrail are assumptions, labelled as such
  everywhere they appear. This repository has no production telemetry.
* **Absolute latency.** Timings are best-of-N on one machine and are published only as ratios and
  counts. The character figures (lookback, leak, first emit) are exact and machine independent, which
  is why they are the headline.
* **Whether the corpus resembles real traffic.** It contains 10 benign cases chosen to be awkward
  rather than representative. A false positive rate on 10 samples is a false positive rate on 10
  samples.

## Consequences

Every renderer prints its caveats, and they are not a footer. A `check` that allowed a request while a
detector timed out prints that above the verdict, because "allowed" and "allowed without checking" are
different claims and only one of them is true. `Transaction.caveats()` is in the JSON payload, the
markdown and the HTML, and a test asserts the payload carries them.

The fixture is also the reason two numbers in this repository are trustworthy in a way a live
integration would not be: the corpus is deterministic, so the leak curve is reproducible to the
character, and a regression in the enforcer shows up as a changed integer rather than as noise.

## Alternatives considered

**Wire in a real model behind an API key.** Would let the repository make one additional claim, the one
about which injections work, at the cost of every other claim becoming unreproducible: a reader could no
longer re-run the numbers, and the corpus results would depend on a model version. The offline
constraint was a requirement here, and the honest response to it is a smaller set of stronger claims.

**Record real model responses as fixtures.** Better than live calls and still model-version specific.
The scripted completions are chosen to put specific shapes in front of the enforcer, which recordings
would do less precisely.

**Say nothing and let the reader assume.** This is the common choice and it is the reason guardrail
reporting is not trusted.

## What would change our mind

Access to a model and a labelled corpus of injections that work against it. Then this repository grows a
sixth experiment, and this ADR gains a section saying which of its claims stopped being caveats.
