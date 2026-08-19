# ADR-001: you cannot un-send a byte

**Status:** accepted
**Date:** 2026-08-19
**Decision owner:** whoever owns the route's policy file

## Context

A guardrail on a streaming response has to decide something a guardrail on a batch response does not:
what to do about the text that has already left. Once a chunk has been written to the client's socket
it is on their screen. No verdict reached afterwards retrieves it.

That leaves exactly two options, and the third one people assume exists does not:

1. **Buffer.** Consume the whole response, check it, then send. Enforcement is complete. Time to first
   token becomes time to last token, which is the reason streaming exists in the first place.
2. **Stream with a bounded lookback.** Hold back the last `L` characters so a pattern can match across
   a chunk boundary, and emit everything before that. Streaming works, and when a secret is found,
   whatever was already emitted is gone.

"Stream and retract" is not an option over HTTP. There is no unsend.

Most guardrail documentation describes option 2 and reports it as though it were option 1: the
response says "blocked" and never says how much went out before the block landed.

## Decision

Stream with a lookback that the policy declares, and publish the leak as a first-class number in every
renderer.

`stream.lookback_chars` is one value with three meanings, and the policy comment says all three:

* the longest cross-boundary match the enforcer can make;
* the maximum number of characters of a detected secret that reach the client first;
* the number of characters of latency before the client sees anything.

`Enforcement.leaked_chars` is capped at the length of the match, `emitted_after_match` is reported
separately, and `first_emit_at_char` is `None` rather than zero when the client never saw anything.
`Transaction.verdict` tests the leak **before** the refusal, so a cut stream that leaked reads as
`leaked` and exits non-zero rather than reading as a successful refusal.

## Consequences

The trade is visible and has no setting where both columns are zero. Measured on the fixture's twenty
character key, at a chunk size of six:

| lookback | leaked | first emit |
| --- | --- | --- |
| 0 | 16 | 9 |
| 8 | 8 | 9 |
| 16 | 0 | 19 |
| 96 | 0 | never |
| buffered | 0 | 274 |

The leak reaches zero at 16 characters of lookback. The shipped policy holds back 96, which buys
margin against a longer secret rather than against this one, and costs about 1.69 characters of
latency per character withheld. Buffering costs 274 characters before the first byte, which is the
entire response.

Two bugs found while measuring this, both of which had made the numbers look better than the behaviour:

**The detection window is not the lookback.** The enforcer scanned twice the lookback, which sounds
sufficient. It is not: with an 8 character lookback the window was 22 characters, and a 20 character
key straddling a chunk boundary had its first characters slide out of the window before its last
arrived. The key was then found only by the end-of-stream check, after the whole response had gone,
and the measured leak was 20 of 20 characters at every lookback below 12. That is the shape of a
detector that is not running, not one that is running late. The window is now never narrower than
`LONGEST_MATCH_CHARS`, which is declared next to the patterns it is derived from.

**A redaction needs alignment, not just a lookback.** The release step emitted one chunk's worth of
text at a time, so a span longer than a chunk was never entirely inside a single release and the
redaction condition never held. A card number was emitted in the clear at *every* lookback including
96, with the report saying `redactions: 0`, which reads as "there was nothing to redact". The release
is now held back to the start of any redactable span that is not yet complete, and a redaction that
genuinely arrives too late is counted in `missed_redactions` and priced as a leak.

## Alternatives considered

**Buffer everything and be done with it.** Correct, and it deletes the product requirement. Available
as `--buffer` on every command and as the last row of every curve, so the cost of choosing it is
measured rather than argued about.

**Retract with a client-side protocol.** Only helps a client you control, and the guardrail's job
includes the case where the client is a browser rendering tokens as they arrive.

**A lookback expressed in tokens.** Tokens are the model's unit and the enforcer never sees them.
Characters are what a proxy actually holds.

## What would change our mind

A transport where an emitted chunk can be reliably revoked before display, or a deployment where time
to first token does not matter. In the second case the answer is to buffer, and this ADR becomes a note
explaining why the option exists.
