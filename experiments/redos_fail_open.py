"""Switching the guardrail off with twenty-four characters, end to end.

This is the attack that is specific to guardrails, and it does not touch the model.

1. A detector's pattern is written the obvious way and is catastrophically ambiguous. Not the
pattern this repository ships: `NAIVE_EXFILTRATION`, kept precisely so this can be reproduced.
2. An attacker sends a short run of letters. Not an injection, not encoded, nothing a reviewer would
look at twice.
3. The pattern backtracks. Twenty-four characters take about two and a half seconds against a budget
of eight milliseconds.
4. The detector exceeds its budget, so it never produces a verdict.
5. The route fails open, and the request the detector existed to stop goes through unchecked.

Step five is the one worth arguing about, because it is the only step that is a decision. Failing
closed instead turns the same input into a denial of service: the attacker cannot get their
injection through, and nobody else can get a support answer either. There is no third option, which
is why `on_unavailable` is in the policy file rather than in an exception handler.

The defence is not a longer timeout. It is that a detector must be linear time by construction,
which `tests/test_detect.py` asserts against adversarial input with a wall clock bound. The timeout
is the backstop, not the plan, and this experiment exists to show what the backstop costs when it is
the only thing standing there.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

import _bootstrap  # noqa: F401 - puts the repository root on the path

from guardrail import detect
from guardrail.detect import EXFILTRATION, NAIVE_EXFILTRATION, REDOS_LENGTHS, redos_curve
from guardrail.policy import PROMPT, RESPONSE, load
from guardrail.proxy import handle
from guardrail.upstream import Upstream, completion

#: The payload. A run of word characters with no match at the end, which is the worst case for an
#: ambiguous pattern: every way of splitting the run has to be tried before the engine can conclude
#: that the phrase is absent.
PAYLOAD_LENGTH = 24


def naive_detector(text: str, name: str = "injection_exfiltration"):
    """The detector this repository does not ship, wired into the registry for one experiment."""
    match = NAIVE_EXFILTRATION.search(text)
    if not match:
        return ()
    return (detect.Finding(detector=name, start=match.start(), end=match.end(),
                           excerpt="masked", confidence="high",
                           note="matched by the naive pattern"),)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="policies/support-assistant.yaml")
    parser.add_argument("--out", default="docs/experiments/redos_fail_open.json")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args(argv)

    policy = load(args.policy)
    budget_ms = policy.detectors["injection_exfiltration"].budget_ms

    print(f"the pattern this repository does not use, against a {budget_ms:g} ms budget")
    print(f"{'chars':>6} {'naive ms':>12} {'shipped ms':>12}  over budget")
    curve = redos_curve(lengths=REDOS_LENGTHS, repeats=args.repeats)
    shipped = []
    for length, elapsed in curve:
        payload = "a" * length
        worst = max(detect.time_pattern(pattern, payload, args.repeats)
                    for pattern in EXFILTRATION)
        shipped.append(worst)
        print(f"{length:6d} {elapsed:12.4f} {worst:12.4f}  "
              f"{'yes' if elapsed > budget_ms else 'no':>11}")

    ratio = curve[-1][1] / max(shipped[-1], 1e-9)
    first_over = next((length for length, elapsed in curve if elapsed > budget_ms), None)
    print(f"\nthe naive pattern is {ratio:,.0f}x the shipped one at {curve[-1][0]} characters")
    print(f"it exceeds the budget from {first_over} characters of input")

    # Now the consequence, through the real proxy: the same request, with the naive detector in
    # place, on a route that fails open and one that fails closed.
    payload = "a" * PAYLOAD_LENGTH
    original = detect.REGISTRY["injection_exfiltration"]
    detect.REGISTRY["injection_exfiltration"] = {"fn": naive_detector, "needs": ()}
    try:
        outcomes = {}
        for label, mode in (("fails open", "open"), ("fails closed", "closed")):
            variant = replace(policy, budget=replace(
                policy.budget, on_unavailable={PROMPT: mode, RESPONSE: mode}))
            transaction = handle(payload, completion("clean_answer"), variant,
                                 upstream=Upstream())
            spend = transaction.prompt_spend
            outcomes[label] = {
                "mode": mode,
                "verdict": transaction.verdict,
                "allowed": transaction.allowed,
                "exit_code": transaction.exit_code,
                "unavailable": list(spend.unavailable) if spend else [],
                "looks_adversarial": list(spend.adversarial) if spend else [],
                "unchecked_sides": list(transaction.unchecked_sides),
            }
            print(f"\n{label}: verdict {transaction.verdict}, exit {transaction.exit_code}, "
                  f"unavailable {', '.join(outcomes[label]['unavailable']) or 'none'}")
            for note in transaction.caveats():
                print(f"  - {note}")

        # And the same payload with the shipped detector, which answers inside its budget.
        detect.REGISTRY["injection_exfiltration"] = original
        clean = handle(payload, completion("clean_answer"), policy, upstream=Upstream())
        print(f"\nwith the shipped pattern: verdict {clean.verdict}, "
              f"unavailable {', '.join(clean.prompt_spend.unavailable) or 'none'}")
    finally:
        detect.REGISTRY["injection_exfiltration"] = original

    payload_json = {
        "budget_ms": budget_ms,
        "payload_length": PAYLOAD_LENGTH,
        "curve": [{"chars": length, "naive_ms": round(elapsed, 4),
                   "shipped_ms": round(worst, 4), "over_budget": elapsed > budget_ms}
                  for (length, elapsed), worst in zip(curve, shipped, strict=True)],
        "first_length_over_budget": first_over,
        "naive_over_shipped_at_worst": round(ratio, 1),
        "outcomes": outcomes,
        "shipped_verdict": clean.verdict,
        "note": ("timings are best-of-N on this machine and are only meaningful as ratios; the "
                 "defence is that detectors are linear time, verified by test, and the timeout is "
                 "the backstop"),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload_json, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
