"""What the guardrail costs, in the two currencies it spends: milliseconds and characters.

Two measurements, and the second is the one nobody bills for.

## Milliseconds

Every detector runs under a budget and the budgets sum to a declared total. This measures the real
cost of a scan across the whole corpus, best of several repeats with the spread reported, and
compares it against what the policy reserved. Absolute figures move between machines, so the numbers
to read are the ratios: how much of the reserved budget is actually used, and how far the worst case
sits from the total.

Only ratios and counts are published as headline figures anywhere in this repository, for the same
reason: a receipt that cannot be reproduced on another machine is not a receipt.

## Characters

The lookback is a latency cost measured in characters of the response, not milliseconds, and that is
the honest unit: it is how much text the model has generated before the client sees anything. At a
lookback of 96 the client waits for 96 characters. Buffered, it waits for all of them. Converting
that to milliseconds needs a tokens-per-second figure this repository does not have and would be
inventing, so it is reported in the unit it was measured in.

The comparison to make is the last two columns: the characters of latency the lookback costs against
the characters of secret it prevents leaking. On this corpus the exchange rate is 1.19 characters of
latency per character withheld at the lookback where the leak first reaches zero, and 6.19 at the
lookback the policy actually ships, which buys margin against a longer secret rather than against
this one.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

import _bootstrap  # noqa: F401 - puts the repository root on the path

import attacks
from guardrail.policy import load
from guardrail.proxy import leak_curve
from guardrail.upstream import completion

LOOKBACKS = (0, 8, 16, 24, 48, 96)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="policies/support-assistant.yaml")
    parser.add_argument("--out", default="docs/experiments/latency_budget.json")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args(argv)

    policy = load(args.policy)
    reserved = sum(detector.budget_ms for detector in policy.detectors.values())

    # Best of N per case, because the interesting quantity is the work the guardrail does and every
    # source of noise on a shared machine adds to it.
    runs = []
    for _ in range(args.repeats):
        total = 0.0
        for _, transaction in attacks.run_all(policy):
            total += transaction.prompt_spend.total_ms if transaction.prompt_spend else 0.0
        runs.append(total)
    best, worst = min(runs), max(runs)
    per_request = best / len(attacks.CASES)

    print(f"prompt-side detector work across {len(attacks.CASES)} cases, best of {args.repeats}")
    print(f"  best      {best:8.3f} ms")
    print(f"  worst     {worst:8.3f} ms   spread {100 * (worst - best) / max(best, 1e-9):5.1f}%")
    print(f"  per case  {per_request:8.3f} ms")
    print(f"  reserved  {reserved:8.3f} ms per request by the policy")
    print(f"  used      {100 * per_request / reserved:8.1f}% of what the policy reserved")
    print(f"  total     {policy.budget.total_ms:8.3f} ms declared for the whole guardrail")

    print("\nthe other currency: characters of latency against characters of leak")
    print(f"{'lookback':>9} {'first emit':>11} {'leaked':>7} {'characters per character':>25}")
    rows = []
    for row in leak_curve(policy, completion("leaks_aws_key"), lookbacks=LOOKBACKS):
        first = row["first_emit_at_char"]
        label = "buffer" if row["lookback"] is None else str(row["lookback"])
        saved = None
        if row["lookback"] is not None and row["lookback"] > 0 and first is not None:
            baseline = rows[0]["leaked_chars"] if rows else row["leaked_chars"]
            prevented = baseline - row["leaked_chars"]
            saved = round(first / prevented, 2) if prevented else None
        rows.append({"lookback": row["lookback"], "first_emit_at_char": first,
                     "leaked_chars": row["leaked_chars"], "chars_of_latency_per_char_saved": saved})
        print(f"{label:>9} {('never' if first is None else first)!s:>11} "
              f"{row['leaked_chars']:7d} {saved!s:>25}")

    exchange = [row["chars_of_latency_per_char_saved"] for row in rows
                if row["chars_of_latency_per_char_saved"] is not None]
    payload = {
        "cases": len(attacks.CASES),
        "repeats": args.repeats,
        "best_total_ms": round(best, 3),
        "worst_total_ms": round(worst, 3),
        "spread_percent": round(100 * (worst - best) / max(best, 1e-9), 1),
        "per_request_ms": round(per_request, 3),
        "reserved_ms_per_request": reserved,
        "share_of_reserved_used": round(per_request / reserved, 4),
        "declared_total_ms": policy.budget.total_ms,
        "lookback_rows": rows,
        "median_chars_of_latency_per_char_saved": (round(statistics.median(exchange), 2)
                                                  if exchange else None),
        "note": ("milliseconds are best-of-N on one machine and are published only as ratios; the "
                 "character figures are exact and machine independent"),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nthe guardrail uses {100 * payload['share_of_reserved_used']:.1f}% of the budget it "
          f"reserves")
    rate = payload["median_chars_of_latency_per_char_saved"]
    print(f"median exchange rate: {rate} characters of latency per character withheld")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
