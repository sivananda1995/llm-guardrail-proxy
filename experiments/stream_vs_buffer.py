"""What streaming enforcement costs, measured on both sides of the trade.

You cannot un-send a byte. That leaves exactly two options and one number to choose between them:

* **buffer**: nothing leaks, and the client waits for the entire response before seeing a character;
* **stream with a lookback of L**: the client sees text after L characters, and up to
`len(match) - L` characters of a detected secret have already gone when the block fires.

This measures both columns for every leaking completion in the fixture, at every lookback, plus the
buffered case. The two numbers move in opposite directions and there is no setting where both are
zero, which is the point: a guardrail on a stream is a dial, not a guarantee, and a report that
quotes "blocked" without the leak is quoting half of it.

The figure to read is `zero_leak_at`: the smallest lookback at which nothing escapes, which for the
fixture's twenty character key is twenty. A policy whose lookback is below the longest secret it
claims to stop is a policy that leaks by construction.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap  # noqa: F401 - puts the repository root on the path

from guardrail.policy import load
from guardrail.proxy import leak_curve
from guardrail.upstream import COMPLETIONS, completion

LOOKBACKS = (0, 4, 8, 12, 16, 20, 24, 48, 96)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="policies/support-assistant.yaml")
    parser.add_argument("--out", default="docs/experiments/stream_vs_buffer.json")
    args = parser.parse_args(argv)

    policy = load(args.policy)
    leaking = [name for name, entry in COMPLETIONS.items() if entry.expect_detectors]

    results = {}
    for name in leaking:
        rows = leak_curve(policy, completion(name), lookbacks=LOOKBACKS)
        streamed = [row for row in rows if row["lookback"] is not None]
        held = rows[-1]
        zero_at = next((row["lookback"] for row in streamed if row["leaked_chars"] == 0), None)
        results[name] = {
            "rows": rows,
            "zero_leak_at": zero_at,
            "worst_leak": max(row["leaked_chars"] for row in streamed),
            "first_emit_at_zero_leak": next(
                (row["first_emit_at_char"] for row in streamed if row["leaked_chars"] == 0), None),
            "buffered_first_emit": held["first_emit_at_char"],
        }

        print(f"\n{name}  ({len(completion(name))} characters)")
        print(f"{'lookback':>9} {'leaked':>7} {'after match':>12} {'first emit':>11} {'cut':>5}")
        for row in rows:
            label = "buffer" if row["lookback"] is None else str(row["lookback"])
            first = "never" if row["first_emit_at_char"] is None else row["first_emit_at_char"]
            print(f"{label:>9} {row['leaked_chars']:7d} {row['emitted_after_match']:12d} "
                  f"{first!s:>11} {row['cut']!s:>5}")

    print("\nsummary")
    print(f"{'completion':22} {'worst leak':>10} {'zero leak at':>13} {'first byte':>11} "
          f"{'buffered':>9}")
    for name, entry in results.items():
        print(f"{name:22} {entry['worst_leak']:10d} {entry['zero_leak_at']!s:>13} "
              f"{entry['first_emit_at_zero_leak']!s:>11} {entry['buffered_first_emit']:9d}")

    zero_points = [entry["zero_leak_at"] for entry in results.values()
                   if entry["zero_leak_at"] is not None]
    payload = {
        "lookbacks": list(LOOKBACKS),
        "policy_lookback": policy.stream.lookback_chars,
        "completions": results,
        "smallest_safe_lookback": max(zero_points) if zero_points else None,
        "note": ("every character held back is a character that cannot leak and a character of "
                 "latency before the first byte; there is no setting where both columns are zero"),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nsmallest lookback that leaks nothing anywhere in the fixture: "
          f"{payload['smallest_safe_lookback']}")
    print(f"the shipped policy holds back {policy.stream.lookback_chars}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
