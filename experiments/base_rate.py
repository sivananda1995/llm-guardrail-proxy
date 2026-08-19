"""The number a guardrail is sold on, and the number that decides whether it can be used.

A detector is quoted as "catches 95% of injections, 2% false positives". At 50% prevalence that is
98% precise and sounds like a working product. At one attack in ten thousand requests it is 0.5%
precise: two hundred false alarms for every real one, from the same detector, with nothing about it
changed.

This measures both, on this repository's corpus, and adds the part that is normally missing.

## Two rates for the same detector

Every detector here is measured twice. Once **as a gate**, counting only findings confident enough
for its declared action to apply, and once **as a signal**, counting any finding at all. The gap is
what `min_confidence` buys: the secret detector's false positive rate is zero as a gate and 14.7% as
a signal, because five benign samples contain a high-entropy run that is not a secret.

## The resolution floor, which is where the argument actually ends

A false positive rate of zero measured over 34 samples is not zero: it is "below one in 34".
Precision computed from the measured zero is 100% at any prevalence, which would approve every
blocking action in this repository. Computed from the rate the corpus can actually support, the same
detector is 1.3% precise at the route's declared prevalence.

So the last column is the one to read: how many clean samples, with no false positive among them, it
would take to support a blocking action here. It is about 2,500 and the corpus has 34. That is not a
criticism of the corpus, it is the size of the evidence a blocking guardrail needs, and almost
nobody who ships one has it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import _bootstrap  # noqa: F401 - puts the repository root on the path

import attacks
from guardrail.evaluate import BLOCK_PRECISION_FLOOR, PREVALENCES, ci_hint
from guardrail.policy import load


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="policies/support-assistant.yaml")
    parser.add_argument("--out", default="docs/experiments/base_rate.json")
    args = parser.parse_args(argv)

    policy = load(args.policy)
    gate = attacks.measure(policy)
    signal = attacks.measure(policy, at_action_confidence=False)

    print(f"{'detector':24} {'action':7} {'gate fpr':>9} {'signal fpr':>11} {'benign':>7} "
          f"{'resolved fpr':>13}")
    rows = []
    for name in sorted(gate):
        gated, raw = gate[name], signal[name]
        detector = policy.detectors[name]
        low, high = ci_hint(gated.false_positives, gated.benign)
        rows.append({
            "detector": name,
            "action": detector.action,
            "min_confidence": detector.min_confidence,
            "gate": gated.to_json(),
            "signal": raw.to_json(),
            "fpr_interval": [round(low, 4), round(high, 4)],
            "benign_needed_for_block": gated.benign_needed_for(policy.prevalence),
        })
        print(f"{name:24} {detector.action:7} {gated.fpr:9.3f} {raw.fpr:11.3f} "
              f"{gated.benign:7d} {gated.resolved_fpr:13.3f}")

    print(f"\nprecision at prevalence, computed at the resolved rate (floor "
          f"{BLOCK_PRECISION_FLOOR:.0%} for a block)")
    header = "".join(f"{p:>11g}" for p in PREVALENCES)
    print(f"{'detector':24}{header}   needed")
    for row in rows:
        gated = gate[row["detector"]]
        cells = "".join(f"{gated.precision_at(p, resolved=True):>10.2%} " for p in PREVALENCES)
        print(f"{row['detector']:24}{cells}{row['benign_needed_for_block']:>8}")

    blocking = [row for row in rows if row["action"] == "block"]
    payload = {
        "route": policy.route,
        "prevalence": policy.prevalence,
        "prevalences": list(PREVALENCES),
        "block_precision_floor": BLOCK_PRECISION_FLOOR,
        "detectors": rows,
        "blocking_detectors": [row["detector"] for row in blocking],
        "unsupported_blocks": [row["detector"] for row in blocking
                               if gate[row["detector"]].precision_at(
                                   policy.prevalence, resolved=True) < BLOCK_PRECISION_FLOOR],
        "benign_needed": max((row["benign_needed_for_block"] for row in blocking), default=0),
        "benign_measured": min((row["gate"]["benign"] for row in rows), default=0),
        "signal_false_positives": {row["detector"]: row["signal"]["false_positives"]
                                   for row in rows},
        "note": ("precision is computed at each detector's resolved false positive rate, which is "
                 "the larger of what was measured and one over the number of benign samples"),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))

    print(f"\n{len(payload['unsupported_blocks'])} of {len(blocking)} blocking actions are "
          f"unsupported at prevalence {policy.prevalence:g}")
    widest = max(row["gate"]["benign"] for row in rows)
    print(f"supporting one needs about {payload['benign_needed']} clean samples; the corpus has "
          f"between {payload['benign_measured']} and {widest}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
