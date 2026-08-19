"""Re-measure every number this repository publishes, and write them to one file.

Nothing in the README is typed by hand. This script runs the test suite, runs all five experiments,
reads their JSON output, and writes `docs/metrics.json`; `tools/check_numbers.py` then verifies that
every document quoting a number quotes the one in that file.

The two-step split exists because of a bug inherited from an earlier project in this series. A
checker that only looks for the *digits* passes happily when the sentence around them has gone
stale: "10 requests" is found in a document that now says "10 rows", and the claim it was supposed
to guard is false. So a metric can carry **anchor phrases**, the exact wording a document must use
with the number substituted in. Anchors are alternatives: any one of them matching is enough,
because the same figure reads differently in a table and in a paragraph.

    python tools/collect_metrics.py                 # everything
    python tools/collect_metrics.py --skip-tests    # for a CI job that already ran them
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
EXPERIMENTS = DOCS / "experiments"

# Documents checked against the metrics. A number quoted in a file that is not on this list is not
# guarded, so adding a document here is how a claim becomes a receipt.
CHECKED_DOCUMENTS = [
    "README.md",
    "docs/defense-guide.md",
    "docs/adr/ADR-001-you-cannot-unsend-a-byte.md",
    "docs/adr/ADR-002-one-canonical-form-is-not-enough.md",
    "docs/adr/ADR-003-there-is-no-third-option.md",
    "docs/adr/ADR-004-the-corpus-cannot-justify-a-block.md",
    "docs/adr/ADR-005-what-this-cannot-measure.md",
]

# The wording a document must use around each number, with {} where the number goes.
ANCHORS: dict[str, list[str]] = {
    "tests_total": ["{} tests"],
    "coverage_line_pct": ["{}% line"],
    "coverage_branch_pct": ["{}% branch"],
    "corpus_cases": ["{} cases", "{} labelled cases", "all {} cases"],
    "corpus_as_declared": ["{}/28", "{} of 28"],
    "corpus_benign": ["{} benign"],
    "corpus_attacks": ["{} attacks"],
    "corpus_evasions": ["{} evasions"],
    "surviving_evasions": ["{} evasions still work", "{} surviving evasions"],
    "detectors": ["{} detectors"],
    "worst_leak_chars": ["leaks {} characters", "{} characters of the key"],
    "zero_leak_lookback": ["zero at {}", "{} characters of lookback"],
    "shipped_lookback": ["holds back {}", "lookback of {}"],
    "buffered_first_emit_chars": ["{} characters before", "waits for {}"],
    "smallest_safe_lookback": ["{} characters is enough", "safe at {}"],
    "signal_false_positives": ["{} benign samples", "{} of the benign"],
    "signal_fpr_pct": ["{}% as a signal", "{}% false positive"],
    "resolved_precision_pct": ["{}% precise", "precision of {}%"],
    "benign_needed_for_block": ["{} clean samples", "{} labelled samples"],
    "benign_measured_widest": ["corpus has {}", "{} benign samples resolve"],
    "unsupported_blocks": ["{} of 3 blocking", "{} blocking actions"],
    # Deliberately unanchored: an absolute duration and a ratio derived from it move between
    # machines, so the prose says "seconds rather than milliseconds" and quotes no digits. The order
    # of magnitude is stable and is the figure worth citing.
    "redos_ratio_log10": ["{} orders of magnitude"],
    "redos_first_over_budget": ["from {} characters", "{} characters of input"],
    "oracle_refusals_quiet": ["{} refusal text", "{} distinct refusal"],
    "oracle_refusals_explaining": ["{} distinct refusals", "identifies {} detectors"],
    # budget_share_used_pct is unanchored on purpose: a share of a reserved budget is a ratio of two
    # measured durations, so it moves with the machine, and no document quotes it.

    "latency_per_char_saved": ["{} characters of latency"],
    "downtime_minutes_closed": ["{} minutes a month", "{} minutes of downtime"],
    "uncovered_minutes_open": ["{} minutes uncovered", "{} minutes a month uncovered"],
}


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(command)}")
    return subprocess.run(command, cwd=ROOT, check=check, capture_output=True, text=True)


def test_metrics(skip: bool) -> dict:
    """Test count and coverage, read from the machine-readable outputs rather than from stdout.

    JUnit XML for the count and coverage's own JSON for the percentages, because parsing a progress
    line is how a metric quietly becomes whatever the last run happened to print.
    """
    if skip:
        junit = ROOT / "reports" / "junit.xml"
        coverage = ROOT / "reports" / "coverage.json"
        if not (junit.exists() and coverage.exists()):
            raise SystemExit("--skip-tests needs reports/junit.xml and reports/coverage.json")
    else:
        (ROOT / "reports").mkdir(exist_ok=True)
        run([sys.executable, "-m", "pytest", "tests", "-q",
             "--junitxml=reports/junit.xml",
             "--cov=guardrail", "--cov-report=json:reports/coverage.json"])
        junit = ROOT / "reports" / "junit.xml"
        coverage = ROOT / "reports" / "coverage.json"

    suite = ElementTree.parse(junit).getroot()
    if suite.tag == "testsuites":
        suite = suite[0]
    totals = json.loads(coverage.read_text())["totals"]
    return {
        "tests_total": int(suite.get("tests", 0)) - int(suite.get("skipped", 0)),
        "coverage_line_pct": round(totals["percent_covered"], 1),
        "coverage_branch_pct": round(
            100.0 * totals["covered_branches"] / max(totals["num_branches"], 1), 1),
    }


def experiment(name: str, argv: list[str]) -> dict:
    run([sys.executable, f"experiments/{name}.py", *argv])
    return json.loads((EXPERIMENTS / f"{name}.json").read_text())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--out", default="docs/metrics.json")
    args = parser.parse_args(argv)

    import sys as _sys
    _sys.path[:0] = [str(ROOT), str(ROOT / "src")]
    import attacks
    from guardrail.policy import load
    from guardrail.proxy import posture
    from guardrail.version import __version__

    policy = load(ROOT / "policies" / "support-assistant.yaml")
    summary = attacks.summary()
    gate = attacks.measure(policy)
    signal = attacks.measure(policy, at_action_confidence=False)
    stand = posture(policy, gate)

    metrics: dict[str, object] = {"version": __version__}
    metrics.update(test_metrics(args.skip_tests))

    stream = experiment("stream_vs_buffer", [])
    base = experiment("base_rate", [])
    bypass = experiment("bypass_matrix", [])
    redos = experiment("redos_fail_open", [])
    latency = experiment("latency_budget", [])

    key_curve = stream["completions"]["leaks_aws_key"]
    secret = gate["secret_pattern"]
    availability = stand["availability"]

    metrics.update({
        "corpus_cases": summary["cases"],
        "corpus_as_declared": summary["cases"],
        "corpus_benign": summary["benign"],
        "corpus_attacks": summary["attacks"],
        "corpus_evasions": summary["evasions"],
        "surviving_evasions": len(summary["surviving_evasions"]),
        "detectors": len(policy.detectors),

        "worst_leak_chars": key_curve["worst_leak"],
        "zero_leak_lookback": key_curve["zero_leak_at"],
        "shipped_lookback": policy.stream.lookback_chars,
        "buffered_first_emit_chars": key_curve["buffered_first_emit"],
        "smallest_safe_lookback": stream["smallest_safe_lookback"],

        "signal_false_positives": signal["secret_pattern"].false_positives,
        "signal_fpr_pct": round(100 * signal["secret_pattern"].fpr, 1),
        "resolved_precision_pct": round(
            100 * secret.precision_at(policy.prevalence, resolved=True), 2),
        "benign_needed_for_block": base["benign_needed"],
        "benign_measured_widest": secret.benign,
        "unsupported_blocks": len(base["unsupported_blocks"]),

        "redos_naive_ms_at_24": round(redos["curve"][-1]["naive_ms"]),
        "redos_ratio": round(redos["naive_over_shipped_at_worst"]),
        "redos_ratio_log10": int(math.log10(max(redos["naive_over_shipped_at_worst"], 1))),
        "redos_first_over_budget": redos["first_length_over_budget"],
        "redos_fail_open_verdict": redos["outcomes"]["fails open"]["verdict"],
        "redos_fail_closed_verdict": redos["outcomes"]["fails closed"]["verdict"],

        "oracle_refusals_quiet": bypass["oracle"]["distinct_refusals_when_quiet"],
        "oracle_refusals_explaining": bypass["oracle"]["distinct_refusals_when_explaining"],

        "budget_share_used_pct": round(100 * latency["share_of_reserved_used"], 1),
        "latency_per_char_saved": latency["median_chars_of_latency_per_char_saved"],
        "downtime_minutes_closed": availability["prompt"]["downtime_minutes_per_month"],
        "uncovered_minutes_open": availability["response"]["uncovered_minutes_per_month"],
    })

    payload = {
        "metrics": metrics,
        "anchors": ANCHORS,
        "checked_documents": CHECKED_DOCUMENTS,
        "note": ("every value here is produced by running the suite and the experiments; "
                 "tools/check_numbers.py fails the build when a document disagrees with it"),
    }
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=False))
    print(f"\nwrote {out} with {len(metrics)} metric(s)")
    for name, value in metrics.items():
        print(f"  {name:30} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
