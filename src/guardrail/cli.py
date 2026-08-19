"""The command line, and the exit codes that make it usable in a pipeline.

## The exit codes are the interface

`guard check` exits **1** when the guardrail did not do its job, which is a narrower claim than
"the request was refused". A refusal is a success: the guardrail decided, and the client got the
constant refusal text. The failures are `leaked`, where part of a detected secret reached the client
before the stream was cut, and `allowed_unchecked`, where a detector never answered and the policy
failed open.
Both are cases where the report says something happened that the guardrail was supposed to prevent,
and both exit non-zero so a pipeline notices without parsing prose.

`guard corpus` exits 1 if any case did not behave as the corpus declares, which is what CI runs.
The verdicts it prints are `allowed`, `allowed_unchecked`, `refused`, `redacted` and `leaked`.

`guard posture --strict` exits 1 when any action is unsupported at the declared prevalence. It is
opt-in, and the reason is worth stating plainly: **on this repository's corpus it fails**. Three
blocking detectors are unsupported, not because the detectors are bad but because 38 labelled
samples cannot resolve a false positive rate small enough to defend a block at a prevalence of
0.0004. Wiring `--strict` into CI would mean either deleting the check or weakening the floor, and
both are worse than an honest red number in a report.

## Every command prints what it did not establish

The caveats are not a footer. A `check` that allowed a request while a detector timed out prints
that above the verdict, because "allowed" and "allowed without checking" are different claims and
only the report knows which one happened.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report as report_module
from .detect import REDOS_LENGTHS, redos_curve
from .errors import GuardrailError
from .evaluate import PREVALENCES, sweep
from .policy import PROMPT, RESPONSE, load
from .proxy import client_sees, handle, leak_curve, posture
from .upstream import COMPLETIONS, Upstream, completion
from .version import __version__

DEFAULT_POLICY = "policies/support-assistant.yaml"


def _corpus():
    """The corpus, imported lazily and with a legible failure.

    `attacks/` is part of the repository rather than of the installed package, because a corpus of
    attack strings does not belong in a wheel that somebody's service imports. So the commands that
    need it say so when it is missing instead of raising an ImportError at startup.
    """
    try:
        import attacks  # noqa: PLC0415 - deliberately lazy; see this function's docstring
    except ImportError as exc:  # pragma: no cover - exercised by running outside the checkout
        raise GuardrailError(
            "the corpus lives in attacks/ in the repository, not in the installed package. Run "
            "this command from a checkout, or use `guard check`, which needs only the policy."
        ) from exc
    return attacks


def _print_caveats(notes: list[str]) -> None:
    if not notes:
        return
    print("\nwhat this did not establish")
    for note in notes:
        print(f"  - {note}")


def cmd_check(args: argparse.Namespace) -> int:
    """One prompt and one scripted response through the proxy."""
    policy = load(args.policy)
    transaction = handle(args.prompt, completion(args.completion), policy,
                         upstream=Upstream(seed=args.seed), stream_response=not args.buffer)
    if args.json:
        print(json.dumps(transaction.to_json(), indent=2))
        return transaction.exit_code

    print(f"verdict      {transaction.verdict}")
    print(f"route        {policy.route}   mode: {'buffered' if args.buffer else 'streamed'}")
    if transaction.refused_at:
        print(f"refused at   {transaction.refused_at} ({transaction.refusal_reason})")
    normalisation = ", ".join(transaction.normalised.applied) or "none"
    print(f"normalised   {normalisation}"
          f"{'   [suspicious]' if transaction.normalised.suspicious else ''}")
    if transaction.findings:
        print("findings")
        for finding in transaction.findings:
            print(f"  {finding.detector:24s} {finding.confidence:6s} "
                  f"[{finding.start}:{finding.end}] {finding.excerpt}")
    else:
        print("findings     none")
    if transaction.prompt_spend:
        spent = transaction.prompt_spend
        print(f"prompt spend {spent.total_ms} ms over {len(spent.runs)} detector(s)"
              f"{'   unavailable: ' + ', '.join(spent.unavailable) if spent.unavailable else ''}")
    if transaction.response:
        state = transaction.response
        # -1 means nothing was ever emitted, which is a different fact from "emitted at char 0" and
        # is printed as a word rather than as a sentinel a reader has to know about.
        first = "never" if state.first_emit_at_char < 0 else f"char {state.first_emit_at_char}"
        print(f"stream       {state.chunks_in} chunks in, {state.chunks_out} out, "
              f"first emit {first}, "
              f"leaked {state.leaked_chars}, redactions {state.redactions}")
    print(f"\nthe client sees:\n  {client_sees(transaction, policy)[:400]}")
    _print_caveats(transaction.caveats())
    return transaction.exit_code


def cmd_corpus(args: argparse.Namespace) -> int:
    """Every labelled case through the real proxy. What CI runs."""
    attacks = _corpus()
    policy = load(args.policy)
    results = attacks.run_all(policy, stream_response=not args.buffer)
    mismatches = []
    print(f"{'case':30s} {'kind':8s} {'verdict':18s} {'leak':>5s}  as declared")
    for case, transaction in results:
        blocked = not transaction.allowed
        redacted = bool(transaction.response and transaction.response.redactions)
        ok = blocked == case.expect_blocked and (redacted or not case.expect_redacted)
        if not ok:
            mismatches.append(case.slug)
        print(f"{case.slug:30s} {case.kind:8s} {transaction.verdict:18s} "
              f"{transaction.leaked_chars:5d}  {'ok' if ok else 'MISMATCH'}")
    total = len(results)
    print(f"\n{total - len(mismatches)}/{total} as declared")
    print(f"evasions that survive canonicalisation: "
          f"{', '.join(attacks.KNOWN_SURVIVING_EVASIONS)}")
    if mismatches:
        print(f"mismatched: {', '.join(mismatches)}")
    return 1 if mismatches else 0


def cmd_posture(args: argparse.Namespace) -> int:
    """The policy's report card at its declared prevalence."""
    attacks = _corpus()
    policy = load(args.policy)
    measured = attacks.measure(policy)
    stand = posture(policy, measured)
    if args.json:
        print(json.dumps(stand, indent=2))
        return 1 if (args.strict and stand["unjustified"]) else 0

    print(f"route {stand['route']}   declared prevalence {stand['prevalence']:g}")
    print(f"{'detector':24s} {'action':7s} {'gate fpr':>9s} {'n':>4s} {'precision':>10s}"
          f"  supported")
    for verdict in stand["verdicts"]:
        rates = measured.get(verdict["detector"])
        print(f"{verdict['detector']:24s} {verdict['action']:7s} "
              f"{rates.fpr if rates else 0:9.3f} {rates.benign if rates else 0:4d} "
              f"{verdict.get('resolved_precision', 0):9.2%}  "
              f"{'yes' if verdict['justified'] else 'NO'}")
    for verdict in stand["verdicts"]:
        if not verdict["justified"]:
            print(f"\n  {verdict['detector']}: {verdict['reason']}")
    for side in (PROMPT, RESPONSE):
        entry = stand["availability"][side]
        print(f"\n{side} fails {'open' if entry['fail_open'] else 'closed'}: combined availability "
              f"{entry['combined_availability']:.4f}, "
              f"{entry['downtime_minutes_per_month']} min/month down, "
              f"{entry['uncovered_minutes_per_month']} min/month uncovered")
    print(f"\n{stand['availability_note']}")
    return 1 if (args.strict and stand["unjustified"]) else 0


def cmd_sweep(args: argparse.Namespace) -> int:
    """Precision at every prevalence, for every detector, measured on the corpus."""
    attacks = _corpus()
    policy = load(args.policy)
    measured = attacks.measure(policy)
    table = sweep(list(measured.values()))
    if args.json:
        print(json.dumps(table, indent=2))
        return 0
    header = "".join(f"{p:>11g}" for p in PREVALENCES)
    print(f"{'detector':24s} {'tpr':>5s} {'fpr':>6s}{header}")
    for row, rates in zip(table, measured.values(), strict=True):
        cells = "".join(f"{rates.precision_at(p, resolved=True):>10.2%} " for p in PREVALENCES)
        print(f"{row['detector']:24s} {row['tpr']:5.2f} {row['fpr']:6.3f}{cells}")
    print("\nprecision computed at each detector's resolved false positive rate, which is the "
          "larger of\nwhat was measured and one over the number of benign samples")
    return 0


def cmd_lookback(args: argparse.Namespace) -> int:
    """The leak against the lookback, on one completion."""
    policy = load(args.policy)
    rows = leak_curve(policy, completion(args.completion),
                      lookbacks=[int(value) for value in args.lookbacks.split(",")])
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"completion {args.completion}")
    print(f"{'lookback':>9s} {'leaked':>7s} {'after match':>12s} {'first emit':>11s} {'cut':>5s}")
    for row in rows:
        label = "buffer" if row["lookback"] is None else str(row["lookback"])
        first = "never" if row["first_emit_at_char"] is None else str(row["first_emit_at_char"])
        print(f"{label:>9s} {row['leaked_chars']:7d} {row['emitted_after_match']:12d} "
              f"{first:>11s} {row['cut']!s:>5s}")
    print("\nevery character held back cannot leak and cannot be shown; the last row is not "
          "streaming")
    return 0


def cmd_redos(args: argparse.Namespace) -> int:
    """The pattern this repository does not use, timed against the detector budget."""
    points = redos_curve(lengths=[int(v) for v in args.lengths.split(",")], repeats=args.repeats)
    budget = args.budget_ms
    if args.json:
        print(json.dumps({"points": [list(point) for point in points], "budget_ms": budget},
                         indent=2))
        return 0
    print(f"{'chars':>6s} {'ms':>12s}  over {budget:g} ms budget")
    for length, elapsed in points:
        print(f"{length:6d} {elapsed:12.4f}  {'yes' if elapsed > budget else 'no'}")
    print("\nthe payload is a run of letters; it does not have to look like an attack, because "
          "it is not\nattacking the model")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Build the payload once and write all three renderings."""
    attacks = _corpus()
    policy = load(args.policy)
    results = attacks.run_all(policy)
    payload = report_module.build(
        policy, results,
        attacks.measure(policy),
        signal_rates=attacks.measure(policy, at_action_confidence=False),
        lookback_curve=leak_curve(policy, completion(args.completion)),
        redos=redos_curve(),
        redos_budget_ms=args.budget_ms,
        surviving_evasions=attacks.KNOWN_SURVIVING_EVASIONS,
    )
    written = report_module.write(payload, Path(args.out))
    for name, path in written.items():
        print(f"{name:9s} {path}")
    return 0


def cmd_completions(_: argparse.Namespace) -> int:
    """What the fixture can stream, so `--completion` is discoverable."""
    print(f"{'name':22s} {'kind':16s} {'chars':>6s}  expects")
    for name, entry in COMPLETIONS.items():
        print(f"{name:22s} {entry.kind:16s} {len(entry):6d}  "
              f"{', '.join(entry.expect_detectors) or 'nothing'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guard",
        description="An LLM guardrail proxy that reports what it let through, not just what it "
                    "caught.")
    parser.add_argument("--version", action="version", version=f"guardrail {__version__}")
    parser.add_argument("--policy", default=DEFAULT_POLICY, help="policy YAML to load")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="one prompt and one scripted response through the proxy")
    check.add_argument("prompt")
    check.add_argument("--completion", default="clean_answer",
                       help="which scripted response to stream back")
    check.add_argument("--buffer", action="store_true",
                       help="buffer the response instead of streaming it")
    check.add_argument("--seed", type=int, default=20260818)
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    corpus = sub.add_parser("corpus", help="every labelled case through the real proxy")
    corpus.add_argument("--buffer", action="store_true")
    corpus.set_defaults(func=cmd_corpus)

    stand = sub.add_parser("posture", help="is each action supported at the declared prevalence")
    stand.add_argument("--strict", action="store_true",
                       help="exit 1 when an action is unsupported; on this corpus, it is")
    stand.add_argument("--json", action="store_true")
    stand.set_defaults(func=cmd_posture)

    table = sub.add_parser("sweep", help="precision at every prevalence")
    table.add_argument("--json", action="store_true")
    table.set_defaults(func=cmd_sweep)

    curve = sub.add_parser("lookback", help="the leak against the lookback")
    curve.add_argument("--completion", default="leaks_aws_key")
    curve.add_argument("--lookbacks", default="0,8,16,24,96")
    curve.add_argument("--json", action="store_true")
    curve.set_defaults(func=cmd_lookback)

    redos = sub.add_parser("redos", help="time the pattern this repository does not use")
    redos.add_argument("--lengths", default=",".join(str(value) for value in REDOS_LENGTHS))
    redos.add_argument("--repeats", type=int, default=3)
    redos.add_argument("--budget-ms", type=float, default=8.0, dest="budget_ms")
    redos.add_argument("--json", action="store_true")
    redos.set_defaults(func=cmd_redos)

    built = sub.add_parser("report", help="write the JSON, markdown and HTML report")
    built.add_argument("--out", default="docs/report")
    built.add_argument("--completion", default="leaks_aws_key")
    built.add_argument("--budget-ms", type=float, default=8.0, dest="budget_ms")
    built.set_defaults(func=cmd_report)

    listed = sub.add_parser("completions", help="the scripted responses the fixture can stream")
    listed.set_defaults(func=cmd_completions)
    return parser


def run(argv: list[str] | None = None) -> int:
    """The entry point. Returns rather than exits, so tests can assert on the code.

    `GuardrailError` is caught and printed as one line, because a policy typo should read like a
    message and not like a stack trace. Everything else propagates: an unexpected exception in a
    guardrail is not something to summarise.
    """
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except GuardrailError as exc:
        print(f"guard: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
