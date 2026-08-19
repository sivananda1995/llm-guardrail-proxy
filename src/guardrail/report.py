"""Three renderers over one payload: JSON for machines, markdown for a review, HTML for a ticket.

Every renderer leads with the same two numbers, and neither is a pass rate.

The first is **how much of a detected secret reached the client**, because a guardrail that reports
"blocked" on a streamed response has told you what it decided and not what escaped while it decided.
The second is **whether the corpus can support the actions the policy takes**, because a blocking
action defended by a false positive rate of zero measured over 34 samples is defended by nothing.

Both are uncomfortable, both are computed rather than asserted, and both appear above the corpus
result in all three renderers. A report that opened with `28/28 as declared` and put the resolution
floor in a footnote would be a marketing document, and the whole argument of this repository is that
guardrail reporting is mostly marketing documents.

The badge and cell CSS classes are namespaced (`badge ok`, `td.cell-bad`) and a test keeps them
apart. That is a scar from an earlier project in this series: two rules of equal specificity
collided, the later one won, and a verdict rendered green on green. Invisible in the source, visible
only in a browser.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .charts import leak_chart, precision_chart, redos_chart
from .evaluate import BLOCK_PRECISION_FLOOR, PREVALENCES, Rates
from .policy import PROMPT, RESPONSE, Policy
from .proxy import Transaction, posture
from .version import __version__

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 28px 56px; background: #faf9f7; color: #24231f;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif; }
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 21px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 30px 0 10px; text-transform: uppercase; letter-spacing: 0.07em;
  color: #6d6b66; font-weight: 600; }
p { margin: 8px 0; }
.sub { color: #6d6b66; font-size: 13px; margin: 0 0 18px; }
.card { background: #fff; border: 1px solid #e6e4df; border-radius: 10px; padding: 18px 20px;
  margin: 0 0 16px; }
.headline { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
.headline strong { font-size: 27px; letter-spacing: -0.02em; }
.badge { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 11px;
  font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.badge.ok { background: #e4f3e9; color: #24623c; }
.badge.bad { background: #fce8e7; color: #9d2a28; }
.badge.warn { background: #fdf1dd; color: #8a5a12; }
.badge.info { background: #e9eef7; color: #2c4f88; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(168px, 1fr)); gap: 12px;
  margin: 0 0 16px; }
.tile { background: #fff; border: 1px solid #e6e4df; border-radius: 10px; padding: 13px 15px; }
.tile .n { font-size: 22px; font-weight: 650; letter-spacing: -0.02em; }
.tile .k { font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; color: #6d6b66; }
.tile.alarm .n { color: #9d2a28; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid #eeece7; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6d6b66; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.cell-ok { color: #24623c; }
td.cell-bad { color: #9d2a28; font-weight: 600; }
td.mono, code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.caveats { border-left: 3px solid #d79a3a; padding: 2px 0 2px 14px; margin: 14px 0 0;
  color: #6d6b66; font-size: 13px; }
.caveats li { margin: 5px 0; }
footer { color: #6d6b66; font-size: 12px; margin: 28px 0 0; }
"""


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def build(policy: Policy, results: list[tuple[Any, Transaction]], measured: dict[str, Rates], *,
          signal_rates: dict[str, Rates] | None = None,
          lookback_curve: list[dict] | None = None,
          redos: list[tuple[int, float]] | None = None,
          redos_budget_ms: float = 8.0,
          surviving_evasions: tuple[str, ...] = ()) -> dict:
    """One payload, from which every renderer is a pure function.

    `measured` is the rate set gated at each detector's `min_confidence`, which is what an action
    has to be defended with. `signal_rates` is the ungated set, and passing it is what makes the
    report show both: one detector at a false positive rate of zero as a gate and 14.7% as a signal.
    """
    stand = posture(policy, measured)
    rows = []
    for case, transaction in results:
        blocked = not transaction.allowed
        redacted = bool(transaction.response and transaction.response.redactions)
        as_declared = blocked == case.expect_blocked and (redacted or not case.expect_redacted)
        rows.append({
            "slug": case.slug, "kind": case.kind, "verdict": transaction.verdict,
            "expect_blocked": case.expect_blocked, "blocked": blocked,
            "expect_redacted": case.expect_redacted, "redacted": redacted,
            "as_declared": as_declared,
            "leaked_chars": transaction.leaked_chars,
            "normalisation": list(transaction.normalised.applied),
            "suspicious": transaction.normalised.suspicious,
            "detectors": sorted({finding.detector for finding in transaction.findings}),
            "note": case.note,
        })

    detectors = []
    for name, detector in sorted(policy.detectors.items()):
        gated = measured.get(name)
        signal = (signal_rates or {}).get(name)
        detectors.append({
            **detector.to_json(),
            "gate": gated.to_json() if gated else None,
            "signal": signal.to_json() if signal else None,
        })

    curve = lookback_curve or []
    return {
        "tool": "guardrail", "version": __version__,
        "route": policy.route, "description": policy.description,
        "prevalence": policy.prevalence,
        "policy": {
            "stream": policy.stream.to_json(), "budget": policy.budget.to_json(),
            "response": policy.response.to_json(),
            "stream_unsafe_detectors": list(policy.stream_unsafe()),
        },
        "corpus": {
            "cases": len(rows),
            "as_declared": sum(1 for row in rows if row["as_declared"]),
            "mismatches": [row["slug"] for row in rows if not row["as_declared"]],
            "blocked": sum(1 for row in rows if row["blocked"]),
            "redacted": sum(1 for row in rows if row["redacted"]),
            "surviving_evasions": list(surviving_evasions),
            "rows": rows,
        },
        "detectors": detectors,
        "posture": stand,
        "leak_curve": curve,
        "leak": {
            "worst_leak_chars": max((row["leaked_chars"] for row in curve), default=0),
            "zero_leak_at": next((row["lookback"] for row in curve
                                  if row["lookback"] is not None and row["leaked_chars"] == 0),
                                 None),
            "buffered_first_emit": next((row["first_emit_at_char"] for row in curve
                                         if row["lookback"] is None), None),
        },
        "redos": {"points": [list(point) for point in (redos or [])],
                  "budget_ms": redos_budget_ms},
        "floor": BLOCK_PRECISION_FLOOR,
        "prevalences": list(PREVALENCES),
        "caveats": caveats(policy, measured),
    }


def caveats(policy: Policy, measured: dict[str, Rates]) -> list[str]:
    """What this report does not establish. Rendered in all three formats, never abbreviated."""
    smallest = min((rates.benign for rates in measured.values()), default=0)
    return [
        "the upstream is a deterministic token stream generator, not a model, so no claim here "
        "is a claim about which injections work on a particular model "
        "(docs/adr/ADR-005-what-this-cannot-measure.md)",
        f"rates are measured on a corpus whose smallest benign population is {smallest} samples, "
        f"so a false positive rate of zero means 'none in {smallest}' and the report prices every "
        f"blocking action at the worst rate that population can support",
        f"the prevalence of {policy.prevalence:g} is declared in the policy, not observed; every "
        "precision figure moves with it, and the sweep exists so a reader can substitute their own",
        "detector timeouts are detected after the call rather than interrupting it, so the budget "
        "is an accounting boundary and the defence against a slow detector is that detectors are "
        "linear time, asserted by test",
        "availability figures are arithmetic on declared nines, not telemetry",
    ]


def as_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=False)


def _row_flag(ok: bool) -> str:
    return "ok" if ok else "MISMATCH"


def as_markdown(payload: dict) -> str:
    """The review format. Leads with the leak and the resolution floor, in that order."""
    corpus = payload["corpus"]
    leak = payload["leak"]
    stand = payload["posture"]
    lines = [
        f"# guardrail report: {payload['route']}",
        "",
        f"`guardrail {payload['version']}` | declared prevalence `{payload['prevalence']:g}` | "
        f"lookback `{payload['policy']['stream']['lookback_chars']}` characters",
        "",
        "## the two numbers that decide whether this guardrail is worth having",
        "",
        f"1. **{leak['worst_leak_chars']} characters** of a detected secret reached the client at "
        f"the worst lookback measured, and **0** at a lookback of "
        f"`{leak['zero_leak_at']}`, which costs `{leak['zero_leak_at']}` characters of latency "
        f"before the first byte.",
        f"2. **{len(stand['unjustified'])} of "
        f"{sum(1 for entry in payload['detectors'] if entry['action'] == 'block')} blocking "
        f"actions** are unsupported by this corpus at the declared prevalence.",
        "",
        "## corpus",
        "",
        f"{corpus['as_declared']}/{corpus['cases']} cases behaved as declared. "
        f"{corpus['blocked']} refused, {corpus['redacted']} redacted. "
        f"Surviving evasions: {', '.join(corpus['surviving_evasions']) or 'none'}.",
        "",
        "| case | kind | verdict | as declared | detectors | leak |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in corpus["rows"]:
        lines.append(
            f"| `{row['slug']}` | {row['kind']} | {row['verdict']} | "
            f"{_row_flag(row['as_declared'])} | {', '.join(row['detectors']) or 'none'} | "
            f"{row['leaked_chars']} |")

    lines += ["", "## detectors, as a gate and as a signal", "",
              "| detector | action | reads | gate FPR | signal FPR | precision at prevalence | "
              "supported |", "| --- | --- | --- | --- | --- | --- | --- |"]
    verdicts = {entry["detector"]: entry for entry in stand["verdicts"]}
    for entry in payload["detectors"]:
        gate = entry["gate"] or {}
        signal = entry["signal"] or {}
        verdict = verdicts.get(entry["name"], {})
        lines.append(
            f"| `{entry['name']}` | {entry['action']} | {entry['reads']} | "
            f"{gate.get('fpr', 0):.3f} (n={gate.get('benign', 0)}) | "
            f"{signal.get('fpr', 0):.3f} | "
            f"{verdict.get('resolved_precision', 0):.2%} | "
            f"{'yes' if verdict.get('justified') else 'no'} |")

    lines += ["", "## what the corpus cannot support", ""]
    for name in stand["unjustified"]:
        lines.append(f"* `{name}`: {verdicts[name]['reason']}.")
    if not stand["unjustified"]:
        lines.append("* every action is supported at the declared prevalence.")

    lines += ["", "## the fail mode, priced", ""]
    for side in (PROMPT, RESPONSE):
        entry = stand["availability"][side]
        lines.append(
            f"* **{side}**: fails {'open' if entry['fail_open'] else 'closed'}. Combined "
            f"availability {entry['combined_availability']:.4f}, "
            f"{entry['downtime_minutes_per_month']} minutes of downtime a month, "
            f"{entry['uncovered_minutes_per_month']} minutes uncovered.")

    lines += ["", "## caveats", ""]
    lines += [f"* {note}" for note in payload["caveats"]]
    lines.append("")
    return "\n".join(lines)


def _tile(number: object, label: str, alarm: bool = False) -> str:
    classes = "tile alarm" if alarm else "tile"
    return (f'<div class="{classes}"><div class="n">{_escape(number)}</div>'
            f'<div class="k">{_escape(label)}</div></div>')


def as_html(payload: dict) -> str:
    """One self-contained file: inline CSS, inline SVG, no script, no network."""
    corpus = payload["corpus"]
    leak = payload["leak"]
    stand = payload["posture"]
    verdicts = {entry["detector"]: entry for entry in stand["verdicts"]}
    blocking = [entry for entry in payload["detectors"] if entry["action"] == "block"]

    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>guardrail report: {_escape(payload['route'])}</title>",
        f"<style>{CSS}</style></head><body><main>",
        f"<h1>guardrail report: {_escape(payload['route'])}</h1>",
        f'<p class="sub">{_escape(payload["description"])} &middot; guardrail '
        f'{_escape(payload["version"])} &middot; declared prevalence '
        f'{payload["prevalence"]:g} &middot; lookback '
        f'{payload["policy"]["stream"]["lookback_chars"]} characters</p>',
        '<div class="card"><div class="headline">',
        f'<strong>{leak["worst_leak_chars"]} characters leaked</strong>',
        '<span class="badge bad">worst lookback measured</span>',
        f'<strong>{len(stand["unjustified"])}/{len(blocking)} blocks unsupported</strong>',
        '<span class="badge warn">at the declared prevalence</span>',
        "</div><p>Both numbers are computed from the runs below rather than declared. The first is "
        "what a streamed response costs when a detector fires late; the second is what this "
        "corpus can actually defend.</p></div>",
        '<div class="grid">',
        _tile(f"{corpus['as_declared']}/{corpus['cases']}", "cases as declared"),
        _tile(corpus["blocked"], "refused"),
        _tile(corpus["redacted"], "redacted"),
        _tile(len(corpus["surviving_evasions"]), "evasions that still work",
              alarm=bool(corpus["surviving_evasions"])),
        _tile(leak["zero_leak_at"] if leak["zero_leak_at"] is not None else "none",
              "lookback for zero leak"),
        _tile(leak["buffered_first_emit"] if leak["buffered_first_emit"] is not None else "n/a",
              "first byte if buffered"),
        "</div>",
    ]

    if payload["leak_curve"]:
        parts += ["<h2>the leak against the lookback</h2>",
                  '<div class="card">', leak_chart(payload["leak_curve"]),
                  "<p>Every character held back is a character that cannot leak and a character "
                  "of latency before the first byte. The rightmost column is not streaming.</p>",
                  "</div>"]

    series = [{"detector": entry["name"],
               "points": [(float(p), value) for p, value in
                          (entry["gate"] or {}).get("precision_at_resolved", {}).items()]}
              for entry in blocking if entry["gate"]]
    if series:
        parts += ["<h2>precision against prevalence, at the rate this corpus can support</h2>",
                  '<div class="card">', precision_chart(series, floor=payload["floor"]),
                  "<p>Computed against each detector's resolved false positive rate, which is the "
                  "larger of what was measured and one over the number of benign samples. A "
                  "measured zero is not a zero.</p></div>"]

    if payload["redos"]["points"]:
        points = [(int(n), float(ms)) for n, ms in payload["redos"]["points"]]
        parts += ["<h2>the guardrail as the target</h2>",
                  '<div class="card">',
                  redos_chart(points, payload["redos"]["budget_ms"]),
                  "<p>A backtracking pattern turns a short input into a budget overrun, and a "
                  "route that fails open is switched off by whoever sends it.</p></div>"]

    parts += ["<h2>corpus</h2><div class=\"card\"><table><thead><tr><th>case</th><th>kind</th>"
              "<th>verdict</th><th>as declared</th><th>detectors</th><th class=\"num\">leak</th>"
              "</tr></thead><tbody>"]
    for row in corpus["rows"]:
        cell = "cell-ok" if row["as_declared"] else "cell-bad"
        parts.append(
            f'<tr><td class="mono">{_escape(row["slug"])}</td><td>{_escape(row["kind"])}</td>'
            f'<td>{_escape(row["verdict"])}</td>'
            f'<td class="{cell}">{_row_flag(row["as_declared"])}</td>'
            f'<td class="mono">{_escape(", ".join(row["detectors"]) or "none")}</td>'
            f'<td class="num">{row["leaked_chars"]}</td></tr>')
    parts.append("</tbody></table></div>")

    parts += ["<h2>detectors, as a gate and as a signal</h2><div class=\"card\"><table><thead><tr>"
              "<th>detector</th><th>action</th><th>reads</th><th class=\"num\">gate FPR</th>"
              "<th class=\"num\">signal FPR</th><th class=\"num\">precision</th>"
              "<th>supported</th></tr></thead><tbody>"]
    for entry in payload["detectors"]:
        gate = entry["gate"] or {}
        signal = entry["signal"] or {}
        verdict = verdicts.get(entry["name"], {})
        supported = verdict.get("justified", False)
        cell = "cell-ok" if supported else "cell-bad"
        parts.append(
            f'<tr><td class="mono">{_escape(entry["name"])}</td>'
            f'<td>{_escape(entry["action"])}</td><td>{_escape(entry["reads"])}</td>'
            f'<td class="num">{gate.get("fpr", 0):.3f} (n={gate.get("benign", 0)})</td>'
            f'<td class="num">{signal.get("fpr", 0):.3f}</td>'
            f'<td class="num">{verdict.get("resolved_precision", 0):.2%}</td>'
            f'<td class="{cell}">{"yes" if supported else "no"}</td></tr>')
    parts.append("</tbody></table></div>")

    if stand["unjustified"]:
        parts.append("<h2>what this corpus cannot support</h2><div class=\"card\"><ul>")
        for name in stand["unjustified"]:
            parts.append(f'<li><code>{_escape(name)}</code>: '
                         f'{_escape(verdicts[name]["reason"])}.</li>')
        parts.append("</ul></div>")

    parts.append("<h2>the fail mode, priced</h2><div class=\"card\"><table><thead><tr><th>side"
                 "</th><th>mode</th><th class=\"num\">combined availability</th>"
                 "<th class=\"num\">downtime min/month</th><th class=\"num\">uncovered min/month"
                 "</th></tr></thead><tbody>")
    for side in (PROMPT, RESPONSE):
        entry = stand["availability"][side]
        parts.append(
            f'<tr><td>{_escape(side)}</td>'
            f'<td>{"open" if entry["fail_open"] else "closed"}</td>'
            f'<td class="num">{entry["combined_availability"]:.4f}</td>'
            f'<td class="num">{entry["downtime_minutes_per_month"]}</td>'
            f'<td class="num">{entry["uncovered_minutes_per_month"]}</td></tr>')
    parts.append("</tbody></table></div>")

    parts.append('<h2>what this does not establish</h2><ul class="caveats">')
    for note in payload["caveats"]:
        parts.append(f"<li>{_escape(note)}</li>")
    parts.append("</ul>")
    parts.append("<footer>Generated offline. No model was called, no key exists, and every figure "
                 "on this page is recomputed by <code>tools/collect_metrics.py</code>.</footer>")
    parts.append("</main></body></html>")
    return "".join(parts)


def write(payload: dict, directory: Path) -> dict[str, Path]:
    """All three formats side by side, because each has an audience and none is a superset."""
    directory.mkdir(parents=True, exist_ok=True)
    written = {
        "json": directory / "report.json",
        "markdown": directory / "report.md",
        "html": directory / "report.html",
    }
    written["json"].write_text(as_json(payload))
    written["markdown"].write_text(as_markdown(payload))
    written["html"].write_text(as_html(payload))
    return written


__all__ = ["as_html", "as_json", "as_markdown", "build", "caveats", "write"]
