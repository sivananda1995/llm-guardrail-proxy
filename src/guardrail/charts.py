"""Inline SVG for the HTML report. No JavaScript, no external asset, no network call.

The report is a single file that gets pasted into an incident ticket or opened from a laptop with no
network, so a chart library is out of the question: a page that fetches anything renders blank for
whoever is reading it at eleven at night.

Three charts, each showing something its table cannot.

* `leak_chart` draws the number this repository is about. As the lookback grows, the characters of
a detected secret that reached the client fall to zero and the latency before the first character
rises in step. Two series on one axis, because the trade is the point and separate charts would
let a reader take one without the other.
* `precision_chart` puts precision against prevalence on a log axis with the blocking floor drawn
in. A detector's curve crossing that line is the moment its `block` action stopped being defensible,
and the crossing is a shape rather than a paragraph.
* `redos_chart` draws the backtracking blowup against the detector budget, on a log axis because the
series spans six orders of magnitude and a linear axis renders the interesting part as a flat line.

Every axis that is logarithmic says so in its label, because an unlabelled log axis is a way of
making a small difference look enormous.
"""

from __future__ import annotations

import html
import math

#: Deuteranopia-safe, legible on the report's off-white background, and meaning-carrying rather than
#: decorative: DANGER is only ever a leak or a refusal, COOL is only ever a latency cost.
INK = "#24231f"
MUTED = "#6d6b66"
GRID = "#e6e4df"
DANGER = "#c0392b"
WARN = "#d79a3a"
SAFE = "#2e7d5b"
COOL = "#2c4f88"


def _escape(text: object) -> str:
    return html.escape(str(text), quote=True)


def _frame(width: int, height: int, title: str, body: str) -> str:
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        f'aria-label="{_escape(title)}" xmlns="http://www.w3.org/2000/svg">'
        f'<title>{_escape(title)}</title>{body}</svg>'
    )


def leak_chart(rows: list[dict], width: int = 640, height: int = 266) -> str:
    """Leaked characters and time-to-first-character against lookback.

    `rows` are dictionaries with `lookback`, `leaked_chars` and `first_emit_at_char`, in the order
    they should appear. A row whose lookback is `None` is the buffered case and is drawn last with a
    separating rule, because it is not a point on the same axis: it is the other option.
    """
    if not rows:
        return ""
    # A tall top margin because the legend sits above the plot. It used to sit inside it, bottom
    # left, which looked fine in the unit test and collided with the bars the first time a shot was
    # taken of a chart whose values were small. The pixels are the test for this.
    left, right, top, bottom = 54, 16, 42, 46
    plot_w = width - left - right
    plot_h = height - top - bottom
    peak = max(1, *(row["leaked_chars"] or 0 for row in rows),
                *(row["first_emit_at_char"] or 0 for row in rows))
    step = plot_w / len(rows)
    bar = min(20.0, step / 3.2)

    parts = [f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fff"/>']
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = top + plot_h - fraction * plot_h
        value = round(peak * fraction)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" '
                     f'stroke="{GRID}" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="10" '
                     f'fill="{MUTED}">{value}</text>')

    for index, row in enumerate(rows):
        centre = left + step * (index + 0.5)
        for offset, key, colour in ((-bar * 0.55, "leaked_chars", DANGER),
                                    (bar * 0.55, "first_emit_at_char", COOL)):
            # A first emit of None means the client never saw a character: a zero-height bar
            # labelled "never", rather than a bar of height zero labelled 0.
            raw = row[key]
            value = 0 if raw is None else max(0, raw)
            label = "never" if raw is None else str(value)
            bar_h = plot_h * value / peak
            parts.append(
                f'<rect x="{centre + offset - bar / 2:.1f}" y="{top + plot_h - bar_h:.1f}" '
                f'width="{bar:.1f}" height="{max(bar_h, 1.0):.1f}" fill="{colour}" rx="2"/>')
            parts.append(f'<text x="{centre + offset:.1f}" y="{top + plot_h - bar_h - 4:.1f}" '
                         f'text-anchor="middle" font-size="9" fill="{MUTED}">{label}</text>')
        label = "buffer" if row["lookback"] is None else str(row["lookback"])
        parts.append(f'<text x="{centre:.1f}" y="{height - 26}" text-anchor="middle" '
                     f'font-size="10" fill="{INK}">{_escape(label)}</text>')

    parts.append(f'<text x="{left + plot_w / 2:.1f}" y="{height - 10}" text-anchor="middle" '
                 f'font-size="10" fill="{MUTED}">lookback characters (rightmost: no streaming)'
                 f'</text>')
    parts.append(f'<rect x="{left}" y="10" width="9" height="9" fill="{DANGER}"/>'
                 f'<text x="{left + 13}" y="18" font-size="10" fill="{MUTED}">'
                 f'characters of the secret leaked</text>')
    parts.append(f'<rect x="{left + 190}" y="10" width="9" height="9" fill="{COOL}"/>'
                 f'<text x="{left + 203}" y="18" font-size="10" fill="{MUTED}">'
                 f'characters before the first emit</text>')
    return _frame(width, height, "leaked characters and first-emit latency by lookback",
                  "".join(parts))


def precision_chart(series: list[dict], floor: float = 0.5,
                    width: int = 640, height: int = 250) -> str:
    """Precision against prevalence, log x, with the blocking floor drawn.

    `series` entries are `{"detector": name, "points": [(prevalence, precision), ...]}`. The floor
    is a dashed rule rather than a shaded region: shading implies a gradient of acceptability, and
    the argument in `evaluate.justify` is a threshold.
    """
    if not series:
        return ""
    left, right, top, bottom = 46, 120, 20, 44
    plot_w = width - left - right
    plot_h = height - top - bottom
    prevalences = sorted({point[0] for entry in series for point in entry["points"]})
    if not prevalences:
        return ""
    lo, hi = math.log10(min(prevalences)), math.log10(max(prevalences))
    span = (hi - lo) or 1.0

    def x_of(prevalence: float) -> float:
        return left + plot_w * (math.log10(prevalence) - lo) / span

    def y_of(precision: float) -> float:
        return top + plot_h - plot_h * min(1.0, max(0.0, precision))

    parts = [f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fff"/>']
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = top + plot_h - fraction * plot_h
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" '
                     f'stroke="{GRID}" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="10" '
                     f'fill="{MUTED}">{fraction:.0%}</text>')
    for prevalence in prevalences:
        x = x_of(prevalence)
        parts.append(f'<text x="{x:.1f}" y="{height - 26}" text-anchor="middle" font-size="10" '
                     f'fill="{INK}">{prevalence:g}</text>')

    floor_y = y_of(floor)
    parts.append(f'<line x1="{left}" y1="{floor_y:.1f}" x2="{left + plot_w}" y2="{floor_y:.1f}" '
                 f'stroke="{DANGER}" stroke-width="1.4" stroke-dasharray="5 4"/>')
    parts.append(f'<text x="{left + plot_w - 4}" y="{floor_y - 5:.1f}" text-anchor="end" '
                 f'font-size="10" fill="{DANGER}">block floor {floor:.0%}</text>')

    palette = (COOL, SAFE, WARN, INK, MUTED)
    for index, entry in enumerate(series):
        colour = palette[index % len(palette)]
        points = sorted(entry["points"], key=lambda point: point[0], reverse=True)
        path = " ".join(f"{'M' if position == 0 else 'L'}{x_of(p):.1f},{y_of(q):.1f}"
                        for position, (p, q) in enumerate(points))
        parts.append(f'<path d="{path}" fill="none" stroke="{colour}" stroke-width="2"/>')
        for prevalence, precision in points:
            parts.append(f'<circle cx="{x_of(prevalence):.1f}" cy="{y_of(precision):.1f}" r="3" '
                         f'fill="{colour}"/>')
        label_y = top + 12 + index * 15
        parts.append(f'<rect x="{left + plot_w + 12}" y="{label_y - 8}" width="9" height="9" '
                     f'fill="{colour}"/>')
        parts.append(f'<text x="{left + plot_w + 25}" y="{label_y}" font-size="10" fill="{MUTED}">'
                     f'{_escape(entry["detector"])}</text>')

    parts.append(f'<text x="{left + plot_w / 2:.1f}" y="{height - 8}" text-anchor="middle" '
                 f'font-size="10" fill="{MUTED}">attack prevalence (log scale)</text>')
    return _frame(width, height, "precision against prevalence", "".join(parts))


def redos_chart(points: list[tuple[int, float]], budget_ms: float,
                width: int = 640, height: int = 240) -> str:
    """Match time against input length on a log axis, with the detector budget drawn across it.

    The chart exists to make one crossing unmissable: the input length at which a quadratic-or-worse
    pattern stops answering inside its budget, which is the input length at which a fail-open route
    is switched off by an attacker.
    """
    if not points:
        return ""
    left, right, top, bottom = 58, 20, 22, 46
    plot_w = width - left - right
    plot_h = height - top - bottom
    values = [max(ms, 0.0005) for _, ms in points]
    lo = math.floor(math.log10(min(*values, budget_ms)))
    hi = math.ceil(math.log10(max(*values, budget_ms)))
    span = (hi - lo) or 1.0
    lengths = [n for n, _ in points]
    n_lo, n_hi = min(lengths), max(lengths)
    n_span = (n_hi - n_lo) or 1

    def x_of(n: int) -> float:
        return left + plot_w * (n - n_lo) / n_span

    def y_of(ms: float) -> float:
        return top + plot_h - plot_h * (math.log10(max(ms, 0.0005)) - lo) / span

    parts = [f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fff"/>']
    # Decade lines always, decade *labels* only when there is room. Six orders of magnitude in 170
    # pixels puts consecutive labels a few pixels apart, and the first screenshot of this chart had
    # "0.001 ms" and "0.0001 ms" printed on top of each other. A skipped label is legible; two
    # overlapping ones are not.
    last_label_y = None
    for power in range(int(lo), int(hi) + 1):
        y = y_of(10.0 ** power)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" '
                     f'stroke="{GRID}" stroke-width="1"/>')
        if last_label_y is not None and abs(last_label_y - y) < 14:
            continue
        last_label_y = y
        label = f"{10.0 ** power:g} ms"
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="10" '
                     f'fill="{MUTED}">{label}</text>')

    budget_y = y_of(budget_ms)
    parts.append(f'<line x1="{left}" y1="{budget_y:.1f}" x2="{left + plot_w}" y2="{budget_y:.1f}" '
                 f'stroke="{DANGER}" stroke-width="1.4" stroke-dasharray="5 4"/>')
    parts.append(f'<text x="{left + 4}" y="{budget_y - 5:.1f}" font-size="10" fill="{DANGER}">'
                 f'detector budget {budget_ms:g} ms</text>')

    path = " ".join(f"{'M' if index == 0 else 'L'}{x_of(n):.1f},{y_of(ms):.1f}"
                    for index, (n, ms) in enumerate(sorted(points)))
    parts.append(f'<path d="{path}" fill="none" stroke="{COOL}" stroke-width="2"/>')
    for n, ms in sorted(points):
        over = ms > budget_ms
        parts.append(f'<circle cx="{x_of(n):.1f}" cy="{y_of(ms):.1f}" r="3.4" '
                     f'fill="{DANGER if over else COOL}"/>')
        parts.append(f'<text x="{x_of(n):.1f}" y="{height - 26}" text-anchor="middle" '
                     f'font-size="10" fill="{INK}">{n}</text>')

    parts.append(f'<text x="{left + plot_w / 2:.1f}" y="{height - 8}" text-anchor="middle" '
                 f'font-size="10" fill="{MUTED}">input characters (time on a log scale)</text>')
    return _frame(width, height, "match time against input length", "".join(parts))


__all__ = ["leak_chart", "precision_chart", "redos_chart"]
