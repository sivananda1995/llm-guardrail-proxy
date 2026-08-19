"""The inline SVG. Structural assertions only: shape, labels, and no network."""

from __future__ import annotations

import pytest

from guardrail.charts import leak_chart, precision_chart, redos_chart

CURVE = [
    {"lookback": 0, "leaked_chars": 16, "first_emit_at_char": 9},
    {"lookback": 8, "leaked_chars": 8, "first_emit_at_char": 9},
    {"lookback": 96, "leaked_chars": 0, "first_emit_at_char": 99},
    {"lookback": None, "leaked_chars": 0, "first_emit_at_char": 274},
]
SERIES = [{"detector": "secret_pattern", "points": [(0.5, 0.97), (0.0001, 0.0034)]}]
POINTS = [(12, 0.001), (16, 9.0), (20, 150.0), (24, 2500.0)]


@pytest.mark.parametrize("svg", [
    leak_chart(CURVE),
    precision_chart(SERIES),
    redos_chart(POINTS, 8.0),
])
def test_every_chart_is_a_single_svg_element(svg):
    assert svg.startswith("<svg")
    assert svg.endswith("</svg>")
    assert svg.count("<svg") == 1


@pytest.mark.parametrize("svg", [
    leak_chart(CURVE),
    precision_chart(SERIES),
    redos_chart(POINTS, 8.0),
])
def test_no_chart_fetches_anything(svg):
    for scheme in ("http://", "https://", "src=", "<image", "<script"):
        assert scheme not in svg.replace('xmlns="http://www.w3.org/2000/svg"', "")


@pytest.mark.parametrize("svg", [
    leak_chart(CURVE),
    precision_chart(SERIES),
    redos_chart(POINTS, 8.0),
])
def test_every_chart_has_a_title_for_a_screen_reader(svg):
    assert "<title>" in svg
    assert 'role="img"' in svg


def test_an_empty_series_renders_nothing_rather_than_an_empty_frame():
    assert leak_chart([]) == ""
    assert precision_chart([]) == ""
    assert redos_chart([], 8.0) == ""


def test_the_leak_chart_labels_the_buffered_column():
    assert ">buffer<" in leak_chart(CURVE)


def test_the_leak_chart_prints_every_value():
    svg = leak_chart(CURVE)
    for row in CURVE:
        assert f'>{row["leaked_chars"]}<' in svg


def test_the_leak_chart_has_two_series_in_its_legend():
    svg = leak_chart(CURVE)
    assert "characters of the secret leaked" in svg
    assert "characters before the first emit" in svg


def test_the_leak_chart_labels_a_response_the_client_never_saw():
    never = [{"lookback": 96, "leaked_chars": 0, "first_emit_at_char": None}]
    assert ">never<" in leak_chart(never)


def test_the_leak_chart_survives_an_all_zero_curve():
    flat = [{"lookback": 96, "leaked_chars": 0, "first_emit_at_char": 0}]
    assert "<svg" in leak_chart(flat)


def test_the_precision_chart_draws_and_labels_the_block_floor():
    svg = precision_chart(SERIES, floor=0.5)
    assert "block floor 50%" in svg
    assert "stroke-dasharray" in svg


def test_the_precision_chart_names_every_detector():
    svg = precision_chart([
        {"detector": "a", "points": [(0.5, 0.9), (0.01, 0.1)]},
        {"detector": "b", "points": [(0.5, 0.8), (0.01, 0.05)]},
    ])
    assert ">a<" in svg and ">b<" in svg


def test_the_precision_chart_says_the_axis_is_logarithmic():
    assert "log scale" in precision_chart(SERIES)


def test_the_precision_chart_survives_a_single_prevalence():
    svg = precision_chart([{"detector": "a", "points": [(0.5, 0.9)]}])
    assert "<svg" in svg


def test_the_precision_chart_ignores_a_series_with_no_points():
    assert precision_chart([{"detector": "a", "points": []}]) == ""


def test_the_redos_chart_draws_the_budget():
    assert "detector budget 8 ms" in redos_chart(POINTS, 8.0)


def test_the_redos_chart_says_the_axis_is_logarithmic():
    assert "log scale" in redos_chart(POINTS, 8.0)


def test_the_redos_chart_labels_every_input_length():
    svg = redos_chart(POINTS, 8.0)
    for length, _ in POINTS:
        assert f">{length}<" in svg


def test_the_redos_chart_survives_a_single_point():
    assert "<svg" in redos_chart([(20, 150.0)], 8.0)


def test_the_redos_chart_survives_a_zero_measurement():
    assert "<svg" in redos_chart([(12, 0.0), (16, 9.0)], 8.0)


def test_a_hostile_detector_name_is_escaped():
    svg = precision_chart([{"detector": '<script>x</script>', "points": [(0.5, 0.9), (0.1, 0.5)]}])
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_the_redos_chart_skips_a_label_rather_than_overlapping_it():
    """Six orders of magnitude in 170 pixels does not fit seven labels, and the first screenshot of
    this chart had two of them printed on top of each other.
    """
    import re

    svg = redos_chart([(12, 0.0002), (24, 2500.0)], 8.0)
    ys = [float(match) for match in re.findall(r'<text x="50" y="([\d.]+)"', svg)]
    assert ys, "the chart labels its decades"
    gaps = [abs(b - a) for a, b in zip(sorted(ys), sorted(ys)[1:], strict=False)]
    assert all(gap >= 14 for gap in gaps), f"labels {gaps} apart"


def test_the_redos_chart_still_draws_every_decade_line():
    from guardrail.charts import GRID

    svg = redos_chart([(12, 0.0002), (24, 2500.0)], 8.0)
    assert svg.count(f'stroke="{GRID}"') >= 7
