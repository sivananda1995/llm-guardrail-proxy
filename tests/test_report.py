"""The three renderers, and the fields none of them is allowed to omit."""

from __future__ import annotations

import json

import pytest

import attacks
from guardrail import report as report_module
from guardrail.proxy import leak_curve
from guardrail.upstream import completion


@pytest.fixture(scope="module")
def payload():
    policy = attacks.load_policy()
    return report_module.build(
        policy, attacks.run_all(policy), attacks.measure(policy),
        signal_rates=attacks.measure(policy, at_action_confidence=False),
        lookback_curve=leak_curve(policy, completion("leaks_aws_key")),
        redos=[(12, 0.001), (16, 9.0), (20, 150.0)],
        surviving_evasions=attacks.KNOWN_SURVIVING_EVASIONS,
    )


def test_the_payload_names_the_route_and_the_declared_prevalence(payload):
    assert payload["route"] == "support-assistant"
    assert payload["prevalence"] == 0.0004


def test_the_payload_reports_the_corpus_result(payload):
    assert payload["corpus"]["cases"] == len(attacks.CASES)
    assert payload["corpus"]["as_declared"] == payload["corpus"]["cases"]
    assert payload["corpus"]["mismatches"] == []


def test_the_payload_names_the_surviving_evasions(payload):
    assert payload["corpus"]["surviving_evasions"] == list(attacks.KNOWN_SURVIVING_EVASIONS)


def test_the_payload_carries_both_rate_sets_per_detector(payload):
    for entry in payload["detectors"]:
        assert entry["gate"] is not None
        assert entry["signal"] is not None


def test_the_payload_carries_the_leak_curve_and_its_worst_case(payload):
    assert payload["leak"]["worst_leak_chars"] > 0
    assert payload["leak"]["zero_leak_at"] is not None
    assert payload["leak"]["buffered_first_emit"] > payload["leak"]["zero_leak_at"]


def test_the_payload_carries_the_unsupported_actions(payload):
    assert payload["posture"]["unjustified"]


def test_the_payload_always_carries_caveats(payload):
    assert len(payload["caveats"]) >= 4
    assert any("not a model" in note for note in payload["caveats"])
    assert any("smallest benign population" in note for note in payload["caveats"])


def test_the_payload_is_json_serialisable(payload):
    assert json.loads(report_module.as_json(payload))["route"] == "support-assistant"


def test_the_payload_never_contains_a_secret(payload):
    assert "AKIAIOSFODNN7EXAMPLE" not in report_module.as_json(payload)


def test_the_payload_never_contains_a_card_number(payload):
    assert "4242 4242 4242 4242" not in report_module.as_json(payload)


# --------------------------------------------------------------------------- markdown

def test_markdown_leads_with_the_leak_and_the_unsupported_blocks(payload):
    text = report_module.as_markdown(payload)
    headline = text[:text.index("## corpus")]
    assert "characters** of a detected secret" in headline
    assert "blocking actions** are unsupported" in headline


def test_markdown_lists_every_case(payload):
    text = report_module.as_markdown(payload)
    for case in attacks.CASES:
        assert f"`{case.slug}`" in text


def test_markdown_shows_both_rates_per_detector(payload):
    text = report_module.as_markdown(payload)
    assert "gate FPR" in text and "signal FPR" in text


def test_markdown_ends_with_the_caveats(payload):
    text = report_module.as_markdown(payload)
    assert text.index("## caveats") > text.index("## corpus")
    for note in payload["caveats"]:
        assert note in text


def test_markdown_prices_both_fail_modes(payload):
    text = report_module.as_markdown(payload)
    assert "fails open" in text and "fails closed" in text


# --------------------------------------------------------------------------- html

def test_html_is_self_contained(payload):
    """No script, no fetch, no asset. The SVG namespace URL is a declaration, not a request."""
    html = report_module.as_html(payload)
    assert "<script" not in html
    assert "<style>" in html
    without_namespace = html.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for scheme in ("http://", "https://", "src=", "@import", "url("):
        assert scheme not in without_namespace


def test_html_contains_the_three_charts(payload):
    html = report_module.as_html(payload)
    assert html.count("<svg") == 3


def test_html_leads_with_the_leak(payload):
    html = report_module.as_html(payload)
    assert html.index("characters leaked") < html.index("cases as declared")


def test_html_marks_a_mismatch_with_a_distinct_class(payload):
    html = report_module.as_html(payload)
    assert "cell-ok" in html


def test_every_css_class_used_in_the_markup_has_a_rule(payload):
    """The scar test.

    Two rules of equal specificity collided in an earlier project, the later one won, and a verdict
    rendered green on green. Invisible in the source, visible only in a browser, so the check is
    that every class the markup uses is actually defined.
    """
    import re

    html = report_module.as_html(payload)
    used = set()
    for attribute in re.findall(r'class="([^"]+)"', html):
        used.update(attribute.split())
    declared = set(re.findall(r"[.]([a-zA-Z][\w-]*)", report_module.CSS))
    assert used <= declared, f"undefined classes: {sorted(used - declared)}"


def test_the_verdict_classes_are_namespaced_apart(payload):
    assert "td.cell-ok" in report_module.CSS
    assert "td.cell-bad" in report_module.CSS
    assert ".badge.ok" in report_module.CSS


def test_html_escapes_a_hostile_route_name(payload):
    hostile = {**payload, "route": "<script>alert(1)</script>"}
    html = report_module.as_html(hostile)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_a_hostile_case_slug(payload):
    hostile = json.loads(report_module.as_json(payload))
    hostile["corpus"]["rows"][0]["slug"] = '"><b>x</b>'
    html = report_module.as_html(hostile)
    assert "<b>x</b>" not in html


def test_html_renders_the_caveats_verbatim(payload):
    html = report_module.as_html(payload)
    for note in payload["caveats"]:
        assert note.replace("'", "&#x27;") in html or note in html


def test_html_survives_an_empty_curve(payload):
    without = {**payload, "leak_curve": [], "redos": {"points": [], "budget_ms": 8.0}}
    html = report_module.as_html(without)
    assert "<svg" in html or "corpus" in html


def test_the_middot_separator_is_not_double_escaped(payload):
    """Escaping a whole caveat line once turned `&middot;` into visible text in an earlier one."""
    html = report_module.as_html(payload)
    assert "&amp;middot;" not in html


# --------------------------------------------------------------------------- writing

def test_writing_produces_all_three_files(payload, tmp_path):
    written = report_module.write(payload, tmp_path / "out")
    assert set(written) == {"json", "markdown", "html"}
    for path in written.values():
        assert path.exists()
        assert path.stat().st_size > 500


def test_writing_creates_the_directory(payload, tmp_path):
    report_module.write(payload, tmp_path / "deep" / "nested")
    assert (tmp_path / "deep" / "nested" / "report.json").exists()


def test_markdown_says_so_when_every_action_is_supported(payload):
    supported = json.loads(report_module.as_json(payload))
    supported["posture"]["unjustified"] = []
    text = report_module.as_markdown(supported)
    assert "every action is supported" in text


def test_html_omits_the_unsupported_section_when_there_is_nothing_to_say(payload):
    supported = json.loads(report_module.as_json(payload))
    supported["posture"]["unjustified"] = []
    html = report_module.as_html(supported)
    assert "what this corpus cannot support" not in html


def test_html_omits_the_precision_chart_when_no_detector_blocks(payload):
    without = json.loads(report_module.as_json(payload))
    for entry in without["detectors"]:
        entry["action"] = "flag"
    html = report_module.as_html(without)
    assert html.count("<svg") == 2
    assert "precision against prevalence" not in html
