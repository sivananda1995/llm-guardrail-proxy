"""Screenshot the real report, so the images in the README are evidence rather than decoration.

Nothing here is staged. The report comes from `guard report`, which runs the whole corpus through
the real proxy, measures the leak curve at every lookback and times the naive pattern. This script
opens that file in a real browser and photographs it.

The browser is doing more than taking a picture. After each shot it reads back the *computed* style
of the verdict badge and asserts that the text and background differ, because in two earlier
projects in this series a badge class and a table-cell class collided at equal CSS specificity, the
later rule won, and the verdict rendered green on green. The Python was correct, the HTML was
correct, the tests passed, and the headline number was invisible. A screenshot tool that can see the
pixels is the right place to check that.

    python tools/capture_screenshots.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "report"
SHOTS = ROOT / "docs" / "screenshots"

# (report file, output name, the section to frame from, the section to stop before, what it shows)
# Each shot is framed by scrolling to a named heading and photographing from there, rather than by a
# pixel offset. A hard-coded crop drifts silently the first time a paragraph gets longer, and then
# the README shows half a chart. `None` for the start means the top of the page, and `None` for the
# end means the bottom.
TARGETS = [
    ("report.html", "report-headline-and-leak.png", None,
     "precision against prevalence, at the rate this corpus can support",
     "the two numbers that decide it: characters leaked, and blocks the corpus cannot support"),
    ("report.html", "report-precision-and-redos.png",
     "precision against prevalence, at the rate this corpus can support", "corpus",
     "precision falling below the blocking floor, and the pattern that blows its budget"),
    ("report.html", "report-corpus-and-posture.png", "corpus", "the fail mode, priced",
     "all 28 labelled cases, and each detector as a gate and as a signal"),
    ("report.html", "report-failmode-and-caveats.png", "the fail mode, priced", None,
     "what failing open costs in coverage, and what the run did not establish"),
]


def _heading_top(page, text: str) -> int | None:
    """The document offset of a section heading, or None when the section is gone."""
    return page.evaluate(
        """(wanted) => {
          for (const h of document.querySelectorAll('h2')) {
            if (h.textContent.trim() === wanted) {
              return Math.round(h.getBoundingClientRect().top + window.scrollY) - 18;
            }
          }
          return null;
        }""",
        text,
    )


def ensure_report() -> None:
    """Build the report if it is missing. A shot of a stale report is worse than no shot."""
    if (REPORT / "report.html").exists():
        return
    print("no report found; running guard report first")
    subprocess.run([sys.executable, "-m", "guardrail.cli", "report", "--out", "docs/report"],
                   cwd=ROOT, check=False, env=_env())


def _env() -> dict:
    """The environment a subprocess needs, because `attacks/` is outside the installed package."""
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = f"src:.:{env.get('PYTHONPATH', '')}"
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--width", type=int, default=1240)
    parser.add_argument("--scale", type=int, default=2, help="device pixel ratio")
    args = parser.parse_args(argv)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "playwright is not installed, so no screenshot can be taken:\n"
            "  pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 2

    ensure_report()
    SHOTS.mkdir(parents=True, exist_ok=True)
    manifest = []
    problems: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for source, name, start, until, caption in TARGETS:
            path = REPORT / source
            if not path.exists():
                problems.append(f"{source} was not produced by guard report")
                continue
            page = browser.new_page(
                viewport={"width": args.width, "height": 1000},
                device_scale_factor=args.scale,
            )
            page.goto(path.as_uri())
            page.wait_for_load_state("load")
            top = _heading_top(page, start) if start else 0
            bottom = _heading_top(page, until) if until else page.evaluate(
                "() => document.body.scrollHeight")
            if top is None or bottom is None:
                problems.append(f"{name}: the report has no heading called "
                                f"{start if top is None else until!r}")
                page.close()
                continue

            # The check the pixels are for: a verdict nobody can read is not a verdict.
            contrast = page.evaluate(
                """() => {
                  const badge = document.querySelector('.badge');
                  if (!badge) return null;
                  const style = getComputedStyle(badge);
                  return {
                    text: badge.textContent.trim(),
                    colour: style.color,
                    background: style.backgroundColor,
                    visible: badge.offsetWidth > 0 && badge.offsetHeight > 0,
                  };
                }"""
            )
            if contrast is None:
                problems.append(f"{name}: no verdict badge in the page")
            else:
                if contrast["colour"] == contrast["background"]:
                    problems.append(
                        f"{name}: the verdict badge is {contrast['colour']} on "
                        f"{contrast['background']}, invisible"
                    )
                if not contrast["visible"]:
                    problems.append(f"{name}: the verdict badge has no size")

            target = SHOTS / name
            # `full_page` is required even though a clip is given: without it Chromium clamps the
            # clip to the viewport, and every shot came out exactly one viewport tall with the
            # bottom of the section missing.
            page.screenshot(path=str(target), full_page=True, clip={
                "x": 0, "y": top, "width": args.width, "height": bottom - top,
            })
            page.close()
            manifest.append(
                {
                    "image": f"docs/screenshots/{name}",
                    "from": f"docs/report/{source}",
                    "caption": caption,
                    "framed": {"from": start or "top of page", "to": until or "end of page"},
                    "badge": contrast,
                    "bytes": target.stat().st_size,
                }
            )
            print(f"{name:32} {target.stat().st_size / 1024:6.0f} KB  {caption}")
        browser.close()

    (SHOTS / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    if problems:
        print("\nproblems:", file=sys.stderr)
        for problem in problems:
            print(f"  x {problem}", file=sys.stderr)
        return 1
    print(f"\n{len(manifest)} screenshot(s) written to docs/screenshots/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
