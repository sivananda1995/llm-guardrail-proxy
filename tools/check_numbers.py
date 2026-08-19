"""Fail the build when a document quotes a number this repository no longer measures.

The naive version of this tool searches each document for the digits of each metric and passes if it
finds them. That version shipped in an earlier project in this series and it passed while three
claims were false, because the digits were present in a sentence that had come to mean something
else: "10 queries" found in a line that now said "10 rows".

Three rules fix it.

**Anchors.** A metric can declare the wording that must surround it. `"{} hops from the edit"` with
the metric at 2 requires the document to contain that phrase; finding a bare 2 somewhere on the page
is not enough. Anchors live in `tools/collect_metrics.py` next to the measurement, so the phrase and
the number get edited together.

**Anchors have to survive line wrapping.** A phrase longer than a few words will span a newline in a
wrapped markdown document and then match nothing, while the prose it was guarding is perfectly
correct. That happened in the project this tool came from, and the rule it produced is that an
anchor names the number and two or three words, never a whole clause.

**Small numbers must be anchored.** A metric below six is so likely to appear by coincidence, in a
version, a heading, a list, that matching its digits proves nothing. Those are checked only through
their anchors, and a small metric with no anchor is reported as a gap in the receipts rather than
silently skipped.

**A number in the README that matches no metric is reported.** That is the other direction of the
same claim: not "is this figure current" but "is anything here unmeasured". Code blocks, inline code
spans and HTML attributes are excluded, because an example invocation is allowed to contain
`--parallelism 10` and a table span is not a claim about the data.

    python tools/check_numbers.py --show-gaps
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Below this, a bare digit match is coincidence rather than evidence.
ANCHOR_REQUIRED_BELOW = 6


def variants(value: object) -> list[str]:
    """Every spelling a document might reasonably use for one measured value."""
    if isinstance(value, bool):
        return ["yes" if value else "no", str(value).lower()]
    if isinstance(value, int):
        return [str(value), f"{value:,}"]
    if isinstance(value, float):
        rounded = round(value, 1)
        out = [f"{value}", f"{rounded}", f"{rounded:,}"]
        if rounded == int(rounded):
            out.append(str(int(rounded)))
        return out
    return [str(value)]


def load_documents(names: list[str]) -> dict[str, str]:
    documents: dict[str, str] = {}
    for name in names:
        path = ROOT / name
        if not path.exists():
            raise SystemExit(f"{name} is on the checked-documents list but does not exist")
        documents[name] = path.read_text()
    return documents


def find_anywhere(documents: dict[str, str], needle: str) -> list[str]:
    return [name for name, text in documents.items() if needle in text]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default="docs/metrics.json")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--show-gaps", action="store_true",
                        help="list the metrics that are too small to check on digits alone")
    args = parser.parse_args(argv)

    payload = json.loads((ROOT / args.metrics).read_text())
    metrics = payload["metrics"]
    anchors = payload.get("anchors", {})
    documents = load_documents(payload["checked_documents"])

    problems: list[str] = []
    checked_phrases = 0
    checked_digits = 0
    unguarded: list[str] = []

    for name, value in sorted(metrics.items()):
        spellings = variants(value)
        templates = anchors.get(name) or []

        if templates:
            # The templates are *alternatives*: a document may say "258 tests" or "258 passing
            # tests" and either satisfies the claim. Requiring all of them was the first version of
            # this rule and it failed the build for prose that was perfectly correct, which is the
            # fastest way to teach somebody to pass --no-verify.
            checked_phrases += 1
            malformed = [tpl for tpl in templates if tpl.count("{}") != 1]
            if malformed:
                problems.append(
                    f"{name}: the anchor {malformed[0]!r} must contain exactly one {{}} so the "
                    "measured value can be substituted into it"
                )
                continue
            wanted = [tpl.format(spelling) for tpl in templates for spelling in spellings]
            if not any(find_anywhere(documents, phrase) for phrase in wanted):
                options = " or ".join(repr(tpl.format(spellings[0])) for tpl in templates)
                problems.append(
                    f"{name}: no document contains {options}. The measured value is {value!r}; "
                    "either the prose is stale or the anchor is."
                )
            continue

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if abs(value) < ANCHOR_REQUIRED_BELOW:
                unguarded.append(
                    f"{name} = {value!r} is smaller than {ANCHOR_REQUIRED_BELOW} and has no "
                    "anchor phrase, so matching its digits would prove nothing"
                )
                continue
            checked_digits += 1
            if not any(find_anywhere(documents, spelling) for spelling in spellings):
                # Not every metric has to be quoted; only ones that are quoted have to be right. A
                # metric nobody mentions is not a failure, so this is silent by design.
                pass

    # Any number in the README that looks like a claim and matches no metric is worth reporting,
    # because it is a number nothing re-measures. Code blocks are excluded: an example invocation is
    # allowed to contain a made-up row count, and flagging it would train the reader to ignore this
    # section.
    readme = re.sub(r"```.*?```", "", documents.get("README.md", ""), flags=re.DOTALL)
    # Inline code spans are excluded for the same reason: `--referee-sample 200` is an invocation,
    # not a claim, and flagging it teaches the reader to skip this section.
    readme = re.sub(r"`[^`]*`", "", readme)
    # HTML attributes carry layout numbers (an image width, a table span) that are not claims about
    # the data, so they go too. Same judgement as the two above.
    readme = re.sub(r"<[^>]+>", "", readme)
    known = {spelling for value in metrics.values() for spelling in variants(value)}
    suspicious = []
    for match in re.finditer(r"(?<![\w.$/^-])(\d[\d,]{2,11})(?![\w.%-])", readme):
        token = match.group(1)
        if token in known or token.replace(",", "") in {s.replace(",", "") for s in known}:
            continue
        line = readme[: match.start()].count("\n") + 1
        suspicious.append(f"README.md:{line} quotes {token}, which no metric measures")

    if problems:
        print(f"{len(problems)} stale claim(s):\n")
        for problem in problems:
            print(f"  x {problem}")
    if unguarded and not args.quiet:
        print(
            f"\n{len(unguarded)} metric(s) are below {ANCHOR_REQUIRED_BELOW} and unanchored, so "
            "nothing checks them" + (":" if args.show_gaps else " (--show-gaps to list)")
        )
        if args.show_gaps:
            for gap in unguarded:
                print(f"  . {gap}")
    if suspicious and not args.quiet:
        print(f"\n{len(suspicious)} number(s) in the README that nothing re-measures:")
        for item in suspicious[:20]:
            print(f"  ? {item}")

    if not problems:
        print(
            f"ok: {checked_phrases} anchored phrase(s) and {checked_digits} value(s) checked "
            f"across {len(documents)} document(s)"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
