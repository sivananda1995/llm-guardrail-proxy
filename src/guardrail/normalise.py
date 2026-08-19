"""The canonical form the guardrail and the model must agree on, and why disagreement is the bypass.

A guardrail reads a string and decides. A model reads a string and generates. If those are not the
*same* string, every difference between them is a bypass, and the differences are not exotic:
they are Unicode compatibility forms, homoglyphs, zero-width characters and base64.

The failure has a shape worth naming, because it is the same shape as a training and serving skew:
two implementations of "the text" that drift apart, with the guardrail confident and wrong. The
remedy is also the same: declare the canonicalisation once, apply it on both sides, and report what
it changed rather than doing it silently.

## What this does and deliberately does not do

**Does.** NFKC folding, so `ｉｇｎｏｒｅ` and `ignore` are the same string. Zero-width and
bidi control removal, so `ig<ZWJ>nore` collapses. A curated homoglyph fold for the Cyrillic and
Greek letters that look like Latin ones. Case folding. Whitespace collapse. One optional round of
base64 decoding, depth limited.

**Does not.** Translate, transliterate whole scripts, or attempt semantic normalisation. Those are
where a normaliser starts changing meaning, and a normaliser that changes meaning gives the model a
different string again in the other direction.

## The measured claim

`experiments/bypass_matrix.py` runs every evasion in the corpus against a raw-string checker and
against this normaliser, and reports how many get through each. The point of publishing both columns
is that the normaliser is the fix and it is not a complete fix: an evasion that survives
canonicalisation is a real finding rather than an embarrassment, and hiding the column would make
the tool look better and be less useful.

## The cost, stated because normalisation is not free

Every transform here runs on every request, in the request path. `experiments/latency_budget.py`
measures it. It is cheap compared to a model call and it is not free, and the reason it is worth
naming is that a normaliser is the sort of thing that gets three more passes added to it over a year
until it is the slowest part of the proxy.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

#: Characters with no width that can sit inside a word and split it for a naive matcher. Zero-width
#: joiner and non-joiner, the zero-width space, the byte-order mark, and the bidi overrides that can
#: reverse displayed text without changing the codepoint order.
INVISIBLE = "".join((
    # Written as escapes rather than as the characters themselves, deliberately. A literal zero-
    # width joiner in source is invisible to a reviewer, survives a copy and paste that mangles it,
    # and makes this constant impossible to audit. The linter agrees, which is how this got fixed.
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # byte-order mark
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi embedding and override
    "\u2066", "\u2067", "\u2068", "\u2069",  # bidi isolates
    "\u00ad",  # soft hyphen
))

#: Homoglyphs NFKC does not fold, because they are genuinely different letters rather than
#: compatibility variants. Cyrillic а is not Latin a to Unicode and is to a reader, which is the
#: whole technique. Curated rather than generated: a generated table folds letters that a human
#: would not confuse and starts changing words in languages that use them.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p",
    "Τ": "t", "Υ": "y", "Χ": "x", "ο": "o", "α": "a",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
}

_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)
_INVISIBLE_TABLE = str.maketrans(dict.fromkeys(INVISIBLE))
_WHITESPACE = re.compile(r"\s+")

#: A base64 run long enough to be worth decoding. Shorter runs are ordinary words: "based" is not
#: base64 and decoding it produces noise that a detector then has to ignore.
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

#: How many rounds of base64 to unwrap. One is the honest default: two rounds is already a signal in
#: itself, and an unbounded loop on attacker-controlled input is a denial of service.
MAX_BASE64_DEPTH = 2


@dataclass(frozen=True)
class Normalised:
    """The canonical text, and every transform that changed it.

    `applied` is the part that matters operationally. A request whose canonical form differs from
    what was sent is a request that was written to be read two ways, and that is worth logging even
    when no detector fires, because it is the cheapest early signal there is.
    """

    text: str
    original: str
    applied: tuple[str, ...] = ()
    #: Text recovered from base64, kept separately so a detector can scan it without the decoded
    #: bytes being spliced into the prompt the model sees.
    decoded: tuple[str, ...] = field(default_factory=tuple)

    @property
    def changed(self) -> bool:
        return self.text != self.original

    @property
    def suspicious(self) -> bool:
        """Whether the transforms that fired are ones a benign request rarely needs.

        Case folding and whitespace collapse fire on almost everything. Invisible-character removal,
        homoglyph folding and base64 decoding do not, and a request that needed all three was
        written by somebody who knew a filter was there.
        """
        return bool({"invisible", "homoglyphs", "base64"} & set(self.applied))

    def scannable(self) -> tuple[str, ...]:
        """Everything a detector should look at: canonical text plus anything decoded out of it."""
        return (self.text, *self.decoded)

    def to_json(self) -> dict:
        return {
            "changed": self.changed,
            "suspicious": self.suspicious,
            "applied": list(self.applied),
            "decoded_segments": len(self.decoded),
            "original_length": len(self.original),
            "canonical_length": len(self.text),
        }


def _decode_base64(text: str, depth: int) -> tuple[str, ...]:
    """Text recovered from base64 runs, at most `depth` rounds deep.

    Only runs that decode to mostly printable text are kept. A random hex blob is valid base64 and
    decodes to bytes that are not text, and feeding those to a detector produces noise that looks
    like a finding.
    """
    if depth <= 0:
        return ()
    found: list[str] = []
    for match in BASE64_RUN.finditer(text):
        candidate = match.group(0)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(character.isprintable() or character.isspace() for character in decoded)
        if not decoded or printable / len(decoded) < 0.9:
            continue
        found.append(decoded)
        found.extend(_decode_base64(decoded, depth - 1))
    return tuple(found)


def canonical(text: str, *, strip_invisible: bool = True, nfkc: bool = True,
              fold_homoglyphs: bool = True, fold_case: bool = True,
              collapse_whitespace: bool = True, decode_base64: bool = True,
              depth: int = MAX_BASE64_DEPTH) -> Normalised:
    """The canonical form, plus a record of which transforms changed anything.

    Order matters and every step of it is load-bearing:

    1. strip invisibles, so they cannot survive inside a homoglyph sequence or split a base64 run;
    2. NFKC, which folds compatibility variants;
    3. homoglyphs, which NFKC does not fold because they are different letters;
    4. **base64, before case folding**: base64 is case sensitive and folding first destroys it;
    5. case;
    6. whitespace.

    Steps 1 and 4 are the two an attacker attacks. Decoding before invisible-stripping loses a run
    split by a zero-width joiner; decoding after case folding loses every run there is.

    Every step has a keyword that switches it off, all defaulting on, and nothing in the request
    path ever passes one. They exist so `experiments/bypass_matrix.py` can measure which step is
    load-bearing for which evasion, and the answer is not "all of them a bit": turning off invisible
    stripping loses exactly the zero-width family and nothing else. A normaliser missing one step is
    not slightly weaker, it is fully bypassable by one family, and that is only visible if the steps
    can be measured apart.
    """
    original = text
    applied: list[str] = []

    if strip_invisible:
        stripped = text.translate(_INVISIBLE_TABLE)
        if stripped != text:
            applied.append("invisible")
        text = stripped

    if nfkc:
        folded = unicodedata.normalize("NFKC", text)
        if folded != text:
            applied.append("nfkc")
        text = folded

    if fold_homoglyphs:
        unglyphed = text.translate(_HOMOGLYPH_TABLE)
        if unglyphed != text:
            applied.append("homoglyphs")
        text = unglyphed

    # Base64 is decoded here, before case folding, and the order is a bug fix rather than a
    # preference. Base64 is case sensitive: `casefold()` turns a valid payload into a run that
    # either fails to decode or decodes to noise, so a normaliser that folds case first can never
    # see an encoded payload at all. The first version of this function folded case first and
    # reported zero base64 findings on a corpus that contained several, which is the quietest kind
    # of wrong.
    decoded = _decode_base64(text, depth) if decode_base64 else ()
    if decoded:
        applied.append("base64")

    if fold_case:
        lowered = text.casefold()
        if lowered != text:
            applied.append("case")
        text = lowered

    if collapse_whitespace:
        collapsed = _WHITESPACE.sub(" ", text).strip()
        if collapsed != text:
            applied.append("whitespace")
        text = collapsed

    return Normalised(text=text, original=original, applied=tuple(applied), decoded=decoded)
