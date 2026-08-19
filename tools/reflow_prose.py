"""Rewrap over-long prose lines, verified so it cannot change what the code says.

Written after three projects in this series each hit the same problem: a repository with a 100
character limit and dense explanatory comments accumulates long lines faster than they can be fixed
by hand, and every naive rewrapper corrupts something. The specific corruptions, in order of
discovery: joining an import statement onto the line above it, dropping the `#:` prefix from a
documentation comment's continuation line, and moving a word between two adjacent string literals in
a way that changed the concatenated text by one space.

So this tool has three passes and every one of them verifies before writing:

1. **Comment blocks**, found with `tokenize` rather than a regex, so a `#` inside a string is never
touched and a markdown heading inside a docstring is never mistaken for a comment.
2. **Docstring prose**, reflowed paragraph by paragraph, leaving blank lines, list markers, tables,
indented blocks and fenced code alone. Verified by comparing the *word sequence* of every string
literal in the file before and after.
3. **String literals**, by moving trailing words into the next adjacent literal or splitting a lone
literal in two. Verified by comparing the concatenation of every string literal exactly, byte for
byte, because this pass can change text and the others cannot.

Any pass whose verification fails leaves the file untouched and says so. That is the whole value: a
rewrapper that is usually right is worse than no rewrapper, because the damage is quiet.

    python tools/reflow_prose.py            # every .py file in the repository
    python tools/reflow_prose.py --check    # report what would change and write nothing
"""

from __future__ import annotations

import argparse
import ast
import io
import pathlib
import re
import textwrap
import tokenize

LIMIT = 100
SKIP_PARTS = {"build", ".venv", "__pycache__", ".ruff_cache", ".pytest_cache"}


def literal_words(tree: ast.AST) -> list[str]:
    """Every word of every string literal, in order. Invariant for passes 1 and 2."""
    return re.findall(r"\S+", "".join(
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ))


def literal_text(tree: ast.AST) -> str:
    """Every string literal concatenated, exactly. Invariant for pass 3."""
    return "".join(node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str))


def comment_lines(text: str) -> set[int]:
    """Line numbers that are whole-line Python comments, via the tokenizer.

    The tokenizer rather than a regex, because `# not a comment` inside a string looks identical to
    a comment and a `## heading` inside a docstring looks like one too.
    """
    lines = text.split("\n")
    found: set[int] = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            whole_line = lines[token.start[0] - 1].lstrip().startswith("#")
            if token.type == tokenize.COMMENT and whole_line:
                found.add(token.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return set()
    return found


def reflow_comments(text: str) -> str:
    """Pass 1: rewrap each block of whole-line comments, keeping its `#` or `#:` prefix."""
    lines = text.split("\n")
    comments = comment_lines(text)
    if not comments:
        return text

    out: list[str] = []
    index = 0
    while index < len(lines):
        if index + 1 not in comments:
            out.append(lines[index])
            index += 1
            continue
        indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
        block: list[str] = []
        end = index
        while (end < len(lines) and end + 1 in comments
               and lines[end][:len(lines[end]) - len(lines[end].lstrip())] == indent):
            block.append(lines[end].lstrip())
            end += 1
        prefix = "#: " if block[0].startswith("#:") else "# "
        bodies = [(entry[2:] if entry.startswith("#:") else entry[1:]).strip() for entry in block]
        joined = " ".join(part for part in bodies if part)
        if not joined:
            out.extend(indent + entry for entry in block)
        else:
            wrapped = textwrap.wrap(joined, width=LIMIT - len(indent) - len(prefix)) or [""]
            out.extend(indent + prefix + part for part in wrapped)
        index = end
    return "\n".join(out)


def _reflow_body(raw: str, indent: int) -> str:
    lines, out, buffer, fenced = raw.split("\n"), [], [], False
    width = LIMIT - indent

    def flush() -> None:
        if buffer:
            out.extend(textwrap.wrap(" ".join(buffer), width=width))
            buffer.clear()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            fenced = not fenced
            out.append(line)
            continue
        if fenced:
            out.append(line)
            continue
        marker = (stripped.startswith(("-", "|", ">", "#", "1.", "2.", "3.", "4.", "5."))
                  or (stripped.startswith("*") and not stripped.startswith("**")))
        if not stripped or marker or (len(line) - len(line.lstrip())) >= 4:
            flush()
            out.append(line)
            continue
        buffer.append(stripped)
    flush()
    return "\n".join(out)


def reflow_docstrings(text: str) -> str:
    """Pass 2: reflow the prose paragraphs of every docstring, leaving structure alone."""
    lines = text.split("\n")
    tree = ast.parse(text)
    edits = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body or not isinstance(body[0], ast.Expr):
            continue
        literal = body[0].value
        if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
            continue
        start, end = literal.lineno - 1, literal.end_lineno - 1
        if end <= start or not any(len(lines[i]) > LIMIT for i in range(start, end + 1)):
            continue
        indent = len(lines[start]) - len(lines[start].lstrip())
        interior = [line[indent:] if line.startswith(" " * indent) else line
                    for line in lines[start + 1:end]]
        rebuilt = [" " * indent + '"""' + lines[start].strip()[3:]]
        rebuilt += [(" " * indent + line).rstrip()
                    for line in _reflow_body("\n".join(interior), indent).split("\n")]
        rebuilt.append(lines[end])
        edits.append((start, end, rebuilt))

    if not edits:
        return text
    new = list(lines)
    for start, end, rebuilt in sorted(edits, reverse=True):
        new[start:end + 1] = rebuilt
    return "\n".join(new)


LONE = re.compile(r'^(\s*)(f?)(["\'])((?:(?!\3).|\\.)*)\3([,)\s]*)$')


def reflow_literals(text: str) -> str:
    """Pass 3: move trailing words off an over-long literal, splitting it if it stands alone."""
    lines = text.split("\n")
    out: list[str] = []
    for line in lines:
        match = LONE.match(line)
        if len(line) <= LIMIT or not match:
            out.append(line)
            continue
        indent, prefix, quote, body, tail = match.groups()
        words, moved = body.split(" "), []
        while len(words) > 1 and len(indent) + 3 + len(prefix) + len(" ".join(words)) > LIMIT:
            moved.insert(0, words.pop())
        if not moved:
            out.append(line)
            continue
        out.append(f'{indent}{prefix}{quote}{" ".join(words)} {quote}')
        out.append(f'{indent}{prefix}{quote}{" ".join(moved)}{quote}{tail}')
    return "\n".join(out)


PASSES = (
    ("comments", reflow_comments, literal_words),
    ("docstrings", reflow_docstrings, literal_words),
    ("literals", reflow_literals, literal_text),
)


def process(path: pathlib.Path, *, check: bool = False) -> list[str]:
    """Apply every pass to one file, verifying each. Returns the passes that changed it."""
    original = path.read_text()
    current = original
    applied: list[str] = []
    for name, transform, invariant in PASSES:
        try:
            before = invariant(ast.parse(current))
        except SyntaxError:
            return applied
        try:
            candidate = transform(current)
        except (SyntaxError, ValueError, IndexError) as exc:
            print(f"  {path}: {name} pass raised {type(exc).__name__}: {exc}")
            continue
        if candidate == current:
            continue
        try:
            after = invariant(ast.parse(candidate))
        except SyntaxError as exc:
            print(f"  {path}: {name} pass produced unparseable output, skipped ({exc})")
            continue
        if before != after:
            print(f"  {path}: {name} pass would have changed the text, skipped")
            continue
        current = candidate
        applied.append(name)
    if applied and not check:
        path.write_text(current)
    return applied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="rewrap prose, verified")
    parser.add_argument("--check", action="store_true", help="report and write nothing")
    parser.add_argument("--rounds", type=int, default=4,
                        help="passes over the tree; splitting a literal can leave a new long line")
    args = parser.parse_args(argv)

    root = pathlib.Path(__file__).resolve().parents[1]
    touched: dict[str, list[str]] = {}
    for _ in range(args.rounds):
        changed_this_round = False
        for path in sorted(root.rglob("*.py")):
            if SKIP_PARTS & set(path.parts):
                continue
            applied = process(path, check=args.check)
            if applied:
                touched.setdefault(str(path.relative_to(root)), []).extend(applied)
                changed_this_round = True
        if not changed_this_round or args.check:
            break

    for name, passes in sorted(touched.items()):
        print(f"{name}: {', '.join(sorted(set(passes)))}")
    print(f"\n{len(touched)} file(s) {'would be ' if args.check else ''}rewrapped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
