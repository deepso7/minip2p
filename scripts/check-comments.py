#!/usr/bin/env python3
"""Ratchet check against implementation comments.

The codebase bans implementation comments: `//` and `/* */` in Rust and
TS/JS, `#` in shell and Python. A decision belongs in an ADR, an explanation
in a clearer name or type, and a workaround in an issue. Rustdoc (`///`, `//!`,
`/** */`, `/*! */`), JSDoc (`/** */`), Python docstrings, and tool directives
(`SAFETY:`, `oxlint-disable`, `@ts-expect-error`, `noqa`, `shellcheck`, ...)
are not counted; a `//` directive's following `//` lines count as part of it.

`scripts/comment-baseline.json` records how many comment lines each file
still has. A file may only go down: more comments than its baseline fails, and
so does a file that dropped below its baseline without updating it.

  check-comments.py              check the ratchet (CI)
  check-comments.py --update     lower the baseline to the current counts
  check-comments.py --list [P..] print every counted comment, optionally
                                 under the given paths
"""

import io
import json
import re
import subprocess
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "comment-baseline.json"

C_LIKE = {".rs", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
HASH = {".sh", ".py"}
EXCLUDED = (
    ".agents/",
    ".claude/",
    "code-ref/",
    "fuzz/corpus/",
    "bindings/ts/react-native/src/generated/",
    "bindings/ts/react-native/src/NativeMinip2p.ts",
    "bindings/ts/react-native/src/native.tsx",
    "bindings/ts/node/src/addon.d.ts",
    "bindings/ts/web/wasm/",
)
DIRECTIVE = re.compile(
    r"^(SAFETY:|(?:ox|es)lint-(?:disable|enable)|@ts-|@vitest-|"
    r"noqa|type:\s*ignore|shellcheck|pragma|prettier-ignore|biome-ignore|"
    r"istanbul|c8 |v8 |@jsx|#region|#endregion|-\*-)"
)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    for name in out.decode().split("\0"):
        if not name or name.startswith(EXCLUDED):
            continue
        suffix = Path(name).suffix
        if suffix in C_LIKE or suffix in HASH:
            if (ROOT / name).is_file():
                yield name


def is_directive(body):
    return bool(DIRECTIVE.match(body.strip()))


def scan_template(text, j):
    """Scan template-literal text from `j`; return (index after the closing
    backtick or after `${`, whether it stopped at `${`)."""
    while j < len(text):
        if text[j] == "\\":
            j += 2
        elif text[j] == "`":
            return j + 1, False
        elif text.startswith("${", j):
            return j + 2, True
        else:
            j += 1
    return j, False


def c_like_comments(text, rust):
    """Yield (line, text) for each counted line of every `//` or `/* */`
    comment. Lexes strings, raw strings, char literals, template literals and
    (for TS/JS) regex literals, guessed from the previous significant
    character `prev`, so `//` inside them is not mistaken for a comment.
    `open_braces` tells a `}` closing a template's `${` from a block's."""
    i, n, line = 0, len(text), 1
    directive_until = 0
    prev = ""
    open_braces = []

    def emit_block(start_line, body, doc):
        if doc or is_directive(body[2:]):
            return
        for k, part in enumerate(body.split("\n")):
            yield start_line + k, part.strip()

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "\n":
            line += 1
            i += 1
            continue
        if c == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            body = text[i + 2 : end]
            doc = (body.startswith("/") and not body.startswith("//")) or (
                rust and body.startswith("!")
            )
            if is_directive(body) or directive_until == line - 1:
                directive_until = line
            elif not doc:
                yield line, text[i:end].strip()
            i = end
            continue
        if c == "/" and nxt == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if rust and text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            raw = text[i:j]
            doc = (raw.startswith("/**") and not raw.startswith("/***") and raw != "/**/") or (
                rust and raw.startswith("/*!")
            )
            yield from emit_block(line, raw, doc)
            line += raw.count("\n")
            i = j
            continue
        if rust:
            m = re.match(r'(b|c)?r(#*)"', text[i:i + 260]) if c in "bcr" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) else None
            if m:
                close = '"' + m.group(2)
                j = text.find(close, i + m.end())
                j = n if j == -1 else j + len(close)
                line += text.count("\n", i, j)
                i, prev = j, '"'
                continue
            if c == "'":
                m = re.match(r"'(\\.[^']*|[^\\'\n])'", text[i:i + 12])
                if m:
                    i += m.end()
                    prev = "'"
                    continue
                i += 1
                continue
        else:
            if c == "`" or (c == "}" and open_braces and open_braces[-1] == "template"):
                if c == "}":
                    open_braces.pop()
                j, expr = scan_template(text, i + 1)
                if expr:
                    open_braces.append("template")
                line += text.count("\n", i, j)
                i, prev = j, "{" if expr else "`"
                continue
            if c == "{":
                open_braces.append("brace")
            elif c == "}" and open_braces:
                open_braces.pop()
            if c == "/" and (prev == "" or prev in "(,=:[!&|?{};+-*%<>~^" or re.search(r"\b(return|typeof|case|in|of|delete|void|throw|new|yield|await)\s*$", text[max(0, i - 12):i])):
                j, in_class = i + 1, False
                while j < n and text[j] != "\n":
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == "[":
                        in_class = True
                    elif text[j] == "]":
                        in_class = False
                    elif text[j] == "/" and not in_class:
                        break
                    j += 1
                i, prev = j + 1, "/"
                continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n" and not rust:
                    break
                j += 1
            line += text.count("\n", i, j)
            i, prev = j + 1, c
            continue
        if not c.isspace():
            prev = c
        i += 1


def python_comments(text):
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                body = tok.string[1:]
                if tok.start[0] == 1 and tok.string.startswith("#!"):
                    continue
                if not is_directive(body):
                    yield tok.start[0], tok.string.strip()
    except (tokenize.TokenError, SyntaxError):
        return


def shell_comments(text):
    heredoc = None
    for number, raw in enumerate(text.split("\n"), 1):
        if heredoc:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        if number == 1 and raw.startswith("#!"):
            continue
        m = re.search(r"<<-?\s*['\"]?([A-Za-z_]+)['\"]?", raw)
        quote, k = None, 0
        while k < len(raw):
            ch = raw[k]
            if quote:
                if ch == "\\" and quote == '"':
                    k += 1
                elif ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "\\":
                k += 1
            elif ch == "#" and (k == 0 or raw[k - 1] in " \t;"):
                if not is_directive(raw[k + 1 :]):
                    yield number, raw[k:].strip()
                break
            k += 1
        if m:
            heredoc = m.group(1)


def comments(path):
    text = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    suffix = Path(path).suffix
    if suffix == ".py":
        return list(python_comments(text))
    if suffix == ".sh":
        return list(shell_comments(text))
    return list(c_like_comments(text, rust=suffix == ".rs"))


def main(argv):
    if argv[:1] == ["--list"]:
        prefixes = tuple(argv[1:])
        for path in tracked_files():
            if prefixes and not path.startswith(prefixes):
                continue
            for number, body in comments(path):
                print(f"{path}:{number}: {body}")
        return 0

    counts = {}
    for path in tracked_files():
        found = len(comments(path))
        if found:
            counts[path] = found
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}

    if argv[:1] == ["--update"]:
        raised = sorted(p for p, c in counts.items() if c > baseline.get(p, 0))
        if raised and baseline:
            print("--update only lowers the baseline; these files gained comments:")
            for p in raised:
                print(f"  {p}: {baseline.get(p, 0)} -> {counts[p]}")
            return 1
        BASELINE.write_text(json.dumps(dict(sorted(counts.items())), indent=2) + "\n")
        print(f"baseline: {sum(counts.values())} comment lines in {len(counts)} files")
        return 0

    failed = False
    for path, found in sorted(counts.items()):
        allowed = baseline.get(path, 0)
        if found > allowed:
            failed = True
            print(f"{path}: {found} comment lines, baseline allows {allowed}")
    stale = sorted(p for p, c in baseline.items() if counts.get(p, 0) < c)
    if stale:
        failed = True
        print("These files lost comments; lock that in with `scripts/check-comments.py --update`:")
        for p in stale:
            print(f"  {p}: {baseline[p]} -> {counts.get(p, 0)}")
    if failed:
        print(
            "\nImplementation comments are banned (see docs/adr and the delete-comment skill):"
            "\nrecord decisions in an ADR, workarounds in an issue, and let the code say the rest."
            "\n`scripts/check-comments.py --list <path>` prints the offending comments."
        )
        return 1
    print(f"comments ratchet ok: {sum(counts.values())} lines left in {len(counts)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
