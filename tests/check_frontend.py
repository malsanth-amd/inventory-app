"""Structural checks for the inline script in static/index.html.

There is no JavaScript engine on the build machine, so this cannot execute the
frontend. It does the next best thing: it checks that every function named by an
inline on*= handler exists, and that bracket nesting has not shifted relative to
the committed version. That catches what an unrunnable edit usually gets wrong —
a dropped brace, or a handler pointing at a function that was renamed.

Bracket counts are compared against HEAD rather than expected to be zero: the
stripper does not attempt to parse regex literals (telling `/` as division from
`/` as a regex needs a real parser), so a few brackets inside patterns are
always miscounted. The absolute number is meaningless; a *change* in it is not.

Run with: python tests/check_frontend.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

INDEX = Path(__file__).resolve().parent.parent / "static" / "index.html"

EXPECTED_FUNCTIONS = [
    "parseBarcode", "itemSerial", "serialMatches", "findItemByScan",
    "onScan", "setScanStatus", "resetScanCount",
    "onSearchInput", "searchBlob", "compareValues", "magnitude",
    "putItem", "formatApiError", "renderTable",
]

BACKSLASH = chr(92)
QUOTES = {'"', "'", "`"}


def strip_literals(body: str) -> str:
    """Remove comments and string literals so bracket counts mean something."""
    out: list[str] = []
    i, n, state = 0, len(body), None
    while i < n:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < n else ""
        if state is None:
            if ch + nxt == "//":
                state, i = "line", i + 2
                continue
            if ch + nxt == "/*":
                state, i = "block", i + 2
                continue
            if ch in QUOTES:
                state, i = ch, i + 1
                continue
            out.append(ch)
        elif state == "line":
            if ch == "\n":
                state = None
                out.append(ch)
        elif state == "block":
            if ch + nxt == "*/":
                state, i = None, i + 2
                continue
        else:  # inside a string literal
            if ch == BACKSLASH:
                i += 2
                continue
            if ch == state:
                state = None
        i += 1
    return "".join(out)


def inline_script(src: str) -> str:
    return max(re.findall(r"<script[^>]*>(.*?)</script>", src, re.S), key=len)


def bracket_deltas(body: str) -> dict[str, int]:
    clean = strip_literals(body)
    return {
        f"{o}{c}": clean.count(o) - clean.count(c)
        for o, c in (("{", "}"), ("(", ")"), ("[", "]"))
    }


def committed_source() -> str | None:
    """static/index.html as of HEAD, or None outside a git checkout."""
    import subprocess

    try:
        result = subprocess.run(
            ["git", "show", "HEAD:static/index.html"],
            cwd=INDEX.parent.parent, capture_output=True, check=True,
        )
        return result.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.CalledProcessError):
        return None


# `onkeydown="if(...)"` and friends are inline statements, not function calls.
JS_KEYWORDS = {"if", "for", "while", "switch", "return", "catch", "typeof", "do"}


def main() -> int:
    src = INDEX.read_text(encoding="utf-8")
    body = inline_script(src)
    print(f"inline script: {len(body.splitlines())} lines")

    failures = 0
    current = bracket_deltas(body)
    baseline_src = committed_source()
    if baseline_src is None:
        print(f"  bracket deltas: {current}  (no HEAD to compare against)")
    else:
        baseline = bracket_deltas(inline_script(baseline_src))
        same = current == baseline
        print(f"  bracket deltas: {current} vs HEAD {baseline}  "
              f"{'UNCHANGED' if same else 'SHIFTED — likely a dropped bracket'}")
        failures += not same

    defined = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)", body))
    defined |= set(
        re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", body)
    )

    handlers = {
        h for h in re.findall(r'on\w+="\s*([A-Za-z_$][\w$]*)\s*\(', src)
        if h not in JS_KEYWORDS
    }
    missing = sorted(h for h in handlers if h not in defined)
    print(f"  inline handlers: {len(handlers)}; undefined: {missing or 'none'}")
    failures += bool(missing)

    for name in EXPECTED_FUNCTIONS:
        present = f"function {name}" in body
        print(f"  {'OK     ' if present else 'MISSING'} {name}")
        failures += not present

    print("\nPASS" if not failures else f"\nFAIL ({failures} problem(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
