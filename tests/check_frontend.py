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
    "_reportTable", "_borrowerDetail", "buildMatchIndex",
    "parseActionRows", "actionRowToUpdate", "renderActionRowsPreview",
    "flagDuplicateActionTargets", "autoLookupRcdPmic", "_cpuInventoryPanel",
    "_findCpuBySerial", "_recordSutAudit", "openAuditHistory", "closeAuditHistory",
    "readSutDimms", "clearDimmDecoder", "_dimmResults", "_dimmInventoryPanel", "_recordDimmAudit",
    "exportAuditLog",
    "openCheckinModal", "openCheckinBatch", "closeCheckinModal", "doCheckin",
    "runAuditScanNow", "loadLastAuditScanRun", "runDimmScanNow", "loadLastDimmScanRun",
    "_renderScanRunSummary",
    "landingAggregates", "renderLanding", "renderLandingStock", "applyFacet",
    "isAvailable", "_renderActiveFilters", "browseAllItems",
    "rowIsBulkAction", "detectColMap", "doImport", "handleFile",
    "collectImportRows", "importDateIsValid", "dateColumnProblems",
]

BACKSLASH = chr(92)
QUOTES = {'"', "'", "`"}


def strip_literals(body: str) -> str:
    """Remove comments and string literals so bracket counts mean something.

    Template literals need a stack rather than a flag. Treating everything
    between two backticks as opaque works until a template contains another one
    inside a ${...} substitution: the scanner then pairs the opening backtick
    with the *nested* one, and the rest of the file is read inside-out. That is
    not hypothetical — it made the whole-file count swing by one purely because
    a render function was rewritten to nest fewer templates, reporting a dropped
    bracket in code the browser parsed without complaint.

    So: literal text inside a template is dropped, but the code inside ${...} is
    kept and scanned as code, which is what it is. The ${ and its matching }
    are delimiters, not braces, and are not emitted.
    """
    out: list[str] = []
    # Frames: ("code", unmatched_braces) or ("tpl", 0). The outermost code frame
    # is never popped.
    stack: list[list] = [["code", 0]]
    state = None            # None | "line" | "block" | "'" | '"'
    i, n = 0, len(body)

    def starts_regex() -> bool:
        """Whether the '/' at *i* opens a regex rather than dividing.

        Decided by what came before it: a value (identifier, number, closing
        bracket) means division, anything else means a pattern. Without this,
        `.replace(/&/g, '&amp;')` reads as division and the quotes inside the
        next pattern re-open string state, so the scanner spends the rest of
        the file inside-out — which is where the "meaningless absolute number"
        in this module's docstring came from.
        """
        k = len(out) - 1
        while k >= 0 and out[k].isspace():
            k -= 1
        if k < 0:
            return True
        prev = out[k]
        if prev in ")]":
            return False
        if prev.isalnum() or prev in "_$":
            # A value ends the expression — unless it is a keyword that takes one.
            word_end = k + 1
            while k >= 0 and (out[k].isalnum() or out[k] in "_$"):
                k -= 1
            word = "".join(out[k + 1:word_end])
            return word in {"return", "typeof", "instanceof", "in", "of", "new",
                            "delete", "void", "case", "do", "else", "yield", "await"}
        return True

    while i < n:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < n else ""

        if state == "line":
            if ch == "\n":
                state = None
                out.append(ch)
            i += 1
            continue
        if state == "block":
            if ch + nxt == "*/":
                state, i = None, i + 2
                continue
            i += 1
            continue
        if state in ("'", '"'):
            if ch == BACKSLASH:
                i += 2
                continue
            if ch == state:
                state = None
            i += 1
            continue

        if stack[-1][0] == "tpl":
            if ch == BACKSLASH:
                i += 2
                continue
            if ch == "`":                      # template ends
                stack.pop()
                i += 1
                continue
            if ch + nxt == "${":               # substitution: code again
                stack.append(["code", 0])
                i += 2
                continue
            i += 1                             # literal text — drop it
            continue

        # inside code
        if ch + nxt == "//":
            state, i = "line", i + 2
            continue
        if ch + nxt == "/*":
            state, i = "block", i + 2
            continue
        if ch in ("'", '"'):
            state, i = ch, i + 1
            continue
        if ch == "`":
            stack.append(["tpl", 0])
            i += 1
            continue
        if ch == "/" and starts_regex():
            i += 1
            in_class = False
            while i < n:
                c = body[i]
                if c == BACKSLASH:
                    i += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    i += 1
                    break
                elif c == "\n":          # unterminated: not a regex after all
                    break
                i += 1
            while i < n and body[i].isalpha():   # flags
                i += 1
            continue
        if ch == "{":
            stack[-1][1] += 1
            out.append(ch)
            i += 1
            continue
        if ch == "}":
            if stack[-1][1] > 0:
                stack[-1][1] -= 1
                out.append(ch)
            elif len(stack) > 1:
                stack.pop()                    # closes a ${...}: a delimiter
            else:
                out.append(ch)                 # genuinely unmatched — let it count
            i += 1
            continue
        out.append(ch)
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
