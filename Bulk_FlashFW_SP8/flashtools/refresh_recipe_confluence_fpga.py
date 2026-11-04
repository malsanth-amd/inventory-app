#!/usr/bin/env python3
"""
refresh_recipe_confluence_fpga.py — FPGA/HPM recipe refresh from the
"SP8 BKC Release" Confluence page's "Board FPGA FW" table, fully automated
(no manual browser step, unlike refresh_recipe_manual_fpga.py / SharePoint).

The page has a table row like:

    Board FPGA FW | eagle_FPGA_0.4.2.tar.gz    | hornbill_FPGA_0.4.2.tar.gz | ...
                  | R0.4.3_R0.4.0 (bold)       | R0.4.5_R0.4.1 (bold)      | ...
                  | (Release Notes)            | (Release Notes)           | ...

IMPORTANT: the bold text (e.g. "R0.4.3_R0.4.0") is the real HPM/FPGA version
- it does NOT match the number embedded in the filename (e.g. "0.4.2" is a
packaging/tool version, not the FPGA revision). This script uses the bold
text, not the filename, for the recipe's "version" field.

AUTH
    Two options, tried in this order:
    1. HTTP Basic Auth with an Atlassian API token (same mechanism Jira uses):
        export CONFLUENCE_EMAIL=you@amd.com
        export CONFLUENCE_API_TOKEN=<token from https://id.atlassian.com/manage-profile/security/api-tokens>
       NOTE: on at least one AMD account this returned 403 "caller cannot
       access Confluence" even though the account can browse the page fine -
       suspected cause: a "scoped" API token was created without Confluence
       read scope (vs. a "classic"/unscoped token). Try creating a classic
       token first.
    2. If that's blocked, a raw browser session cookie as a fallback:
        export CONFLUENCE_SESSION_COOKIE="cloud.session.token=...; ..."
       (copy the full Cookie header value from your browser's DevTools
       Network tab for a request to amd.atlassian.net while logged in).
       This is fragile - session cookies expire (hours to ~1 day) - but was
       confirmed working: pasting the API URL directly into an authenticated
       browser tab returned valid page JSON when the API token did not.

VERIFIED AGAINST THE REAL PAGE
    The HTML parsing (find_fpga_row_cells / extract_board_entry) was tested
    against the actual storage HTML returned for this page and correctly
    extracted all 4 board/filename/version triples (eagle, hornbill, falcon,
    seagull), matching the Board FPGA FW table. "duck" has no dedicated
    attachment on that row - confirmed from the page's per-system Ingredient
    Table that duck shares Hornbill's FPGA image/version - so duck's entry
    is cloned from hornbill's (see BOARD_ALIASES below).

USAGE
    python refresh_recipe_confluence_fpga.py --list-only
    python refresh_recipe_confluence_fpga.py
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
import yaml

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency. Run: pip install beautifulsoup4", file=sys.stderr)
    raise

from launcher_utils import app_dir

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"
DEFAULT_PAGE_URL = "https://amd.atlassian.net/wiki/spaces/SERVERDEBUG/pages/1733047956/SP8+BKC+Release"

BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]

# duck has no dedicated attachment in the Board FPGA FW table - confirmed from
# the page's Duck System Configuration ingredient table that it shares
# Hornbill's FPGA image/version. Applied after parsing (see main()).
BOARD_ALIASES = {"duck": "hornbill"}

# Matches "<board>_FPGA_<anything>.tar.gz", case-insensitive, board captured.
FILENAME_RE = re.compile(r"^([a-zA-Z]+)_FPGA_.*\.tar\.gz$", re.IGNORECASE)
ROW_LABEL_HINTS = ("board fpga fw", "fpga fw", "fpga")


def _raw_cookies():
    """Parse CONFLUENCE_SESSION_COOKIE ('name1=val1; name2=val2') into a dict,
    or None if not set. Fallback for orgs where the API-token path is blocked."""
    raw = os.environ.get("CONFLUENCE_SESSION_COOKIE")
    if not raw:
        return None
    jar = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            jar[name.strip()] = value.strip()
    return jar or None


def auth():
    """Basic Auth tuple for requests, or None.

    Deliberately returns None whenever a session cookie is present - sending
    both Basic Auth and a cookie in the same request can confuse Atlassian's
    edge auth (observed: a 403 that went away once only the cookie was sent).
    """
    if _raw_cookies():
        return None
    email = os.environ.get("CONFLUENCE_EMAIL")
    token = os.environ.get("CONFLUENCE_API_TOKEN")
    if not email or not token:
        return None
    return (email, token)


def cookies():
    return _raw_cookies()


def have_credentials():
    return bool(auth() or cookies())


def auth_mode():
    if cookies():
        return "cookie"
    if os.environ.get("CONFLUENCE_EMAIL") and os.environ.get("CONFLUENCE_API_TOKEN"):
        return "api-token"
    return "none"


def request_headers():
    """A real browser User-Agent (python-requests' default UA is a well-known
    bot signature Cloudflare/Atlassian's edge can block outright) plus the
    XSRF bypass header Atlassian's cookie-session API calls often require."""
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "X-Atlassian-Token": "no-check",
        "Accept": "application/json, text/plain, */*",
    }


def parse_page_url(page_url):
    """https://amd.atlassian.net/wiki/spaces/X/pages/1733047956/Title
    -> (base='https://amd.atlassian.net/wiki', page_id='1733047956')"""
    m = re.search(r"(https?://[^/]+/wiki)/spaces/[^/]+/pages/(\d+)", page_url)
    if not m:
        raise ValueError(f"Could not parse a Confluence page URL out of: {page_url}")
    return m.group(1), m.group(2)


def fetch_page_storage(page_url, verify=True):
    base, page_id = parse_page_url(page_url)
    api_url = f"{base}/rest/api/content/{page_id}"
    resp = requests.get(
        api_url,
        params={"expand": "body.storage,version"},
        auth=auth(),
        cookies=cookies(),
        headers=request_headers(),
        verify=verify,
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    storage_html = data["body"]["storage"]["value"]
    return base, page_id, storage_html


def find_fpga_row_cells(storage_html):
    """Return the list of <td>/<th> cells in whichever table row looks like
    the "Board FPGA FW" row (fuzzy-matched on the first cell's text)."""
    soup = BeautifulSoup(storage_html, "html.parser")

    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        label = cells[0].get_text(strip=True).lower()
        if any(hint in label for hint in ROW_LABEL_HINTS):
            return cells[1:]  # skip the label cell itself

    raise ValueError(
        "Could not find a table row matching any of "
        f"{ROW_LABEL_HINTS} in the Confluence page. Use --dump-raw to inspect "
        "the actual HTML and adjust ROW_LABEL_HINTS / find_fpga_row_cells()."
    )


def extract_board_entry(cell):
    """From one table cell, pull out (board, filename, version)."""
    # Filename: look at attachment macro attributes first, then plain link
    # text/href, then any text ending in .tar.gz as a last resort.
    filename = None
    for attr in ("ri:filename", "filename"):
        tag = cell.find(attrs={attr: True})
        if tag:
            filename = tag.get(attr)
            break
    if not filename:
        for a in cell.find_all("a"):
            text = a.get_text(strip=True)
            href = a.get("href", "")
            for candidate in (text, href):
                if candidate.lower().endswith(".tar.gz"):
                    filename = candidate.rsplit("/", 1)[-1]
                    break
            if filename:
                break
    if not filename:
        text_match = re.search(r"[\w.-]+\.tar\.gz", cell.get_text())
        if text_match:
            filename = text_match.group(0)

    if not filename:
        return None  # not every cell necessarily has one (e.g. empty trailing cells)

    board_match = FILENAME_RE.match(filename)
    board = board_match.group(1).lower() if board_match else None

    # Version: first bold/strong text in the cell
    version = None
    strong = cell.find(["strong", "b"])
    if strong:
        version = strong.get_text(strip=True)
    if not version:
        # Fallback: a line that looks like R<num>.<num>[_R<num>.<num>] or similar
        m = re.search(r"\bR?\d+\.\d+(?:\.\d+)?(?:_R?\d+\.\d+(?:\.\d+)?)?\b", cell.get_text())
        version = m.group(0) if m else None

    return {"board": board, "filename": filename, "version": version}


def download_attachment(base, page_id, filename, dest_dir, verify=True):
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    url = f"{base}/download/attachments/{page_id}/{quote(filename)}"
    resp = requests.get(url, auth=auth(), cookies=cookies(), headers=request_headers(), verify=verify, stream=True, timeout=120)
    resp.raise_for_status()
    with open(dest, "wb") as fp:
        for chunk in resp.iter_content(chunk_size=1 << 20):
            fp.write(chunk)
    return dest, url


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--page-url", default=DEFAULT_PAGE_URL)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--dump-raw", help="Write the raw Confluence page storage HTML here for debugging")
    parser.add_argument("--list-only", action="store_true", help="Show what would be downloaded, don't download/write")
    args = parser.parse_args()
    verify = not args.insecure

    if not have_credentials():
        print("ERROR: Set either (CONFLUENCE_EMAIL + CONFLUENCE_API_TOKEN) or CONFLUENCE_SESSION_COOKIE. "
              "See the module docstring for both options.", file=sys.stderr)
        return 1

    print(f"=== Fetching {args.page_url} (auth mode: {auth_mode()}) ===")
    try:
        base, page_id, storage_html = fetch_page_storage(args.page_url, verify=verify)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR fetching Confluence page: {e}\n"
              f"If this is 401/403 with an API token, try creating a CLASSIC (not scoped) token, "
              f"or fall back to CONFLUENCE_SESSION_COOKIE (see module docstring).", file=sys.stderr)
        return 1

    if args.dump_raw:
        Path(args.dump_raw).write_text(storage_html, encoding="utf-8")
        print(f"Raw page storage HTML written to {args.dump_raw}")

    try:
        cells = find_fpga_row_cells(storage_html)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    entries = []
    for cell in cells:
        entry = extract_board_entry(cell)
        if entry and entry["board"] in BOARD_CODES and entry["filename"] and entry["version"]:
            entries.append(entry)
        elif entry:
            print(f"  WARNING: skipping a cell with incomplete/unrecognized data: {entry}", file=sys.stderr)

    if not entries:
        print("ERROR: Found the FPGA row but couldn't extract any valid board/filename/version triples. "
              "Re-run with --dump-raw and inspect the HTML.", file=sys.stderr)
        return 1

    by_board = {e["board"]: e for e in entries}
    for alias_board, source_board in BOARD_ALIASES.items():
        if alias_board not in by_board and source_board in by_board:
            aliased = dict(by_board[source_board])
            aliased["board"] = alias_board
            aliased["aliased_from"] = source_board
            entries.append(aliased)
            by_board[alias_board] = aliased

    print("\n=== Found FPGA entries ===")
    for e in entries:
        note = f"  [aliased from {e['aliased_from']}]" if e.get("aliased_from") else ""
        print(f"  {e['board']:10s}: {e['filename']}  (version='{e['version']}'){note}")

    if args.list_only:
        print("\n--list-only set, nothing downloaded or written.")
        return 0

    output_path = Path(args.output)
    recipe = {"firmware": {}, "metadata": {}}
    if output_path.is_file():
        recipe = yaml.safe_load(output_path.read_text()) or recipe
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"\nBacked up previous recipe to {backup}")

    print("\n=== Downloading ===")
    fw_dir = Path(args.firmware_dir)
    changes = []
    for e in entries:
        board = e["board"]
        dest_dir = fw_dir / "hpm" / board
        dest, url = download_attachment(base, page_id, e["filename"], dest_dir, verify=verify)
        print(f"  {board:10s}: downloaded {dest}")

        recipe["firmware"].setdefault(board, {})
        old_version = recipe["firmware"][board].get("hpm", {}).get("version")
        recipe["firmware"][board]["hpm"] = {"version": e["version"], "url": url}
        if old_version != e["version"]:
            changes.append(f"{board}.hpm: {old_version} -> {e['version']}")

    with open(output_path, "w") as fp:
        yaml.safe_dump(recipe, fp, sort_keys=False)

    print(f"\n=== Wrote {output_path} ===")
    if changes:
        print("Changes:")
        for c in changes:
            print(f"  {c}")
    else:
        print("No version changes vs. previous recipe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
