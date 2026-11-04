#!/usr/bin/env python3
"""
refresh_recipe_bkc_page.py — Refresh BIOS + BMC + FPGA/HPM in recipe.yaml
from ONE source: the "SP8 BKC Release" Confluence page.

    https://amd.atlassian.net/wiki/spaces/SERVERDEBUG/pages/1733047956/SP8+BKC+Release

The page lays out one column per board-group (Eagle, Hornbill/Duck, Falcon,
Seagull) and one row per component (BIOS, Board FPGA FW, BMC FW):

- FPGA: reuses refresh_recipe_confluence_fpga.py's already-verified
  find_fpga_row_cells()/extract_board_entry() unchanged - this page's FPGA
  table was tested against the real page in that script.
- BMC: the version is parsed DIRECTLY from the page's BMC FW row (same
  fuzzy-row-match pattern as BIOS/FPGA), and that EXACT version's folder
  is resolved on the share - NOT "latest by modification time" like
  refresh_recipe_fileshare.py's find_latest_bmc() does. Those two can
  disagree in practice: the share can have a newer, not-yet-BKC-blessed
  build (e.g. a WIP/candidate) with a more recent mtime than the version
  the page actually pins as current - confirmed happening for real (page
  said v2.18.0.100I, the share's newest-by-mtime folder was v3.0.0.101C).
- BIOS: NEW parsing (find_bios_section()/extract_bios_filenames()) - this
  is the actual gap this script closes. Each board cell shows one or two
  plain-text filenames (e.g. "REAV0080I / TEAV0080I"); the Artifactory
  "Index of ..." folder link for the CURRENT release build is SHARED
  across every board and sits in its own cell/row below the filenames
  (confirmed against the real page - NOT embedded per-board-cell, which
  an earlier version of this script wrongly assumed, silently leaving
  BIOS untouched in recipe.yaml every run). The per-board filename PREFIX
  (e.g. "REAV") is derived straight from the page text rather than a
  hardcoded table, and the shared folder is walked once (via
  refresh_recipe_fileshare.py's artifactory_walk_latest_files()) and
  matched per board by that prefix.

UNVERIFIED AGAINST THE LIVE PAGE: the BIOS/BMC row parsing hasn't been
fully confirmed against every variation the real page's HTML might take
(confirmed working for the table layout seen so far - see above). Run
with --list-only first and inspect the output; if it doesn't find what's
expected, re-run with --dump-raw <path> and inspect the real HTML to
adjust BIOS_ROW_LABEL_HINTS/find_bios_section() or
BMC_ROW_LABEL_HINTS/find_bmc_row_cells() accordingly.

AUTH
    Same as refresh_recipe_confluence_fpga.py - see that module's docstring
    for both the API-token and session-cookie options
    (CONFLUENCE_EMAIL/CONFLUENCE_API_TOKEN, or CONFLUENCE_SESSION_COOKIE).

USAGE
    python refresh_recipe_bkc_page.py --list-only
    python refresh_recipe_bkc_page.py
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

import yaml

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency. Run: pip install beautifulsoup4", file=sys.stderr)
    raise

from launcher_utils import app_dir
from refresh_recipe_confluence_fpga import (
    DEFAULT_PAGE_URL,
    BOARD_ALIASES,
    auth,
    auth_mode,
    cookies,
    download_attachment,
    extract_board_entry,
    fetch_page_storage,
    find_fpga_row_cells,
    have_credentials,
    request_headers,
)
from refresh_recipe_fileshare import (
    BMC_SUFFIXES_TO_STRIP,
    DEFAULT_BMC_SHARE,
    SHARE_PROBE_TIMEOUT,
    _probe_host_reachable,
    artifactory_auth,
    artifactory_headers,
    artifactory_walk_latest_files,
    file_uri_to_path,
    run_with_timeout,
)
import requests
from urllib.parse import urlparse

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"

BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]

BIOS_ROW_LABEL_HINTS = ("bios",)
# e.g. "REAV0080I" (older "pi/<rev>" releases: pure digits + optional letter
# suffix) or "WEAV6A28N" (newer "weekly/<rev>" releases: AMD's version body
# can mix digits and letters, e.g. "6A28N" - confirmed on the real page
# after the "pi" format BIOS row disappeared in favor of this one. Letters
# prefix + an alphanumeric body starting with a digit.
BIOS_FILENAME_RE = re.compile(r"\b([A-Z]{3,6})([0-9][0-9A-Z]{2,6})\b")
BIOS_SUFFIXES_TO_STRIP = [".tar.gz", ".tgz", ".zip"]

BMC_ROW_LABEL_HINTS = ("bmc",)
# e.g. "v2.18.0.100I" or "sp7_v2.18.0.100I" - same convention as
# refresh_recipe_fileshare.py's BMC_VERSION_FOLDER_RE, just matched as a
# substring anywhere in the row's text rather than a whole-folder-name match.
BMC_VERSION_RE = re.compile(r"v(\d+\.\d+\.\d+\.\d+[A-Za-z]?)", re.IGNORECASE)


def strip_suffix(filename, suffixes):
    for suf in suffixes:
        if filename.lower().endswith(suf.lower()):
            return filename[: -len(suf)]
    return Path(filename).stem


def _find_link(cells, hints=("artifactory", "index of")):
    """Return the first <a> href across `cells` whose href or link text
    matches any of `hints` (case-insensitive), or None."""
    for cell in cells:
        for a in cell.find_all("a"):
            href = a.get("href", "")
            text = a.get_text(strip=True)
            if any(h in href.lower() or h in text.lower() for h in hints):
                return href
    return None


def find_bios_section(storage_html):
    """Returns (board_cells, shared_folder_url) for the BIOS row.

    The per-board filenames (e.g. "REAV0080I / TEAV0080I") sit in one row
    labeled "BIOS"; the Artifactory "Index of ..." folder link is SHARED
    across every board and sits in its own cell/row below the filenames -
    confirmed against the real page, NOT embedded inside each per-board
    cell as originally assumed (that assumption made BIOS resolution
    silently fail for every board, leaving recipe.yaml's BIOS entries from
    whatever source last touched them, e.g. refresh-fileshare's "weekly"
    folder). Checks the matched row's own cells first (in case a future
    page revision DOES embed it per-cell), then the next couple of rows
    for a shared link.
    """
    soup = BeautifulSoup(storage_html, "html.parser")
    rows = soup.find_all("tr")
    for i, row in enumerate(rows):
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        label = cells[0].get_text(strip=True).lower()
        if not any(hint in label for hint in BIOS_ROW_LABEL_HINTS):
            continue
        board_cells = cells[1:]
        folder_url = _find_link(board_cells)
        if not folder_url:
            for next_row in rows[i + 1:i + 3]:
                next_cells = next_row.find_all(["td", "th"])
                folder_url = _find_link(next_cells)
                if folder_url:
                    break
        return board_cells, folder_url
    raise ValueError(
        "Could not find a table row matching any of "
        f"{BIOS_ROW_LABEL_HINTS} in the Confluence page. Use --dump-raw to inspect "
        "the actual HTML and adjust BIOS_ROW_LABEL_HINTS / find_bios_section()."
    )


def extract_bios_filenames(cell):
    """From one BIOS board cell, pull out the filename(s) shown as plain
    text (e.g. "REAV0080I" / "TEAV0080I"). Returns None if none found."""
    text = cell.get_text(" ", strip=True)
    matches = BIOS_FILENAME_RE.findall(text)
    if not matches:
        return None
    # Two filenames (e.g. REAV0080I / TEAV0080I) are both kept; the first
    # is used as the default BIOS image - UNVERIFIED which variant is
    # "primary" vs a redundant/secondary image without seeing the real
    # page's surrounding context. Override via --bios-variant if wrong.
    return [f"{prefix}{build}" for prefix, build in matches]


def resolve_bios_artifact(folder_url, prefix, verify=True):
    """Walk the page-linked Artifactory folder and return the file whose
    name starts with `prefix` (derived from the page itself, not a
    hardcoded table)."""
    files = artifactory_walk_latest_files(folder_url, max_depth=1, verify=verify)
    matches = [f for f in files if f["name"].upper().startswith(prefix.upper())]
    if not matches:
        raise FileNotFoundError(
            f"No BIOS artifact under {folder_url} starting with prefix '{prefix}'. "
            f"Files found: {[f['name'] for f in files]}"
        )
    chosen = max(matches, key=lambda f: f["last_modified"])
    return {
        "download_url": chosen["download_url"],
        "version": strip_suffix(Path(chosen["name"]).name, BIOS_SUFFIXES_TO_STRIP),
        "name": Path(chosen["name"]).name,
    }


# Board-group column order on the page (Eagle | Hornbill/Duck | Falcon | Seagull).
# Hornbill and Duck share one column/cell (same as the FPGA table's BOARD_ALIASES).
BIOS_COLUMN_BOARDS = ["eagle", "hornbill", "falcon", "seagull"]


def find_bmc_row_cells(storage_html):
    """Same fuzzy row-label match pattern as find_fpga_row_cells(), looking
    for the "BMC FW" row instead."""
    soup = BeautifulSoup(storage_html, "html.parser")
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        label = cells[0].get_text(strip=True).lower()
        if any(hint in label for hint in BMC_ROW_LABEL_HINTS):
            return cells[1:]
    raise ValueError(
        "Could not find a table row matching any of "
        f"{BMC_ROW_LABEL_HINTS} in the Confluence page. Use --dump-raw to inspect "
        "the actual HTML and adjust BMC_ROW_LABEL_HINTS / find_bmc_row_cells()."
    )


def extract_bmc_version_from_page(storage_html):
    """The page shows ONE shared BMC version across every board (unlike
    BIOS/FPGA, which are per-board) - scan whichever row cells exist and
    return the first version string found."""
    cells = find_bmc_row_cells(storage_html)
    for cell in cells:
        m = BMC_VERSION_RE.search(cell.get_text(" ", strip=True))
        if m:
            return m.group(1)
    return None


def resolve_bmc_at_version(share_uri, version, subfolder="BMC", file_pattern="*.tar", timeout=30):
    """Resolve the BMC firmware file for the EXACT version the BKC page
    pins - not "latest by modification time" like
    refresh_recipe_fileshare.py's find_latest_bmc() does (confirmed those
    two can disagree: the share can have a newer, not-yet-BKC-blessed
    build with a more recent mtime than what the page actually lists as
    current)."""
    host = urlparse(share_uri).netloc
    if host and not _probe_host_reachable(host):
        raise ConnectionError(f"Cannot reach SMB host '{host}' (port 445) within {SHARE_PROBE_TIMEOUT}s.")

    share_path = Path(file_uri_to_path(share_uri))
    version_folder_name = version if version.lower().startswith("v") else f"v{version}"

    def _resolve_version_dir():
        candidate = share_path / version_folder_name
        if candidate.is_dir():
            return candidate
        # Case-insensitive fallback, same defensiveness as find_latest_bmc().
        if share_path.is_dir():
            for entry in share_path.iterdir():
                if entry.is_dir() and entry.name.lower() == version_folder_name.lower():
                    return entry
        raise FileNotFoundError(
            f"BKC page says the current BMC version is {version_folder_name}, but no matching folder "
            f"was found under {share_path}. The share and the page may be out of sync - check manually."
        )

    def _resolve_and_list():
        version_dir = _resolve_version_dir()
        search_dir = version_dir / subfolder if subfolder else version_dir
        if subfolder and not search_dir.is_dir():
            for entry in version_dir.iterdir():
                if entry.is_dir() and entry.name.lower() == subfolder.lower():
                    search_dir = entry
                    break
            else:
                raise FileNotFoundError(f"Expected a '{subfolder}' subfolder inside {version_dir}")
        return search_dir, list(search_dir.glob(file_pattern))

    try:
        search_dir, files = run_with_timeout(_resolve_and_list, timeout)
    except TimeoutError:
        raise TimeoutError(f"Listing the {version_folder_name} folder did not respond within {timeout}s.")

    if not files:
        raise FileNotFoundError(f"No files matching '{file_pattern}' found in {search_dir}")

    sp7_named = [f for f in files if "sp7" in f.name.lower()]
    chosen = max(sp7_named or files, key=lambda p: p.stat().st_mtime)
    return {
        "path": chosen,
        "version": strip_suffix(chosen.name, BMC_SUFFIXES_TO_STRIP),
        "version_folder": version_folder_name,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--page-url", default=DEFAULT_PAGE_URL)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--bmc-share", default=DEFAULT_BMC_SHARE)
    parser.add_argument("--bios-variant", type=int, default=0,
                         help="Index into the filename(s) listed per board's BIOS cell, if more than one "
                              "is shown (default: 0, the first one listed)")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--dump-raw", help="Write the raw Confluence page storage HTML here for debugging")
    parser.add_argument("--list-only", action="store_true", help="Show what would be downloaded, don't download/write")
    args = parser.parse_args()
    verify = not args.insecure

    if not have_credentials():
        print("ERROR: Set either (CONFLUENCE_EMAIL + CONFLUENCE_API_TOKEN) or CONFLUENCE_SESSION_COOKIE. "
              "See refresh_recipe_confluence_fpga.py's module docstring for both options.", file=sys.stderr)
        return 1

    print(f"=== Fetching {args.page_url} (auth mode: {auth_mode()}) ===")
    try:
        base, page_id, storage_html = fetch_page_storage(args.page_url, verify=verify)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR fetching Confluence page: {e}", file=sys.stderr)
        return 1

    if args.dump_raw:
        Path(args.dump_raw).write_text(storage_html, encoding="utf-8")
        print(f"Raw page storage HTML written to {args.dump_raw}")

    # -- FPGA (unchanged, reused as-is) --------------------------------
    fpga_entries = []
    try:
        fpga_cells = find_fpga_row_cells(storage_html)
        for cell in fpga_cells:
            entry = extract_board_entry(cell)
            if entry and entry["board"] in BOARD_CODES and entry["filename"] and entry["version"]:
                fpga_entries.append(entry)
        by_board = {e["board"]: e for e in fpga_entries}
        for alias_board, source_board in BOARD_ALIASES.items():
            if alias_board not in by_board and source_board in by_board:
                aliased = dict(by_board[source_board])
                aliased["board"] = alias_board
                aliased["aliased_from"] = source_board
                fpga_entries.append(aliased)
                by_board[alias_board] = aliased
    except ValueError as e:
        print(f"WARNING: FPGA row not parsed - {e}", file=sys.stderr)

    print("\n=== FPGA entries found ===")
    for e in fpga_entries:
        print(f"  {e['board']:10s}: {e['filename']}  (version='{e['version']}')")

    # -- BMC (version pinned from the page, NOT "latest by mtime") ------
    print(f"\n=== BMC: resolving the page-pinned version on {args.bmc_share} ===")
    bmc_latest = None
    try:
        bmc_version = extract_bmc_version_from_page(storage_html)
        if not bmc_version:
            print("  WARNING: could not find a BMC version on the page.", file=sys.stderr)
        else:
            print(f"  Page shows BMC version: v{bmc_version}")
            bmc_latest = resolve_bmc_at_version(args.bmc_share, bmc_version)
            print(f"  Resolved: {bmc_latest['version_folder']}/{bmc_latest['path'].name}  (version='{bmc_latest['version']}')")
    except ValueError as e:
        print(f"  WARNING: BMC row not parsed - {e}", file=sys.stderr)
    except Exception as e:
        print(f"  WARNING: BMC lookup failed - {e}", file=sys.stderr)

    # -- BIOS (new parsing, UNVERIFIED against the live page) -----------
    print("\n=== BIOS: parsing page ===")
    bios_entries = {}
    try:
        bios_cells, bios_folder_url = find_bios_section(storage_html)
        if not bios_folder_url:
            print("  WARNING: could not find the shared Artifactory 'Index of ...' folder link "
                  "anywhere near the BIOS row.", file=sys.stderr)
        else:
            print(f"  Artifactory folder (shared across all boards): {bios_folder_url}")
            for board, cell in zip(BIOS_COLUMN_BOARDS, bios_cells):
                filenames = extract_bios_filenames(cell)
                if not filenames:
                    print(f"  {board:10s}: WARNING - could not extract a filename from this cell", file=sys.stderr)
                    continue
                variant_idx = min(args.bios_variant, len(filenames) - 1)
                chosen_filename = filenames[variant_idx]
                prefix = BIOS_FILENAME_RE.match(chosen_filename).group(1)
                print(f"  {board:10s}: page shows {filenames} -> using '{chosen_filename}' (prefix '{prefix}')")
                try:
                    resolved = resolve_bios_artifact(bios_folder_url, prefix, verify=verify)
                    bios_entries[board] = resolved
                    print(f"  {board:10s}: resolved to {resolved['name']} (version='{resolved['version']}')")
                except Exception as e:
                    print(f"  {board:10s}: WARNING - {e}", file=sys.stderr)
            if "hornbill" in bios_entries and "duck" not in bios_entries:
                bios_entries["duck"] = dict(bios_entries["hornbill"])
    except ValueError as e:
        print(f"WARNING: BIOS row not parsed - {e}\n"
              f"This is the least-verified part of this script (no live page access to confirm "
              f"its real HTML structure) - re-run with --dump-raw and adjust BIOS_ROW_LABEL_HINTS/"
              f"find_bios_section() if needed.", file=sys.stderr)

    if args.list_only:
        print("\n--list-only set, nothing downloaded or written.")
        return 0

    if not fpga_entries and not bmc_latest and not bios_entries:
        print("\nERROR: nothing could be resolved for any component - aborting without touching recipe.yaml.", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    recipe = {"firmware": {}, "metadata": {}}
    if output_path.is_file():
        recipe = yaml.safe_load(output_path.read_text()) or recipe
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"\nBacked up previous recipe to {backup}")

    fw_dir = Path(args.firmware_dir)
    changes = []

    print("\n=== Downloading ===")
    for board in BOARD_CODES:
        recipe["firmware"].setdefault(board, {})

        fpga_entry = next((e for e in fpga_entries if e["board"] == board), None)
        if fpga_entry:
            dest_dir = fw_dir / "hpm" / board
            dest, url = download_attachment(base, page_id, fpga_entry["filename"], dest_dir, verify=verify)
            old_version = recipe["firmware"][board].get("hpm", {}).get("version")
            recipe["firmware"][board]["hpm"] = {"version": fpga_entry["version"], "url": url}
            if old_version != fpga_entry["version"]:
                changes.append(f"{board}.hpm: {old_version} -> {fpga_entry['version']}")

        if bmc_latest:
            bmc_dest_dir = fw_dir / "bmc" / board
            bmc_dest_dir.mkdir(parents=True, exist_ok=True)
            bmc_dest = bmc_dest_dir / bmc_latest["path"].name
            if not bmc_dest.exists():
                shutil.copy2(bmc_latest["path"], bmc_dest)
            old_version = recipe["firmware"][board].get("bmc", {}).get("version")
            recipe["firmware"][board]["bmc"] = {"version": bmc_latest["version"], "url": bmc_dest.as_uri()}
            if old_version != bmc_latest["version"]:
                changes.append(f"{board}.bmc: {old_version} -> {bmc_latest['version']}")

        if board in bios_entries:
            info = bios_entries[board]
            bios_dest_dir = fw_dir / "bios" / board
            bios_dest_dir.mkdir(parents=True, exist_ok=True)
            bios_dest = bios_dest_dir / info["name"]
            if not bios_dest.exists():
                resp = requests.get(info["download_url"], headers=artifactory_headers(),
                                     auth=artifactory_auth(), verify=verify, stream=True, timeout=120)
                resp.raise_for_status()
                with open(bios_dest, "wb") as fp:
                    for chunk in resp.iter_content(chunk_size=1 << 20):
                        fp.write(chunk)
            old_version = recipe["firmware"][board].get("bios", {}).get("version")
            recipe["firmware"][board]["bios"] = {"version": info["version"], "url": info["download_url"]}
            if old_version != info["version"]:
                changes.append(f"{board}.bios: {old_version} -> {info['version']}")

    recipe.setdefault("metadata", {})["bkc_page_source"] = args.page_url

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
