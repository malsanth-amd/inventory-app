#!/usr/bin/env python3
"""
refresh_recipe_bkc_page_browser.py — Same job as refresh_recipe_bkc_page.py
(BIOS + BMC + FPGA/HPM from the "SP8 BKC Release" Confluence page in one
shot), but fetches the page and downloads FPGA attachments via a REAL
AUTOMATED BROWSER instead of raw HTTP requests.

WHY THIS EXISTS
    Same reason refresh_recipe_confluence_fpga_browser.py exists: a
    corporate proxy/CASB in front of amd.atlassian.net has been observed to
    403 every raw-HTTP auth method (API token, browser session cookie, a
    spoofed browser User-Agent) even with genuinely valid credentials, while
    the exact same URL works fine pasted into a real logged-in browser tab.
    This drives a real browser (Playwright + Chromium) instead.

    BIOS (Artifactory) and BMC (SMB file share) are NOT behind that same
    proxy/CASB restriction as far as is known, so those two components
    still use plain `requests`/filesystem access, unchanged from
    refresh_recipe_bkc_page.py - only the Confluence page fetch and FPGA
    attachment downloads go through the browser.

    BMC's version is parsed DIRECTLY from the page (same as BIOS/FPGA),
    then that EXACT version's folder is resolved on the share - NOT
    "latest by modification time". Those can disagree in practice: the
    share can have a newer, not-yet-BKC-blessed build with a more recent
    mtime than what the page actually lists as current.

SETUP (one-time)
    pip install playwright
    playwright install chromium

LOGIN
    Uses a persistent browser profile stored in ./.browser_profile next to
    this script - same as refresh_recipe_confluence_fpga_browser.py (in
    fact the SAME profile dir works for both, since it's the same AMD SSO
    session). By default, every run tries invisibly (headless) first using
    whatever login is already cached there - a visible Chromium window
    only pops up if that turns out to not be logged in (first run, or an
    expired session); log into AMD SSO there if prompted, then the script
    continues automatically and no window appears on subsequent runs.
    Pass --headless to force headless and fail outright instead of ever
    showing a window (for unattended/scheduled use).

USAGE
    python refresh_recipe_bkc_page_browser.py --list-only
    python refresh_recipe_bkc_page_browser.py
    python refresh_recipe_bkc_page_browser.py --headless   # after first login
"""

import argparse
import shutil
import sys
from pathlib import Path

import requests
import yaml

try:
    from playwright.sync_api import sync_playwright  # noqa: F401 (imported for the dependency check)
except ImportError:
    print("Missing dependency. Run: pip install playwright && playwright install chromium", file=sys.stderr)
    raise

from launcher_utils import app_dir
from refresh_recipe_confluence_fpga import BOARD_ALIASES, DEFAULT_PAGE_URL
from refresh_recipe_confluence_fpga_browser import (
    DEFAULT_PROFILE_DIR,
    download_all_attachments_via_browser,
    ensure_chromium_installed,
    fetch_page_storage_via_browser,
)
from refresh_recipe_fileshare import (
    DEFAULT_BMC_SHARE,
    artifactory_auth,
    artifactory_headers,
)
from refresh_recipe_bkc_page import (
    BIOS_COLUMN_BOARDS,
    BIOS_FILENAME_RE,
    BOARD_CODES,
    extract_bios_filenames,
    extract_bmc_version_from_page,
    find_bios_section,
    resolve_bios_artifact,
    resolve_bmc_at_version,
)
from refresh_recipe_confluence_fpga import extract_board_entry, find_fpga_row_cells

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--page-url", default=DEFAULT_PAGE_URL)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--bmc-share", default=DEFAULT_BMC_SHARE)
    parser.add_argument("--bios-variant", type=int, default=0,
                         help="Index into the filename(s) listed per board's BIOS cell, if more than one is shown")
    parser.add_argument("--profile-dir", default=str(DEFAULT_PROFILE_DIR),
                         help="Persistent browser profile dir (shared with refresh-confluence-browser - keeps you logged in between runs)")
    parser.add_argument("--headless", action="store_true",
                         help="Force headless and FAIL instead of ever showing a browser window if login "
                              "is needed - for unattended/scheduled runs. By default (this flag omitted), "
                              "a quiet headless attempt is tried first automatically using your cached "
                              "login, and a visible window only appears if that's not actually logged in "
                              "(first use, or an expired session).")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--dump-raw", help="Write the raw page storage HTML here for debugging")
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args()
    verify = not args.insecure
    profile_dir = Path(args.profile_dir)
    profile_dir.mkdir(parents=True, exist_ok=True)

    try:
        ensure_chromium_installed()
    except Exception as e:
        print(f"ERROR: Could not install Chromium automatically - {e}\n"
              f"Try running `playwright install chromium` manually, or on a machine/network where it "
              f"succeeds and copy the %LOCALAPPDATA%\\ms-playwright\\chromium-* folder over.", file=sys.stderr)
        return 1

    print(f"=== Fetching {args.page_url} via real browser (headless={args.headless}) ===")
    try:
        base, page_id, storage_html = fetch_page_storage_via_browser(args.page_url, profile_dir, args.headless, verify)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.dump_raw:
        Path(args.dump_raw).write_text(storage_html, encoding="utf-8")
        print(f"Raw page storage HTML written to {args.dump_raw}")

    # -- FPGA (reused unchanged) ------------------------------------
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

    # -- BIOS (Artifactory via plain requests, unaffected by the proxy issue) --
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
        print(f"WARNING: BIOS row not parsed - {e}", file=sys.stderr)

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

    print("\n=== Downloading FPGA attachments ===")
    # Always headless here - login was already confirmed (visibly, if
    # needed) by fetch_page_storage_via_browser() above, and this reuses
    # the same persisted profile, so there's nothing left to show a user.
    downloaded_fpga = download_all_attachments_via_browser(
        fpga_entries, profile_dir, True, verify, base, page_id, fw_dir
    ) if fpga_entries else {}

    print("\n=== Downloading BIOS/copying BMC ===")
    for board in BOARD_CODES:
        recipe["firmware"].setdefault(board, {})

        if board in downloaded_fpga:
            dest, url = downloaded_fpga[board]
            fpga_entry = next(e for e in fpga_entries if e["board"] == board)
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
