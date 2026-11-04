#!/usr/bin/env python3
"""
refresh_recipe_bkc_page_cli.py — Same job as refresh_recipe_bkc_page.py
(BIOS + BMC + FPGA/HPM from the "SP8 BKC Release" Confluence page in one
shot), but fetches the page content via the authenticated `atlassian` CLI
instead of raw HTTP requests or a live browser.

WHY THIS EXISTS
    Raw HTTP (refresh_recipe_bkc_page.py) and a live browser
    (refresh_recipe_bkc_page_browser.py) both exist because of a corporate
    proxy/CASB that blocks unrecognized clients - but the browser path
    carries real complexity (SSO-login auto-escalation, hostname false
    positives, Chromium auto-download, timeout flakiness - most of the
    hard bugs found this session). The `atlassian` CLI, confirmed working
    directly against the live page, is a MUCH simpler, more reliable way
    to fetch the page's content specifically - it has its own
    already-hardened authenticated client that this CASB evidently allows
    through (every parsing function - FPGA/BIOS/BMC - was re-verified
    against the real page's HTML fetched this way).

    FPGA attachments are downloaded from SharePoint instead of as a
    Confluence attachment: raw HTTP downloads of the actual .tar.gz files
    from Confluence are blocked (confirmed - redirected into the same
    id.atlassian.com "request access"/login flow with a TLS error), and
    the atlassian CLI has no command for downloading Confluence
    attachments either (its `rest` escape hatch only allows genuine REST
    API paths, not /wiki/download/... URLs). SharePoint, reached via
    Microsoft Graph (sharepoint_fpga.py), has the same files mirrored and
    needs no browser at all - just a one-time Microsoft device-code
    sign-in (see SETUP below). This fully replaces the Playwright/Chromium
    FPGA-download path this script used earlier in its development; that
    mechanism still exists for refresh-bkc-page-browser/
    refresh-confluence-browser, unaffected by this change.

SETUP (one-time, per machine/user)
    1. Install the `atlassian` CLI - see GETTING_STARTED.txt's
       "INSTALLING THE ATLASSIAN CLI" section for the exact one-time
       install command (native Windows: a PowerShell script; run it in a
       REAL PowerShell window, not this app's own console).
    2. Log in once (read-only is enough for this script):
           atlassian auth device start --read-only --profile ro
       Open the URL it prints, enter the code, complete SSO, then:
           atlassian auth device finish --profile ro
    3. Microsoft sign-in (for the FPGA-download step, via SharePoint) is
       driven automatically on first use - this script will print a URL
       and a short code the first time it needs it, and the resulting
       token is saved for every later run. No separate install needed.

USAGE
    python refresh_recipe_bkc_page_cli.py --list-only
    python refresh_recipe_bkc_page_cli.py
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import requests
import yaml

from launcher_utils import app_dir
from refresh_recipe_confluence_fpga import BOARD_ALIASES, DEFAULT_PAGE_URL, extract_board_entry, find_fpga_row_cells, parse_page_url
from refresh_recipe_fileshare import DEFAULT_BMC_SHARE, artifactory_auth, artifactory_headers
from sharepoint_fpga import download_fpga_from_sharepoint
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

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"
DEFAULT_CLI_PROFILE = "ro"


def find_atlassian_cli():
    """Locate the atlassian CLI executable. Checks PATH first, then the
    default per-platform install locations the CLI's own installer uses -
    needed because a freshly-installed CLI's PATH update is often not yet
    visible to an already-running process/terminal (hit this exact gotcha
    mid-session - a brand new terminal window was required for `atlassian`
    to resolve on PATH right after installing)."""
    found = shutil.which("atlassian") or shutil.which("atlassian.exe")
    if found:
        return found
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "atlassian-cli" / "atlassian.exe",
        Path.home() / ".local" / "bin" / "atlassian",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def fetch_page_storage_via_cli(page_url, profile=DEFAULT_CLI_PROFILE, cli_path=None, timeout=60):
    base, page_id = parse_page_url(page_url)
    cli = cli_path or find_atlassian_cli()
    if not cli:
        raise FileNotFoundError(
            "The 'atlassian' CLI was not found on PATH or in its default install location. "
            "See GETTING_STARTED.txt's 'INSTALLING THE ATLASSIAN CLI' section for the one-time "
            "install + login steps, then re-run this (a NEW terminal/app launch may be needed "
            "for a freshly-installed CLI to resolve on PATH)."
        )

    cmd = [cli, "--profile", profile, "confluence", "page", "get", page_id,
           "--body-format", "storage", "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"'atlassian' CLI did not respond within {timeout}s.")

    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        if any(m in stderr.lower() for m in ("not logged in", "auth", "credential", "unauthorized")):
            raise RuntimeError(
                f"'atlassian' CLI reported an authentication problem: {stderr}\n"
                f"Run:  atlassian auth device start --read-only --profile {profile}\n"
                f"      (open the URL it prints, complete SSO, then)\n"
                f"      atlassian auth device finish --profile {profile}"
            )
        raise RuntimeError(f"'atlassian' CLI exited {result.returncode}: {stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ValueError(f"'atlassian' CLI did not return valid JSON (first 500 chars):\n{result.stdout[:500]}")

    storage = data.get("body", {}).get("storage", {}).get("value")
    if not storage:
        raise ValueError(
            f"CLI response was valid JSON but missing body.storage - likely wrong --body-format "
            f"or a permissions issue. Top-level keys seen: {list(data.keys())}"
        )
    return base, page_id, storage


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--page-url", default=DEFAULT_PAGE_URL)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--bmc-share", default=DEFAULT_BMC_SHARE)
    parser.add_argument("--bios-variant", type=int, default=0,
                         help="Index into the filename(s) listed per board's BIOS cell, if more than one is shown")
    parser.add_argument("--cli-profile", default=DEFAULT_CLI_PROFILE,
                         help=f"atlassian CLI credential profile to use for the page fetch (default: {DEFAULT_CLI_PROFILE})")
    parser.add_argument("--atlassian-cli", default=None, help="Override path to the atlassian CLI executable")
    parser.add_argument("--no-auto-auth", action="store_true",
                         help="For the FPGA-download step: fail immediately instead of prompting for an "
                              "interactive Microsoft sign-in if not already authenticated - for "
                              "unattended/scheduled runs where no one is present to complete it.")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--dump-raw", help="Write the raw page storage HTML here for debugging")
    parser.add_argument("--list-only", action="store_true", help="Show what would be downloaded, don't download/write")
    args = parser.parse_args()
    verify = not args.insecure

    print(f"=== Fetching {args.page_url} via the atlassian CLI (profile={args.cli_profile}) ===")
    try:
        base, page_id, storage_html = fetch_page_storage_via_cli(args.page_url, args.cli_profile, args.atlassian_cli)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.dump_raw:
        Path(args.dump_raw).write_text(storage_html, encoding="utf-8")
        print(f"Raw page storage HTML written to {args.dump_raw}")

    # -- FPGA (parsing reused unchanged) --------------------------------
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

    # -- BIOS (Artifactory via plain requests - confirmed NOT behind the --
    # -- same CASB restriction as the Confluence REST/download endpoints) --
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

    downloaded_fpga = {}
    if fpga_entries:
        print("\n=== Downloading FPGA attachments (from SharePoint) ===")
        for e in fpga_entries:
            board, filename = e["board"], e["filename"]
            # Boards aliased from another board (e.g. duck -> hornbill) have no SharePoint
            # link of their own - they share the source board's site/folder.
            sharepoint_board = e.get("aliased_from", board)
            dest_dir = fw_dir / "hpm" / board
            try:
                dest = download_fpga_from_sharepoint(sharepoint_board, filename, dest_dir, auto_auth=not args.no_auto_auth)
                downloaded_fpga[board] = (dest, dest.as_uri())
                print(f"  {board:10s}: downloaded {filename}")
            except Exception as ex:
                print(f"  {board:10s}: WARNING - FPGA download failed - {ex}", file=sys.stderr)

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
