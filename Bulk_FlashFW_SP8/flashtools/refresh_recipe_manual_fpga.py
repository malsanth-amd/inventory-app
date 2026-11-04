#!/usr/bin/env python3
"""
refresh_recipe_manual_fpga.py — FPGA/HPM recipe refresh via manual download.

The FPGA source for these boards lives on SharePoint, which is gated by
Microsoft 365/Azure AD SSO (confirmed: GET returns 401 Unauthorized for an
unauthenticated client). There's no API key or service-account path wired
up here, so this does NOT download automatically - it's a human-in-the-loop
helper:

  1. Tells you which boards are missing a staged FPGA file, and gives you
     the SharePoint link to open by hand (optionally opens it in your
     default browser with --open-browser).
  2. You download the file from SharePoint and drop it into this script's
     per-board staging folder (printed in the output).
  3. Re-run the script: it picks the newest file in each board's staging
     folder (by modification time) and merges it into recipe.yaml's "hpm"
     entry for that board - "bmc" and "bios" entries are left untouched.

This is NOT unattended/automatable as-is. To make it automatic, someone
with SharePoint admin rights needs to register an Azure AD app with
Sites.Read.All (or similar) so the script can call Microsoft Graph instead
of relying on a human to click through the browser.

KNOWN GAPS
  - "duck" shares a SharePoint site with "hornbill" ("Hornbill and Duck
    Platforms") but no folder link for duck specifically was provided -
    FPGA_SHAREPOINT_LINKS["duck"] is None until you supply one.
  - The exact firmware file extension on these SharePoint folders is
    unconfirmed; --pattern defaults to "*.tar.gz" (matching the HPM.1
    bundle format used elsewhere in this recipe) - adjust if the real
    files use a different extension (.zip, .bin, etc).

USAGE
    # Check status for all configured boards, don't download/open anything
    python refresh_recipe_manual_fpga.py

    # Open each missing board's SharePoint folder in your browser
    python refresh_recipe_manual_fpga.py --open-browser

    # After downloading, re-run to pick up the staged files
    python refresh_recipe_manual_fpga.py
"""

import argparse
import shutil
import sys
import webbrowser
from pathlib import Path

import yaml

from launcher_utils import app_dir

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_DROP_DIR = SCRIPT_DIR / "manual_downloads" / "fpga"

# SharePoint is browser-UI-only (AllItems.aspx?id=...), not a download API -
# these are "open this folder" links for a human, not fetchable URLs.
FPGA_SHAREPOINT_LINKS = {
    "falcon": "https://amdcloud.sharepoint.com/sites/server/Falcon%20and%20Seagull%20Platforms/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2Fserver%2FFalcon%20and%20Seagull%20Platforms%2FShared%20Documents%2F07%5FFPGA%2FFalcon&viewid=904e49ab%2Da872%2D44c5%2D90e3%2Dbb155d1cfe5d&viewpath=%2Fsites%2Fserver%2FFalcon%20and%20Seagull%20Platforms%2FShared%20Documents%2FForms%2FAllItems%2Easpx",
    "seagull": "https://amdcloud.sharepoint.com/sites/server/Falcon%20and%20Seagull%20Platforms/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2Fserver%2FFalcon%20and%20Seagull%20Platforms%2FShared%20Documents%2F07%5FFPGA%2FSeagull&viewid=904e49ab%2Da872%2D44c5%2D90e3%2Dbb155d1cfe5d&viewpath=%2Fsites%2Fserver%2FFalcon%20and%20Seagull%20Platforms%2FShared%20Documents%2FForms%2FAllItems%2Easpx",
    "hornbill": "https://amdcloud.sharepoint.com/sites/server/Hornbill%20and%20Duck%20Platforms/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2Fserver%2FHornbill%20and%20Duck%20Platforms%2FShared%20Documents%2F07%5FFPGA%2FrevA&viewid=af555a60%2D0ba2%2D4421%2D9ff8%2D53f32a17745e&d=wed2707ac60584619a2c86f61571fcefb&csf=1&CID=7f4b06a9%2Dd982%2D4481%2Daa2c%2D8b7d90f471ac&FolderCTID=0x01200014D2059F6B98B04C81ED3F716463B3C4",
    "eagle": "https://amdcloud.sharepoint.com/sites/server/Eagle%20and%20Dodo%20Platforms/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2Fserver%2FEagle%20and%20Dodo%20Platforms%2FShared%20Documents%2F07%5FFPGA%2FrevA&viewid=8645e58e%2Dc1ac%2D4875%2D89fc%2Df575a61c215c&d=wca9d4ca147104deba8c7add89b873233&csf=1&CID=795c94fa%2D3046%2D4247%2Dbdb3%2Da9403807c521&FolderCTID=0x012000AD8C9DBEFC82B24CA1B3A0C496289DB4",
    "duck": None,  # shares the Hornbill site but no board-specific folder link was supplied - see KNOWN GAPS
}

FPGA_SUFFIXES_TO_STRIP = [".tar.gz", ".tgz", ".zip", ".bin"]
# Files a browser download manager leaves behind mid-download - never treat these as "staged"
INCOMPLETE_DOWNLOAD_SUFFIXES = (".crdownload", ".part", ".tmp", ".download")


def strip_suffix(filename, suffixes):
    for suf in suffixes:
        if filename.lower().endswith(suf.lower()):
            return filename[: -len(suf)]
    return Path(filename).stem


def find_staged_file(drop_dir, pattern):
    if not drop_dir.is_dir():
        return None
    candidates = [
        f for f in drop_dir.glob(pattern)
        if f.is_file() and not f.name.lower().endswith(INCOMPLETE_DOWNLOAD_SUFFIXES)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda f: f.stat().st_mtime)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--boards", nargs="+", default=list(FPGA_SHAREPOINT_LINKS.keys()),
                         choices=list(FPGA_SHAREPOINT_LINKS.keys()))
    parser.add_argument("--drop-dir", default=str(DEFAULT_DROP_DIR),
                         help="Per-board staging folder root - drop downloaded files into <drop-dir>/<board>/")
    parser.add_argument("--pattern", default="*.tar.gz", help="Glob pattern to find the staged FPGA file")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--open-browser", action="store_true",
                         help="Open the SharePoint folder in your default browser for any board missing a staged file")
    args = parser.parse_args()

    drop_root = Path(args.drop_dir)
    staged = {}
    missing = []

    print("=== FPGA manual-download status ===")
    for board in args.boards:
        board_dir = drop_root / board
        link = FPGA_SHAREPOINT_LINKS.get(board)
        found = find_staged_file(board_dir, args.pattern)

        if found:
            version = strip_suffix(found.name, FPGA_SUFFIXES_TO_STRIP)
            staged[board] = {"path": found, "version": version}
            print(f"  {board:10s}: staged -> {found.name}  (version='{version}')")
        else:
            missing.append(board)
            board_dir.mkdir(parents=True, exist_ok=True)
            if link:
                print(f"  {board:10s}: MISSING. Download the latest FPGA image from:")
                print(f"               {link}")
                print(f"             and save it into: {board_dir}")
                if args.open_browser:
                    webbrowser.open(link)
            else:
                print(f"  {board:10s}: MISSING, and no SharePoint link is configured for this board "
                      f"(see FPGA_SHAREPOINT_LINKS in this script). Manually place the file into: {board_dir}")

    if not staged:
        print("\nNo boards have a staged file yet. Download the files above, then re-run this script.")
        return 1 if missing else 0

    # Merge into existing recipe, preserving bios/bmc and any un-staged boards' hpm entries
    output_path = Path(args.output)
    recipe = {"firmware": {}, "metadata": {}}
    if output_path.is_file():
        recipe = yaml.safe_load(output_path.read_text()) or recipe
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"\nBacked up previous recipe to {backup}")

    changes = []
    for board, info in staged.items():
        recipe["firmware"].setdefault(board, {})
        old_version = recipe["firmware"][board].get("hpm", {}).get("version")
        recipe["firmware"][board]["hpm"] = {
            "version": info["version"],
            "url": info["path"].resolve().as_uri(),
        }
        if old_version != info["version"]:
            changes.append(f"{board}.hpm: {old_version} -> {info['version']}")

    with open(output_path, "w") as fp:
        yaml.safe_dump(recipe, fp, sort_keys=False)

    print(f"\n=== Wrote {output_path} ===")
    if changes:
        print("Changes:")
        for c in changes:
            print(f"  {c}")
    else:
        print("No version changes vs. previous recipe.")

    if missing:
        print(f"\nNote: {len(missing)} board(s) still missing a staged file and were left unchanged in recipe.yaml: "
              f"{', '.join(missing)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
