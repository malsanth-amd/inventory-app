#!/usr/bin/env python3
"""
sharepoint_fpga.py — Download a specific, already-identified FPGA firmware
file from SharePoint via Microsoft Graph, as an alternative to a Confluence
attachment download (which needs either raw HTTP, blocked by a CASB, or a
full Playwright/Chromium browser).

DESIGN: this module NEVER independently decides "which FPGA version is
current" - it only searches a board's SharePoint folder tree for an EXACT
filename match that the caller already knows is correct (from Confluence's
FPGA row parsing in refresh_recipe_confluence_fpga.py). This matters
because SharePoint folder/filenames encode a packaging/tool version (e.g.
"0.4.4") that does NOT match the real FPGA version Confluence shows as
bold text (e.g. "R0.4.7_R0.4.4") - guessing "latest" independently here
would risk exactly the kind of version-mismatch bug already hit twice this
session (BMC's "latest by mtime" picking a non-blessed build; BIOS's
original per-cell link assumption). Confirmed in testing: naive "latest by
name" would also pick a stale/legacy-format folder on at least one board's
SharePoint site (mixed "<board>_FPGA_X.Y.Z" and older "<board>_HPMFPGA_RX.Y.Z"
naming side by side) - another reason not to guess here.

SETUP (one-time, per machine/user)
    The first time this is needed, ensure_graph_authenticated() below walks
    you through a one-time Microsoft device-code sign-in (same flow as
    signing into Teams/Outlook on a new device) and the resulting token is
    saved to ~/.config/microsoft-graph/token.json - every later run
    silently refreshes it with no further prompts, unless the account goes
    ~90 days without any use.
"""

import urllib.parse
from pathlib import Path

from graph_client import GraphClient

# Known SharePoint document-library root folders per board - the exact
# folder path a board's firmware lives under is NOT uniform (confirmed:
# falcon/seagull use "07_FPGA/Falcon"/"07_FPGA/Seagull", eagle/hornbill use
# a shared "07_FPGA/revA"). Reuses the same per-board URLs already in
# refresh_recipe_manual_fpga.py's FPGA_SHAREPOINT_LINKS rather than
# duplicating them - this module just parses the (site, folder) out of
# those same links instead of requiring a human to open them.
from refresh_recipe_manual_fpga import FPGA_SHAREPOINT_LINKS

# The subfolder containing the Redfish-compatible firmware package. Boards
# also have a "viaDediprog" sibling (a physical-programmer image format,
# NOT compatible with this toolkit's Redfish-based flashing) - never used
# as a fallback here, since silently grabbing the wrong format would be a
# worse failure mode than just reporting "not found".
FIRMWARE_SUBFOLDER = "viaBMC"


def parse_sharepoint_folder_url(url):
    """Extract (site_path, folder_path) from a SharePoint 'AllItems.aspx?
    id=...' folder-sharing link, e.g.:
      https://amdcloud.sharepoint.com/sites/server/Hornbill%20and%20Duck%20Platforms/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2Fserver%2FHornbill%20and%20Duck%20Platforms%2FShared%20Documents%2F07%5FFPGA%2FrevA&...
    -> site_path = "/sites/server/Hornbill and Duck Platforms"
       folder_path = "07_FPGA/revA"
    """
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if "id" not in qs:
        raise ValueError(f"No 'id' query parameter found in SharePoint URL: {url}")
    id_param = qs["id"][0]

    library_markers = ("/Shared Documents/", "/Shared%20Documents/")
    marker = next((m for m in library_markers if m in id_param), None)
    if not marker:
        raise ValueError(f"Could not find a document-library marker in the 'id' param: {id_param}")

    idx = id_param.index(marker)
    site_path = id_param[:idx]
    folder_path = id_param[idx + len(marker):]
    return site_path, folder_path


def ensure_graph_authenticated(client=None):
    """Block until `client` has a usable Microsoft Graph token, driving a
    one-time interactive device-code sign-in if needed. Never prints the
    raw device_code value (a sensitive one-time auth artifact) - only the
    user-facing verification URL and short display code. complete_auth()
    itself polls for up to ~120s (Microsoft's token endpoint, every 5s) -
    if the user hasn't finished within that window, ask them to re-run
    rather than looping indefinitely on one device code (it also has its
    own ~15min expiry). Returns the (possibly newly-authenticated)
    GraphClient."""
    client = client or GraphClient()
    if client.is_authenticated():
        return client

    auth = client.start_auth()
    print("\n=== Microsoft sign-in required (one-time setup) ===")
    print(f"  1. Open: {auth['url']}")
    print(f"  2. Enter code: {auth['user_code']}")
    print("  3. Complete sign-in with your AMD account.")
    print("  Waiting for sign-in to complete (up to ~2 minutes) ...")

    result = client.complete_auth(auth["device_code"])
    if result.get("status") != "ok":
        raise RuntimeError(
            f"Microsoft sign-in did not complete: {result.get('error', 'unknown error')}. "
            f"Re-run this command to get a fresh sign-in link."
        )
    print("  Signed in - token saved, future runs won't prompt again.")
    return client


def resolve_site_and_drive(client, site_path, hostname="amdcloud.sharepoint.com"):
    """Direct site-by-path lookup (one Graph call, deterministic - no
    name-search ambiguity) + its default document library's drive id."""
    encoded_path = urllib.parse.quote(site_path, safe="/")
    site = client.get(f"/sites/{hostname}:{encoded_path}")
    drive = client.get(f"/sites/{site['id']}/drive")
    return site["id"], drive["id"]


def find_fpga_file(client, drive_id, folder_path, filename, verbose=False):
    """Search every subfolder under folder_path (not just the
    alphabetically/mtime "latest" one - deliberately, see module docstring)
    for filename inside a FIRMWARE_SUBFOLDER child, returning its full
    drive-relative path, or None if not found anywhere."""
    top = client.try_get(f"/drives/{drive_id}/root:/{urllib.parse.quote(folder_path)}:/children")
    if not top:
        return None
    for entry in top.get("value", []):
        if not entry.get("folder"):
            continue
        via_path = f"{folder_path}/{entry['name']}/{FIRMWARE_SUBFOLDER}"
        if verbose:
            print(f"    checking {via_path} ...")
        sub = client.try_get(f"/drives/{drive_id}/root:/{urllib.parse.quote(via_path)}:/children")
        if not sub:
            continue
        for f in sub.get("value", []):
            if f.get("name") == filename:
                return f"{via_path}/{filename}"
    return None


def download_fpga_from_sharepoint(board, filename, dest_dir, verbose=False, auto_auth=True):
    """Download `filename` (already known-correct, from Confluence's FPGA
    row parsing) for `board` from its SharePoint FPGA folder. Returns the
    local destination Path. Raises on any failure - caller decides whether
    to treat that as fatal or fall back to another download mechanism.
    By default (auto_auth=True) drives a one-time interactive device-code
    sign-in automatically the first time this is run on a machine; pass
    auto_auth=False for unattended/scheduled runs where no one is present
    to complete a sign-in (fails fast instead of hanging on a prompt)."""
    link = FPGA_SHAREPOINT_LINKS.get(board)
    if not link:
        raise ValueError(f"No SharePoint link configured for board '{board}' in FPGA_SHAREPOINT_LINKS "
                          f"(refresh_recipe_manual_fpga.py) - cannot resolve its FPGA folder.")

    site_path, folder_path = parse_sharepoint_folder_url(link)
    client = GraphClient()
    if not client.is_authenticated():
        if not auto_auth:
            raise RuntimeError(
                "Not logged in to Microsoft Graph, and auto_auth is disabled for this run. "
                "Run once interactively first to complete the one-time sign-in."
            )
        client = ensure_graph_authenticated(client)

    _site_id, drive_id = resolve_site_and_drive(client, site_path)
    if verbose:
        print(f"    searching {site_path} for {filename} ...")
    file_path = find_fpga_file(client, drive_id, folder_path, filename, verbose=verbose)
    if not file_path:
        raise FileNotFoundError(
            f"'{filename}' was not found in any version folder under {folder_path} "
            f"on the '{site_path}' SharePoint site (searched every subfolder's "
            f"'{FIRMWARE_SUBFOLDER}' child)."
        )

    content = client.get_bytes(f"/drives/{drive_id}/root:/{urllib.parse.quote(file_path)}:/content")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    dest.write_bytes(content)
    return dest
