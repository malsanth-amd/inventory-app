#!/usr/bin/env python3
"""
refresh_recipe_fileshare.py — Alternative to refresh_recipe.py (Nexus).

Finds the LATEST BMC firmware on an internal file share and the LATEST BIOS
firmware on an Artifactory weekly feed, downloads them, and merges the
result into recipe.yaml (only the "bmc" and "bios" keys are touched per
board - "hpm"/FPGA is left exactly as it already is in recipe.yaml, since
that source only tracks BMC + BIOS).

SOURCES (defaults, override with flags/env vars)
    BMC : file://atlcorpnetfs/BiosOnly/BMC_Release/sp7/
          (UNC file share - browsed directly, no download needed, the file
          is just referenced/copied from the share)
    BIOS: https://mkmartifactory.amd.com:8443/artifactory/fw-bios-dev-local/PlatformBIOS/Venicesp8/weekly/
          (Artifactory generic repo - browsed via the Storage REST API,
          then the chosen artifact is downloaded over HTTPS)

HOW "LATEST" IS DECIDED
    Primarily by file modification time / Artifactory `lastModified`
    (most robust against unknown naming schemes). A human-readable version
    string is also extracted from the filename for labeling/diffing, on a
    best-effort basis - verify it with --list-only before trusting it.

BIOS -> BOARD MAPPING
    BIOS filenames encode the board via a prefix (see BOARD_BIOS_PREFIX
    below, derived from the existing recipe.yaml: WHOV=duck/hornbill,
    WEAV=eagle, WFAV=falcon, WSGV=seagull). Verify/adjust this map if
    Artifactory's naming convention differs.

AUTH
    BMC share  : whatever Windows credentials/VPN access you already have
                 to \\atlcorpnetfs.
    Artifactory: tries anonymous first; set ARTIFACTORY_API_KEY (sent as
                 X-JFrog-Art-Api) or ARTIFACTORY_USER/ARTIFACTORY_PASS
                 (basic auth) if the repo requires auth.

USAGE
    # See what would be picked, without downloading or touching recipe.yaml
    python refresh_recipe_fileshare.py --list-only

    # Actually refresh (downloads into --firmware-dir, updates recipe.yaml)
    python refresh_recipe_fileshare.py
"""

import argparse
import os
import re
import shutil
import socket
import sys
import threading
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse

import requests
import yaml

from launcher_utils import app_dir

SHARE_PROBE_TIMEOUT = 5  # seconds - fail fast instead of hanging on SMB negotiation

SCRIPT_DIR = app_dir()
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"

DEFAULT_BMC_SHARE = "file://atlcorpnetfs/BiosOnly/BMC_Release/sp7/"
DEFAULT_BIOS_REPO = "https://mkmartifactory.amd.com:8443/artifactory/fw-bios-dev-local/PlatformBIOS/Venicesp8/weekly/"

BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]

# VERIFY against real Artifactory filenames - see module docstring.
BOARD_BIOS_PREFIX = {
    "duck": "WHOV",
    "hornbill": "WHOV",
    "eagle": "WEAV",
    "falcon": "WFAV",
    "seagull": "WSGV",
}

BMC_SUFFIXES_TO_STRIP = [".static.mtd.tar", ".mtd.tar", ".tar"]
BIOS_SUFFIXES_TO_STRIP = [".tar.gz", ".tgz", ".zip"]


def strip_suffix(filename, suffixes):
    for suf in suffixes:
        if filename.lower().endswith(suf.lower()):
            return filename[: -len(suf)]
    return Path(filename).stem


def file_uri_to_path(uri):
    """file://host/share/path -> \\\\host\\share\\path (UNC), handling both
    file://host/... and file:///C:/... forms."""
    parsed = urlparse(uri)
    if parsed.netloc:
        unc = f"\\\\{parsed.netloc}{parsed.path}"
    else:
        unc = parsed.path.lstrip("/")
    return str(PureWindowsPath(unc.replace("/", "\\")))


# ----------------------------------------------------------------------------
# BMC share
# ----------------------------------------------------------------------------

def run_with_timeout(fn, timeout, *args, **kwargs):
    """Run fn in a daemon thread and bound it with a hard wall-clock timeout.

    Needed because filesystem calls against a dead/filtered SMB path (e.g.
    is_dir(), rglob()) can hang indefinitely with no OSError raised - a TCP
    connect succeeding is not proof the SMB protocol layer will ever respond.
    The thread is abandoned (not killed) on timeout; harmless for a
    short-lived CLI but means don't call this in a tight loop.
    """
    result = {}

    def _runner():
        try:
            result["value"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller's thread
            result["error"] = e

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError(f"Operation timed out after {timeout}s (thread abandoned)")
    if "error" in result:
        raise result["error"]
    return result["value"]


def _probe_host_reachable(host, port=445, timeout=SHARE_PROBE_TIMEOUT):
    """Fail fast on an unreachable/unresolvable SMB host instead of letting
    the OS hang for minutes on filesystem calls against a dead UNC path.

    socket.create_connection()'s timeout does NOT bound DNS resolution
    (getaddrinfo can hang indefinitely on some resolvers), so the probe
    runs in a daemon thread and is abandoned (not joined) on timeout.
    """
    result = {"ok": False}

    def _attempt():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                result["ok"] = True
        except OSError:
            result["ok"] = False

    t = threading.Thread(target=_attempt, daemon=True)
    t.start()
    t.join(timeout)
    return result["ok"] if not t.is_alive() else False


# Matches version-labeled subfolders like "v2.18.0.100I" or "v3.0.0.101A".
# Used only to FILTER OUT stray non-release folders (AI, DOC, JIRA, debug/MRL
# variants like "v2.18.0.080D-DEBUG-..." or "v2.16.0.071F-MRL") - the ordering
# among folders that pass this filter is by modification time, not version
# number (see find_latest_bmc).
BMC_VERSION_FOLDER_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\.(\d+)([A-Za-z]*)$", re.IGNORECASE)


def find_latest_bmc(share_uri, file_pattern="*.tar", subfolder="BMC", timeout=30):
    """Pick the most-recently-modified version subfolder (by folder mtime -
    same "latest by modification time" approach used for BIOS/Artifactory's
    lastModified), then the newest firmware file inside its `subfolder`
    (e.g. .../sp7/v3.0.0.101A/BMC/*.tar). Pass subfolder="" to search the
    version folder directly instead.

    Folders are still required to match BMC_VERSION_FOLDER_RE so stray
    non-release folders (AI, DOC, JIRA, debug/MRL variants, etc.) are never
    considered - only the *ordering* among valid version folders is by mtime.

    Both directory operations are single-level (non-recursive) and bounded
    by `timeout`, since this share has ~70+ subfolders and an unbounded
    recursive walk (rglob) can take minutes.
    """
    host = urlparse(share_uri).netloc
    if host and not _probe_host_reachable(host):
        raise ConnectionError(
            f"Cannot reach SMB host '{host}' (port 445) within {SHARE_PROBE_TIMEOUT}s. "
            f"Check VPN/network access before retrying."
        )

    share_path = Path(file_uri_to_path(share_uri))

    def _list_top_level():
        if not share_path.is_dir():
            raise FileNotFoundError(
                f"Cannot access BMC share at {share_path} (from {share_uri}). "
                f"TCP port 445 is reachable but the path doesn't exist, isn't shared, "
                f"or access was denied - check the path and your share permissions."
            )
        return list(share_path.iterdir())  # single level - fast even with many entries

    try:
        entries = run_with_timeout(_list_top_level, timeout)
    except TimeoutError:
        raise TimeoutError(
            f"Listing {share_path} did not respond within {timeout}s. The host accepted a TCP "
            f"connection on port 445 but the SMB share itself is not responding - check VPN/"
            f"network access, that the share exists, and that you have permission to browse it."
        )

    version_dirs = [e for e in entries if e.is_dir() and BMC_VERSION_FOLDER_RE.match(e.name)]

    if not version_dirs:
        raise FileNotFoundError(
            f"No folders under {share_path} matched the version pattern {BMC_VERSION_FOLDER_RE.pattern}. "
            f"Share layout may have changed - check manually and adjust BMC_VERSION_FOLDER_RE."
        )

    latest_dir = max(version_dirs, key=lambda e: e.stat().st_mtime)

    # The .tar lives inside a "BMC" subfolder of the version folder, e.g.
    # .../sp7/v3.0.0.101A/BMC/*.tar - not directly in the version folder itself.
    def _resolve_search_dir():
        if subfolder:
            candidate = latest_dir / subfolder
            if candidate.is_dir():
                return candidate
            # case-insensitive fallback (SMB shares are usually case-insensitive
            # already, but be defensive)
            for entry in latest_dir.iterdir():
                if entry.is_dir() and entry.name.lower() == subfolder.lower():
                    return entry
            raise FileNotFoundError(
                f"Expected a '{subfolder}' subfolder inside {latest_dir} but didn't find one. "
                f"Pass --bmc-subfolder '' to search {latest_dir} directly instead, or the correct subfolder name."
            )
        return latest_dir

    def _list_files_in_latest():
        search_dir = _resolve_search_dir()
        return search_dir, list(search_dir.glob(file_pattern))

    try:
        search_dir, files = run_with_timeout(_list_files_in_latest, timeout)
    except TimeoutError:
        raise TimeoutError(f"Listing {latest_dir} did not respond within {timeout}s.")

    if not files:
        raise FileNotFoundError(f"No files matching '{file_pattern}' found in {search_dir}")

    # Prefer a base "sp7_..." image over any oddly-named variant in the same folder
    sp7_named = [f for f in files if "sp7" in f.name.lower()]
    chosen = max(sp7_named or files, key=lambda p: p.stat().st_mtime)

    version = strip_suffix(chosen.name, BMC_SUFFIXES_TO_STRIP)
    return {"path": chosen, "version": version, "version_folder": latest_dir.name}


# ----------------------------------------------------------------------------
# Artifactory BIOS repo
# ----------------------------------------------------------------------------

def artifactory_headers():
    headers = {}
    api_key = os.environ.get("ARTIFACTORY_API_KEY")
    if api_key:
        headers["X-JFrog-Art-Api"] = api_key
    return headers


def artifactory_auth():
    user = os.environ.get("ARTIFACTORY_USER")
    password = os.environ.get("ARTIFACTORY_PASS")
    return (user, password) if user and password else None


def artifactory_storage_url(browse_url):
    """Turn a human-browsable Artifactory URL into its Storage REST API
    equivalent: .../artifactory/<repo>/<path> -> .../artifactory/api/storage/<repo>/<path>"""
    marker = "/artifactory/"
    idx = browse_url.index(marker) + len(marker)
    base, rest = browse_url[:idx], browse_url[idx:]
    return f"{base}api/storage/{rest}"


def artifactory_list(url, verify=True):
    api_url = artifactory_storage_url(url)
    resp = requests.get(api_url, headers=artifactory_headers(), auth=artifactory_auth(), verify=verify, timeout=60)
    resp.raise_for_status()
    return resp.json()


def artifactory_walk_latest_files(base_url, max_depth=2, verify=True):
    """Recursively list an Artifactory folder (e.g. date-stamped weekly
    subfolders) and return a flat list of {name, download_url, last_modified}
    for every file found, up to max_depth levels deep."""
    files = []

    def _walk(url, depth):
        data = artifactory_list(url, verify=verify)
        for child in data.get("children", []):
            child_url = url.rstrip("/") + child["uri"]
            if child.get("folder"):
                if depth < max_depth:
                    _walk(child_url, depth + 1)
            else:
                info = requests.get(
                    artifactory_storage_url(child_url),
                    headers=artifactory_headers(), auth=artifactory_auth(),
                    verify=verify, timeout=30,
                ).json()
                files.append({
                    "name": child["uri"].lstrip("/"),
                    "download_url": child_url,
                    "last_modified": info.get("lastModified", ""),
                })

    _walk(base_url, 0)
    return files


def find_latest_bios(repo_url, board, verify=True, max_depth=2):
    prefix = BOARD_BIOS_PREFIX.get(board)
    if not prefix:
        raise ValueError(f"No BIOS filename prefix configured for board '{board}' in BOARD_BIOS_PREFIX")

    all_files = artifactory_walk_latest_files(repo_url, max_depth=max_depth, verify=verify)
    matches = [f for f in all_files if f["name"].upper().startswith(prefix.upper())
               and any(f["name"].lower().endswith(s) for s in BIOS_SUFFIXES_TO_STRIP)]
    if not matches:
        raise FileNotFoundError(
            f"No BIOS artifact found under {repo_url} starting with prefix '{prefix}' for board '{board}'. "
            f"Run with --list-only to see what's actually there."
        )

    latest = max(matches, key=lambda f: f["last_modified"])
    version = strip_suffix(Path(latest["name"]).name, BIOS_SUFFIXES_TO_STRIP)
    return {"download_url": latest["download_url"], "version": version, "name": Path(latest["name"]).name}


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bmc-share", default=DEFAULT_BMC_SHARE)
    parser.add_argument("--bios-repo", default=DEFAULT_BIOS_REPO)
    parser.add_argument("--boards", nargs="+", default=BOARD_CODES, choices=BOARD_CODES)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification for the Artifactory request")
    parser.add_argument("--bmc-timeout", type=int, default=30, help="Max seconds to wait for the BMC share to respond")
    parser.add_argument("--bmc-subfolder", default="BMC",
                         help="Subfolder inside the version folder where the .tar lives "
                              "(e.g. v3.0.0.101A/BMC/*.tar). Pass '' to search the version folder directly.")
    parser.add_argument("--list-only", action="store_true",
                         help="Just show what would be selected as 'latest' - no download, no recipe.yaml write")
    args = parser.parse_args()
    verify = not args.insecure

    print(f"=== BMC: scanning {args.bmc_share} ===")
    try:
        bmc_latest = find_latest_bmc(args.bmc_share, subfolder=args.bmc_subfolder, timeout=args.bmc_timeout)
        print(f"  Latest BMC: {bmc_latest['version_folder']}/{bmc_latest['path'].name}  (version='{bmc_latest['version']}')")
    except Exception as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return 1

    print(f"\n=== BIOS: scanning {args.bios_repo} ===")
    bios_latest = {}
    for board in args.boards:
        try:
            info = find_latest_bios(args.bios_repo, board, verify=verify)
            bios_latest[board] = info
            print(f"  {board:10s}: {info['name']}  (version='{info['version']}', modified={info.get('last_modified', '?')})")
        except Exception as e:
            print(f"  {board:10s}: ERROR - {e}", file=sys.stderr)

    if args.list_only:
        print("\n--list-only set, nothing downloaded or written.")
        return 0

    # Load existing recipe to preserve "hpm" blocks and merge in-place
    output_path = Path(args.output)
    recipe = {"firmware": {}, "metadata": {}}
    if output_path.is_file():
        recipe = yaml.safe_load(output_path.read_text()) or recipe
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"\nBacked up previous recipe to {backup}")

    print("\n=== Downloading / staging firmware ===")
    fw_dir = Path(args.firmware_dir)
    changes = []

    for board in args.boards:
        recipe["firmware"].setdefault(board, {})
        old_bmc = recipe["firmware"][board].get("bmc", {}).get("version")
        old_bios = recipe["firmware"][board].get("bios", {}).get("version")

        # BMC: same shared image for every board (matches current recipe convention)
        bmc_dest_dir = fw_dir / "bmc" / board
        bmc_dest_dir.mkdir(parents=True, exist_ok=True)
        bmc_dest = bmc_dest_dir / bmc_latest["path"].name
        if not bmc_dest.exists():
            print(f"  Copying BMC image for {board}: {bmc_latest['path'].name}")
            shutil.copy2(bmc_latest["path"], bmc_dest)
        recipe["firmware"][board]["bmc"] = {
            "version": bmc_latest["version"],
            "url": bmc_dest.as_uri(),
        }
        if old_bmc != bmc_latest["version"]:
            changes.append(f"{board}.bmc: {old_bmc} -> {bmc_latest['version']}")

        # BIOS: per-board artifact
        if board in bios_latest:
            info = bios_latest[board]
            bios_dest_dir = fw_dir / "bios" / board
            bios_dest_dir.mkdir(parents=True, exist_ok=True)
            bios_dest = bios_dest_dir / info["name"]
            if not bios_dest.exists():
                print(f"  Downloading BIOS for {board}: {info['name']} ...")
                resp = requests.get(info["download_url"], headers=artifactory_headers(),
                                     auth=artifactory_auth(), verify=verify, stream=True, timeout=120)
                resp.raise_for_status()
                with open(bios_dest, "wb") as fp:
                    for chunk in resp.iter_content(chunk_size=1 << 20):
                        fp.write(chunk)
            recipe["firmware"][board]["bios"] = {
                "version": info["version"],
                "url": info["download_url"],
            }
            if old_bios != info["version"]:
                changes.append(f"{board}.bios: {old_bios} -> {info['version']}")
        else:
            print(f"  Skipping BIOS for {board} (lookup failed above, leaving existing recipe entry untouched)")

    recipe.setdefault("metadata", {})["bmc_bios_source"] = {
        "bmc_share": args.bmc_share,
        "bios_repo": args.bios_repo,
    }

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
