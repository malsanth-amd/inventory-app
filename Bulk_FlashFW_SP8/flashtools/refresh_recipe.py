#!/usr/bin/env python3
"""
refresh_recipe.py — Pull the latest BKC recipe for a project from the Nexus
MCP server and write it out in the board-keyed schema flash_system.py expects:

    firmware:
      <board>:
        bios: {version: ..., url: ...}
        bmc:  {version: ..., url: ...}
        hpm:  {version: ..., url: ...}   # HPM = FPGA
    metadata:
      bkc_candidate: ...
      project: ...

This talks directly to the Nexus MCP server documented in the nexus-bkc skill
(http://pdase-mcp-nexus.amd.com:8083/mcp/) using the official `mcp` Python
client (streamable-HTTP transport) — no Claude session required.

SETUP
    pip install mcp pyyaml
    export NEXUS_API_KEY=<key from your Nexus administrator>

USAGE
    # Latest release for venice-sp8 (default)
    python refresh_recipe.py

    # Latest release for a different project
    python refresh_recipe.py --project venice-sp7

    # A specific named release/candidate instead of "latest"
    python refresh_recipe.py --name bkc_venice-sp8_26.09.25 --type candidate

    # Inspect exactly what Nexus returned, without touching recipe.yaml
    python refresh_recipe.py --dump-raw raw_response.yaml --output /dev/null

NOTE ON SCHEMA
    get_release_recipe()/get_candidate_recipe() are documented to return a
    human-readable recipe (markdown tables by default, or format="yaml").
    This script requests format="yaml" and then normalizes whatever key
    names come back (case/space-insensitive) into the schema above. If
    Nexus's actual field names don't match what's expected here, use
    --dump-raw to see the raw payload and adjust `normalize_recipe()`.
"""

import argparse
import asyncio
import os
import re
import shutil
import sys
from pathlib import Path

import yaml

try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:
    print("Missing dependency. Run: pip install mcp", file=sys.stderr)
    raise

from launcher_utils import app_dir

SCRIPT_DIR = app_dir()
DEFAULT_MCP_URL = os.environ.get("NEXUS_MCP_URL", "http://pdase-mcp-nexus.amd.com:8083/mcp/")
DEFAULT_OUTPUT = SCRIPT_DIR / "recipe.yaml"

BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]


def _text_from_result(result):
    """MCP tool results come back as a list of content blocks; pull text out."""
    parts = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def _strip_code_fence(text):
    m = re.match(r"^```(?:ya?ml)?\s*\n(.*)\n```\s*$", text.strip(), re.DOTALL)
    return m.group(1) if m else text


def _norm_key(k):
    return re.sub(r"[\s_]+", "", str(k)).lower()


def _find(d, *candidates):
    """Case/space-insensitive key lookup in a dict."""
    if not isinstance(d, dict):
        return None
    norm_map = {_norm_key(k): v for k, v in d.items()}
    for c in candidates:
        v = norm_map.get(_norm_key(c))
        if v is not None:
            return v
    return None


def normalize_recipe(raw_yaml_text, project):
    """Best-effort normalization of whatever Nexus's get_*_recipe(format="yaml")
    returns into the {firmware: {board: {bios/bmc/hpm: {version,url}}}} schema.

    Handles two shapes we might reasonably get back:
      A) Already keyed by board, e.g. {"firmware": {"eagle": {"bios": {...}}}}
      B) A flat/tabular shape, e.g. {"platform_firmware": [{"Platform": "eagle",
         "BIOS Version": "...", "BIOS URL": "...", "BMC Version": "...", ...}]}
    """
    data = yaml.safe_load(_strip_code_fence(raw_yaml_text))
    if not isinstance(data, dict):
        raise ValueError("Unexpected recipe format from Nexus (not a YAML mapping). Use --dump-raw to inspect.")

    firmware = {}

    # Shape A: already board-keyed under "firmware"
    fw_block = _find(data, "firmware")
    if isinstance(fw_block, dict) and all(isinstance(v, dict) for v in fw_block.values()):
        looks_like_board_keyed = any(
            _find(v, "bios") or _find(v, "bmc") or _find(v, "hpm") for v in fw_block.values()
        )
        if looks_like_board_keyed:
            for board, entry in fw_block.items():
                board_key = board.lower()
                firmware[board_key] = {}
                for comp in ("bios", "bmc", "hpm"):
                    comp_entry = _find(entry, comp)
                    if comp_entry:
                        firmware[board_key][comp] = {
                            "version": _find(comp_entry, "version"),
                            "url": _find(comp_entry, "url", "download_url", "link"),
                        }

    # Shape B: tabular rows, one per platform
    if not firmware:
        rows = _find(data, "platform_firmware", "platform firmware", "platforms", "firmware_table")
        if isinstance(rows, list):
            for row in rows:
                platform = _find(row, "platform", "board")
                if not platform:
                    continue
                board_key = str(platform).lower()
                firmware.setdefault(board_key, {})
                for comp, names in (
                    ("bios", ("bios version", "bios")),
                    ("bmc", ("bmc version", "bmc")),
                    ("hpm", ("hpm version", "hpm", "hpm fpga version")),
                ):
                    version = _find(row, *names)
                    url = _find(row, f"{names[0]} url", f"{comp} url", f"{comp}_url")
                    if version:
                        firmware[board_key][comp] = {"version": version, "url": url}

    if not firmware:
        raise ValueError(
            "Could not recognize the recipe structure returned by Nexus.\n"
            "Re-run with --dump-raw to see the exact payload and adjust normalize_recipe() accordingly.\n"
            f"Top-level keys seen: {list(data.keys())}"
        )

    metadata = _find(data, "metadata") or {}
    out_metadata = {
        "bkc_candidate": _find(metadata, "bkc_candidate") or _find(data, "bkc_candidate"),
        "project": project,
    }

    return {"firmware": firmware, "metadata": out_metadata}


async def fetch_recipe(mcp_url, api_key, project, name=None, kind="release"):
    headers = {"X-API-Key": api_key} if api_key else {}

    async with streamablehttp_client(mcp_url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            list_tool = "search_releases" if (name and kind == "release") else \
                        "search_candidates" if (name and kind == "candidate") else \
                        "list_releases" if kind == "release" else "list_candidates"

            list_args = {"project": project, "limit": 10}
            if name:
                arg_name = "bkc_release_name" if kind == "release" else "bkc_candidate_name"
                list_args = {arg_name: name, "project": project}

            listing = await session.call_tool(list_tool, list_args)
            listing_text = _text_from_result(listing)
            listing_data = yaml.safe_load(_strip_code_fence(listing_text))

            entries = listing_data if isinstance(listing_data, list) else \
                      listing_data.get("results") or listing_data.get("releases") or \
                      listing_data.get("candidates") or []
            if not entries:
                raise ValueError(f"No {kind}s found for project={project} name={name!r}.\nRaw response:\n{listing_text}")

            top = entries[0]  # list_* is assumed most-recent-first per skill docs
            id_field = "candidate_id" if kind == "candidate" else "release_id"
            release_id = _find(top, id_field, "release_id", "candidate_id", "id")
            label = _find(top, "bkc_release", "bkc_candidate", "name")
            print(f"Using {kind} '{label}' ({id_field}={release_id})")

            recipe_tool = "get_candidate_recipe" if kind == "candidate" else "get_release_recipe"
            recipe_result = await session.call_tool(
                recipe_tool, {"release_id": release_id, "project": project, "format": "yaml"}
            )
            return _text_from_result(recipe_result)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default="venice-sp8", choices=["venice-sp7", "venice-sp8", "turin"])
    parser.add_argument("--type", dest="kind", default="release", choices=["release", "candidate"])
    parser.add_argument("--name", help="Specific release/candidate name (partial match). Omit for latest.")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL)
    parser.add_argument("--api-key", default=os.environ.get("NEXUS_API_KEY"),
                         help="Nexus MCP API key (or set NEXUS_API_KEY)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Path to write the normalized recipe.yaml")
    parser.add_argument("--dump-raw", help="Also write the raw Nexus response to this path, for debugging schema mismatches")
    args = parser.parse_args()

    if not args.api_key:
        print("ERROR: No Nexus API key. Set NEXUS_API_KEY or pass --api-key.\n"
              "Contact the Nexus administrator to obtain one (see nexus-bkc skill docs).", file=sys.stderr)
        return 1

    print(f"Fetching latest {args.kind} recipe for project={args.project} from {args.mcp_url} ...")
    raw_text = asyncio.run(fetch_recipe(args.mcp_url, args.api_key, args.project, args.name, args.kind))

    if args.dump_raw:
        Path(args.dump_raw).write_text(raw_text)
        print(f"Raw Nexus response written to {args.dump_raw}")

    normalized = normalize_recipe(raw_text, args.project)

    output_path = Path(args.output)
    if output_path.is_file():
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"Backed up previous recipe to {backup}")

        try:
            old = yaml.safe_load(output_path.read_text())
            print("\nChanges vs. previous recipe:")
            for board, entry in normalized["firmware"].items():
                old_entry = (old or {}).get("firmware", {}).get(board, {})
                for comp in ("bios", "bmc", "hpm"):
                    new_v = entry.get(comp, {}).get("version")
                    old_v = old_entry.get(comp, {}).get("version")
                    if new_v != old_v:
                        print(f"  {board}.{comp}: {old_v} -> {new_v}")
        except Exception:
            pass

    with open(output_path, "w") as fp:
        yaml.safe_dump(normalized, fp, sort_keys=False)

    print(f"\nWrote {output_path}")
    print(f"Boards: {list(normalized['firmware'].keys())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
