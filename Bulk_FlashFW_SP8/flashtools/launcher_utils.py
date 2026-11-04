#!/usr/bin/env python3
"""
launcher_utils.py — Shared helper for building subprocess commands that work
both as plain `python <script>.py` calls (dev/debug) and inside a PyInstaller
`--onefile` build (where sys.executable is the compiled EXE itself, not a
generic Python interpreter capable of running an arbitrary sibling .py file).

Every call site that used to hand-build `[sys.executable, "-u", "<script>.py", ...]`
should instead call build_subcommand(), passing the dispatcher subcommand name
that flash_tools_app.py maps back to that same script's main().
"""

import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def build_subcommand(subcommand, script_filename, extra_args=None, unbuffered=False):
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, subcommand]
    else:
        cmd = [sys.executable] + (["-u"] if unbuffered else []) + [str(SCRIPT_DIR / script_filename)]
    return cmd + (extra_args or [])


def app_dir():
    """Directory for user-facing data files (recipe.yaml, systems.csv,
    cg_assets.csv, fleet_logs, downloaded firmware, ...).

    In a frozen (PyInstaller) build, every module's own __file__ resolves
    into the bundle's internal extraction/library dir (e.g. dist\\FlashTools\\
    _internal\\), NOT the folder containing the actual FlashTools.exe a
    recipient drops their data files next to. sys.executable always points
    at the real EXE location (both onefile and onedir), so that's the
    correct base in frozen mode. In normal (non-frozen) dev use, this is
    unchanged - same source folder __file__ always pointed to."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return SCRIPT_DIR


def bundled_script_available(script_path, default_path):
    """True if `script_path` can actually be run via build_subcommand().

    The bundled default script (e.g. ac_cycle.py) is compiled INTO the EXE
    when frozen - it's no longer a loose .py file sitting on disk next to
    FlashTools.exe, so an os.path.isfile() check on it (which worked fine
    pre-packaging) always fails frozen, silently disabling that code path.
    A custom override path (the user passed their own script) still needs
    to exist as a real file either way, frozen or not."""
    if getattr(sys, "frozen", False) and script_path == default_path:
        return True
    return os.path.isfile(script_path)


# Flags whose value is a credential - never write these in cleartext to any
# log file or echoed command line (e.g. flash_fleet.py's per-system
# fleet_logs/<name>.log, which embeds the exact argv a system was flashed
# with, --bmc-pass included, straight from the CSV's bmc_pass column).
_SECRET_FLAGS = {"--bmc-pass", "--pdu-pass", "--pdu-community", "--fvddr-token", "--api-key"}


def redact_cmd_for_display(cmd):
    """Return a copy of an argv list with any credential flag's value
    replaced by '***' - safe to print/log/echo."""
    redacted = list(cmd)
    for i, arg in enumerate(redacted):
        if arg in _SECRET_FLAGS and i + 1 < len(redacted):
            redacted[i + 1] = "***"
    return redacted
