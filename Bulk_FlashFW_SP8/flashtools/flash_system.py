#!/usr/bin/env python3
"""
flash_system.py — Given only a system name, resolve its BMC, decide which
BIOS / BMC / FPGA(HPM) firmware it needs, and flash it directly via Redfish.

This reimplements the firmware_update() flow extracted from
bkc_venice-sp8_v3.1.exe (project/venice-sp8/crb/redfish.py), minus PRISM/Nexus
plumbing: it talks straight to the SUT's BMC over Redfish HTTPS.

WORKFLOW
  1. Resolve system name -> BMC IP + board/platform code, via a ChangeGear
     asset export CSV (see --cg-cache) or manual overrides.
  2. Load recipe.yaml (board -> {bios,bmc,hpm}{version,url}) - this is the
     "intended" firmware, pulled verbatim out of the BKC installer.
  3. Query the BMC's current BIOS/BMC/HPM(FPGA) versions via Redfish.
  4. Diff current vs. recipe, print the plan, ask for confirmation.
  5. Flash whatever differs, in the safe order BMC -> HPM(FPGA) -> BIOS,
     because a BMC factory reset invalidates the other two.

BEFORE YOU RUN THIS AGAINST REAL HARDWARE
  - Review the CONFIG section below and the --cg-cache column names against
    your actual ChangeGear export - the column names here are guesses and
    MUST be verified.
  - Set BMC_USER / BMC_PASS (or pass --bmc-user/--bmc-pass). No credentials
    are hardcoded.
  - Run with --dry-run first. It only prints what would happen.
  - This script powers off the SUT, flashes firmware, and factory-resets the
    BMC when a BMC update is needed. These are destructive, hard-to-reverse
    actions on real hardware - only run it deliberately.

Usage:
    python flash_system.py <system_name> [options]
    python flash_system.py sut-rack3-u12 --dry-run
    python flash_system.py sut-rack3-u12 --bmc-ip 10.1.2.3 --platform eagle
"""

import argparse
import csv
import getpass
import os
import re
import subprocess
import sys
import time
import json
from pathlib import Path

import requests
import urllib3
import yaml

from launcher_utils import app_dir, build_subcommand, bundled_script_available

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------------------------------------------
# CONFIG - adjust these to match your environment before relying on this script
# ----------------------------------------------------------------------------

SCRIPT_DIR = app_dir()

DEFAULT_RECIPE_PATH = SCRIPT_DIR / "recipe.yaml"
DEFAULT_FIRMWARE_DIR = SCRIPT_DIR / "bin" / "firmware"  # expects bios/<plat>, bmc/<plat>, hpm/<plat>
DEFAULT_CG_CACHE_CSV = os.environ.get("CG_ASSET_CACHE_CSV", str(SCRIPT_DIR / "cg_assets.csv"))

BOARD_CODES = ["duck", "eagle", "falcon", "hornbill", "seagull"]

# Column names to try, in order, when reading the ChangeGear export CSV.
# VERIFY THESE against a real cg-asset-query export before trusting this script.
CG_NAME_COLUMNS = ["Asset Name", "AssetName", "Name", "Host Name", "Hostname"]
CG_IP_COLUMNS = ["BMC IP", "BMC IP Address", "IPMI IP", "Management IP", "IP Address", "IP"]
CG_MODEL_COLUMNS = ["Model", "Platform", "Board", "Asset Model", "Configuration Item Type"]

# Redfish timing (mirrors the values found in the extracted redfish.py)
HTTP_TIMEOUT = 60
HTTP_TIMEOUT_MONITOR = 120
CHECK_SUT_POWER_INTERVAL = 20
RETRIES_CHECK_SUT_POWER = 3
FACTORY_RESET_WAIT = 1200     # 20 min
HPM_UPDATE_WAIT = 120
BIOS_UPDATE_WAIT = 120
BEFORE_FACTORY_RESET_WAIT = 60
BMC_RESPONSIVE_RETRIES = 20
BMC_RESPONSIVE_INTERVAL = 30
# After pushing new BMC firmware, the BMC reboots to apply it before anything
# (including a factory-reset request) can reach it again. AMD's own BKC notes
# say this can take ~20 minutes - retry generously (30 min ceiling) rather
# than a short fixed sleep, which previously caused factory_reset() to throw
# ConnectionError against a BMC still mid-reboot.
POST_FLASH_RESPONSIVE_RETRIES = 60
POST_FLASH_RESPONSIVE_INTERVAL = 30
# A single successful probe is not proof of STABLE responsiveness - BMCs
# observed flickering (one request succeeds, the next 60s later gets
# connection-refused again) during multi-stage post-flash boot. Require
# this many consecutive successes, spaced out, before trusting it.
STABLE_RESPONSIVE_CONFIRMATIONS = 3
STABLE_RESPONSIVE_CONFIRMATION_INTERVAL = 15
# Baseline tolerance for a transient disconnect on ANY Redfish call (not just
# the long post-flash wait) - observed blips of a few tens of seconds even
# outside the big reboot windows.
REQUEST_DISCONNECT_RETRIES = 6
REQUEST_DISCONNECT_INTERVAL = 10
# FVDDR's own AC-cycle API can fail a single attempt with a one-shot
# "Connection failed" error (its own backend to PDU/BMC, not ours, and not
# an auth problem) even when the underlying push already succeeded. Retry
# the whole ac_cycle.py invocation rather than treating one failure as fatal.
FVDDR_AC_CYCLE_RETRIES = 3
FVDDR_AC_CYCLE_RETRY_INTERVAL = 30


# ----------------------------------------------------------------------------
# System name -> BMC IP / platform resolution
# ----------------------------------------------------------------------------

def _find_column(fieldnames, candidates):
    lower_map = {f.lower(): f for f in fieldnames}
    for c in candidates:
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    return None


def resolve_from_cg_cache(system_name, cache_path):
    """Look up a system in a cached ChangeGear asset export CSV.

    Produce this CSV with the cg-asset-query skill (exports ChangeGear
    asset data by Asset Name) and point --cg-cache at it, or export your
    own with at least Name/BMC-IP/Model columns.
    """
    path = Path(cache_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"ChangeGear asset cache not found at {path}.\n"
            f"Run the cg-asset-query skill for '{system_name}' first (or any export covering it),\n"
            f"save it to this path, or pass --bmc-ip/--platform directly."
        )

    with open(path, newline="", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        name_col = _find_column(reader.fieldnames, CG_NAME_COLUMNS)
        ip_col = _find_column(reader.fieldnames, CG_IP_COLUMNS)
        model_col = _find_column(reader.fieldnames, CG_MODEL_COLUMNS)

        if not name_col:
            raise ValueError(
                f"Could not find an asset-name column in {path}. "
                f"Columns present: {reader.fieldnames}. Update CG_NAME_COLUMNS."
            )

        for row in reader:
            if row.get(name_col, "").strip().lower() == system_name.strip().lower():
                bmc_ip = row.get(ip_col, "").strip() if ip_col else ""
                model_raw = row.get(model_col, "").strip() if model_col else ""
                if not bmc_ip:
                    raise ValueError(f"Found '{system_name}' in {path} but no IP column matched ({CG_IP_COLUMNS}).")
                platform = normalize_platform(model_raw)
                if not platform:
                    raise ValueError(
                        f"Found '{system_name}' with model/board text '{model_raw}' but could not map it to "
                        f"a known board code {BOARD_CODES}. Pass --platform explicitly."
                    )
                return {"bmc_ip": bmc_ip, "platform": platform, "raw_model": model_raw}

    raise ValueError(f"System '{system_name}' not found in {path}.")


def normalize_platform(text):
    text_lower = text.lower()
    for code in BOARD_CODES:
        if code in text_lower:
            return code
    return None


# ----------------------------------------------------------------------------
# System name -> PDU info, from an export of the FVDDR System Tracker
# (http://10.148.170.16:3000/ - click "Export" on the Systems page).
#
# UNVERIFIED: this environment has no network/browser access to that
# dashboard, so the exact export format (CSV vs XLSX, column names, whether
# PDU IP/Port/Vendor are separate columns or one combined "PDU" text field
# like "10.148.160.176 Port A7, A8 Eaton G3") could not be confirmed. This
# parser handles both a separate-columns export AND a combined-text-field
# export defensively - if it doesn't find your real export's shape, use
# --dump-pdu-row to see exactly what was parsed and adjust accordingly.
# ----------------------------------------------------------------------------

FVDDR_NAME_COLUMNS = ["System Name", "SystemName", "Name", "Asset Name"]
FVDDR_IP_COLUMNS = ["PDU IP", "PDU Ip", "PDU Address"]
FVDDR_PORT_COLUMNS = ["PDU Port", "Port", "Outlet"]
FVDDR_VENDOR_COLUMNS = ["PDU Vendor", "Vendor", "PDU Type"]
FVDDR_COMBINED_COLUMNS = ["PDU"]  # e.g. "10.148.160.176\nPort A7, A8\nEaton G3"

KNOWN_PDU_VENDORS = ["eaton", "delta", "enlogic", "nvent", "tripplite",
                     "vertiv", "raritan", "chatsworth", "topline", "puppetmaster"]


def _parse_combined_pdu_field(text):
    """Best-effort split of a single free-text PDU cell into ip/port/vendor."""
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    port_match = re.search(r"\bport\s+([A-Za-z]?\d+)", text, re.IGNORECASE)
    vendor = next((v for v in KNOWN_PDU_VENDORS if v in text.lower()), None)
    return {
        "pdu_ip": ip_match.group(1) if ip_match else None,
        "pdu_port": port_match.group(1) if port_match else None,
        "pdu_vendor": vendor,
    }


def resolve_pdu_from_fvddr_cache(system_name, cache_path, dump_row=False):
    """Look up a system's PDU vendor/IP/port from an exported FVDDR System
    Tracker CSV. Produce it via the dashboard's "Export" button and point
    --pdu-cache at the saved file."""
    path = Path(cache_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"FVDDR System Tracker export not found at {path}.\n"
            f"Open http://10.148.170.16:3000/, search '{system_name}', click Export, "
            f"save it to this path, or pass --pdu-vendor/--pdu-ip/--pdu-port directly."
        )

    with open(path, newline="", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        name_col = _find_column(reader.fieldnames, FVDDR_NAME_COLUMNS)
        if not name_col:
            raise ValueError(
                f"Could not find a system-name column in {path}. "
                f"Columns present: {reader.fieldnames}. Update FVDDR_NAME_COLUMNS."
            )

        ip_col = _find_column(reader.fieldnames, FVDDR_IP_COLUMNS)
        port_col = _find_column(reader.fieldnames, FVDDR_PORT_COLUMNS)
        vendor_col = _find_column(reader.fieldnames, FVDDR_VENDOR_COLUMNS)
        combined_col = _find_column(reader.fieldnames, FVDDR_COMBINED_COLUMNS)

        for row in reader:
            if row.get(name_col, "").strip().lower() != system_name.strip().lower():
                continue

            if dump_row:
                print(f"  Raw FVDDR row for '{system_name}': {row}")

            if ip_col or port_col or vendor_col:
                info = {
                    "pdu_ip": row.get(ip_col, "").strip() if ip_col else None,
                    "pdu_port": row.get(port_col, "").strip() if port_col else None,
                    "pdu_vendor": row.get(vendor_col, "").strip().lower() if vendor_col else None,
                }
            elif combined_col:
                info = _parse_combined_pdu_field(row.get(combined_col, ""))
            else:
                raise ValueError(
                    f"Found '{system_name}' in {path} but no PDU IP/Port/Vendor or combined 'PDU' "
                    f"column matched. Columns present: {reader.fieldnames}. "
                    f"Re-run with --dump-pdu-row to inspect the raw row, or pass --pdu-* flags directly."
                )

            missing = [k for k, v in info.items() if not v]
            if missing:
                raise ValueError(
                    f"Found '{system_name}' in {path} but couldn't extract {missing} from its PDU data. "
                    f"Re-run with --dump-pdu-row to inspect the raw row, or pass --pdu-* flags directly."
                )
            return info

    raise ValueError(f"System '{system_name}' not found in {path}.")


def resolve_system(args):
    if args.bmc_ip and args.platform:
        return {"bmc_ip": args.bmc_ip, "platform": args.platform.lower(), "raw_model": "(manual override)"}

    info = resolve_from_cg_cache(args.system_name, args.cg_cache)

    if args.bmc_ip:
        info["bmc_ip"] = args.bmc_ip
    if args.platform:
        info["platform"] = args.platform.lower()

    return info


# ----------------------------------------------------------------------------
# Recipe (what firmware SHOULD be on the box)
# ----------------------------------------------------------------------------

def load_recipe(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"recipe.yaml not found at {path}")
    with open(path) as fp:
        return yaml.safe_load(fp)


def get_recipe_entry(recipe, platform):
    try:
        return recipe["firmware"][platform]
    except KeyError:
        raise ValueError(
            f"No firmware recipe for platform '{platform}' in recipe.yaml. "
            f"Known platforms: {list(recipe.get('firmware', {}).keys())}"
        )


def apply_version_overrides(recipe_entry, args):
    """Return a copy of recipe_entry with any --<component>-file/-version
    overrides applied. An overridden component is always force-included in
    the flash plan (see build_plan) and, if no explicit --<component>-version
    label was given, skips the post-flash version-equality assertion (we
    can't know what version a user-supplied file actually is without asking
    them to tell us)."""
    entry = {k: dict(v) for k, v in recipe_entry.items()}
    overrides = {
        "bmc": (args.bmc_file, args.bmc_version),
        "hpm": (args.hpm_file, args.hpm_version),
        "bios": (args.bios_file, args.bios_version),
    }
    for component, (file_override, version_override) in overrides.items():
        if not file_override:
            continue
        path = Path(file_override)
        if not path.is_file():
            raise FileNotFoundError(f"--{component}-file not found: {path}")
        entry.setdefault(component, {})
        entry[component]["override_file"] = path
        entry[component]["override_has_version_label"] = bool(version_override)
        entry[component]["version"] = version_override or f"(custom: {path.name}, unverified)"
    return entry


def ensure_firmware_binary(component, platform, entry, args):
    """Return a local path to the firmware file for `component` (bios/bmc/hpm).
    If an --<component>-file override is set (see apply_version_overrides),
    that exact file is used, bypassing recipe/download resolution entirely.
    Otherwise downloads from the recipe's signed URL if --download is set,
    or expects it under --firmware-dir/<component>/<platform>/..."""
    if entry.get("override_file"):
        return entry["override_file"]

    url = entry["url"]
    filename = url.split("/")[-1].split("?")[0]  # strip SAS query string

    if args.download:
        dest_dir = Path(args.download_cache) / component / platform
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / filename
        if not dest.exists() or args.force_download:
            print(f"  Downloading {component} firmware for {platform}: {filename} ...")
            resp = requests.get(url, stream=True, timeout=120)
            resp.raise_for_status()
            with open(dest, "wb") as fp:
                for chunk in resp.iter_content(chunk_size=1 << 20):
                    fp.write(chunk)
        return dest

    local_path = Path(args.firmware_dir) / component / platform / filename
    if not local_path.is_file():
        raise FileNotFoundError(
            f"{component.upper()} firmware not found at {local_path}. "
            f"Either place it there, or re-run with --download to pull it from {url.split('?')[0]}"
        )
    return local_path


# ----------------------------------------------------------------------------
# Redfish client - mirrors project/venice-sp8/crb/redfish.py
# ----------------------------------------------------------------------------

class RedfishClient:
    def __init__(self, bmc_ip, user, password):
        self.bmc = bmc_ip
        self.user = user
        self.password = password
        self.host_serial = self._get_host_serial()

    # -- low level -----------------------------------------------------
    @staticmethod
    def _with_disconnect_retry(fn, label,
                                max_retries=REQUEST_DISCONNECT_RETRIES,
                                interval=REQUEST_DISCONNECT_INTERVAL):
        """Retry a Redfish call through a brief connection blip.

        BMCs on these boards have been observed to flicker - one request
        succeeds, the very next one (even seconds to tens of seconds later)
        gets connection-refused - independent of any big post-flash reboot
        window. A bare ConnectionError here must not propagate as fatal on
        the first hiccup; give it a short baseline retry budget first.
        Longer post-flash waits (30 min) are handled separately by
        wait_responsive()/_poll_task(), which call this at a smaller scale
        on top of their own outer retry loop.
        """
        last_err = None
        for attempt in range(max_retries):
            try:
                return fn()
            except requests.exceptions.ConnectionError as e:
                last_err = e
                if attempt < max_retries - 1:
                    time.sleep(interval)
        raise last_err

    def _get(self, path, timeout=HTTP_TIMEOUT, need_response=False, params=None):
        def _do():
            r = requests.get(
                f"https://{self.bmc}{path}",
                auth=(self.user, self.password),
                verify=False,
                timeout=timeout,
                params=params,
            )
            if need_response:
                return r
            r.raise_for_status()
            return r.json()
        return self._with_disconnect_retry(_do, f"GET {path}")

    def _post(self, path, payload, headers=None, timeout=HTTP_TIMEOUT, need_response=False):
        def _do():
            r = requests.post(
                f"https://{self.bmc}{path}",
                auth=(self.user, self.password),
                headers=headers or {"OData-Version": "4.0", "Content-Type": "application/json"},
                data=payload,
                verify=False,
                timeout=timeout,
            )
            if need_response:
                return r
            r.raise_for_status()
            return None if r.status_code == 204 else r.json()
        return self._with_disconnect_retry(_do, f"POST {path}")

    def _get_host_serial(self):
        result = self._get("/redfish/v1/Systems")
        return result["Members"][0]["@odata.id"].split("/")[4]

    # -- version queries -------------------------------------------------
    def get_bmc_version(self):
        result = self._get("/redfish/v1/Managers/bmc")
        img_url = result["Links"]["ActiveSoftwareImage"]["@odata.id"]
        return self._get(img_url)["Version"]

    def get_bios_version(self):
        return self._get("/redfish/v1/UpdateService/FirmwareInventory/bios_active")["Version"]

    def get_hpm_version(self):
        return self._get("/redfish/v1/UpdateService/FirmwareInventory/hpm_fpga_active")["Version"]

    # -- power -------------------------------------------------------
    def is_power_on(self):
        result = self._get(f"/redfish/v1/Systems/{self.host_serial}")
        return result.get("PowerState") in ("On", "Enabled", "on", "enabled")

    def power_off(self):
        if not self.is_power_on():
            return
        print("  Powering off SUT ...")
        self._post(
            f"/redfish/v1/Systems/{self.host_serial}/Actions/ComputerSystem.Reset",
            json.dumps({"ResetType": "ForceOff"}),
        )
        for _ in range(RETRIES_CHECK_SUT_POWER):
            time.sleep(CHECK_SUT_POWER_INTERVAL)
            if not self.is_power_on():
                return
        raise RuntimeError("SUT did not power off")

    def power_on(self):
        if self.is_power_on():
            return
        print("  Powering on SUT ...")
        self._post(
            f"/redfish/v1/Systems/{self.host_serial}/Actions/ComputerSystem.Reset",
            json.dumps({"ResetType": "On"}),
        )
        for _ in range(RETRIES_CHECK_SUT_POWER):
            time.sleep(CHECK_SUT_POWER_INTERVAL)
            if self.is_power_on():
                return
        raise RuntimeError("SUT did not power on")

    # -- firmware push -------------------------------------------------
    def push_update(self, firmware_path, label):
        with open(firmware_path, "rb") as fp:
            binary = fp.read()
        print(f"  Uploading {label} ({len(binary)/1e6:.1f} MB) to UpdateService ...")
        result = self._post(
            "/redfish/v1/UpdateService/update",
            binary,
            headers={"Content-Type": "application/octet-stream"},
            timeout=100,
            need_response=False,
        )
        task_url = result["@odata.id"]
        print(f"  Task created: {task_url}")
        self._poll_task(task_url, label)

    def _poll_task(self, task_url, label,
                   max_disconnect_retries=POST_FLASH_RESPONSIVE_RETRIES,
                   disconnect_interval=POST_FLASH_RESPONSIVE_INTERVAL):
        """Poll a Redfish update Task until it completes.

        The BMC can legitimately go unreachable WHILE a task is still
        "Running" (not just after it reports "Completed") - e.g. it reboots
        partway through applying firmware. A bare ConnectionError here must
        NOT be treated as fatal; retry patiently (same window as
        factory_reset's post-flash wait) before giving up.
        """
        disconnect_count = 0
        while True:
            try:
                r = self._get(task_url, timeout=HTTP_TIMEOUT_MONITOR, need_response=True)
            except requests.exceptions.ConnectionError:
                disconnect_count += 1
                if disconnect_count > max_disconnect_retries:
                    raise RuntimeError(
                        f"{label}: BMC stayed unreachable for over "
                        f"{max_disconnect_retries * disconnect_interval // 60} min while polling the update task. "
                        f"Do not AC-cycle - wait longer, or check with Smart Hands if it never comes back."
                    )
                print(f"    [{label}] BMC unreachable (likely rebooting to apply firmware) - "
                      f"retry {disconnect_count}/{max_disconnect_retries} in {disconnect_interval}s ...")
                time.sleep(disconnect_interval)
                continue

            disconnect_count = 0  # reset once we're back in contact

            if r.status_code == 404:
                print(f"    [{label}] Task no longer found - BMC likely rebooted after applying the update. "
                      f"Treating as complete; version will be verified next.")
                break
            if r.status_code not in (200, 202, 303, 304):
                break
            decoded = r.json()
            state = decoded.get("TaskState")
            print(f"    [{label}] TaskState={state}")
            if state == "Completed":
                break
            if state not in ("New", "Starting", "Pending", "Running"):
                raise RuntimeError(f"{label} update task ended in state {state}: {decoded.get('Messages')}")
            time.sleep(10)

    def factory_reset(self):
        print(f"  Waiting for BMC to come back up after the firmware flash "
              f"(can take ~20 min per AMD's BKC notes - up to {POST_FLASH_RESPONSIVE_RETRIES * POST_FLASH_RESPONSIVE_INTERVAL // 60} min here) ...")
        if not self.wait_responsive(max_retries=POST_FLASH_RESPONSIVE_RETRIES, interval=POST_FLASH_RESPONSIVE_INTERVAL):
            raise RuntimeError(
                "BMC did not become responsive after the firmware flash within the expected window.\n"
                "DO NOT AC-cycle the system - per AMD's guidance, power-cycling mid-update can corrupt "
                "the flash, whereas a BMC that's just still rebooting/applying firmware is normal. "
                "Wait longer and re-run, or check with Smart Hands if it stays down past ~30-40 minutes."
            )
        print(f"  BMC responsive. Waiting {BEFORE_FACTORY_RESET_WAIT}s settle time before factory reset ...")
        time.sleep(BEFORE_FACTORY_RESET_WAIT)
        print("  Factory-resetting BMC (Manager.ResetToDefaults / ResetAll) ...")
        try:
            r = self._post(
                "/redfish/v1/Managers/bmc/Actions/Manager.ResetToDefaults",
                json.dumps({"ResetType": "ResetAll"}),
                need_response=True,
                timeout=HTTP_TIMEOUT_MONITOR,
            )
        except Exception:
            r = self._post(
                "/redfish/v1/Managers/bmc/Actions/Manager.ResetToDefaults",
                json.dumps({"ResetToDefaultsType": "ResetAll"}),
                need_response=True,
                timeout=HTTP_TIMEOUT_MONITOR,
            )
        if not r.ok:
            raise RuntimeError(f"Factory reset failed [{r.status_code}]: {r.text}")
        print(f"  Waiting {FACTORY_RESET_WAIT}s for BMC to come back after factory reset ...")
        time.sleep(FACTORY_RESET_WAIT)

    def wait_responsive(self, max_retries=BMC_RESPONSIVE_RETRIES, interval=BMC_RESPONSIVE_INTERVAL):
        """A single successful probe is not proof the BMC is STABLY back -
        it's been observed to flicker (one request succeeds, the next one
        tens of seconds later gets connection-refused) during multi-stage
        post-flash boot. Require STABLE_RESPONSIVE_CONFIRMATIONS consecutive
        successes, spaced out, before returning True."""
        consecutive_ok = 0
        for attempt in range(max_retries):
            try:
                self._get("/redfish/v1/Managers/bmc")
                consecutive_ok += 1
                if consecutive_ok >= STABLE_RESPONSIVE_CONFIRMATIONS:
                    return True
                print(f"  BMC responded ({consecutive_ok}/{STABLE_RESPONSIVE_CONFIRMATIONS} stable confirmations) - "
                      f"confirming it stays up before proceeding ...")
                time.sleep(STABLE_RESPONSIVE_CONFIRMATION_INTERVAL)
            except Exception:
                if consecutive_ok:
                    print(f"  BMC dropped again after {consecutive_ok} successful check(s) - resetting confirmation count.")
                consecutive_ok = 0
                print(f"  BMC not responsive yet (attempt {attempt+1}/{max_retries}), retrying in {interval}s ...")
                time.sleep(interval)
        return False


# ----------------------------------------------------------------------------
# AC cycle. Four ways to automate this, tried in order:
#   1. --ac-cycle-cmd: an explicit shell command you supply (highest priority).
#   2. FVDDR System Tracker's ac_cycle.py (default, if present): calls the
#      dashboard's own REST API (/api/systems, /api/systems/{id}/power) by
#      system name directly - no PDU vendor/IP/port lookup needed at all.
#   3. --pdu-vendor + --pdu-ip (+ port/creds): auto-invokes the power-control
#      skill's scripts/ac_cycle.py, which handles real PDU control (SNMP or
#      vendor HTTP API) and waits for the BMC to come back.
#   4. None of the above: falls back to prompting for manual action.
# ----------------------------------------------------------------------------

DEFAULT_POWER_CONTROL_SCRIPT = os.path.expanduser(
    r"~\.claude\skills\power-control\scripts\ac_cycle.py"
)
DEFAULT_FVDDR_AC_CYCLE_SCRIPT = str(SCRIPT_DIR / "ac_cycle.py")


def build_pdu_ac_cycle_cmd(args, bmc_ip, bmc_user, bmc_pass):
    script = args.power_control_script or DEFAULT_POWER_CONTROL_SCRIPT
    if not os.path.isfile(script):
        raise FileNotFoundError(
            f"power-control's ac_cycle.py not found at {script}. "
            f"Pass --power-control-script to point at it, or install the power-control skill."
        )
    cmd = [
        sys.executable, script,
        "--vendor", args.pdu_vendor,
        "--port", str(args.pdu_port),
        "--pdu-ip", args.pdu_ip,
        "--bmc-ip", bmc_ip,
        "--bmc-user", bmc_user,
        "--bmc-pass", bmc_pass,
        "--yes",
    ]
    if args.pdu_user:
        cmd += ["--pdu-user", args.pdu_user]
    if args.pdu_pass:
        cmd += ["--pdu-pass", args.pdu_pass]
    if args.pdu_community:
        cmd += ["--pdu-community", args.pdu_community]
    return cmd


def build_fvddr_ac_cycle_cmd(args):
    script = args.fvddr_script or DEFAULT_FVDDR_AC_CYCLE_SCRIPT
    if not bundled_script_available(script, DEFAULT_FVDDR_AC_CYCLE_SCRIPT):
        raise FileNotFoundError(f"FVDDR ac_cycle.py not found at {script}")
    # -u: unbuffered, keeps stdout/stderr in chronological order. A custom
    # --fvddr-script override still runs as a real sibling .py file even when
    # frozen (build_subcommand only takes the dispatcher shortcut for the
    # bundled default script).
    if script == DEFAULT_FVDDR_AC_CYCLE_SCRIPT:
        cmd = build_subcommand("ac-cycle", "ac_cycle.py", [args.system_name], unbuffered=True)
    else:
        cmd = [sys.executable, "-u", script, args.system_name]
    if args.fvddr_token:
        cmd += ["--token", args.fvddr_token]
    if args.fvddr_delay is not None:
        cmd += ["--delay", str(args.fvddr_delay)]
    if args.fvddr_base_url:
        cmd += ["--base-url", args.fvddr_base_url]
    cmd += ["--sut-wait", "0"]  # we do our own wait_responsive() polling right after
    return cmd


def ac_cycle(args, bmc_ip=None, bmc_user=None, bmc_pass=None):
    fvddr_script = args.fvddr_script or DEFAULT_FVDDR_AC_CYCLE_SCRIPT
    if args.ac_cycle_cmd:
        print(f"  Running AC-cycle command: {args.ac_cycle_cmd}")
        rc = os.system(args.ac_cycle_cmd)
        if rc != 0:
            raise RuntimeError(f"AC-cycle command exited with code {rc}")
    elif bundled_script_available(fvddr_script, DEFAULT_FVDDR_AC_CYCLE_SCRIPT) and not args.no_fvddr_ac_cycle:
        cmd = build_fvddr_ac_cycle_cmd(args)
        print(f"  Auto AC-cycling '{args.system_name}' via FVDDR System Tracker ...")
        rc = None
        for attempt in range(FVDDR_AC_CYCLE_RETRIES):
            rc = subprocess.call(cmd)
            if rc == 0:
                break
            if attempt < FVDDR_AC_CYCLE_RETRIES - 1:
                print(f"  FVDDR ac_cycle.py failed (exit {rc}), retry {attempt + 2}/{FVDDR_AC_CYCLE_RETRIES} "
                      f"in {FVDDR_AC_CYCLE_RETRY_INTERVAL}s - its own API can fail a single attempt with a "
                      f"transient 'Connection failed' error unrelated to auth ...")
                time.sleep(FVDDR_AC_CYCLE_RETRY_INTERVAL)
        if rc != 0:
            raise RuntimeError(
                f"FVDDR ac_cycle.py failed after {FVDDR_AC_CYCLE_RETRIES} attempts (exit {rc}). Check its "
                f"output above - if it reported 'Auth failed', pass --fvddr-token. Do not AC-cycle by hand "
                f"on top of a failed attempt without understanding what state the system was left in."
            )
    elif args.pdu_vendor and args.pdu_ip:
        cmd = build_pdu_ac_cycle_cmd(args, bmc_ip, bmc_user, bmc_pass)
        print(f"  Auto AC-cycling via power-control ({args.pdu_vendor} PDU {args.pdu_ip}:{args.pdu_port}) ...")
        rc = subprocess.call(cmd)
        if rc != 0:
            raise RuntimeError(
                f"power-control ac_cycle.py exited with code {rc}. "
                f"Check its JSON/stderr output above. Do not AC-cycle by hand on top of a failed attempt "
                f"without understanding what state the PDU/outlet was left in."
            )
    else:
        input("  >>> Please AC power-cycle the system now, then press Enter to continue ...")


# ----------------------------------------------------------------------------
# Main flow
# ----------------------------------------------------------------------------

# Pulls the "v<major>.<minor>.<patch>.<build><letter>" core out of a version
# string, ignoring any filename-derived prefix/suffix noise (e.g. recipe.yaml
# may say "obmc-phosphor-image-sp7_v2.18.0.100I" from a firmware filename
# while the BMC itself self-reports just "sp7_v2.18.0.100i" - same version,
# different formatting. A naive exact-string compare treats that as a
# mismatch and triggers a needless reflash of already-correct firmware.
_VERSION_CORE_RE = re.compile(r"v?(\d+\.\d+\.\d+\.\d+[a-zA-Z]?)", re.IGNORECASE)


def versions_equal(a, b):
    if not a or not b:
        return a == b
    if a.strip().lower() == b.strip().lower():
        return True
    ma, mb = _VERSION_CORE_RE.search(a), _VERSION_CORE_RE.search(b)
    if ma and mb:
        return ma.group(1).lower() == mb.group(1).lower()
    return False


def build_plan(client, recipe_entry, args):
    plan = {}
    current = {}

    current["bmc"] = client.get_bmc_version()
    if not args.skip_bmc and (args.force or recipe_entry["bmc"].get("override_file")
                               or not versions_equal(current["bmc"], recipe_entry["bmc"]["version"])):
        plan["bmc"] = recipe_entry["bmc"]

    current["hpm"] = client.get_hpm_version()
    if not args.skip_hpm and (args.force or recipe_entry["hpm"].get("override_file")
                               or not versions_equal(current["hpm"], recipe_entry["hpm"]["version"]) or "bmc" in plan):
        plan["hpm"] = recipe_entry["hpm"]

    current["bios"] = client.get_bios_version()
    if not args.skip_bios and (args.force or recipe_entry["bios"].get("override_file")
                                or not versions_equal(current["bios"], recipe_entry["bios"]["version"]) or "bmc" in plan):
        plan["bios"] = recipe_entry["bios"]

    return current, plan


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("system_name", nargs="?", default=None,
                         help="System/asset name to flash (not required with --refresh-only)")
    parser.add_argument("--bmc-ip", help="Override BMC IP instead of resolving via ChangeGear")
    parser.add_argument("--platform", choices=BOARD_CODES, help="Override board/platform code")
    parser.add_argument("--cg-cache", default=DEFAULT_CG_CACHE_CSV, help="Path to ChangeGear asset export CSV")
    parser.add_argument("--recipe", default=str(DEFAULT_RECIPE_PATH), help="Path to recipe.yaml")
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR), help="Local firmware tree (bios/bmc/hpm/<platform>/...)")
    parser.add_argument("--download", action="store_true", help="Download firmware from the recipe's signed URLs instead of using --firmware-dir")
    parser.add_argument("--download-cache", default=str(SCRIPT_DIR / "downloaded_firmware"), help="Where to cache downloaded firmware")
    parser.add_argument("--force-download", action="store_true", help="Re-download even if a cached copy exists")
    parser.add_argument("--bmc-user", default=os.environ.get("BMC_USER", "root"), help="BMC username (default: root, or set BMC_USER)")
    parser.add_argument("--bmc-pass", default=os.environ.get("BMC_PASS", "0penBmc"), help="BMC password (default: 0penBmc, or set BMC_PASS)")
    parser.add_argument("--bmc-default-user", default=os.environ.get("BMC_DEFAULT_USER"), help="BMC username to use AFTER a factory reset, if different")
    parser.add_argument("--bmc-default-pass", default=os.environ.get("BMC_DEFAULT_PASS", "0penBmc"), help="BMC password to use AFTER a factory reset (default: 0penBmc, the OpenBMC factory default)")
    parser.add_argument("--ac-cycle-cmd", help="Shell command to AC-cycle the system (e.g. a PDU CLI call); omit to be prompted manually")
    parser.add_argument("--pdu-vendor", default=os.environ.get("PDU_VENDOR"),
                         help="PDU vendor for auto AC-cycling via the power-control skill (e.g. eaton, delta, enlogic, nvent, tripplite)")
    parser.add_argument("--pdu-ip", default=os.environ.get("PDU_IP"), help="PDU IP for auto AC-cycling")
    parser.add_argument("--pdu-port", default=os.environ.get("PDU_PORT"), help="PDU outlet/port (e.g. 7, or Y15 for Delta)")
    parser.add_argument("--pdu-user", default=os.environ.get("PDU_USER"), help="PDU web UI username (HTTP vendors: eaton, delta)")
    parser.add_argument("--pdu-pass", default=os.environ.get("PDU_PASS"), help="PDU web UI password (HTTP vendors: eaton, delta)")
    parser.add_argument("--pdu-community", default=os.environ.get("PDU_COMMUNITY"), help="PDU SNMP read-write community string (SNMP vendors)")
    parser.add_argument("--power-control-script", default=None,
                         help=f"Path to power-control's ac_cycle.py (default: {DEFAULT_POWER_CONTROL_SCRIPT})")
    parser.add_argument("--pdu-cache", default=os.environ.get("PDU_CACHE", str(SCRIPT_DIR / "fvddr_systems.csv")),
                         help="Path to an exported FVDDR System Tracker CSV (http://10.148.170.16:3000/, "
                              "click Export), used to auto-resolve --pdu-vendor/--pdu-ip/--pdu-port by system name "
                              "when those aren't passed explicitly")
    parser.add_argument("--dump-pdu-row", action="store_true", help="Print the raw matched row from --pdu-cache, for debugging its format")
    parser.add_argument("--fvddr-script", default=None,
                         help=f"Path to the FVDDR System Tracker ac_cycle.py (default: {DEFAULT_FVDDR_AC_CYCLE_SCRIPT})")
    parser.add_argument("--fvddr-token", default=os.environ.get("FVDDR_TOKEN"), help="X-Admin-Token for the FVDDR API, if required")
    parser.add_argument("--fvddr-delay", type=int, default=None, help="Use off->wait N sec->on instead of the single ac_cycle action")
    parser.add_argument("--fvddr-base-url", default=None, help="Override the FVDDR API base URL")
    parser.add_argument("--no-fvddr-ac-cycle", action="store_true", help="Don't use the FVDDR script even if present - fall through to --pdu-* or manual prompt")
    parser.add_argument("--skip-bmc", action="store_true")
    parser.add_argument("--skip-hpm", action="store_true", help="Skip FPGA/HPM firmware")
    parser.add_argument("--skip-bios", action="store_true")
    parser.add_argument("--force", action="store_true", help="Reflash components even if versions already match")
    parser.add_argument("--bmc-file", default=None, help="Flash this specific local BMC firmware file instead of recipe.yaml's pinned version (always force-included)")
    parser.add_argument("--hpm-file", default=None, help="Flash this specific local HPM/FPGA firmware file instead of recipe.yaml's pinned version (always force-included)")
    parser.add_argument("--bios-file", default=None, help="Flash this specific local BIOS firmware file instead of recipe.yaml's pinned version (always force-included)")
    parser.add_argument("--bmc-version", default=None, help="Expected version label for --bmc-file (used for the plan display and post-flash verification; omit to skip verification for this component)")
    parser.add_argument("--hpm-version", default=None, help="Expected version label for --hpm-file (see --bmc-version)")
    parser.add_argument("--bios-version", default=None, help="Expected version label for --bios-file (see --bmc-version)")
    parser.add_argument("--dry-run", action="store_true", help="Only resolve system + print the flash plan, don't touch hardware")
    parser.add_argument("-y", "--yes", action="store_true", help="Don't prompt for confirmation before flashing (use with care)")
    parser.add_argument("--refresh-recipe", action="store_true",
                         help="Before deciding what to flash, refresh recipe.yaml from --recipe-source")
    parser.add_argument("--refresh-only", action="store_true",
                         help="Run the --refresh-recipe step then exit, without resolving/flashing any system. "
                              "Lets a fleet runner refresh recipe.yaml once before dispatching many parallel flashes "
                              "(concurrent --refresh-recipe writes from multiple instances would race/corrupt it).")
    parser.add_argument("--recipe-source", default="nexus",
                         choices=["nexus", "fileshare", "fpga-manual", "fpga-confluence", "fpga-confluence-browser",
                                  "bkc-page", "bkc-page-browser", "bkc-page-cli"],
                         help="Where to pull the latest firmware info from when --refresh-recipe is set: "
                              "'nexus' = Nexus BKC release/candidate (BIOS+BMC+HPM/FPGA); "
                              "'fileshare' = BMC network share + Artifactory BIOS feed (BIOS+BMC only, "
                              "HPM/FPGA entries in recipe.yaml are left untouched); "
                              "'fpga-manual' = pick up an operator-downloaded FPGA/HPM file from a local staging "
                              "folder (SharePoint requires SSO login, not automated); "
                              "'fpga-confluence' = parse+download from the 'SP8 BKC Release' Confluence page's "
                              "Board FPGA FW table via raw HTTP (blocked by a CASB/proxy on at least one account - "
                              "see fpga-confluence-browser if this 403s); "
                              "'fpga-confluence-browser' = same as fpga-confluence but fetches via a real automated "
                              "browser (bypasses the CASB block, requires one-time interactive SSO login). "
                              "fpga-* sources only touch HPM/FPGA; BIOS/BMC entries are left untouched; "
                              "'bkc-page' = BIOS+BMC+HPM/FPGA all from the 'SP8 BKC Release' Confluence page in one "
                              "shot, version pinned exactly as shown on the page for every component - see "
                              "refresh_recipe_bkc_page.py's docstring for caveats); "
                              "'bkc-page-browser' = same as bkc-page but fetches the Confluence page/FPGA "
                              "attachments via a real automated browser (needed if bkc-page 403s due to a "
                              "CASB/proxy blocking raw HTTP); "
                              "'bkc-page-cli' (RECOMMENDED if bkc-page 403s) = same as bkc-page but fetches the "
                              "page via the authenticated `atlassian` CLI instead of raw HTTP - simpler and more "
                              "reliable than bkc-page-browser for the page/metadata fetch (still uses a browser "
                              "just for the FPGA attachment download step, which the CLI can't do). Requires the "
                              "`atlassian` CLI installed and logged in once - see GETTING_STARTED.txt.")
    parser.add_argument("--nexus-project", default="venice-sp8", choices=["venice-sp7", "venice-sp8", "turin"],
                         help="Project to query on Nexus when --recipe-source=nexus")
    parser.add_argument("--nexus-type", default="release", choices=["release", "candidate"],
                         help="Use the latest release (stable) or candidate (pre-release) when refreshing from Nexus")
    parser.add_argument("--nexus-name", help="Specific BKC release/candidate name to pull instead of latest (Nexus only)")
    parser.add_argument("--bmc-share", default=None, help="Override the BMC share path for --recipe-source=fileshare")
    parser.add_argument("--bios-repo", default=None, help="Override the Artifactory BIOS repo URL for --recipe-source=fileshare")
    parser.add_argument("--fpga-drop-dir", default=None, help="Override the FPGA manual-download staging folder for --recipe-source=fpga-manual")
    parser.add_argument("--open-browser", action="store_true", help="For --recipe-source=fpga-manual: open missing boards' SharePoint links in your browser")
    parser.add_argument("--confluence-page-url", default=None, help="Override the Confluence page URL for --recipe-source=fpga-confluence(-browser)")
    parser.add_argument("--browser-profile-dir", default=None, help="Override the persistent browser profile dir for --recipe-source=fpga-confluence-browser/bkc-page-browser")
    parser.add_argument("--browser-headless", action="store_true", help="For --recipe-source=fpga-confluence-browser/bkc-page-browser: skip showing the browser window (only after you've logged in once). For --recipe-source=bkc-page-cli: fail instead of prompting for an interactive Microsoft sign-in if one is needed (unattended runs).")
    parser.add_argument("--cli-profile", default=None, help="atlassian CLI credential profile to use for --recipe-source=bkc-page-cli (default: ro)")
    parser.add_argument("--atlassian-cli", default=None, help="Override path to the atlassian CLI executable for --recipe-source=bkc-page-cli")
    args = parser.parse_args()

    if args.system_name and not args.ac_cycle_cmd and not (args.pdu_vendor and args.pdu_ip and args.pdu_port):
        try:
            pdu_info = resolve_pdu_from_fvddr_cache(args.system_name, args.pdu_cache, dump_row=args.dump_pdu_row)
            args.pdu_vendor = args.pdu_vendor or pdu_info["pdu_vendor"]
            args.pdu_ip = args.pdu_ip or pdu_info["pdu_ip"]
            args.pdu_port = args.pdu_port or pdu_info["pdu_port"]
            print(f"Resolved PDU for '{args.system_name}' from {args.pdu_cache}: "
                  f"vendor={args.pdu_vendor} ip={args.pdu_ip} port={args.pdu_port}")
        except FileNotFoundError:
            # The optional --pdu-cache file simply doesn't exist - the common,
            # expected case (it's only needed for the power-control PDU
            # fallback, not the default FVDDR auto-AC-cycle path). Silent by
            # design: printing this on every single system in a fleet run
            # added pure noise with nothing actionable in it.
            pass
        except ValueError as e:
            # The cache file DOES exist but something in it is actually wrong
            # (bad columns, system not found, ambiguous data) - worth seeing.
            print(f"(PDU auto-resolution skipped: {e})\n"
                  f"AC-cycle will fall back to manual prompting unless --pdu-* flags are passed.", file=sys.stderr)

    if args.refresh_recipe:
        print(f"=== Refreshing recipe from {args.recipe_source} ===")
        if args.recipe_source == "nexus":
            refresh_cmd = build_subcommand(
                "refresh-nexus", "refresh_recipe.py",
                ["--project", args.nexus_project, "--type", args.nexus_type, "--output", args.recipe],
            )
            if args.nexus_name:
                refresh_cmd += ["--name", args.nexus_name]
        elif args.recipe_source == "fileshare":
            refresh_cmd = build_subcommand(
                "refresh-fileshare", "refresh_recipe_fileshare.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.bmc_share:
                refresh_cmd += ["--bmc-share", args.bmc_share]
            if args.bios_repo:
                refresh_cmd += ["--bios-repo", args.bios_repo]
        elif args.recipe_source == "fpga-manual":
            refresh_cmd = build_subcommand(
                "refresh-manual-fpga", "refresh_recipe_manual_fpga.py",
                ["--output", args.recipe],
            )
            if args.fpga_drop_dir:
                refresh_cmd += ["--drop-dir", args.fpga_drop_dir]
            if args.open_browser:
                refresh_cmd += ["--open-browser"]
        elif args.recipe_source == "fpga-confluence":
            refresh_cmd = build_subcommand(
                "refresh-confluence", "refresh_recipe_confluence_fpga.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.confluence_page_url:
                refresh_cmd += ["--page-url", args.confluence_page_url]
        elif args.recipe_source == "fpga-confluence-browser":
            refresh_cmd = build_subcommand(
                "refresh-confluence-browser", "refresh_recipe_confluence_fpga_browser.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.confluence_page_url:
                refresh_cmd += ["--page-url", args.confluence_page_url]
            if args.browser_profile_dir:
                refresh_cmd += ["--profile-dir", args.browser_profile_dir]
            if args.browser_headless:
                refresh_cmd += ["--headless"]
        elif args.recipe_source == "bkc-page":
            refresh_cmd = build_subcommand(
                "refresh-bkc-page", "refresh_recipe_bkc_page.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.bmc_share:
                refresh_cmd += ["--bmc-share", args.bmc_share]
            if args.confluence_page_url:
                refresh_cmd += ["--page-url", args.confluence_page_url]
        elif args.recipe_source == "bkc-page-browser":
            refresh_cmd = build_subcommand(
                "refresh-bkc-page-browser", "refresh_recipe_bkc_page_browser.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.bmc_share:
                refresh_cmd += ["--bmc-share", args.bmc_share]
            if args.confluence_page_url:
                refresh_cmd += ["--page-url", args.confluence_page_url]
            if args.browser_profile_dir:
                refresh_cmd += ["--profile-dir", args.browser_profile_dir]
            if args.browser_headless:
                refresh_cmd += ["--headless"]
        else:  # bkc-page-cli
            refresh_cmd = build_subcommand(
                "refresh-bkc-page-cli", "refresh_recipe_bkc_page_cli.py",
                ["--output", args.recipe, "--firmware-dir", args.firmware_dir],
            )
            if args.bmc_share:
                refresh_cmd += ["--bmc-share", args.bmc_share]
            if args.confluence_page_url:
                refresh_cmd += ["--page-url", args.confluence_page_url]
            if args.browser_headless:
                # FPGA now downloads from SharePoint (no browser) - "headless" for this
                # source means "unattended", so don't hang on an interactive Microsoft
                # sign-in prompt if one is needed.
                refresh_cmd += ["--no-auto-auth"]
            if args.cli_profile:
                refresh_cmd += ["--cli-profile", args.cli_profile]
            if args.atlassian_cli:
                refresh_cmd += ["--atlassian-cli", args.atlassian_cli]

        rc = subprocess.call(refresh_cmd)
        # fpga-manual returns 1 when SOME boards still lack a staged file, which is
        # informational, not fatal - the board you're actually flashing may already
        # be staged. Only nexus/fileshare/fpga-confluence failures should hard-abort.
        if rc != 0 and args.recipe_source != "fpga-manual":
            print(f"\nFailed to refresh recipe from {args.recipe_source} (see error above). "
                  "Re-run without --refresh-recipe to use the existing cached recipe.yaml, "
                  "or fix the connection/credentials and retry.", file=sys.stderr)
            return 1
        elif rc != 0:
            print("\n(Some FPGA boards still need a manual download - continuing with whatever recipe.yaml has.)")
        print()

    if args.refresh_only:
        print("--refresh-only set, exiting without resolving/flashing any system.")
        return 0

    if not args.system_name:
        print("ERROR: system_name is required unless --refresh-only is set.", file=sys.stderr)
        return 2

    print(f"=== Resolving system '{args.system_name}' ===")
    sysinfo = resolve_system(args)
    print(f"  BMC IP   : {sysinfo['bmc_ip']}")
    print(f"  Platform : {sysinfo['platform']}  (from: {sysinfo['raw_model']})")

    if not args.bmc_user:
        args.bmc_user = input("BMC username: ").strip()
    if not args.bmc_pass:
        args.bmc_pass = getpass.getpass("BMC password: ")

    recipe = load_recipe(args.recipe)
    recipe_entry = get_recipe_entry(recipe, sysinfo["platform"])
    recipe_entry = apply_version_overrides(recipe_entry, args)
    for component in ("bmc", "hpm", "bios"):
        if recipe_entry[component].get("override_file"):
            print(f"  Override : {component.upper()} <- {recipe_entry[component]['override_file']} "
                  f"(version label: {recipe_entry[component]['version']})")

    print("\n=== Checking current firmware via Redfish ===")
    try:
        client = RedfishClient(sysinfo["bmc_ip"], args.bmc_user, args.bmc_pass)
        current, plan = build_plan(client, recipe_entry, args)
    except requests.exceptions.ConnectionError:
        print(f"\nBMC at {sysinfo['bmc_ip']} is not reachable right now (connection refused/timed out). "
              f"If it recently had firmware pushed to it, this is expected while it reboots - "
              f"wait a few minutes and try again. Do not AC-cycle it.", file=sys.stderr)
        return 1

    print(f"  BMC : current={current['bmc']}   recipe={recipe_entry['bmc']['version']}")
    print(f"  HPM : current={current['hpm']}   recipe={recipe_entry['hpm']['version']}")
    print(f"  BIOS: current={current['bios']}   recipe={recipe_entry['bios']['version']}")

    if not plan:
        print("\nAll firmware already matches the recipe. Nothing to do.")
        return 0

    print("\n=== Flash plan ===")
    for component, entry in plan.items():
        print(f"  {component.upper():5s}: -> {entry['version']}")

    if args.dry_run:
        print("\n--dry-run set, exiting without touching hardware.")
        return 0

    if not args.yes:
        resp = input("\nProceed with flashing the above components on "
                      f"{args.system_name} ({sysinfo['bmc_ip']})? This will power off the SUT. [y/N] ")
        if resp.strip().lower() != "y":
            print("Aborted.")
            return 1

    # Resolve binaries up front so we fail fast on missing files
    binaries = {}
    for component, entry in plan.items():
        binaries[component] = ensure_firmware_binary(component, sysinfo["platform"], entry, args)

    print("\n=== Flashing ===")
    client.power_off()

    try:
        bmc_was_updated = False
        if "bmc" in plan:
            print("\n-- BMC firmware --")
            client.push_update(binaries["bmc"], "BMC")
            client.factory_reset()

            # Factory reset reverts BMC credentials
            if args.bmc_default_pass:
                client = RedfishClient(sysinfo["bmc_ip"], args.bmc_default_user or args.bmc_user, args.bmc_default_pass)
            else:
                print("  NOTE: BMC factory reset reverts credentials to factory default.")
                new_user = input(f"  BMC username after reset [{args.bmc_user}]: ").strip() or args.bmc_user
                new_pass = getpass.getpass("  BMC password after reset: ")
                client = RedfishClient(sysinfo["bmc_ip"], new_user, new_pass)

            if not client.wait_responsive():
                ac_cycle(args, sysinfo["bmc_ip"], client.user, client.password)
                if not client.wait_responsive():
                    raise RuntimeError("BMC did not become responsive after factory reset + AC cycle")

            actual = client.get_bmc_version()
            if recipe_entry["bmc"].get("override_file") and not recipe_entry["bmc"].get("override_has_version_label"):
                print(f"  BMC now at {actual} (custom file, no expected version given - skipping verification)")
            elif not versions_equal(actual, recipe_entry["bmc"]["version"]):
                raise RuntimeError(f"BMC version mismatch after flash: got {actual}, expected {recipe_entry['bmc']['version']}")
            else:
                print(f"  BMC now at {actual} - OK")
            bmc_was_updated = True

        if "hpm" in plan:
            print("\n-- FPGA (HPM) firmware --")
            client.push_update(binaries["hpm"], "HPM/FPGA")
            print(f"  Waiting {HPM_UPDATE_WAIT}s after HPM update ...")
            time.sleep(HPM_UPDATE_WAIT)
            ac_cycle(args, sysinfo["bmc_ip"], client.user, client.password)
            if not client.wait_responsive():
                raise RuntimeError("BMC did not become responsive after HPM/FPGA AC cycle")
            actual = client.get_hpm_version()
            if recipe_entry["hpm"].get("override_file") and not recipe_entry["hpm"].get("override_has_version_label"):
                print(f"  FPGA/HPM now at {actual} (custom file, no expected version given - skipping verification)")
            elif not versions_equal(actual, recipe_entry["hpm"]["version"]) and not bmc_was_updated:
                raise RuntimeError(f"HPM/FPGA version mismatch after flash: got {actual}, expected {recipe_entry['hpm']['version']}")
            else:
                print(f"  FPGA/HPM now at {actual} - OK")

        if "bios" in plan:
            print("\n-- BIOS firmware --")
            client.push_update(binaries["bios"], "BIOS")
            print(f"  Waiting {BIOS_UPDATE_WAIT}s after BIOS update ...")
            time.sleep(BIOS_UPDATE_WAIT)
            if not client.wait_responsive():
                raise RuntimeError("BMC did not become responsive after BIOS update")
            actual = client.get_bios_version()
            if recipe_entry["bios"].get("override_file") and not recipe_entry["bios"].get("override_has_version_label"):
                print(f"  BIOS now at {actual} (custom file, no expected version given - skipping verification)")
            elif not versions_equal(actual, recipe_entry["bios"]["version"]) and not bmc_was_updated:
                raise RuntimeError(f"BIOS version mismatch after flash: got {actual}, expected {recipe_entry['bios']['version']}")
            else:
                print(f"  BIOS now at {actual} - OK")
    except Exception as e:
        print(
            "\n"
            "!!! Flashing step failed/interrupted !!!\n"
            f"    {e}\n\n"
            "DO NOT AC-cycle or power-cycle the system right now. Per AMD's BKC guidance, interrupting "
            "power mid-update is what corrupts the flash - a BMC that's slow to respond (still rebooting, "
            "applying firmware) is normal and not itself a sign of corruption. Wait, re-check the BMC's "
            "responsiveness, and only escalate (Smart Hands / reflash via dediprog) if it stays unreachable "
            "well past the component's expected window.\n",
            file=sys.stderr,
        )
        raise

    client.power_on()
    print("\n=== Done. Firmware updated successfully. ===")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
