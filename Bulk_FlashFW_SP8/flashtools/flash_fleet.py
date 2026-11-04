#!/usr/bin/env python3
"""
flash_fleet.py — Run flash_system.py across multiple systems in parallel.

Each system runs as its own flash_system.py subprocess, output redirected to
a per-system log file (parallel processes writing to the same terminal would
interleave into an unreadable mess). Prints a live one-line-per-system status
table and a final pass/fail summary.

CSV FORMAT (systems.csv)
    system_name,bmc_ip,platform[,bmc_user,bmc_pass,bmc_file,bmc_version,hpm_file,hpm_version,bios_file,bios_version]
    eagle-0906,10.148.164.69,eagle
    eagle-0912,10.148.164.70,eagle
    hornbill-1549,10.148.174.75,hornbill,,,C:\fw\bmc_hornbill.tar,sp7_v2.18.0.100I,,,,

    bmc_user/bmc_pass columns are optional per-row overrides - if omitted,
    flash_system.py's own defaults (root/0penBmc) apply.

    bmc_file/bmc_version/hpm_file/hpm_version/bios_file/bios_version are
    also optional per-row overrides, taking priority over the matching
    --bmc-file/-version CLI flags for that row only. This is what lets ONE
    fleet run mix different platforms with different firmware each: give
    each row the file(s) appropriate to ITS platform (e.g. Eagle rows get
    an Eagle BIOS, Hornbill rows get a Hornbill BIOS) - the CLI flags are
    just the fallback for rows that don't specify their own.

SAFETY
    - Requires --yes: with many systems in parallel and output redirected to
      log files (not your terminal), there is no reasonable way to answer an
      interactive y/N confirmation per system. --yes is mandatory for any
      real (non---dry-run) fleet flash - you are explicitly asked once, here,
      instead of N times buried in log files.
    - --refresh-recipe is run ONCE up front (via flash_system.py --refresh-only),
      not per-system - concurrent writers to the same recipe.yaml would race.

USAGE
    # See the plan for every system, no hardware touched
    python flash_fleet.py systems.csv --dry-run

    # Refresh recipe.yaml once, then flash everything, 4 at a time
    python flash_fleet.py systems.csv --refresh-recipe --recipe-source fileshare --yes --max-parallel 4

    # Just flash using whatever recipe.yaml already has
    python flash_fleet.py systems.csv --yes
"""

import argparse
import csv
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from launcher_utils import app_dir, build_subcommand

SCRIPT_DIR = app_dir()
DEFAULT_LOG_DIR = SCRIPT_DIR / "fleet_logs"


def load_systems(csv_path):
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found. Create it with columns: system_name,bmc_ip,platform")

    systems = []
    with open(path, newline="", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        required = {"system_name", "bmc_ip", "platform"}
        missing = required - set(f.strip() for f in (reader.fieldnames or []))
        if missing:
            raise ValueError(f"{path} is missing required column(s): {missing}. Found: {reader.fieldnames}")
        for row in reader:
            row = {k.strip(): (v.strip() if v else v) for k, v in row.items()}
            if not row.get("system_name"):
                continue  # skip blank rows
            systems.append(row)
    if not systems:
        raise ValueError(f"No systems found in {path}")
    return systems


def build_cmd(row, args):
    cmd = build_subcommand(  # -u: unbuffered, keeps log lines in chronological order
        "system", "flash_system.py",
        [row["system_name"], "--bmc-ip", row["bmc_ip"], "--platform", row["platform"]],
        unbuffered=True,
    )
    if row.get("bmc_user"):
        cmd += ["--bmc-user", row["bmc_user"]]
    if row.get("bmc_pass"):
        cmd += ["--bmc-pass", row["bmc_pass"]]
    if args.dry_run:
        cmd += ["--dry-run"]
    if args.yes:
        cmd += ["-y"]
    if args.force:
        cmd += ["--force"]
    if args.skip_bmc:
        cmd += ["--skip-bmc"]
    if args.skip_hpm:
        cmd += ["--skip-hpm"]
    if args.skip_bios:
        cmd += ["--skip-bios"]
    # Per-row CSV columns (bmc_file, bmc_version, ...) take priority over the
    # matching --bmc-file/-version CLI flags, which are the fallback for any
    # row that doesn't specify its own. This is what lets one fleet run mix
    # different firmware per platform: a CSV with per-row overrides handles
    # multi-platform batches, while the CLI flags alone still work for the
    # common single-platform case.
    for row_file_key, row_ver_key, cli_file_attr, cli_ver_attr, file_flag, ver_flag in (
        ("bmc_file", "bmc_version", "bmc_file", "bmc_version", "--bmc-file", "--bmc-version"),
        ("hpm_file", "hpm_version", "hpm_file", "hpm_version", "--hpm-file", "--hpm-version"),
        ("bios_file", "bios_version", "bios_file", "bios_version", "--bios-file", "--bios-version"),
    ):
        file_val = row.get(row_file_key) or getattr(args, cli_file_attr)
        if file_val:
            cmd += [file_flag, file_val]
            ver_val = row.get(row_ver_key) or getattr(args, cli_ver_attr)
            if ver_val:
                cmd += [ver_flag, ver_val]
    return cmd


def run_one(row, args, log_dir):
    name = row["system_name"]
    log_path = log_dir / f"{name}.log"
    cmd = build_cmd(row, args)
    start = time.time()
    with open(log_path, "w", encoding="utf-8") as log_fp:
        proc = subprocess.run(cmd, stdout=log_fp, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    elapsed = time.time() - start
    return {
        "system": name,
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "elapsed": elapsed,
        "log": str(log_path),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path", nargs="?", default=str(SCRIPT_DIR / "systems.csv"))
    parser.add_argument("--max-parallel", type=int, default=4, help="Max systems to flash concurrently (default: 4)")
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR))
    parser.add_argument("--dry-run", action="store_true", help="Pass --dry-run through to every system - no hardware touched")
    parser.add_argument("-y", "--yes", action="store_true", help="Required for a real (non-dry-run) fleet flash - see module docstring for why")
    parser.add_argument("--force", action="store_true", help="Pass --force through to every system")
    parser.add_argument("--skip-bmc", action="store_true")
    parser.add_argument("--skip-hpm", action="store_true")
    parser.add_argument("--skip-bios", action="store_true")
    parser.add_argument("--bmc-file", default=None, help="Flash this exact local BMC firmware file on every system in the batch (forwarded to flash_system.py's --bmc-file)")
    parser.add_argument("--hpm-file", default=None, help="Flash this exact local FPGA/HPM firmware file on every system in the batch")
    parser.add_argument("--bios-file", default=None, help="Flash this exact local BIOS firmware file on every system in the batch")
    parser.add_argument("--bmc-version", default=None, help="Expected version label for --bmc-file (used for verification; omit to skip it)")
    parser.add_argument("--hpm-version", default=None, help="Expected version label for --hpm-file")
    parser.add_argument("--bios-version", default=None, help="Expected version label for --bios-file")
    parser.add_argument("--refresh-recipe", action="store_true", help="Refresh recipe.yaml ONCE before dispatching (not per-system)")
    parser.add_argument("--recipe-source", default="nexus",
                         choices=["nexus", "fileshare", "fpga-manual", "fpga-confluence", "fpga-confluence-browser",
                                  "bkc-page", "bkc-page-browser", "bkc-page-cli"])
    args = parser.parse_args()

    if not args.dry_run and not args.yes:
        print("ERROR: a real fleet flash requires --yes (interactive per-system confirmation isn't possible "
              "when output is redirected to per-system log files). Re-run with --dry-run to preview, "
              "or add --yes once you've reviewed the plan.", file=sys.stderr)
        return 2

    systems = load_systems(args.csv_path)
    print(f"Loaded {len(systems)} system(s) from {args.csv_path}:")
    for row in systems:
        print(f"  {row['system_name']:15s} {row['bmc_ip']:16s} {row['platform']}")

    if args.refresh_recipe:
        print(f"\n=== Refreshing recipe.yaml once from {args.recipe_source} ===")
        refresh_cmd = build_subcommand(
            "system", "flash_system.py",
            ["--refresh-only", "--refresh-recipe", "--recipe-source", args.recipe_source],
        )
        rc = subprocess.call(refresh_cmd)
        if rc != 0:
            print(f"Refresh failed (exit {rc}) - aborting before touching any system.", file=sys.stderr)
            return 1

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Dispatching {len(systems)} system(s), up to {args.max_parallel} in parallel ===")
    print(f"Per-system output: {log_dir}\\<system_name>.log\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
        futures = {pool.submit(run_one, row, args, log_dir): row["system_name"] for row in systems}
        for future in as_completed(futures):
            name = futures[future]
            result = future.result()
            status = "OK" if result["success"] else f"FAILED (exit {result['returncode']})"
            print(f"  [{status}] {name}  ({result['elapsed']:.0f}s)  log: {result['log']}")
            results.append(result)

    print("\n=== Summary ===")
    ok = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    print(f"  {len(ok)}/{len(results)} succeeded")
    if failed:
        print("  Failed systems:")
        for r in failed:
            print(f"    {r['system']}: exit {r['returncode']} - see {r['log']}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
