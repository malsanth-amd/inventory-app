#!/usr/bin/env python3
"""
PPIN → CPU serial number — read the PPIN fuse off a SUT's BMC and decode it.

For each SUT named on the command line this:
  1. SSHes to the BMC (the SUT name *is* the BMC host — port 22),
  2. runs `apml_tool <socket> --showppinfuse`,
  3. pulls the 64-bit PPIN fuse value out of the output,
  4. decodes it to the CPU serial number of the part installed in that socket.

Step 4 follows the rules on the SERVERDEBUG "PPIN to SN" Confluence page; see
the PPIN → serial number section below.

Usage:
    python ppin_sn.py seagull-0112
    python ppin_sn.py seagull-0112 seagull-0113 --socket 0,1
    python ppin_sn.py seagull-0112 --json
    python ppin_sn.py seagull-0112 --raw        # also dump apml_tool's output

Credentials come from BMC_USER / BMC_PASSWORD in .env (see .env.example), or
can be overridden with --user/--password on the command line.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass

import paramiko
from dotenv import load_dotenv

load_dotenv()

DEFAULT_USER     = os.getenv("BMC_USER", "root")
DEFAULT_PASSWORD = os.getenv("BMC_PASSWORD", "")
DEFAULT_PORT     = int(os.getenv("BMC_PORT", "22"))
DEFAULT_TIMEOUT  = 20.0


# ── PPIN → serial number ──────────────────────────────────────────────────────
#
# From the SERVERDEBUG "PPIN to SN" page. The fuse is three packed fields:
#
#   bits 63..21  lot number, base 37, written as 7 characters
#   bits 20..14  date code, 7 bits
#   bits 13..0   unit number, printed as 4 digits
#
# The lot alphabet is not plain base-36: remainders 0-26 map to '@' and 'A'-'Z'
# (64 + r), and 27-36 map to '0'-'9' (21 + r). The date code becomes a letter
# from 'M' (77 + dc // 10) followed by dc % 10.

class DecodeUnavailable(Exception):
    """Raised when a PPIN cannot be turned into a serial number."""


def decode_ppin(ppin: str) -> str:
    """Return the CPU serial number for *ppin*, hex with or without 0x."""
    text = str(ppin).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text or any(c not in "0123456789abcdef" for c in text):
        raise DecodeUnavailable(f"{ppin!r} is not a hex PPIN")
    value = int(text, 16)

    lot_number, lot = value >> 21, ""
    for _ in range(7):
        r = lot_number % 37
        lot_number //= 37
        lot = chr(r + 64 if r < 27 else r + 21) + lot

    date_code = (value >> 14) & 0x7F
    return f"{lot}{chr(date_code // 10 + 77)}{date_code % 10}{value & 0x3FFF:04d}"


def extract_ppins(output: str) -> list[tuple[str, str]]:
    """Every (label, ppin) pair in apml_tool's output, one per matching line.

    A two-socket board prints a fuse per socket, so the label — whatever text
    precedes the value on its line — is what tells them apart.
    """
    found: list[tuple[str, str]] = []
    for line in output.splitlines():
        m = _PPIN_ANY_LINE.search(line)
        if not m:
            continue
        label = line[:m.start()].strip(" :=-|\t") or "PPIN"
        found.append((label, m.group(1).upper().rjust(16, "0")))
    return found


# A PPIN is 64 bits; the register drops leading zeros, so accept 13-16 digits.
_PPIN_ANY_LINE = re.compile(r"\b(?:0[xX])?([0-9a-fA-F]{13,16})\b")


# ── talking to the BMC ────────────────────────────────────────────────────────

# apml_tool prints the fuse inside a box-drawn table whose exact shape varies by
# firmware, e.g.
#     | PPIN FUSE  | 0x1234567890ABCDEF |
#     PPIN Fuse: 1234567890abcdef
# so match on the word PPIN plus the first hex run on the same line, skipping
# label text such as "FUSE" (whose letters are themselves hex digits).
#
# The value is often shorter than 16 digits — the register drops leading zeros,
# so 0x2b620df48c84013 is a 15-digit print of 0x02b620df48c84013. The Confluence
# page is explicit that it must be left-padded to 16 before decoding.
#
# Without a PPIN label to anchor on, a short token is indistinguishable from any
# other number in the output, so the unlabelled fallbacks stay strict: an
# 0x-prefixed run of 8+ digits, or a bare run of exactly 16.
_PPIN_LINE   = re.compile(r"ppin[^\n]{0,80}?(?<![0-9A-Za-z])(?:0[xX])?([0-9a-fA-F]{1,16})(?![0-9A-Za-z])",
                          re.IGNORECASE)
_PPIN_PREFIX = re.compile(r"(?<![0-9A-Za-z])0[xX]([0-9a-fA-F]{8,16})(?![0-9A-Za-z])")
_PPIN_BARE   = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{16})(?![0-9A-Za-z])")


def parse_ppin(output: str) -> str:
    """Pull the PPIN fuse value out of apml_tool's output.

    Returns 16 uppercase hex digits, left-padded with zeros as the Confluence
    page requires. Raises ValueError if nothing looks like a PPIN — an all-zero
    or all-F fuse is reported as-is; that is a real answer (unfused / unreadable
    part) and the caller decides what to do with it.
    """
    for pattern in (_PPIN_LINE, _PPIN_PREFIX, _PPIN_BARE):
        m = pattern.search(output)
        if m:
            return m.group(1).upper().rjust(16, "0")
    raise ValueError("no PPIN fuse value found in apml_tool output")


@dataclass
class Result:
    host:   str
    socket: int
    ppin:   str | None = None
    serial: str | None = None
    error:  str | None = None
    raw:    str = ""


def _run(client: paramiko.SSHClient, command: str, timeout: float) -> tuple[int, str, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def read_sut(host: str, sockets: list[int], *, user: str, password: str | None,
             key_filename: str | None, port: int, timeout: float) -> list[Result]:
    """SSH to one BMC and read the PPIN fuse for each socket."""
    results = [Result(host=host, socket=s) for s in sockets]

    client = paramiko.SSHClient()
    # Lab BMCs regenerate their host keys on reflash, so known_hosts is noise
    # here rather than protection.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user,
            password=password, key_filename=key_filename,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            look_for_keys=bool(key_filename), allow_agent=bool(key_filename),
        )
    except paramiko.AuthenticationException:
        for r in results:
            r.error = f"authentication failed for {user}@{host}"
        return results
    except Exception as e:                      # socket errors, timeouts, DNS
        for r in results:
            r.error = f"could not reach {host}:{port} - {e}"
        return results

    try:
        for r in results:
            try:
                code, out, err = _run(client, f"apml_tool {r.socket} --showppinfuse", timeout)
            except Exception as e:
                r.error = f"apml_tool failed to run - {e}"
                continue
            r.raw = (out + err).strip()
            if code != 0:
                first = next((ln for ln in r.raw.splitlines() if ln.strip()), "")
                r.error = f"apml_tool exited {code}" + (f" - {first.strip()}" if first else "")
                continue
            try:
                r.ppin = parse_ppin(r.raw)
            except ValueError as e:
                r.error = str(e)
                continue
            try:
                r.serial = decode_ppin(r.ppin)
            except DecodeUnavailable as e:
                r.error = str(e)
    finally:
        client.close()
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_sockets(value: str) -> list[int]:
    try:
        sockets = [int(p) for p in value.replace(" ", "").split(",") if p != ""]
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a socket list: {value!r}")
    if not sockets:
        raise argparse.ArgumentTypeError("at least one socket required")
    return sockets


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Read the CPU PPIN fuse off a SUT's BMC and decode it to a serial number.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:  python ppin_sn.py seagull-0112 seagull-0113 --socket 0,1",
    )
    ap.add_argument("sut", nargs="+", help="SUT / BMC hostname(s), e.g. seagull-0112")
    ap.add_argument("-s", "--socket", type=_parse_sockets, default=[0],
                    help="socket index, or a comma-separated list (default: 0)")
    ap.add_argument("-u", "--user", default=DEFAULT_USER, help=f"BMC user (default: {DEFAULT_USER})")
    ap.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="BMC password (default: from BMC_PASSWORD)")
    ap.add_argument("-i", "--key", help="SSH private key file; used instead of a password")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"BMC SSH port (default: {DEFAULT_PORT})")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-step timeout in seconds")
    ap.add_argument("--json", action="store_true", dest="as_json", help="print results as JSON")
    ap.add_argument("--raw", action="store_true", help="also print apml_tool's output")
    args = ap.parse_args(argv)

    results: list[Result] = []
    for host in args.sut:
        results.extend(read_sut(
            host, args.socket,
            user=args.user,
            password=None if args.key else args.password,
            key_filename=args.key,
            port=args.port,
            timeout=args.timeout,
        ))

    if args.as_json:
        payload = [
            {k: v for k, v in (
                ("sut", r.host), ("socket", r.socket), ("ppin", r.ppin),
                ("serial", r.serial), ("error", r.error),
                ("raw", r.raw if args.raw else None),
            ) if v is not None}
            for r in results
        ]
        print(json.dumps(payload, indent=2))
    else:
        width = max((len(r.host) for r in results), default=4)
        for r in results:
            line = f"{r.host:<{width}}  socket {r.socket}  "
            if r.ppin:
                line += f"PPIN {r.ppin}  SN {r.serial or '?'}"
            else:
                line += "PPIN ?"
            if r.error:
                line += f"  [{r.error}]"
            print(line)
            if args.raw and r.raw:
                print("\n".join(f"    {ln}" for ln in r.raw.splitlines()))

    # Non-zero if nothing could be read at all; a missing decode still counts as
    # a successful read, so scripts can collect PPINs before the rules land.
    return 0 if any(r.ppin for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
