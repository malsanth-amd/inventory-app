#!/usr/bin/env python3
"""
refresh_recipe_confluence_fpga_browser.py — Same job as
refresh_recipe_confluence_fpga.py (parse the Board FPGA FW table on the
"SP8 BKC Release" Confluence page, download the attachments, update
recipe.yaml), but fetches the page via a REAL AUTOMATED BROWSER instead of
raw HTTP requests.

WHY THIS EXISTS
    requests.get() to the Confluence REST API returned 403 with every auth
    method tried (API token - both classic and scoped, browser session
    cookie, even with a spoofed browser User-Agent + X-Atlassian-Token
    header). But pasting the exact same URL into an actual logged-in
    browser tab returned valid JSON every time. This strongly suggests a
    corporate proxy/CASB (e.g. Zscaler, Netskope) in front of
    amd.atlassian.net that only allows traffic through a real, recognized
    browser - not a bare script, regardless of credentials.

    So: drive a REAL browser (Playwright + Chromium) to the same REST API
    URL that already works manually, read its response body, and feed it
    through the exact same parser already validated against the real page
    (find_fpga_row_cells / extract_board_entry, imported unchanged from
    refresh_recipe_confluence_fpga.py).

SETUP (one-time)
    pip install playwright
    playwright install chromium

LOGIN
    Uses a persistent browser profile stored in ./.browser_profile next to
    this script. By default, every run tries invisibly (headless) first
    using whatever login is already cached there - a VISIBLE Chromium
    window only pops up if that turns out to not be logged in (first run,
    or an expired session); log into AMD SSO there if prompted, then the
    script continues automatically and no window appears on subsequent
    runs. Pass --headless to force headless and fail outright instead of
    ever showing a window (for unattended/scheduled use).

USAGE
    python refresh_recipe_confluence_fpga_browser.py --list-only
    python refresh_recipe_confluence_fpga_browser.py
    python refresh_recipe_confluence_fpga_browser.py --headless   # after first login, skip showing the window
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
except ImportError:
    print("Missing dependency. Run: pip install playwright && playwright install chromium", file=sys.stderr)
    raise

# Reuse the already-validated parsing logic and constants unchanged.
from refresh_recipe_confluence_fpga import (
    BOARD_ALIASES,
    BOARD_CODES,
    DEFAULT_FIRMWARE_DIR,
    DEFAULT_OUTPUT,
    DEFAULT_PAGE_URL,
    extract_board_entry,
    find_fpga_row_cells,
    parse_page_url,
)
from launcher_utils import app_dir

SCRIPT_DIR = app_dir()
DEFAULT_PROFILE_DIR = SCRIPT_DIR / ".browser_profile"
LOGIN_WAIT_TIMEOUT_MS = 120_000  # 2 min to let the user complete SSO/MFA if prompted


def ensure_chromium_installed():
    """Download Chromium into Playwright's per-user cache
    (%LOCALAPPDATA%\\ms-playwright on Windows) if it isn't there yet - lets
    FlashTools.exe (which bundles the `playwright` Python package itself,
    but NOT Chromium - that would mean redownloading a fresh browser into
    every build) fetch it once per machine on first use instead of
    requiring a separate manual `playwright install chromium` step.

    Chromium's download goes over plain HTTPS straight to Microsoft's CDN
    via Playwright's own Node-based downloader (not through requests/
    urllib3) - unlike the Confluence API 403s this script exists to work
    around, whether AMD's corporate proxy/CASB also blocks THIS download
    is unverified. If it fails, run `playwright install chromium` once on
    a machine/network where it succeeds, then copy that machine's
    %LOCALAPPDATA%\\ms-playwright\\chromium-* folder to the target machine.
    """
    # Without this, a frozen (PyInstaller) build resolves Playwright's
    # browser cache to a path INSIDE the bundled _internal\playwright\
    # folder instead of the normal shared per-user cache - confirmed by
    # testing the compiled EXE directly. That means it can't see a
    # Chromium a recipient may already have from any other Playwright use
    # on that machine, and would redownload into a spot no other tool
    # shares. Force the standard, OS-documented default location so
    # behavior matches a normal (non-frozen) `pip install playwright` use
    # regardless of frozen/non-frozen quirks.
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", os.path.expandvars(r"%LOCALAPPDATA%\ms-playwright"))

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        exe = p.chromium.executable_path
    if os.path.exists(exe):
        return True

    print(f"Chromium not found at {exe} - downloading now (one-time, ~150-300MB, needs network access) ...")
    from playwright.__main__ import main as playwright_main
    old_argv = sys.argv
    try:
        # Both targets: "chromium" (the headed browser) and
        # "chromium-headless-shell" (a separate executable newer
        # Playwright versions require specifically for headless=True
        # launches - confirmed by testing --headless against a machine
        # that only had "chromium" installed, which failed looking for
        # the headless-shell binary specifically) - install both up front
        # so --headless works on first run too, not just headed.
        sys.argv = ["playwright", "install", "chromium", "chromium-headless-shell"]
        try:
            playwright_main()
        except SystemExit as e:
            if e.code not in (0, None):
                raise RuntimeError(f"playwright install chromium failed (exit {e.code})")
    finally:
        sys.argv = old_argv

    if not os.path.exists(exe):
        raise RuntimeError(f"playwright install reported success but {exe} still doesn't exist")
    return True


def _looks_logged_in(url, title):
    """Confluence's REST API returns a bare 403 JSON for an unauthenticated
    request - it does NOT redirect to an SSO login page the way the normal
    human-facing page does. So login must be confirmed via the human page,
    never via the API endpoint's response alone.

    Checks the URL's actual HOSTNAME, not a naive substring match on the
    whole URL - a plain `"atlassian.net" in url` check was fooled by
    id.atlassian.com's "request access"/"join" flow
    (id.atlassian.com/join/user-access?...&continue=https://amd.atlassian.net/...),
    which legitimately contains the literal text "atlassian.net" inside its
    `continue=` query parameter while the user is still on a DIFFERENT
    domain (id.atlassian.com) that hasn't finished anything yet - that
    false positive made this function report "logged in" prematurely.
    """
    host = urlparse(url).hostname or ""
    login_markers = ("login", "sso", "okta", "signin", "authorize", "microsoftonline")
    if any(m in host.lower() for m in login_markers):
        return False
    if any(m in (title or "").lower() for m in ("sign in", "log in", "login")):
        return False
    return host.lower() == "amd.atlassian.net" or host.lower().endswith(".amd.atlassian.net")


def ensure_browser_logged_in(page_url, profile_dir, headless, verify):
    """Make sure the persistent browser profile in profile_dir has a valid
    login session for page_url's site - auto-escalating from an invisible
    (headless) attempt to a visible one if that's not logged in (first use,
    or an expired session), same policy as fetch_page_storage_via_browser().

    For callers that need the browser logged in WITHOUT also needing the
    page content fetched through it - e.g. refresh_recipe_bkc_page_cli.py,
    which gets the page's HTML from the `atlassian` CLI instead (more
    reliable than scraping it through a live browser) but still needs a
    logged-in browser afterward to download FPGA attachments (raw HTTP
    downloads are blocked the same way the raw page-fetch is - confirmed
    separately, not just assumed)."""
    attempts = [True] if headless else [True, False]
    for attempt_num, attempt_headless in enumerate(attempts):
        is_last_attempt = attempt_num == len(attempts) - 1
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=attempt_headless,
                ignore_https_errors=not verify,
            )
            try:
                page = context.pages[0] if context.pages else context.new_page()
                mode = "headless, using cached login" if attempt_headless else "visible window"
                print(f"  Navigating to {page_url} to establish/confirm login ({mode}) ...")
                try:
                    page.goto(page_url, wait_until="domcontentloaded", timeout=LOGIN_WAIT_TIMEOUT_MS)
                except PlaywrightTimeoutError as e:
                    if headless:
                        raise ValueError(
                            f"Timed out loading the page in forced --headless mode: {e}. "
                            f"Re-run without --headless to try a visible window instead."
                        )
                    if not is_last_attempt:
                        print(f"  Headless navigation timed out ({e}) - retrying with a visible window ...")
                        continue
                    raise
                print(f"  Landed on: {page.url}  (title: {page.title()!r})")

                if not _looks_logged_in(page.url, page.title()):
                    if headless:
                        raise ValueError(
                            "Not logged in and running --headless, so there's no window to log in with. "
                            "Re-run without --headless at least once to complete SSO login interactively."
                        )
                    if not is_last_attempt:
                        print("  Not logged in yet - retrying with a visible window for SSO login ...")
                        continue
                    print("  Looks like a login page - please complete SSO login in the opened browser window.")
                    print(f"  Waiting up to {LOGIN_WAIT_TIMEOUT_MS // 1000}s for you to finish ...")
                    page.wait_for_function(
                        "() => { const h = window.location.hostname.toLowerCase(); "
                        "return (h === 'amd.atlassian.net' || h.endsWith('.amd.atlassian.net')) && "
                        "!/login|sso|okta|signin|authorize|microsoftonline/i.test(h); }",
                        timeout=LOGIN_WAIT_TIMEOUT_MS,
                    )
                    page.wait_for_load_state("domcontentloaded", timeout=LOGIN_WAIT_TIMEOUT_MS)
                    print(f"  Login confirmed, now on: {page.url}")
                return  # logged in - no need to try the next (visible) attempt
            finally:
                context.close()


def fetch_page_storage_via_browser(page_url, profile_dir, headless, verify):
    base, page_id = parse_page_url(page_url)
    api_url = f"{base}/rest/api/content/{page_id}?expand=body.storage,version"

    # Auto-escalation: try invisibly (headless) first, reusing whatever
    # login session is already saved in profile_dir - a visible window
    # only appears if that turns out to NOT be logged in (first use, or
    # an expired session). An explicit --headless (e.g. for unattended/
    # scheduled runs) skips this fallback entirely and fails outright
    # instead of ever popping up a window.
    attempts = [True] if headless else [True, False]

    with sync_playwright() as p:
        body_text = None
        for attempt_num, attempt_headless in enumerate(attempts):
            is_last_attempt = attempt_num == len(attempts) - 1
            context = p.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=attempt_headless,
                ignore_https_errors=not verify,
            )
            try:
                page = context.pages[0] if context.pages else context.new_page()

                # Step 1: visit the HUMAN-FACING page first. Unlike the API
                # endpoint, this one genuinely redirects to SSO when logged out,
                # giving us something to detect and wait on.
                #
                # wait_until="domcontentloaded" (not "networkidle"): Confluence
                # is a SPA with persistent background polling/presence pings,
                # so it may never go fully network-idle within any timeout -
                # a known Playwright/Atlassian gotcha, confirmed happening
                # here (a 120s "networkidle" wait timed out on this exact
                # page). domcontentloaded is sufficient since all we actually
                # check afterward is the URL/title (login) or evaluated body
                # text (API content), not network quiescence.
                mode = "headless, using cached login" if attempt_headless else "visible window"
                print(f"  Navigating to {page_url} to establish/confirm login ({mode}) ...")
                try:
                    page.goto(page_url, wait_until="domcontentloaded", timeout=LOGIN_WAIT_TIMEOUT_MS)
                except PlaywrightTimeoutError as e:
                    if headless:
                        raise ValueError(
                            f"Timed out loading the page in forced --headless mode: {e}. "
                            f"Re-run without --headless to try a visible window instead."
                        )
                    if not is_last_attempt:
                        print(f"  Headless navigation timed out ({e}) - retrying with a visible window ...")
                        continue
                    raise
                print(f"  Landed on: {page.url}  (title: {page.title()!r})")

                if not _looks_logged_in(page.url, page.title()):
                    if headless:
                        raise ValueError(
                            "Not logged in and running --headless, so there's no window to log in with. "
                            "Re-run without --headless at least once to complete SSO login interactively."
                        )
                    if not is_last_attempt:
                        print("  Not logged in yet - retrying with a visible window for SSO login ...")
                        continue
                    print("  Looks like a login page - please complete SSO login in the opened browser window.")
                    print(f"  Waiting up to {LOGIN_WAIT_TIMEOUT_MS // 1000}s for you to finish ...")
                    # Checks window.location.HOSTNAME specifically, not the whole href -
                    # a whole-href substring check was fooled by id.atlassian.com's
                    # "request access" flow, whose URL legitimately contains the literal
                    # text "atlassian.net" inside its continue= query parameter while
                    # still sitting on a different (id.atlassian.com) domain.
                    page.wait_for_function(
                        "() => { const h = window.location.hostname.toLowerCase(); "
                        "return (h === 'amd.atlassian.net' || h.endsWith('.amd.atlassian.net')) && "
                        "!/login|sso|okta|signin|authorize|microsoftonline/i.test(h); }",
                        timeout=LOGIN_WAIT_TIMEOUT_MS,
                    )
                    page.wait_for_load_state("domcontentloaded", timeout=LOGIN_WAIT_TIMEOUT_MS)
                    print(f"  Login confirmed, now on: {page.url}")

                # Step 2: NOW hit the API endpoint - the session cookie set during
                # step 1 should carry over to this same browser context.
                print(f"  Navigating to {api_url}")
                page.goto(api_url, wait_until="domcontentloaded", timeout=LOGIN_WAIT_TIMEOUT_MS)
                print(f"  Landed on: {page.url}")

                body_text = page.evaluate("() => document.body.innerText")
            finally:
                context.close()
            break  # success - no need to try the next (visible) attempt

    try:
        data = json.loads(body_text)
    except json.JSONDecodeError:
        raise ValueError(
            f"Browser did not return JSON for the API URL - got this instead (first 500 chars):\n"
            f"{body_text[:500]}"
        )

    if "body" not in data or "storage" not in data.get("body", {}):
        raise ValueError(
            f"Response was valid JSON but missing body.storage - likely an error payload, a permissions "
            f"issue, or the 'expand' query param got dropped. Full response:\n"
            f"{json.dumps(data, indent=2)[:2000]}"
        )

    storage_html = data["body"]["storage"]["value"]
    return base, page_id, storage_html


def download_all_attachments_via_browser(entries, profile_dir, headless, verify, base, page_id, fw_dir):
    """Download every board's attachment through the SAME real browser
    session used for login/fetch (one context for all files, not one per
    file). Deliberately NOT using requests/urllib3 for this: AMD's network
    sits behind a TLS-intercepting proxy whose re-signed cert is trusted by
    Windows/the browser but not by Python's certifi bundle, which made a
    plain requests.get() to api.media.atlassian.com fail with
    CERTIFICATE_VERIFY_FAILED even with valid cookies. Chromium already
    trusts that proxy cert, so letting it do the actual download sidesteps
    the problem entirely.
    """
    from urllib.parse import quote

    results = {}
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir), headless=headless, ignore_https_errors=not verify,
        )
        try:
            page = context.pages[0] if context.pages else context.new_page()
            for e in entries:
                board = e["board"]
                filename = e["filename"]
                dest_dir = fw_dir / "hpm" / board
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / filename
                url = f"{base}/download/attachments/{page_id}/{quote(filename)}"

                print(f"  {board:10s}: downloading {filename} ...")
                with page.expect_download(timeout=120_000) as download_info:
                    try:
                        page.goto(url, timeout=120_000)
                    except Exception:
                        pass  # Chromium treats an attachment response as a download, not a navigation - expected
                download = download_info.value
                download.save_as(str(dest))
                results[board] = (dest, url)
        finally:
            context.close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--page-url", default=DEFAULT_PAGE_URL)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--firmware-dir", default=str(DEFAULT_FIRMWARE_DIR))
    parser.add_argument("--profile-dir", default=str(DEFAULT_PROFILE_DIR),
                         help="Persistent browser profile dir (keeps you logged in between runs)")
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

    try:
        cells = find_fpga_row_cells(storage_html)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    entries = []
    for cell in cells:
        entry = extract_board_entry(cell)
        if entry and entry["board"] in BOARD_CODES and entry["filename"] and entry["version"]:
            entries.append(entry)
        elif entry:
            print(f"  WARNING: skipping a cell with incomplete/unrecognized data: {entry}", file=sys.stderr)

    if not entries:
        print("ERROR: Found the FPGA row but couldn't extract any valid board/filename/version triples. "
              "Re-run with --dump-raw and inspect the HTML.", file=sys.stderr)
        return 1

    by_board = {e["board"]: e for e in entries}
    for alias_board, source_board in BOARD_ALIASES.items():
        if alias_board not in by_board and source_board in by_board:
            aliased = dict(by_board[source_board])
            aliased["board"] = alias_board
            aliased["aliased_from"] = source_board
            entries.append(aliased)
            by_board[alias_board] = aliased

    print("\n=== Found FPGA entries ===")
    for e in entries:
        note = f"  [aliased from {e['aliased_from']}]" if e.get("aliased_from") else ""
        print(f"  {e['board']:10s}: {e['filename']}  (version='{e['version']}'){note}")

    if args.list_only:
        print("\n--list-only set, nothing downloaded or written.")
        return 0

    output_path = Path(args.output)
    recipe = {"firmware": {}, "metadata": {}}
    if output_path.is_file():
        recipe = yaml.safe_load(output_path.read_text()) or recipe
        backup = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy(output_path, backup)
        print(f"\nBacked up previous recipe to {backup}")

    print("\n=== Downloading (via browser) ===")
    fw_dir = Path(args.firmware_dir)
    # Always headless here - login was already confirmed (visibly, if
    # needed) by fetch_page_storage_via_browser() above, and this reuses
    # the same persisted profile, so there's nothing left to show a user.
    downloaded = download_all_attachments_via_browser(entries, profile_dir, True, verify, base, page_id, fw_dir)

    changes = []
    for e in entries:
        board = e["board"]
        dest, url = downloaded[board]
        print(f"  {board:10s}: downloaded {dest}")

        recipe["firmware"].setdefault(board, {})
        old_version = recipe["firmware"][board].get("hpm", {}).get("version")
        recipe["firmware"][board]["hpm"] = {"version": e["version"], "url": url}
        if old_version != e["version"]:
            changes.append(f"{board}.hpm: {old_version} -> {e['version']}")

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
