"""
FVDDR Inventory Management — FastAPI backend
Reads/writes inventory.json from a configurable shared drive path.
Admin-only writes: POST/PUT/DELETE require a valid session token.
"""

import asyncio
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import smtplib
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone, date as _date
from fnmatch import fnmatch
from email import encoders as email_encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import openpyxl
import pandas as pd
try:
    import msoffcrypto
    _HAS_MSOFFCRYPTO = True
except ImportError:
    _HAS_MSOFFCRYPTO = False
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator, model_validator

load_dotenv()

_CONFIGURED_DIR = Path(os.getenv("INVENTORY_DATA_DIR", "./data"))
_FALLBACK_DIR   = Path("./data")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

# BMC login for the CPU Decoder tab's "read from a SUT" button. Server-side only
# — a root password must never travel from the browser over plain HTTP.
BMC_USER     = os.getenv("BMC_USER", "root")
BMC_PASSWORD = os.getenv("BMC_PASSWORD", "")
BMC_PORT     = int(os.getenv("BMC_PORT", "22"))
BMC_TIMEOUT  = float(os.getenv("BMC_TIMEOUT", "20"))

# Nightly CPU audit scan — reads every system named in AUDIT_SYSTEMS_CSV once a
# day and stamps the `audit` field of each CPU it finds (see run_audit_scan,
# near the rest of the CPU Decoder machinery, for what that actually does).
#
# The CSV this shipped with is a dated export — fvddr-systems-2026-11-02_all.csv
# — which will go stale the next time the lab's system list changes. Point this
# at a file path that gets overwritten on every export, rather than renaming
# the env var's default each time a new dated file appears.
AUDIT_SYSTEMS_CSV = os.getenv(
    "AUDIT_SYSTEMS_CSV", r"C:\inventory-app\fvddr-systems-2026-11-02_all.csv"
)
AUDIT_SCAN_ENABLED = os.getenv("AUDIT_SCAN_ENABLED", "true").strip().lower() not in ("0", "false", "no", "")
AUDIT_SCAN_HOUR    = int(os.getenv("AUDIT_SCAN_HOUR", "0"))
AUDIT_SCAN_MINUTE  = int(os.getenv("AUDIT_SCAN_MINUTE", "30"))
# A pause between systems so 90-odd back-to-back SSH sessions do not land on
# the network, or on whatever is watching it, as a sweep.
AUDIT_SCAN_HOST_DELAY_SEC = float(os.getenv("AUDIT_SCAN_HOST_DELAY_SEC", "1.5"))

# Nightly DIMM audit scan — same CSV, same `audit` column, but for DIMMs: for
# each system it auto-grabs the OS IP (Redfish first, a SOL console login as
# fallback — see run_dimm_audit_scan near the rest of this machinery), SSHes
# into the OS, and runs a dmidecode-based DIMM read. A separate toggle and
# clock from the CPU scan above, since this is the one part of either scan
# that can log in to a SUT's own console rather than only its BMC.
DIMM_SCAN_ENABLED = os.getenv("DIMM_SCAN_ENABLED", "true").strip().lower() not in ("0", "false", "no", "")
DIMM_SCAN_HOUR    = int(os.getenv("DIMM_SCAN_HOUR", "1"))
DIMM_SCAN_MINUTE  = int(os.getenv("DIMM_SCAN_MINUTE", "30"))
DIMM_SCAN_HOST_DELAY_SEC = float(os.getenv("DIMM_SCAN_HOST_DELAY_SEC", "1.5"))
# Off by default: console logins can bump whoever is already on that console.
# Turn on only after Redfish-only discovery has been verified against the fleet.
DIMM_SOL_FALLBACK_ENABLED = os.getenv("DIMM_SOL_FALLBACK_ENABLED", "false").strip().lower() not in ("0", "false", "no", "")
# OS login(s) the DIMM scan tries, in order — see _os_credential_cascade. Real
# credentials for real lab systems, so (like BMC_USER/BMC_PASSWORD above) they
# come only from .env, never hardcoded here.
OS_LOGIN_1_USER     = os.getenv("OS_LOGIN_1_USER", "").strip()
OS_LOGIN_1_PASSWORD = os.getenv("OS_LOGIN_1_PASSWORD", "").strip()
OS_LOGIN_2_USER     = os.getenv("OS_LOGIN_2_USER", "").strip()
OS_LOGIN_2_PASSWORD = os.getenv("OS_LOGIN_2_PASSWORD", "").strip()
OS_LOGIN_3_USER     = os.getenv("OS_LOGIN_3_USER", "").strip()
OS_LOGIN_3_PASSWORD = os.getenv("OS_LOGIN_3_PASSWORD", "").strip()

# Multi-admin support: ADMIN_1_USERNAME/PASSWORD … ADMIN_3_USERNAME/PASSWORD
# Falls back to legacy ADMIN_USERNAME/PASSWORD if numbered entries are not set.
def _load_admin_credentials() -> dict[str, str]:
    creds: dict[str, str] = {}
    for i in range(1, 4):
        u = os.getenv(f"ADMIN_{i}_USERNAME", "").strip()
        p = os.getenv(f"ADMIN_{i}_PASSWORD", "").strip()
        if u and p:
            creds[u] = p
    if not creds:
        # Legacy single-admin fallback
        u = os.getenv("ADMIN_USERNAME", "").strip()
        p = os.getenv("ADMIN_PASSWORD", "").strip()
        if u and p:
            creds[u] = p
    return creds


# True when nothing at all was configured and the placeholder below is in use.
# _check_credentials refuses to migrate a placeholder into admins.json, so an
# unconfigured deployment never gets a working "admin"/"changeme" login.
_ADMIN_CREDS_ARE_PLACEHOLDER = False

ADMIN_CREDENTIALS: dict[str, str] = _load_admin_credentials()
if not ADMIN_CREDENTIALS:
    # Nothing configured: keep a placeholder so first-run bootstrap still creates
    # an account, but mark it so it can never be used as a live .env credential.
    ADMIN_CREDENTIALS = {"admin": "changeme"}
    _ADMIN_CREDS_ARE_PLACEHOLDER = True

SUPER_ADMIN_USERNAME: str = os.getenv("SUPER_ADMIN_USERNAME", "FVDDR_Admin").strip()
# Optional second superadmin for maintenance. Empty by default: no account is
# created implicitly, and no password is compiled into this file. Set
# DEVELOPER_USERNAME in .env and create the account like any other admin.
DEVELOPER_USERNAME: str = os.getenv("DEVELOPER_USERNAME", "").strip()
# Legacy account this file used to bootstrap with a fixed, unchangeable password.
# Still recognised only so the server can warn that it is present; it is granted
# no privileges here any more.
_LEGACY_DEV_USERNAME = "FVDDR_Dev"

SMTP_HOST      = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT      = int(os.getenv("SMTP_PORT", "587").strip())
SMTP_USER      = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD  = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM      = os.getenv("SMTP_FROM", SMTP_USER).strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Inventory Manager").strip()
# Set to "false" to skip STARTTLS (use for port-25 internal relays that don't require TLS)
_raw_tls = os.getenv("SMTP_USE_TLS", "").strip().lower()
SMTP_USE_TLS   = _raw_tls != "false"  # default True; set SMTP_USE_TLS=false for port-25 relay
# Comma-separated emails always CC'd on every reminder (e.g. admin, FVDDR manager)
REMINDER_CC: list[str] = [e.strip() for e in os.getenv("REMINDER_CC", "").split(",") if e.strip()]
# Email address that receives inventory submission requests from users
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", SMTP_FROM).strip()


def _resolve_data_dir() -> Path:
    """Return the configured data directory, falling back to ./data if the
    drive or root path is not accessible (e.g. shared drive not yet mounted)."""
    # Check that the drive/root anchor exists before trying to create subdirs.
    anchor = Path(_CONFIGURED_DIR.anchor)  # e.g. "Z:\\" or "\\server\share"
    if anchor != Path(".") and not anchor.exists():
        print("=" * 60)
        print(f"  WARNING: Configured data path is not accessible:")
        print(f"    {_CONFIGURED_DIR}")
        print(f"  The drive or network share '{anchor}' was not found.")
        print(f"  Possible causes:")
        print(f"    • The drive letter is not mapped yet")
        print(f"    • The network share is offline")
        print(f"    • The path in .env is incorrect")
        print(f"  Falling back to local storage: {_FALLBACK_DIR.resolve()}")
        print(f"  Fix INVENTORY_DATA_DIR in .env and restart to use the shared drive.")
        print("=" * 60)
        _FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
        return _FALLBACK_DIR

    try:
        _CONFIGURED_DIR.mkdir(parents=True, exist_ok=True)
        return _CONFIGURED_DIR
    except OSError as exc:
        print("=" * 60)
        print(f"  WARNING: Could not create data directory:")
        print(f"    {_CONFIGURED_DIR}")
        print(f"  Error: {exc}")
        print(f"  Falling back to local storage: {_FALLBACK_DIR.resolve()}")
        print(f"  Fix INVENTORY_DATA_DIR in .env and restart to use the shared drive.")
        print("=" * 60)
        _FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
        return _FALLBACK_DIR


DATA_DIR    = _resolve_data_dir()
DATA_FILE   = DATA_DIR / "inventory.json"   # legacy path; used only for one-time migration
DB_FILE     = DATA_DIR / "inventory.db"
ADMINS_FILE = DATA_DIR / "admins.json"


# ── password hashing (PBKDF2-SHA256, stdlib only) ────────────────────────────

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        _, algo, salt, dk_hex = stored.split(":", 3)
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), 260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _read_admins() -> list[dict]:
    if not ADMINS_FILE.exists():
        return []
    try:
        return json.loads(ADMINS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _write_admins(admins: list[dict]) -> None:
    tmp = ADMINS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(admins, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(ADMINS_FILE)


def _bootstrap_admins() -> None:
    """Bootstrap admin accounts into admins.json on first run.

    Only the accounts configured in .env are created. Nothing is added on later
    starts: an account deleted by a superadmin stays deleted.
    """
    first_run = not (ADMINS_FILE.exists() and ADMINS_FILE.stat().st_size > 2)
    if first_run:
        admins = [{"username": u, "hash": _hash_password(p)} for u, p in ADMIN_CREDENTIALS.items()]
        _write_admins(admins)
        print(f"  Admin credentials bootstrapped -> {ADMINS_FILE}")
        print(f"  Plain-text passwords in .env are no longer used.")
        return

    # Warn — loudly — if the retired hardcoded account is still in admins.json.
    # Its password used to be fixed in source and could not be rotated, so it
    # must be deleted or have its password changed before it means anything.
    if any(a.get("username") == _LEGACY_DEV_USERNAME for a in _read_admins()):
        print("=" * 60)
        print(f"  SECURITY: the legacy '{_LEGACY_DEV_USERNAME}' account still exists.")
        print(f"  It used to ship with a fixed password compiled into server.py.")
        print(f"  It no longer has superadmin rights, but it can still log in.")
        print(f"  Delete it in Settings -> Admin accounts, or change its password.")
        print("=" * 60)


_bootstrap_admins()


def _check_credentials(username: str, password: str) -> bool:
    """Authenticate against the PBKDF2 hashes in admins.json.

    An account configured in .env but missing from admins.json is accepted once
    against the plain-text value and immediately written back as a hash. That
    covers accounts that predate hashing or were lost when admins.json was
    rewritten -- the superadmin named by SUPER_ADMIN_USERNAME is often one of
    them, since renaming other accounts can leave it present only in .env.

    After that single migration the plain-text value is no longer a usable
    credential: the next login verifies against the stored hash. The built-in
    "admin"/"changeme" placeholder never takes this path, so an unconfigured
    deployment does not get a usable default login.
    """
    admins = _read_admins()
    for admin in admins:
        if admin["username"] == username:
            return _verify_password(password, admin["hash"])

    if _ADMIN_CREDS_ARE_PLACEHOLDER:
        return False
    stored = ADMIN_CREDENTIALS.get(username)
    if not stored or not hmac.compare_digest(password, stored):
        return False

    admins.append({"username": username, "hash": _hash_password(password)})
    _write_admins(admins)
    print(f"  Migrated .env account '{username}' into {ADMINS_FILE} as a PBKDF2 hash.")
    return True


# In-memory session store: token → username
# Tokens are invalidated when the server restarts.
_sessions: dict[str, str] = {}


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Starts the nightly audit-scan loop alongside the server, stops it with it.

    _audit_scan_loop / _dimm_scan_loop are defined later in this module (by
    the CPU Decoder / read-sut code they share matching logic with), but that
    is only a name this function looks up when it actually runs — at server
    startup, by which time the whole module has finished importing. Defined
    here, immediately before `app = FastAPI(...)`, purely because the FastAPI
    constructor needs the function object to exist at the point it is passed in.
    """
    tasks = []
    if AUDIT_SCAN_ENABLED:
        tasks.append(asyncio.create_task(_audit_scan_loop()))
    if DIMM_SCAN_ENABLED:
        tasks.append(asyncio.create_task(_dimm_scan_loop()))
    yield
    for task in tasks:
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="FVDDR Inventory Management", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# /api/items serialises the whole inventory on every poll — 6.2 MB at ~9.7k rows,
# twice a minute per open tab. It is highly repetitive JSON: gzip takes it to
# roughly 0.36 MB.
app.add_middleware(GZipMiddleware, minimum_size=1024)

bearer = HTTPBearer(auto_error=False)


# ── auth helpers ──────────────────────────────────────────────────────────────



def _is_superadmin(username: str) -> bool:
    """Superadmin names are matched only when configured, so an empty
    DEVELOPER_USERNAME never matches an empty session username."""
    if not username:
        return False
    return username == SUPER_ADMIN_USERNAME or (
        bool(DEVELOPER_USERNAME) and username == DEVELOPER_USERNAME
    )


def _get_role(username: str) -> str:
    if DEVELOPER_USERNAME and username == DEVELOPER_USERNAME:
        return "developer"
    if username == SUPER_ADMIN_USERNAME:
        return "superadmin"
    return "admin"


def _require_admin(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not creds or creds.credentials not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin login required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _require_superadmin(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not creds or creds.credentials not in _sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin login required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not _is_superadmin(_sessions[creds.credentials]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires superadmin privileges.",
        )


# ── data helpers ──────────────────────────────────────────────────────────────

_CANONICAL_CATEGORIES = ["DIMMs", "CPU (Silicon)", "Storage", "Systems", "Accessories"]
_CAT_NORM: dict[str, str] = {
    c.lower().replace(" ", "").replace("(", "").replace(")", ""): c
    for c in _CANONICAL_CATEGORIES
}

# Physical condition, tracked separately from check-out state so an item can be
# both checked out and faulty — which is exactly how a fault is usually found.
#   Good    — fit for use (the default, and what a blank value means)
#   Suspect — failed once, needs retesting; still on the shelf, but flagged
#   Bad     — confirmed faulty
_CONDITIONS = ["Good", "Suspect", "Bad"]
_CONDITION_NORM = {c.lower(): c for c in _CONDITIONS}


def _normalize_condition(raw: str | None) -> str:
    """Blank reads as Good, so the 9.7k rows that predate this column need no backfill."""
    key = str(raw or "").strip().lower()
    if not key:
        return "Good"
    return _CONDITION_NORM.get(key, str(raw).strip())


def _normalize_category(raw: str | None) -> str:
    if not raw:
        return raw or ""
    key = raw.strip().lower().replace(" ", "").replace("(", "").replace(")", "")
    return _CAT_NORM.get(key, raw.strip())


# ── SQLite storage ─────────────────────────────────────────────────────────────

import sqlite3 as _sqlite3
import threading as _threading

# All item fields stored in SQLite, in order.
_ITEM_FIELDS = [
    "id", "vendor", "name", "part_number", "serial_number",
    "rank", "speed", "capacity", "density", "dimm_type", "rcd", "pmic", "category",
    # audit: where a CPU was last physically seen, written by the CPU decoder
    # when it reads a system. Distinct from location, which is where the item is
    # filed — the gap between the two is the point.
    "location", "audit", "tray", "team", "owner",
    "checkout_user", "checkout_email", "checkout_date", "loan_until",
    "condition", "condition_note",
    "notes", "modified_by", "createdAt", "updatedAt",
]

_DB_LOCK = _threading.Lock()   # serialises writes; reads are concurrent (WAL mode)


def _db_connect() -> _sqlite3.Connection:
    conn = _sqlite3.connect(str(DB_FILE), check_same_thread=False, timeout=10)
    conn.row_factory = _sqlite3.Row
    return conn


def _init_db() -> None:
    """Create the items table (and indexes) if they don't exist yet."""
    cols_ddl = ",\n    ".join(
        f"{f} TEXT NOT NULL DEFAULT ''" for f in _ITEM_FIELDS
    )
    with _db_connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")   # concurrent reads while writing
        conn.execute("PRAGMA synchronous=NORMAL")  # safe + faster than FULL
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS items (
                {cols_ddl},
                PRIMARY KEY (id)
            )
        """)
        # Index for common filter/sort queries
        conn.execute("CREATE INDEX IF NOT EXISTS idx_category  ON items(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_createdAt ON items(createdAt)")

        # One row per CPU a nightly scan looked at, matched or not. The `audit`
        # column on items only ever holds the latest sighting — this is the
        # trail: ordered by time, it is where a given chip has actually been
        # seen, not just where it is filed. item_id is NULL when the scan
        # decoded a serial that nothing in the inventory carries, so a CPU
        # that is physically in the lab but was never entered is still visible
        # here rather than silently dropped.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cpu_audit_log (
                id            TEXT NOT NULL PRIMARY KEY,
                item_id       TEXT,
                serial_number TEXT NOT NULL,
                host          TEXT NOT NULL,
                found         INTEGER NOT NULL,
                scanned_at    TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_item    ON cpu_audit_log(item_id, scanned_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_scanned ON cpu_audit_log(scanned_at)")

        # One row per completed scan (nightly or manual) — which hosts it
        # covered and which it could not, and why. Without this, "which
        # systems failed last night" only ever existed in the HTTP response of
        # that one request: answerable while the page was open, gone the
        # moment it was not, and never answerable at all for the unattended
        # 00:30 run.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_scan_runs (
                id                TEXT NOT NULL PRIMARY KEY,
                started_at        TEXT NOT NULL,
                elapsed_sec       REAL,
                hosts_total       INTEGER NOT NULL,
                hosts_ok          INTEGER NOT NULL,
                cpus_seen         INTEGER NOT NULL,
                cpus_matched      INTEGER NOT NULL,
                cpus_unmatched    INTEGER NOT NULL,
                hosts_failed_json TEXT NOT NULL,
                error             TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON audit_scan_runs(started_at)")

        # Added when the DIMM scan joined the CPU one in the same two tables,
        # rather than a parallel dimm_audit_log/dimm_scan_runs pair — existing
        # rows default to 'cpu' and are unaffected.
        for table in ("cpu_audit_log", "audit_scan_runs"):
            try:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN kind TEXT NOT NULL DEFAULT "cpu"')
            except _sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_kind ON cpu_audit_log(kind, scanned_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_kind ON audit_scan_runs(kind, started_at)")

        # Schema migrations — add new columns to existing databases (idempotent)
        for col, definition in [
            ("dimm_type", "TEXT NOT NULL DEFAULT ''"),
            ("rcd",       "TEXT NOT NULL DEFAULT ''"),
            ("pmic",      "TEXT NOT NULL DEFAULT ''"),
            # Physical condition, independent of check-out state: an item can be
            # both out and faulty. Existing rows get '', which reads as Good.
            ("condition",      "TEXT NOT NULL DEFAULT ''"),
            ("condition_note", "TEXT NOT NULL DEFAULT ''"),
            # Last seen, as recorded by a SUT scan: "seagull-0152 · 2026-11-01".
            ("audit",          "TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                conn.execute(f'ALTER TABLE items ADD COLUMN "{col}" {definition}')
            except _sqlite3.OperationalError as exc:
                # Only "already there" is an acceptable failure. The old blanket
                # except also swallowed "database is locked", silently skipping
                # the migration and leaving the app running against a schema it
                # believed it had.
                if "duplicate column" not in str(exc).lower():
                    raise
        conn.commit()

        # Verify every expected column exists. This matters more than it looks:
        # SQLite resolves a double-quoted identifier that matches no column to a
        # *string literal* rather than failing, so SELECT "condition" on a table
        # without that column quietly returns the text "condition" for every row.
        # A migration that silently did not run would therefore surface as bad
        # data, not as an error.
        present = {row[1] for row in conn.execute("PRAGMA table_info(items)")}
        missing = [f for f in _ITEM_FIELDS if f not in present]
        if missing:
            raise RuntimeError(
                f"items table is missing column(s): {', '.join(missing)}. "
                f"The schema migration did not complete; refusing to start "
                f"rather than read string literals as data."
            )


def _migrate_from_json() -> None:
    """One-time import of inventory.json into SQLite on first start.

    Guarded by a persistent marker file rather than the current row count:
    row count legitimately drops to 0 once an admin deletes everything, and
    re-running the import in that case would silently resurrect deleted data
    on the next server restart if inventory.json (or a failed rename of it)
    still happened to be sitting in the data directory.
    """
    marker = DATA_DIR / ".migrated"
    if marker.exists():
        return
    if not DATA_FILE.exists():
        marker.write_text(_now(), encoding="utf-8")
        return

    try:
        content = DATA_FILE.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, list) and data:
            _write(data)
            print(f"[DB] Migrated {len(data)} items from inventory.json → inventory.db")
        # Rename the old JSON as a backup so it isn't re-imported on next start
        bak = DATA_FILE.with_name("inventory.json.bak")
        DATA_FILE.rename(bak)
        print(f"[DB] Original JSON kept as: {bak}")
    except Exception as exc:
        print(f"[DB] WARNING: JSON→SQLite migration failed: {exc}")
        print("[DB] The app will start with an empty inventory. Restore inventory.json and restart to retry.")
    finally:
        marker.write_text(_now(), encoding="utf-8")


# SQLite caps host parameters per statement (999 on older builds), so large
# id lists are deleted in chunks inside one transaction.
_SQL_CHUNK = 500

_COLS_SQL         = ", ".join(f'"{f}"' for f in _ITEM_FIELDS)
_PLACEHOLDERS_SQL = ", ".join("?" * len(_ITEM_FIELDS))

# Everything a handler may change on an existing row; id and createdAt are fixed
# at creation time.
_UPDATABLE_FIELDS = [f for f in _ITEM_FIELDS if f not in ("id", "createdAt")]


def _row_values(item: dict) -> list[str]:
    """Flatten an item dict into column order, coercing every value to TEXT."""
    return [str(item.get(f) or "") for f in _ITEM_FIELDS]


# SQLite's compiled variable limit is 999 on builds older than 3.32, so an
# `id IN (...)` over a long list is fetched in chunks rather than one statement.
_SQL_PARAM_LIMIT = 500


def _chunks(seq: list, size: int):
    for start in range(0, len(seq), size):
        yield seq[start:start + size]


class _BatchRowsGone(Exception):
    """Rows vanished between validation and the UPDATE — a concurrent delete."""

    def __init__(self, ids: list[str]):
        super().__init__(f"{len(ids)} row(s) no longer exist")
        self.ids = ids


def _read() -> list[dict]:
    """Return all items ordered newest-first, with category normalised."""
    with _db_connect() as conn:
        rows = conn.execute(
            f"SELECT {_COLS_SQL} FROM items ORDER BY createdAt DESC"
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["category"]  = _normalize_category(item.get("category", ""))
        item["condition"] = _normalize_condition(item.get("condition", ""))
        result.append(item)
    return result


def _write(items: list[dict]) -> None:
    """Replace the whole table atomically inside a single transaction.

    Only for the one-time JSON migration, which legitimately owns every row.
    Request handlers must never use this: they would have to read the table,
    edit a Python copy and write it all back, and any other request that read
    the table before that write lands silently resurrects the rows it deleted.
    Handlers use the targeted helpers below, which touch only their own rows.
    """
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute("BEGIN EXCLUSIVE")
            conn.execute("DELETE FROM items")
            conn.executemany(
                f"INSERT INTO items ({_COLS_SQL}) VALUES ({_PLACEHOLDERS_SQL})",
                [_row_values(item) for item in items],
            )
            conn.commit()


def _insert_items(items: list[dict]) -> None:
    """Append rows. Existing rows are left untouched."""
    if not items:
        return
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.executemany(
                f"INSERT INTO items ({_COLS_SQL}) VALUES ({_PLACEHOLDERS_SQL})",
                [_row_values(item) for item in items],
            )
            conn.commit()


def _update_items_rows(changes_by_id: dict[str, dict]) -> list[dict]:
    """Apply many row updates in one transaction; return the merged rows.

    The whole batch succeeds or none of it does. One statement per row still,
    but one BEGIN/commit for the lot instead of per row: bulk check in/out used
    to pay two connections and a commit per item, which measured 271x the cost
    of this on 200 rows. Callers validate first — by the time this runs every id
    is known to exist and to be at the version the caller read.
    """
    if not changes_by_id:
        return []
    sets = ", ".join(f'"{f}" = ?' for f in _UPDATABLE_FIELDS)
    ids = list(changes_by_id)
    merged_rows: list[dict] = []
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = {}
                for chunk in _chunks(ids, _SQL_PARAM_LIMIT):
                    marks = ",".join("?" * len(chunk))
                    for row in conn.execute(
                        f"SELECT {_COLS_SQL} FROM items WHERE id IN ({marks})", chunk
                    ):
                        existing[row["id"]] = dict(row)

                missing = [i for i in ids if i not in existing]
                if missing:
                    # Validated moments ago, so this means a concurrent delete.
                    raise _BatchRowsGone(missing)

                params = []
                for item_id, changes in changes_by_id.items():
                    merged = {**existing[item_id], **changes}
                    params.append(
                        [str(merged.get(f) or "") for f in _UPDATABLE_FIELDS] + [item_id]
                    )
                    merged["category"]  = _normalize_category(merged.get("category", ""))
                    merged["condition"] = _normalize_condition(merged.get("condition", ""))
                    merged_rows.append(merged)

                conn.executemany(f"UPDATE items SET {sets} WHERE id = ?", params)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    return merged_rows


def _apply_import(new_items: list[dict], changes_by_id: dict[str, dict]) -> list[dict]:
    """Insert new rows and update existing ones in a single transaction.

    One spreadsheet routinely carries both jobs — parts arriving, parts coming
    back, loans changing hands. Applying them as two requests would land the
    creates and then discover a bad update row, leaving half the file in the
    table with nothing to say which half: exactly the partial-failure problem
    _update_items_rows was written to remove. Either the whole sheet applies or
    none of it does.

    Returns the merged updated rows, as _update_items_rows does; the inserted
    rows are already known to the caller.
    """
    if not new_items and not changes_by_id:
        return []
    sets = ", ".join(f'"{f}" = ?' for f in _UPDATABLE_FIELDS)
    ids = list(changes_by_id)
    merged_rows: list[dict] = []
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = {}
                for chunk in _chunks(ids, _SQL_PARAM_LIMIT):
                    marks = ",".join("?" * len(chunk))
                    for row in conn.execute(
                        f"SELECT {_COLS_SQL} FROM items WHERE id IN ({marks})", chunk
                    ):
                        existing[row["id"]] = dict(row)

                missing = [i for i in ids if i not in existing]
                if missing:
                    # Validated moments ago, so this means a concurrent delete.
                    raise _BatchRowsGone(missing)

                params = []
                for item_id, changes in changes_by_id.items():
                    merged = {**existing[item_id], **changes}
                    params.append(
                        [str(merged.get(f) or "") for f in _UPDATABLE_FIELDS] + [item_id]
                    )
                    merged["category"]  = _normalize_category(merged.get("category", ""))
                    merged["condition"] = _normalize_condition(merged.get("condition", ""))
                    merged_rows.append(merged)

                if params:
                    conn.executemany(f"UPDATE items SET {sets} WHERE id = ?", params)
                if new_items:
                    conn.executemany(
                        f"INSERT INTO items ({_COLS_SQL}) VALUES ({_PLACEHOLDERS_SQL})",
                        [_row_values(item) for item in new_items],
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    return merged_rows


def _update_item_row(item_id: str, changes: dict) -> dict | None:
    """Merge *changes* into one row; return the merged item, or None if it's gone.

    The SELECT and the UPDATE share one transaction, so no other writer can
    interleave between reading the old row and storing the merged one.
    """
    sets = ", ".join(f'"{f}" = ?' for f in _UPDATABLE_FIELDS)
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"SELECT {_COLS_SQL} FROM items WHERE id = ?", (item_id,)
            ).fetchone()
            if row is None:
                conn.rollback()
                return None
            merged = {**dict(row), **changes}
            conn.execute(
                f"UPDATE items SET {sets} WHERE id = ?",
                [str(merged.get(f) or "") for f in _UPDATABLE_FIELDS] + [item_id],
            )
            conn.commit()
    merged["category"]  = _normalize_category(merged.get("category", ""))
    merged["condition"] = _normalize_condition(merged.get("condition", ""))
    return merged


# Columns the decoder can answer for, in the order their parameters are bound.
# rcd and pmic came first; speed and dimm_type joined later, each because the
# decoder knows the part number better than the import did — speed disagreed
# with the decoder on every DIMM in the table, and dimm_type was blank on all
# 9,737 rows of the inventory.
_DECODER_COLUMNS = ("rcd", "pmic", "speed", "dimm_type")


def _decoder_update_sql(overwrite: bool) -> str:
    """One UPDATE per part number, covering every row that shares it.

    Built rather than written out: at four columns the hand-maintained version
    needed sixteen positional parameters in two orders, and a miscount there
    writes the right value into the wrong column.

    Both variants skip rows that would not change, so updatedAt never churns and
    a repeat run is a no-op. Fill mode only touches blanks — a vendor an admin
    corrected by hand survives the background pass. Overwrite mode replaces what
    is stored, which is what the manual button is for.
    """
    if overwrite:
        sets  = ", ".join(f"{c} = CASE WHEN ? != '' THEN ? ELSE {c} END" for c in _DECODER_COLUMNS)
        where = " OR ".join(f"(? != '' AND {c} != ?)" for c in _DECODER_COLUMNS)
    else:
        sets  = ", ".join(f"{c} = CASE WHEN {c} = '' THEN ? ELSE {c} END" for c in _DECODER_COLUMNS)
        where = " OR ".join(f"({c} = '' AND ? != '')" for c in _DECODER_COLUMNS)
    return f"""
        UPDATE items
           SET {sets},
               updatedAt   = ?,
               modified_by = CASE WHEN ? != '' THEN ? ELSE modified_by END
         WHERE trim(part_number) = ?
           AND lower(category) LIKE '%dimm%'
           AND ({where})
    """


def _decoder_update_params(values: list[str], now: str, actor: str, pn: str,
                           overwrite: bool) -> list:
    """Parameters in the order _decoder_update_sql binds them.

    Overwrite names each value twice per clause ("WHEN ? != '' THEN ?"), fill
    once; the SET and WHERE clauses bind the same values in the same order.
    """
    per_clause = 2 if overwrite else 1
    repeated = [v for value in values for v in [value] * per_clause]
    return repeated + [now, actor, actor, pn] + repeated


def _speed_with_units(value) -> str:
    """The decoder answers "12800"; the column reads "12800 MT/s" everywhere else.

    Storing the bare number would leave the table showing two spellings of the
    same thing, so a plain number gains the unit and anything already carrying
    one is left exactly as it came.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    return f"{text} MT/s" if text.isdigit() else text


def _fill_rcd_pmic(updates: dict[str, dict], actor: str = "", overwrite: bool = False) -> dict:
    """Apply decoder results to every DIMM row matching each part number, in one
    transaction.

    *updates* maps a part number to {"rcd": ..., "pmic": ..., "speed": ...}. The
    decoder answers per part number, not per unit, so one statement per part
    number covers every row that shares it — a few dozen statements instead of
    one request per row.

    Default is fill-only: a column that already holds a value is left alone, so a
    vendor an admin corrected by hand survives the background auto-fill. The manual
    "Lookup RCD/PMIC" button passes overwrite=True, which is the refresh it has
    always been — decoder values replace whatever is stored.
    """
    if not updates:
        return {"updated": 0, "per_part_number": {}}

    sql = _decoder_update_sql(overwrite)
    now = _now()
    per_pn: dict[str, int] = {}
    total = 0
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for pn, vals in updates.items():
                values = [
                    _speed_with_units(vals.get(col)) if col == "speed"
                    else str(vals.get(col) or "").strip()
                    for col in _DECODER_COLUMNS
                ]
                if not any(values):
                    continue
                params = _decoder_update_params(values, now, actor, pn, overwrite)
                cur = conn.execute(sql, params)
                if cur.rowcount > 0:
                    per_pn[pn] = cur.rowcount
                    total += cur.rowcount
            conn.commit()
    return {"updated": total, "per_part_number": per_pn}


def _delete_ids(ids: list[str]) -> int:
    """Delete exactly these ids; return how many rows actually went away."""
    if not ids:
        return 0
    deleted = 0
    with _DB_LOCK:
        with _db_connect() as conn:
            for start in range(0, len(ids), _SQL_CHUNK):
                chunk = ids[start:start + _SQL_CHUNK]
                marks = ", ".join("?" * len(chunk))
                deleted += conn.execute(
                    f"DELETE FROM items WHERE id IN ({marks})", chunk
                ).rowcount
            conn.commit()
    return deleted


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Prepare the database at import, not only under __main__. Both calls are
# idempotent, and doing it here means any entry point that loads this module —
# `uvicorn server:app`, a test client, a maintenance script — gets a migrated
# schema instead of querying columns that were never added.
_init_db()
_migrate_from_json()


# ── schemas ───────────────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    username: str
    password: str


# ── field validation ──────────────────────────────────────────────────────────
#
# Every write path — the add/edit form, the check-out modal, bulk check-out and
# spreadsheet import — funnels through ItemIn, so this is the one place that can
# hold the line for all of them. Validation used to live in the UI, and only in
# the check-out modal: the import path enforced nothing, which is how 192 of 193
# check-outs ended up with no email and no date, leaving the reminder system
# with nothing to work from.

# Caps are generous — they exist to stop absurd input, not to police content.
_FIELD_MAX_CHARS: dict[str, int] = {
    "name": 300, "notes": 4000, "serial_number": 300, "part_number": 200,
    "condition_note": 1000,
}
_DEFAULT_FIELD_MAX = 200

# Excel dates arrive from pandas as "2026-01-05 00:00:00", or occasionally as a
# raw serial number. Anything genuinely ambiguous (05/01/2026 — which month?) is
# rejected rather than guessed at.
_EXCEL_EPOCH = _date(1899, 12, 30)

# A trailing clock time, as pandas appends to every Excel date cell.
_TIME_SUFFIX_RE = re.compile(r"[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?\s*(?:[AP]M)?$", re.I)


def _coerce_date(value: str, field: str) -> str:
    """Return an ISO YYYY-MM-DD date, or "" — raising ValueError if unreadable."""
    raw = str(value or "").strip()
    if not raw:
        return ""

    # Strip the time, and only the time. Splitting on the first space instead
    # ate the day out of "20 Sep 2026" and left "20", which made the two
    # space-separated formats below unreachable: both were rejected with a
    # message telling the author to use a format they had every reason to
    # believe was already accepted.
    head = _TIME_SUFFIX_RE.sub("", raw).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%b-%Y", "%d %b %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(head, fmt).date().isoformat()
        except ValueError:
            pass

    # Excel serial day number; bounded to a sane window (roughly 1954-2064)
    if head.isdigit() and 20000 <= int(head) <= 60000:
        return (_EXCEL_EPOCH + timedelta(days=int(head))).isoformat()

    raise ValueError(
        f"{field} must be a date in YYYY-MM-DD form (got {raw!r}). "
        f"Formats like 05/01/2026 are ambiguous and are not accepted."
    )


class ItemIn(BaseModel):
    vendor: str | None = ""
    name: str
    part_number: str | None = ""
    serial_number: str | None = ""
    rank: str | None = ""
    speed: str | None = ""
    capacity: str | None = ""
    density: str | None = ""
    dimm_type: str | None = ""   # ES or CS (Engineering / Commercial Sample)
    rcd: str | None = ""
    pmic: str | None = ""
    category: str | None = ""
    location: str | None = ""
    tray: str | None = ""
    team: str | None = ""
    owner: str | None = ""
    checkout_user: str | None = ""
    checkout_email: str | None = ""
    checkout_date: str | None = ""
    loan_until: str | None = ""   # ISO date YYYY-MM-DD
    condition: str | None = ""        # Good | Suspect | Bad; blank reads as Good
    condition_note: str | None = ""   # why — "failed MemTest at 4800, bank 3"
    notes: str | None = ""

    @model_validator(mode="before")
    @classmethod
    def _tidy_strings(cls, data):
        """Trim whitespace and turn None into "" before any field validator runs."""
        if not isinstance(data, dict):
            return data
        return {
            k: ("" if v is None else v.strip() if isinstance(v, str) else v)
            for k, v in data.items()
        }

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Item Description is required.")
        return v

    @field_validator("category")
    @classmethod
    def _known_category(cls, v: str | None) -> str:
        raw = str(v or "").strip()
        if not raw:
            return ""
        normalized = _normalize_category(raw)
        if normalized not in _CANONICAL_CATEGORIES:
            raise ValueError(
                f"Unknown category {raw!r}. Expected one of: "
                + ", ".join(_CANONICAL_CATEGORIES)
            )
        return normalized

    @field_validator("condition")
    @classmethod
    def _known_condition(cls, v: str | None) -> str:
        normalized = _normalize_condition(v)
        if normalized not in _CONDITIONS:
            raise ValueError(
                f"Unknown condition {str(v).strip()!r}. Expected one of: "
                + ", ".join(_CONDITIONS)
            )
        return normalized

    @field_validator("checkout_email")
    @classmethod
    def _valid_email(cls, v: str | None) -> str:
        raw = str(v or "").strip()
        if raw and not _EMAIL_RE.fullmatch(raw):
            raise ValueError(f"{raw!r} is not a valid email address.")
        return raw

    @field_validator("checkout_date")
    @classmethod
    def _valid_checkout_date(cls, v: str | None) -> str:
        return _coerce_date(v, "Check Out Date")

    @field_validator("loan_until")
    @classmethod
    def _valid_loan_until(cls, v: str | None) -> str:
        return _coerce_date(v, "Loan Until")

    @model_validator(mode="after")
    def _check_lengths_and_dates(self):
        for field, value in self.__dict__.items():
            if isinstance(value, str):
                cap = _FIELD_MAX_CHARS.get(field, _DEFAULT_FIELD_MAX)
                if len(value) > cap:
                    raise ValueError(f"{field} is longer than {cap} characters.")
        # A loan that ends before it starts is a typo, not a valid record.
        if self.checkout_date and self.loan_until and self.loan_until < self.checkout_date:
            raise ValueError(
                f"Loan Until ({self.loan_until}) is before Check Out Date ({self.checkout_date})."
            )
        # A bare "Bad" ages into a mystery: nobody later knows what failed or how.
        # The reason is the entire value of the flag, so it is required with it.
        if self.condition in ("Bad", "Suspect") and not (self.condition_note or "").strip():
            raise ValueError(
                f"Say what is wrong with it: a reason is required when condition is "
                f"{self.condition} (for example 'failed MemTest at 4800, bank 3')."
            )
        return self


class BatchUpdateRow(BaseModel):
    """One row of a bulk edit: which item, the new body, and the version read."""
    id: str
    item: ItemIn
    expected_updated_at: str | None = None


class BatchIn(BaseModel):
    """One uploaded sheet: rows to add, and rows that act on items already here.

    Both halves travel together because they come from one file. A row with a
    blank Action is a new item (`items`); a row naming check_out / check_in /
    change_user is matched against the inventory by the client and arrives here
    as an update. `updates` defaults to empty, so a caller that only adds items
    sends exactly what it always did.
    """
    items: list[ItemIn]
    updates: list[BatchUpdateRow] = []


class BatchUpdateIn(BaseModel):
    updates: list[BatchUpdateRow]


def _borrower_is_contactable(body: ItemIn, existing: dict | None = None) -> bool:
    """True unless this write would create or change an unreachable check-out.

    A named borrower needs an email or no reminder can ever reach them — that is
    exactly how 192 check-outs became untrackable. But rows written before this
    rule must stay editable: if the borrower is unchanged and was already stored
    without an address, the write is left alone. Clearing the check-out, or
    correcting any other field on such a row, therefore still works; only naming
    a *new* borrower without an address is refused.

    Spreadsheet import (/api/items/batch) does not call this at all — see the
    note there. Every other write path does.
    """
    user = (body.checkout_user or "").strip()
    if not user or (body.checkout_email or "").strip():
        return True
    if existing is not None:
        prev_user = str(existing.get("checkout_user") or "").strip()
        prev_mail = str(existing.get("checkout_email") or "").strip()
        if prev_user == user and not prev_mail:
            return True   # pre-existing legacy state, unchanged by this write
    return False


def _uncontactable_detail(user: str) -> str:
    return (
        f"Check Out Email is required when an item is checked out to '{user}'. "
        "Without an address, loan reminders and return requests cannot reach them."
    )


def _get_item(item_id: str) -> dict | None:
    with _db_connect() as conn:
        row = conn.execute(
            f"SELECT {_COLS_SQL} FROM items WHERE id = ?", (item_id,)
        ).fetchone()
    return dict(row) if row else None


def _get_items(item_ids) -> dict[str, dict]:
    """Fetch many rows by id, keyed by id. Ids that do not exist are absent."""
    ids = list(dict.fromkeys(item_ids))   # de-duplicate, keep order
    if not ids:
        return {}
    found: dict[str, dict] = {}
    with _db_connect() as conn:
        for chunk in _chunks(ids, _SQL_PARAM_LIMIT):
            marks = ",".join("?" * len(chunk))
            for row in conn.execute(
                f"SELECT {_COLS_SQL} FROM items WHERE id IN ({marks})", chunk
            ):
                found[row["id"]] = dict(row)
    return found


class RcdPmicIn(BaseModel):
    rcd:   str | None = ""
    pmic:  str | None = ""
    # Joined later than the other two; the endpoint keeps its old name.
    speed:     str | None = ""
    dimm_type: str | None = ""


class BulkRcdPmicIn(BaseModel):
    """Decoder results keyed by part number, as returned by /api/lookup-pn."""
    updates: dict[str, RcdPmicIn]
    # False (background auto-fill): only empty columns are filled.
    # True  (manual Lookup button): decoder values replace what is stored.
    overwrite: bool = False


# The decoder answers per part number, and the whole inventory has well under a
# hundred distinct ones; anything far beyond that is a malformed payload.
_MAX_BULK_PNS = 1000

# A bulk check in/out sheet covers a lab's worth of parts, not the whole
# inventory. The cap keeps one request from holding the write lock indefinitely:
# each row is validated against its stored copy, re-read inside the transaction,
# and merged, so the cost is real.
_MAX_BATCH_UPDATE = 5000

# New rows are a different matter and get their own, far larger ceiling.
# Inserting is one executemany with nothing to validate against: 9,006 rows land
# in 134ms and 50,000 in under a second, measured. Importing a whole inventory
# is an ordinary thing to want — it is how this system gets populated — and
# capping it at the bulk-edit limit refused a 9,006-row file that had nothing
# wrong with it. This ceiling is here to bound the request body, not the lock.
_MAX_IMPORT_ROWS = 50_000


# ── auth routes ───────────────────────────────────────────────────────────────

@app.post("/api/login")
def login(body: LoginIn):
    if not _check_credentials(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = secrets.token_hex(32)
    _sessions[token] = body.username
    return {"token": token, "username": body.username, "is_superadmin": _is_superadmin(body.username), "role": _get_role(body.username)}


@app.post("/api/logout", status_code=204)
def logout(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if creds and creds.credentials in _sessions:
        del _sessions[creds.credentials]


@app.get("/api/me")
def me(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if creds and creds.credentials in _sessions:
        uname = _sessions[creds.credentials]
        return {"authenticated": True, "username": uname, "is_superadmin": _is_superadmin(uname), "role": _get_role(uname)}
    return {"authenticated": False, "is_superadmin": False, "role": "guest"}


# ── credential management routes ─────────────────────────────────────────────

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

class ChangeUsernameIn(BaseModel):
    current_password: str
    new_username: str

class AddAdminIn(BaseModel):
    username: str
    password: str


@app.get("/api/admin/users", dependencies=[Depends(_require_superadmin)])
def list_admin_users():
    return [{"username": a["username"]} for a in _read_admins()]


@app.post("/api/admin/change-password", dependencies=[Depends(_require_admin)])
def change_password(body: ChangePasswordIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if len(body.new_password) < 6:
        raise HTTPException(status_code=422, detail="New password must be at least 6 characters.")
    username = _sessions.get(creds.credentials, "")
    admins   = _read_admins()
    for admin in admins:
        if admin["username"] == username:
            if not _verify_password(body.current_password, admin["hash"]):
                raise HTTPException(status_code=401, detail="Current password is incorrect.")
            admin["hash"] = _hash_password(body.new_password)
            _write_admins(admins)
            return {"changed": True}
    raise HTTPException(status_code=404, detail="Admin account not found.")


@app.post("/api/admin/change-username", dependencies=[Depends(_require_admin)])
def change_username(body: ChangeUsernameIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    new_username = body.new_username.strip()
    if not new_username:
        raise HTTPException(status_code=422, detail="New username cannot be empty.")
    current_username = _sessions.get(creds.credentials, "")
    if current_username == SUPER_ADMIN_USERNAME:
        raise HTTPException(status_code=400, detail="The superadmin username cannot be changed.")
    admins = _read_admins()
    for admin in admins:
        if admin["username"] == current_username:
            if not _verify_password(body.current_password, admin["hash"]):
                raise HTTPException(status_code=401, detail="Current password is incorrect.")
            if any(a["username"] == new_username for a in admins if a["username"] != current_username):
                raise HTTPException(status_code=409, detail=f"Username '{new_username}' already exists.")
            admin["username"] = new_username
            _write_admins(admins)
            _sessions[creds.credentials] = new_username
            return {"changed": True, "username": new_username}
    raise HTTPException(status_code=404, detail="Admin account not found.")


@app.post("/api/admin/users", dependencies=[Depends(_require_superadmin)])
def add_admin_user(body: AddAdminIn):
    if not body.username.strip():
        raise HTTPException(status_code=422, detail="Username cannot be empty.")
    if len(body.password) < 6:
        raise HTTPException(status_code=422, detail="Password must be at least 6 characters.")
    admins = _read_admins()
    if any(a["username"] == body.username for a in admins):
        raise HTTPException(status_code=409, detail=f"Username '{body.username}' already exists.")
    admins.append({"username": body.username, "hash": _hash_password(body.password)})
    _write_admins(admins)
    return {"added": True, "username": body.username}


@app.delete("/api/admin/users/{username}", status_code=204, dependencies=[Depends(_require_superadmin)])
def remove_admin_user(username: str, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    current = _sessions.get(creds.credentials, "")
    if username == current:
        raise HTTPException(status_code=400, detail="You cannot remove your own account.")
    admins = _read_admins()
    if len(admins) <= 1:
        raise HTTPException(status_code=400, detail="Cannot remove the last admin account.")
    new_admins = [a for a in admins if a["username"] != username]
    if len(new_admins) == len(admins):
        raise HTTPException(status_code=404, detail="Admin user not found.")
    _write_admins(new_admins)


# ── item routes ───────────────────────────────────────────────────────────────

def _items_version() -> str:
    """A token that changes whenever the items table does, without reading it.

    COUNT(*) catches deletes; MAX(updatedAt) catches inserts and edits, since
    every write path stamps _now() — microsecond ISO, so two writes cannot share
    a timestamp. One indexed-ish aggregate instead of the full scan, normalise
    and serialise that answering the request properly costs.
    """
    with _db_connect() as conn:
        count, newest = conn.execute(
            "SELECT COUNT(*), COALESCE(MAX(updatedAt), '') FROM items"
        ).fetchone()
    digest = hashlib.sha256(f"{count}:{newest}".encode()).hexdigest()[:32]
    return f'"{digest}"'


@app.get("/api/items")
def list_items(
    response: Response,
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
):
    """The whole inventory, or 304 when the caller's copy is still current.

    Every open tab re-asks for this every 30 seconds. Unconditionally, that is a
    full table scan, a per-row normalise, a JSON serialise and a gzip of roughly
    5 MB on a 9,000-item inventory — overwhelmingly to produce a byte-identical
    answer to the one the browser already has. The conditional path does one
    aggregate and returns an empty body instead.
    """
    tag = _items_version()
    # A middleware or proxy may weaken the tag it passes through; compare on the
    # strong form so W/"x" and "x" are still recognised as the same version.
    headers = {"ETag": tag, "Cache-Control": "no-cache"}
    if if_none_match and if_none_match.removeprefix("W/") == tag:
        return Response(status_code=304, headers=headers)

    # Serialised here rather than returned as a list, to skip FastAPI's
    # jsonable_encoder. That pass exists to coerce types json cannot handle, and
    # every column in this table is TEXT — so on 8,665 rows it walked every dict
    # and every value to produce what json.dumps produces anyway, at 283ms
    # against 32ms. It was the single largest cost in the response, larger than
    # the query, the normalise and the gzip put together.
    #
    # no-cache on the header means "revalidate before reusing", not "do not
    # store": it is what keeps the browser asking conditionally.
    return Response(
        content=json.dumps(_read()),
        media_type="application/json",
        headers=headers,
    )


@app.post("/api/items", status_code=201)
def create_item(body: ItemIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    if not _borrower_is_contactable(body):
        raise HTTPException(status_code=422, detail=_uncontactable_detail(body.checkout_user))
    item = {
        "id": uuid.uuid4().hex,
        "createdAt": _now(),
        "updatedAt": _now(),
        **body.model_dump(),
    }
    if actor:
        item["modified_by"] = actor
    _insert_items([item])
    item["category"]  = _normalize_category(item.get("category", ""))
    item["condition"] = _normalize_condition(item.get("condition", ""))
    return item


def _validate_update_rows(updates: list[BatchUpdateRow]) -> tuple[list[dict], bool]:
    """Check every row of a bulk edit; return (problems, any_row_was_stale).

    Shared by /api/items/batch and /api/items/batch-update so the two cannot
    drift: an import carrying Action rows has to refuse exactly what the bulk
    edit refuses, or the same sheet would be accepted by one route and rejected
    by the other. Collects every bad row rather than stopping at the first, so
    one retry can fix the lot.
    """
    existing_by_id = _get_items(u.id for u in updates)
    problems: list[dict] = []
    stale = False
    seen: set[str] = set()
    for n, upd in enumerate(updates, start=1):
        existing = existing_by_id.get(upd.id)
        if upd.id in seen:
            problems.append({"row": n, "id": upd.id, "name": upd.item.name,
                             "error": "This item appears twice in the same batch."})
            continue
        seen.add(upd.id)
        if existing is None:
            problems.append({"row": n, "id": upd.id, "name": upd.item.name,
                             "error": "Item not found — it may have been deleted."})
        elif upd.expected_updated_at and upd.expected_updated_at != existing.get("updatedAt", ""):
            stale = True
            problems.append({
                "row": n, "id": upd.id, "name": upd.item.name,
                "error": (f"Changed by {existing.get('modified_by') or 'someone else'} "
                          "since this file was matched. Reload and try again."),
            })
        elif not _borrower_is_contactable(upd.item, existing):
            problems.append({"row": n, "id": upd.id, "name": upd.item.name,
                             "error": _uncontactable_detail(upd.item.checkout_user)})
    return problems, stale


def _row_problems_error(problems: list[dict], stale: bool, verb: str) -> HTTPException:
    return HTTPException(
        status_code=409 if stale else 422,
        detail={
            "message": f"{len(problems)} row(s) could not be {verb} — nothing was changed.",
            "rows": problems[:50],
            "truncated": len(problems) > 50,
        },
    )


@app.post("/api/items/batch", status_code=201)
def create_items_batch(body: BatchIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    """Apply one uploaded sheet: new items and check in/out rows, in one go.

    An admin's spreadsheet is rarely all one thing — parts arriving, parts
    coming back, a loan changing hands. Splitting that across two uploads meant
    sending the same file twice and remembering which half each pass ignored, so
    both halves land here, in a single transaction: either the whole sheet
    applies or none of it does.
    """
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""

    # Two ceilings, because the two halves cost very different amounts. The
    # Action rows are validated and merged row by row with the write lock held;
    # the new rows are one executemany.
    if len(body.updates) > _MAX_BATCH_UPDATE:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Too many check in/out rows in one file ({len(body.updates)}); "
                f"the limit is {_MAX_BATCH_UPDATE}. Split the Action rows across "
                "two uploads — the new items can all go in one."
            ),
        )
    total = len(body.items) + len(body.updates)
    if total > _MAX_IMPORT_ROWS:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Too many rows in one file ({total}); the limit is {_MAX_IMPORT_ROWS}. "
                "Split the spreadsheet and upload it in parts."
            ),
        )

    # New rows deliberately do NOT require a borrower to be contactable, unlike
    # every other write path (_borrower_is_contactable). A spreadsheet is usually
    # a record of check-outs that already happened, often off a whiteboard or a
    # previous system that never captured addresses. Refusing the whole file
    # meant the choice was to invent addresses or not record the loans at all,
    # and the second is what actually happened. Loading them uncontactable at
    # least makes them visible: the Reports view counts them per borrower
    # (checkout_without_email) and the Loans view greys out Send Reminder.
    # Naming a borrower by hand still requires an address — there the cost is
    # one field, not a re-keyed spreadsheet.
    #
    # The exemption covers *new* rows only. An Action row below names a borrower
    # for an item already on the shelf, which is the same act as the check-out
    # modal and is held to the same rule.
    created = []
    for item_in in body.items:
        item = {
            "id": uuid.uuid4().hex,
            "createdAt": _now(),
            "updatedAt": _now(),
            **item_in.model_dump(),
        }
        if actor:
            item["modified_by"] = actor
        created.append(item)

    changes_by_id: dict[str, dict] = {}
    if body.updates:
        problems, stale = _validate_update_rows(body.updates)
        if problems:
            raise _row_problems_error(problems, stale, "applied")
        now = _now()
        for upd in body.updates:
            changes = {**upd.item.model_dump(), "updatedAt": now}
            if actor:
                changes["modified_by"] = actor
            changes_by_id[upd.id] = changes

    try:
        updated = _apply_import(created, changes_by_id)
    except _BatchRowsGone as gone:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"{len(gone.ids)} row(s) were deleted while applying — nothing was changed.",
                "rows": [{"id": i, "error": "Item not found — it may have been deleted."} for i in gone.ids[:50]],
                "truncated": len(gone.ids) > 50,
            },
        )
    return {"imported": len(created), "updated": len(updated), "items": updated}


@app.post("/api/items/batch-update")
def update_items_batch(body: BatchUpdateIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    """Apply many item edits as one all-or-nothing change.

    Bulk check in/out used to issue one PUT per row. That is slow (271x the cost
    of a single batched transaction on 200 rows, before network latency), but
    the real problem was partial failure: a row that failed halfway left every
    earlier row applied, with no way to tell which ones. So this validates the
    whole payload first and refuses it entirely if any row is bad — the caller
    fixes the sheet and retries, rather than reconciling a half-applied edit.

    Returns the updated rows so the caller can patch its copy instead of
    re-downloading the inventory.
    """
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""

    if not body.updates:
        return {"updated": 0, "items": []}
    if len(body.updates) > _MAX_BATCH_UPDATE:
        raise HTTPException(
            status_code=413,
            detail=f"Too many rows in one batch ({len(body.updates)}); limit is {_MAX_BATCH_UPDATE}.",
        )

    problems, stale = _validate_update_rows(body.updates)
    if problems:
        raise _row_problems_error(problems, stale, "applied")

    now = _now()
    changes_by_id = {}
    for upd in body.updates:
        changes = {**upd.item.model_dump(), "updatedAt": now}
        if actor:
            changes["modified_by"] = actor
        changes_by_id[upd.id] = changes

    try:
        updated = _update_items_rows(changes_by_id)
    except _BatchRowsGone as gone:
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"{len(gone.ids)} row(s) were deleted while applying — nothing was changed.",
                "rows": [{"id": i, "error": "Item not found — it may have been deleted."} for i in gone.ids[:50]],
                "truncated": len(gone.ids) > 50,
            },
        )
    return {"updated": len(updated), "items": updated}


@app.put("/api/items/{item_id}")
def update_item(
    item_id: str,
    body: ItemIn,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    expected_updated_at: str | None = Header(default=None, alias="X-Expected-Updated-At"),
):
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    existing = _get_item(item_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Item not found")

    # Optimistic concurrency. Every PUT carries the client's whole copy of the
    # row, so two admins editing different fields of the same item used to end
    # with the second save silently discarding the first. When the caller tells
    # us which version it read, a mismatch is refused instead.
    if expected_updated_at and expected_updated_at != existing.get("updatedAt", ""):
        raise HTTPException(
            status_code=409,
            detail=(
                f"This item was changed by {existing.get('modified_by') or 'someone else'} "
                "while you were editing it. Reload and reapply your change so theirs "
                "is not overwritten."
            ),
        )

    if not _borrower_is_contactable(body, existing):
        raise HTTPException(status_code=422, detail=_uncontactable_detail(body.checkout_user))
    changes = {**body.model_dump(), "updatedAt": _now()}
    if actor:
        changes["modified_by"] = actor
    updated = _update_item_row(item_id, changes)
    if updated is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated


@app.delete("/api/items/{item_id}", status_code=204, dependencies=[Depends(_require_admin)])
def delete_item(item_id: str):
    if _delete_ids([item_id]) == 0:
        raise HTTPException(status_code=404, detail="Item not found")


@app.post("/api/items/bulk-rcd-pmic")
def bulk_rcd_pmic(body: BulkRcdPmicIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    """Fill RCD/PMIC across every DIMM sharing each part number, in one transaction.

    Replaces the client-side loop that issued one PUT per row: that took minutes
    over thousands of items and left the table half-filled whenever the tab was
    closed before it finished.
    """
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    if len(body.updates) > _MAX_BULK_PNS:
        raise HTTPException(
            status_code=422,
            detail=f"Too many part numbers in one request (max {_MAX_BULK_PNS}).",
        )
    updates = {
        pn.strip(): vals.model_dump()
        for pn, vals in body.updates.items()
        if pn.strip()
    }
    return _fill_rcd_pmic(updates, actor, body.overwrite)


class BatchDeleteIn(BaseModel):
    ids: list[str]

@app.post("/api/items/batch-delete", status_code=200, dependencies=[Depends(_require_admin)])
def batch_delete_items(body: BatchDeleteIn):
    # dict.fromkeys de-duplicates while keeping the caller's order
    return {"deleted": _delete_ids(list(dict.fromkeys(body.ids)))}


class AuditIn(BaseModel):
    ids: list[str]
    audit: str
    # Optional, and only to feed cpu_audit_log (see record_audit): the browser
    # already knows which system it just read, and sending it here is what
    # lets a one-off "Get CPU Serial Number" read join the same trail the
    # nightly scan writes to, instead of only ever updating the single
    # `audit` field and leaving no history behind it.
    host: str = ""
    # This endpoint is shared by the CPU and DIMM single-host lookups; without
    # this, every manual DIMM read logged into cpu_audit_log as kind="cpu" —
    # the sighting was real, only its label was wrong. Defaults to "cpu" so
    # old callers (and the CPU lookup, which never sends this) keep working.
    kind: str = "cpu"

    @field_validator("kind")
    @classmethod
    def _kind_known(cls, v: str) -> str:
        if v not in ("cpu", "dimm"):
            raise ValueError('kind must be "cpu" or "dimm"')
        return v


# Scanning a system is how a CPU's whereabouts get confirmed, so the decoder
# records what it found. Admin-only, deliberately: /api/cpu/read-sut itself is
# open to the lab, and a view-only user triggering a read must not end up
# writing to the inventory as a side effect.
_MAX_AUDIT_LEN = 120


def _apply_audit_fields(ids: list[str], note: str) -> list[dict]:
    """Stamp `audit` + updatedAt on these items, in one transaction.

    Shared by POST /api/items/audit (a scan triggered from the browser, which
    pre-checks existence itself for a clean 404) and the nightly
    run_audit_scan (which calls this directly and treats a row vanishing
    mid-scan as that one host's problem, not a reason to stop the run).
    """
    ids = list(dict.fromkeys(ids))
    if not ids:
        return []
    now = _now()
    return _update_items_rows({i: {"audit": note, "updatedAt": now} for i in ids})


@app.post("/api/items/audit", dependencies=[Depends(_require_admin)])
def record_audit(body: AuditIn):
    """Stamp the audit field on the items a SUT scan just identified.

    Also logs to cpu_audit_log when the caller names the host — which the
    browser now does on every "Get CPU Serial Number" read, not only the
    nightly batch scan. Without that, a CPU looked at one system at a time all
    day could show 49 items with a current `audit` value and still have zero
    rows of actual history behind any of them, which is exactly backwards for
    a feature whose whole point is the trail.
    """
    note = body.audit.strip()[:_MAX_AUDIT_LEN]
    ids = list(dict.fromkeys(body.ids))
    if not ids:
        return {"updated": 0}
    existing = _get_items(ids)
    missing = [i for i in ids if i not in existing]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"{len(missing)} item(s) no longer exist.",
        )
    try:
        updated = _apply_audit_fields(ids, note)
    except _BatchRowsGone as gone:
        raise HTTPException(status_code=409,
                            detail=f"{len(gone.ids)} item(s) were deleted while recording.")
    host = body.host.strip()
    if host:
        _record_audit_log([
            {"item_id": i["id"], "serial": i.get("serial_number") or i["id"],
             "host": host, "found": True}
            for i in updated
        ], kind=body.kind)
    return {"updated": len(updated), "audit": note}


@app.get("/api/items/{item_id}/audit-history", dependencies=[Depends(_require_admin)])
def item_audit_history(item_id: str, limit: int = Query(default=90, ge=1, le=500)):
    """Every scan that has looked at this item, newest first.

    The `audit` field only ever holds the latest sighting; this is the trail
    that field cannot keep — where a CPU has actually been seen, across every
    night a scan ran, not just the most recent one.
    """
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT host, found, scanned_at FROM cpu_audit_log "
            "WHERE item_id = ? ORDER BY scanned_at DESC LIMIT ?",
            (item_id, limit),
        ).fetchall()
    return {"history": [dict(r) for r in rows]}


@app.get("/api/admin/audit-scan/runs", dependencies=[Depends(_require_admin)])
def audit_scan_runs(limit: int = Query(default=10, ge=1, le=100)):
    """Recent scans, newest first — which systems each one could not reach.

    The live response from POST /api/admin/audit-scan/run only ever existed
    for the one request that triggered it: open to a page that was not
    watching, or to the unattended 00:30 run, "which systems failed" had
    nothing to answer from. This is that answer, kept.
    """
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_scan_runs WHERE kind = 'cpu' ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    runs = []
    for r in rows:
        run = dict(r)
        run["hosts_failed"] = json.loads(run.pop("hosts_failed_json"))
        runs.append(run)
    return {"runs": runs}


@app.get("/api/admin/dimm-scan/runs", dependencies=[Depends(_require_admin)])
def dimm_scan_runs(limit: int = Query(default=10, ge=1, le=100)):
    """The DIMM scan's own twin of GET /api/admin/audit-scan/runs."""
    with _db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_scan_runs WHERE kind = 'dimm' ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    runs = []
    for r in rows:
        run = dict(r)
        run["hosts_failed"] = json.loads(run.pop("hosts_failed_json"))
        runs.append(run)
    return {"runs": runs}


@app.get("/api/admin/audit-log/export", dependencies=[Depends(_require_admin)])
def export_audit_log(
    kind: str = Query(default="all", pattern="^(all|cpu|dimm)$"),
    latest_only: bool = Query(default=False),
    limit: int = Query(default=20000, ge=1, le=200000),
):
    """Every sighting from both the CPU and DIMM scans, as a CSV download.

    cpu_audit_log only ever answers "what has this scan seen" one row at a
    time through the API; this is that trail made into a single file someone
    can open in Excel, archive, or hand to someone who does not have access
    to this app at all. item_id is left-joined against the current inventory
    rather than denormalized at scan time, so a renamed or relocated item
    shows its current name/location here — a deleted item's rows still
    export, just with those columns blank, the same way item_audit_history
    already tolerates a vanished item_id. `item_serial_number` is the item's
    own full stored serial (e.g. a CPU's <serial>_<part number>-<rev>), kept
    separate from `serial_number` (what the scan itself decoded/read), so a
    reviewer can see both without cross-referencing the inventory by hand.

    latest_only narrows each *system* to its own most recently scanned date,
    rather than one date shared across the whole fleet — a system read by
    hand this afternoon and one last scanned three nights ago both show their
    own latest entry, instead of a single global cutoff silently dropping
    whichever systems were not touched on the single most recent date overall.
    Hostnames are compared case-insensitively for this grouping, since the
    same system can be logged with different casing depending on whether a
    scan or a manual lookup recorded it.
    """
    kind_filter = "AND kind = ?" if kind != "all" else ""
    kind_params: tuple = (kind,) if kind != "all" else ()

    with _db_connect() as conn:
        if latest_only:
            rows = conn.execute(
                f"""
                WITH latest_per_host AS (
                    SELECT lower(host) AS host_key, MAX(date(scanned_at)) AS latest_date
                    FROM cpu_audit_log
                    WHERE 1=1 {kind_filter}
                    GROUP BY lower(host)
                )
                SELECT l.scanned_at, l.kind, l.host, l.serial_number, l.found,
                       l.item_id, i.name AS item_name, i.category AS item_category,
                       i.location AS item_location, i.part_number AS item_part_number,
                       i.serial_number AS item_serial_number
                FROM cpu_audit_log l
                JOIN latest_per_host lph
                  ON lph.host_key = lower(l.host) AND lph.latest_date = date(l.scanned_at)
                LEFT JOIN items i ON i.id = l.item_id
                WHERE 1=1 {kind_filter}
                ORDER BY l.host, l.scanned_at DESC
                LIMIT ?
                """,
                (*kind_params, *kind_params, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT l.scanned_at, l.kind, l.host, l.serial_number, l.found,
                       l.item_id, i.name AS item_name, i.category AS item_category,
                       i.location AS item_location, i.part_number AS item_part_number,
                       i.serial_number AS item_serial_number
                FROM cpu_audit_log l
                LEFT JOIN items i ON i.id = l.item_id
                WHERE 1=1 {kind_filter}
                ORDER BY l.scanned_at DESC
                LIMIT ?
                """,
                (*kind_params, limit),
            ).fetchall()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["scanned_at", "kind", "host", "serial_number", "found",
                      "item_id", "item_name", "item_category", "item_location",
                      "item_part_number", "item_serial_number"])
    for r in rows:
        writer.writerow([
            r["scanned_at"], r["kind"], r["host"], r["serial_number"], "yes" if r["found"] else "no",
            r["item_id"] or "", r["item_name"] or "", r["item_category"] or "",
            r["item_location"] or "", r["item_part_number"] or "", r["item_serial_number"] or "",
        ])

    today = _date.today().isoformat()
    suffix = ("" if kind == "all" else f"_{kind}") + ("_latest" if latest_only else "")
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit_log{suffix}_{today}.csv"'},
    )


# ── reporting ─────────────────────────────────────────────────────────────────

# Aggregates run in SQLite rather than over the JSON the browser already holds:
# the questions below ("how many are available", "what is running low") are
# GROUP BYs over the whole table, and shipping 9.7k rows to compute them in the
# client is what the Reports view exists to replace.

_SQL_CHECKED_OUT = "trim(checkout_user) <> ''"
# A faulty part is not stock, however it is shelved. Blank condition means Good,
# so this has to test for the fault rather than for the absence of 'Good'.
_SQL_BAD = "lower(trim(condition)) = 'bad'"
_SQL_SUSPECT = "lower(trim(condition)) = 'suspect'"
_SQL_USABLE = f"NOT ({_SQL_BAD})"


@app.get("/api/reports/summary", dependencies=[Depends(_require_admin)])
def reports_summary(low_stock_threshold: int = Query(default=3, ge=0, le=1000)):
    """Counts the inventory table can answer but the UI previously could not."""
    today = _date.today().isoformat()

    with _db_connect() as conn:
        def rows(sql: str, args: tuple = ()) -> list[dict]:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]

        def one(sql: str, args: tuple = ()):
            return conn.execute(sql, args).fetchone()[0]

        by_category = rows(f"""
            SELECT category,
                   COUNT(*)                                             AS total,
                   SUM(CASE WHEN {_SQL_CHECKED_OUT} THEN 1 ELSE 0 END)  AS checked_out,
                   SUM(CASE WHEN {_SQL_BAD} THEN 1 ELSE 0 END)          AS bad,
                   SUM(CASE WHEN {_SQL_SUSPECT} THEN 1 ELSE 0 END)      AS suspect,
                   SUM(CASE WHEN {_SQL_USABLE} AND NOT ({_SQL_CHECKED_OUT})
                            THEN 1 ELSE 0 END)                          AS available
              FROM items
             GROUP BY category
             ORDER BY total DESC
        """)
        for row in by_category:
            row["category"] = _normalize_category(row["category"])

        by_team = rows(f"""
            SELECT CASE WHEN trim(team) = '' THEN '(none)' ELSE team END AS team,
                   COUNT(*)                                    AS total,
                   SUM(CASE WHEN {_SQL_CHECKED_OUT} THEN 1 ELSE 0 END) AS checked_out
              FROM items
             GROUP BY 1
             ORDER BY total DESC
             LIMIT 25
        """)

        # Stock levels per part number — the "do we have any spare?" question.
        stock = rows(f"""
            SELECT trim(part_number) AS part_number,
                   MIN(name)                                   AS example_name,
                   COUNT(*)                                    AS total,
                   SUM(CASE WHEN {_SQL_USABLE} AND NOT ({_SQL_CHECKED_OUT})
                            THEN 1 ELSE 0 END)                          AS available,
                   SUM(CASE WHEN {_SQL_BAD} THEN 1 ELSE 0 END)          AS bad
              FROM items
             WHERE trim(part_number) <> ''
             GROUP BY 1
             ORDER BY available ASC, total DESC
        """)
        low_stock = [s for s in stock if s["available"] <= low_stock_threshold][:25]
        most_held = sorted(stock, key=lambda s: -s["total"])[:15]

        borrowers = rows(f"""
            SELECT checkout_user,
                   MIN(CASE WHEN trim(checkout_email) <> '' THEN checkout_email END) AS email,
                   COUNT(*)                                             AS items,
                   SUM(CASE WHEN trim(checkout_email) = '' THEN 1 ELSE 0 END) AS without_email,
                   MIN(CASE WHEN trim(checkout_date) <> '' THEN checkout_date END) AS since
              FROM items
             WHERE {_SQL_CHECKED_OUT}
             GROUP BY checkout_user
             ORDER BY items DESC
        """)

        overdue = rows(f"""
            SELECT id, name, part_number, checkout_user, checkout_email, loan_until
              FROM items
             WHERE {_SQL_CHECKED_OUT}
               AND trim(loan_until) <> ''
               AND loan_until < ?
             ORDER BY loan_until ASC
             LIMIT 50
        """, (today,))

        total = one("SELECT COUNT(*) FROM items")
        checked_out = one(f"SELECT COUNT(*) FROM items WHERE {_SQL_CHECKED_OUT}")
        bad = one(f"SELECT COUNT(*) FROM items WHERE {_SQL_BAD}")
        suspect = one(f"SELECT COUNT(*) FROM items WHERE {_SQL_SUSPECT}")
        available = one(
            f"SELECT COUNT(*) FROM items WHERE {_SQL_USABLE} AND NOT ({_SQL_CHECKED_OUT})"
        )

        # Failure rate per part number and per vendor — the signal a validation
        # lab actually wants out of marking things bad.
        faults_by_part = rows(f"""
            SELECT trim(part_number) AS part_number,
                   MIN(name)                                   AS example_name,
                   COUNT(*)                                    AS total,
                   SUM(CASE WHEN {_SQL_BAD} THEN 1 ELSE 0 END) AS bad,
                   SUM(CASE WHEN {_SQL_SUSPECT} THEN 1 ELSE 0 END) AS suspect
              FROM items
             WHERE trim(part_number) <> ''
             GROUP BY 1
            HAVING bad > 0 OR suspect > 0
             ORDER BY bad DESC, suspect DESC
             LIMIT 25
        """)
        faults_by_vendor = rows(f"""
            SELECT CASE WHEN trim(vendor) = '' THEN '(none)' ELSE vendor END AS vendor,
                   COUNT(*)                                    AS total,
                   SUM(CASE WHEN {_SQL_BAD} THEN 1 ELSE 0 END) AS bad,
                   SUM(CASE WHEN {_SQL_SUSPECT} THEN 1 ELSE 0 END) AS suspect
              FROM items
             GROUP BY 1
            HAVING bad > 0 OR suspect > 0
             ORDER BY bad DESC
        """)
        faulty = rows(f"""
            SELECT id, name, part_number, serial_number, category,
                   condition, condition_note, modified_by, updatedAt
              FROM items
             WHERE {_SQL_BAD} OR {_SQL_SUSPECT}
             ORDER BY CASE WHEN {_SQL_BAD} THEN 0 ELSE 1 END, updatedAt DESC
             LIMIT 100
        """)

        # Gaps worth acting on, each phrased as a count of rows.
        gaps = {
            "no_location":        one("SELECT COUNT(*) FROM items WHERE trim(location) = ''"),
            "no_part_number":     one("SELECT COUNT(*) FROM items WHERE trim(part_number) = ''"),
            "no_serial":          one("SELECT COUNT(*) FROM items WHERE trim(serial_number) = ''"),
            "dimms_without_rcd":  one("SELECT COUNT(*) FROM items WHERE lower(category) LIKE '%dimm%' AND trim(rcd) = ''"),
            "dimms_without_speed": one("SELECT COUNT(*) FROM items WHERE lower(category) LIKE '%dimm%' AND trim(speed) = ''"),
            "checkout_without_email": one(f"SELECT COUNT(*) FROM items WHERE {_SQL_CHECKED_OUT} AND trim(checkout_email) = ''"),
            "checkout_without_date":  one(f"SELECT COUNT(*) FROM items WHERE {_SQL_CHECKED_OUT} AND trim(checkout_date) = ''"),
            "checkout_without_due":   one(f"SELECT COUNT(*) FROM items WHERE {_SQL_CHECKED_OUT} AND trim(loan_until) = ''"),
        }

    return {
        "generated_at": _now(),
        "totals": {
            "items": total,
            "checked_out": checked_out,
            "available": available,   # excludes faulty units
            "bad": bad,
            "suspect": suspect,
            "part_numbers": len(stock),
        },
        "by_category": by_category,
        "by_team": by_team,
        "borrowers": borrowers,
        "low_stock": low_stock,
        "low_stock_threshold": low_stock_threshold,
        "most_held": most_held,
        "overdue": overdue,
        "faults_by_part": faults_by_part,
        "faults_by_vendor": faults_by_vendor,
        "faulty": faulty,
        "gaps": gaps,
    }


# ── email reminders ───────────────────────────────────────────────────────────

class ReminderIn(BaseModel):
    subject: str | None = None
    message: str | None = None
    ids:     list[str] | None = None   # if set, only send for these item IDs


class ReturnRequestIn(BaseModel):
    ids:     list[str]
    cc:      list[str] | None = None   # extra CC addresses chosen by admin
    message: str | None = None


def _esc(val: object) -> str:
    """Escape a value for interpolation into an HTML email body.

    Everything these templates interpolate is attacker-reachable: item names and
    serial numbers come from uploaded spreadsheets, and the submission form is
    open to anyone on the network. Unescaped, a crafted value becomes arbitrary
    markup — including links — inside an email the admin trusts.
    """
    return html.escape(str(val if val is not None else ""), quote=True)


def _header_safe(val: str) -> str:
    """Strip CR/LF so a value cannot inject extra SMTP headers, and bound length."""
    return re.sub(r"[\r\n]+", " ", str(val or "")).strip()[:200]


def _smtp_send(to_addr: str, msg: MIMEMultipart, extra_cc: list[str] | None = None) -> None:
    """Low-level: open an SMTP connection and send *msg*. Raises RuntimeError on failure."""
    all_rcpt = [to_addr] + REMINDER_CC + (extra_cc or [])
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.ehlo()
            if SMTP_USE_TLS:
                smtp.starttls()
                smtp.ehlo()
            if SMTP_USER and SMTP_PASSWORD:
                smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.sendmail(SMTP_FROM, all_rcpt, msg.as_string())
    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError(f"SMTP authentication failed: {exc}") from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f"SMTP error: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not connect to SMTP server ({SMTP_HOST}:{SMTP_PORT}): {exc}") from exc


def _build_reminder_msg(to_addr: str, checkout_user: str, items_list: list[dict], extra_message: str = "") -> MIMEMultipart:
    """Build a MIMEMultipart reminder email for one or more items addressed to *to_addr*."""
    count = len(items_list)
    subject = (
        f"[FVDDR Inventory] Please return: {items_list[0].get('name', 'an item')}"
        if count == 1
        else f"[Lab Inventory] Please return {count} checked-out items"
    )

    # ── plain text ──
    lines = [f"Hi {checkout_user},\n"]
    if count == 1:
        lines.append("This is a reminder that you have checked out the following item from the lab inventory:\n")
    else:
        lines.append(f"This is a reminder that you have {count} items checked out from the lab inventory:\n")

    for item in items_list:
        lines.append(f"  Item  : {item.get('name', '—')}")
        if item.get("serial_number"):
            lines.append(f"  S/N   : {item['serial_number']}")
        if item.get("loan_until"):
            lines.append(f"  Due   : {item['loan_until']}")
        elif item.get("checkout_date"):
            lines.append(f"  Since : {item['checkout_date']}")
        lines.append("")

    lines.append("Please return each item as soon as it is no longer needed.")
    if extra_message:
        lines.append(f"\nPlease reply to this email if require to extend loan period.")
    lines.append("\nThank you,\nFVDDR Inventory Admin")
    body_text = "\n".join(lines)

    # ── HTML ──
    rows_html = ""
    for item in items_list:
        due_cell  = item.get("loan_until") or item.get("checkout_date") or "—"
        due_label = "Due" if item.get("loan_until") else "Since"
        sn_cell   = f"<br><span style='color:#777;font-size:0.9em'>S/N: {_esc(item['serial_number'])}</span>" if item.get("serial_number") else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{_esc(item.get('name','—'))}{sn_cell}</td>"
            f"<td style='padding:6px 0;color:#555'>{due_label}: {_esc(due_cell)}</td>"
            f"</tr>"
        )

    intro = (
        "you have checked out the following item from the lab inventory:"
        if count == 1
        else f"you have <strong>{count} items</strong> checked out from the lab inventory:"
    )
    body_html = (
        f"<p>Hi {_esc(checkout_user)},</p>"
        f"<p>This is a reminder that {intro}</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>{rows_html}</table>"
        f"<p>Please <strong>return</strong> each item as soon as it is no longer needed or <strong>reply</strong> to this email if require to extend loan period.</p>"
        + (f"<p>{_esc(extra_message)}</p>" if extra_message else "")
        + "<p>Thank you,<br>FVDDR Inventory Admin</p>"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM}>" if SMTP_FROM_NAME else SMTP_FROM
    msg["To"]      = to_addr
    if REMINDER_CC:
        msg["Cc"]  = ", ".join(REMINDER_CC)
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))
    return msg


def _send_reminder_email(item: dict, extra_message: str = "") -> None:
    """Send a reminder for a single item. Raises RuntimeError on failure."""
    if not SMTP_HOST:
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST (and related vars) in .env.")
    to_addr = (item.get("checkout_email") or "").strip()
    if not to_addr:
        raise RuntimeError("No checkout email address is set for this item.")
    checkout_user = item.get("checkout_user") or "there"
    msg = _build_reminder_msg(to_addr, checkout_user, [item], extra_message)
    _smtp_send(to_addr, msg)


class CheckoutNotifyIn(BaseModel):
    ids: list[str]


def _build_checkout_msg(to_addr: str, checkout_user: str, items_list: list[dict]) -> MIMEMultipart:
    count = len(items_list)
    subject = (
        f"[FVDDR Lab Inventory] Checked out to you: {items_list[0].get('name', 'an item')}"
        if count == 1
        else f"[FVDDR Lab Inventory] {count} items checked out to you"
    )

    lines = [f"Hi {checkout_user},\n"]
    lines.append(
        "The following item has been checked out to you from the lab inventory:\n"
        if count == 1
        else f"The following {count} items have been checked out to you from the lab inventory:\n"
    )
    for item in items_list:
        lines.append(f"  Item    : {item.get('name', '—')}")
        if item.get("part_number"):  lines.append(f"  Part No : {item['part_number']}")
        if item.get("serial_number"): lines.append(f"  S/N     : {item['serial_number']}")
        if item.get("checkout_date"): lines.append(f"  Date    : {item['checkout_date']}")
        if item.get("loan_until"):    lines.append(f"  Due     : {item['loan_until']}")
        if item.get("location"):      lines.append(f"  Location: {item['location']}")
        lines.append("")
    lines.append("Please return the item(s) by the due date or reply to this email to request an extension.")
    lines.append("\nThank you,\nFVDDR Inventory Admin")
    body_text = "\n".join(lines)

    rows_html = ""
    for item in items_list:
        due = item.get("loan_until") or item.get("checkout_date") or "—"
        due_label = "Due" if item.get("loan_until") else "Checked out"
        sn = f"<br><span style='color:#777;font-size:0.9em'>S/N: {_esc(item['serial_number'])}</span>" if item.get("serial_number") else ""
        pn = f"<br><span style='color:#777;font-size:0.9em'>PN: {_esc(item['part_number'])}</span>"   if item.get("part_number")  else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{_esc(item.get('name','—'))}{sn}{pn}</td>"
            f"<td style='padding:6px 0;color:#555'>{due_label}: {_esc(due)}</td>"
            f"</tr>"
        )
    body_html = (
        f"<p>Hi {_esc(checkout_user)},</p>"
        f"<p>{'The following item has' if count == 1 else f'The following {count} items have'} been checked out to you from the lab inventory:</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>{rows_html}</table>"
        f"<p>Please return the item(s) by the due date, or <strong>reply</strong> to this email to request an extension.</p>"
        f"<p>Thank you,<br>FVDDR Inventory Admin</p>"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM}>" if SMTP_FROM_NAME else SMTP_FROM
    msg["To"]      = to_addr
    if REMINDER_CC:
        msg["Cc"]  = ", ".join(REMINDER_CC)
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))
    return msg


@app.post("/api/items/notify-checkout", dependencies=[Depends(_require_admin)])
def notify_checkout(body: CheckoutNotifyIn):
    """Send a checkout confirmation email to the checkout_email of each given item ID.
    Silently skips items without a checkout_email. Never raises on email failure."""
    if not SMTP_HOST:
        return {"sent": 0, "skipped": len(body.ids), "note": "SMTP not configured"}
    all_items = _read()
    id_set    = set(body.ids)
    targets   = [i for i in all_items if i["id"] in id_set
                 and (i.get("checkout_email") or "").strip()
                 and (i.get("checkout_user") or "").strip()]
    skipped   = len(body.ids) - len(targets)
    # Group by email so one message lists all items for the same recipient
    groups: dict[str, list[dict]] = {}
    for item in targets:
        groups.setdefault(item["checkout_email"].strip().lower(), []).append(item)
    sent = 0
    for to_addr, item_list in groups.items():
        try:
            checkout_user = item_list[0].get("checkout_user", "there")
            msg = _build_checkout_msg(to_addr, checkout_user, item_list)
            _smtp_send(to_addr, msg)
            sent += len(item_list)
        except Exception:
            pass   # best-effort — don't fail the checkout if email breaks
    return {"sent": sent, "skipped": skipped}


@app.post("/api/items/{item_id}/send-reminder", dependencies=[Depends(_require_superadmin)])
def send_item_reminder(item_id: str, body: ReminderIn):
    items = _read()
    item = next((i for i in items if i["id"] == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    try:
        _send_reminder_email(item, extra_message=body.message or "")
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"sent": True, "to": item.get("checkout_email", "")}


@app.post("/api/reminders/send-bulk", dependencies=[Depends(_require_superadmin)])
def send_bulk_reminders(body: ReminderIn):
    """Send one consolidated email per user listing all their checked-out items."""
    if not SMTP_HOST:
        raise HTTPException(status_code=422, detail="SMTP is not configured. Set SMTP_HOST (and related vars) in .env.")

    all_items = _read()
    id_filter = set(body.ids) if body.ids else None

    # Group checked-out items by checkout_email (case-insensitive)
    groups: dict[str, list[dict]] = {}
    skipped: list[str] = []
    for item in all_items:
        if id_filter is not None and item["id"] not in id_filter:
            continue
        if not (item.get("checkout_user") or "").strip():
            continue
        email = (item.get("checkout_email") or "").strip().lower()
        if not email:
            skipped.append(item.get("name", item["id"]))
            continue
        groups.setdefault(email, []).append(item)

    sent, errors = [], []
    for email, group in groups.items():
        checkout_user = group[0].get("checkout_user") or "there"
        try:
            msg = _build_reminder_msg(email, checkout_user, group, extra_message=body.message or "")
            _smtp_send(email, msg)
            sent.append({
                "to": email,
                "user": checkout_user,
                "items": [i.get("name") for i in group],
            })
        except RuntimeError as exc:
            errors.append({
                "to": email,
                "user": checkout_user,
                "items": [i.get("name") for i in group],
                "error": str(exc),
            })

    return {"sent": sent, "skipped_no_email": skipped, "errors": errors}


def _build_return_request_msg(
    to_addr: str,
    checkout_user: str,
    items_list: list[dict],
    extra_cc: list[str],
    message: str,
) -> tuple[MIMEMultipart, list[str]]:
    """Build a return-request email (admin-initiated, directed at the checkout user)."""
    count = len(items_list)
    subject = (
        f"[FVDDR Inventory] Return requested: {items_list[0].get('name', 'an item')}"
        if count == 1
        else f"[FVDDR Inventory] Please return {count} items to the lab"
    )

    lines = [f"Hi {checkout_user},\n"]
    lines.append(
        "The FVDDR Lab Admin is requesting that you return the following item:\n"
        if count == 1
        else f"The FVDDR Lab Admin is requesting that you return the following {count} items:\n"
    )
    for item in items_list:
        lines.append(f"  Item     : {item.get('name', '—')}")
        if item.get("part_number"):   lines.append(f"  Part No  : {item['part_number']}")
        if item.get("serial_number"): lines.append(f"  S/N      : {item['serial_number']}")
        if item.get("category"):      lines.append(f"  Category : {item['category']}")
        if item.get("location"):      lines.append(f"  Location : {item['location']}")
        if item.get("loan_until"):    lines.append(f"  Due      : {item['loan_until']}")
        elif item.get("checkout_date"): lines.append(f"  Since    : {item['checkout_date']}")
        lines.append("")
    if message:
        lines.append(f"Note from Admin:\n{message}\n")
    lines.append("Please reply to this email to confirm your return or to discuss the timeline.")
    lines.append("\nThank you,\nFVDDR Inventory Admin")
    body_text = "\n".join(lines)

    rows_html = ""
    for item in items_list:
        due_cell  = item.get("loan_until") or item.get("checkout_date") or "—"
        due_label = "Due" if item.get("loan_until") else "Since"
        sn  = f"<br><span style='color:#777;font-size:0.85em'>S/N: {_esc(item['serial_number'])}</span>" if item.get("serial_number") else ""
        pn  = f"<br><span style='color:#777;font-size:0.85em'>PN: {_esc(item['part_number'])}</span>"   if item.get("part_number")  else ""
        loc = f"<br><span style='color:#777;font-size:0.85em'>Location: {_esc(item['location'])}</span>" if item.get("location") else ""
        cat = f"<span style='color:#777;font-size:0.85em'>{_esc(item['category'])}</span>" if item.get("category") else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{_esc(item.get('name','—'))}{sn}{pn}{loc}</td>"
            f"<td style='padding:6px 8px 6px 0;color:#555'>{cat}</td>"
            f"<td style='padding:6px 0;color:#555;white-space:nowrap'>{due_label}: {_esc(due_cell)}</td>"
            f"</tr>"
        )

    intro = (
        "the FVDDR Lab Admin is requesting that you return the following item:"
        if count == 1
        else f"the FVDDR Lab Admin is requesting that you return the following <strong>{count} items</strong>:"
    )
    msg_block = f"<p style='background:#fffbe6;border-left:3px solid #f59e0b;padding:10px 14px;border-radius:4px;margin:12px 0'><strong>Note from Admin:</strong><br>{_esc(message)}</p>" if message else ""
    body_html = (
        f"<p>Hi {_esc(checkout_user)},</p>"
        f"<p>This is to let you know that {intro}</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>{rows_html}</table>"
        + msg_block
        + f"<p>Please <strong>reply to this email</strong> to confirm your return or discuss the timeline.</p>"
        f"<p>Thank you,<br>FVDDR Inventory Admin</p>"
    )

    all_cc = list(dict.fromkeys(REMINDER_CC + extra_cc))  # deduplicate, preserve order
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM}>" if SMTP_FROM_NAME else SMTP_FROM
    msg["To"]      = to_addr
    if all_cc:
        msg["Cc"]  = ", ".join(all_cc)
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))
    return msg, all_cc


@app.post("/api/items/request-return", dependencies=[Depends(_require_superadmin)])
def request_return(body: ReturnRequestIn):
    """Send a return-request email to each checked-out user for the given item IDs.
    Groups multiple items per user into one email. Accepts optional extra CC addresses."""
    if not SMTP_HOST:
        raise HTTPException(status_code=422, detail="SMTP is not configured. Set SMTP_HOST (and related vars) in .env.")

    all_items = _read()
    id_set    = set(body.ids)
    extra_cc  = [e.strip() for e in (body.cc or []) if e.strip()]
    message   = (body.message or "").strip()

    # Only include items that have a checkout user and email
    groups: dict[str, list[dict]] = {}
    skipped: list[str] = []
    for item in all_items:
        if item["id"] not in id_set:
            continue
        if not (item.get("checkout_user") or "").strip():
            skipped.append(item.get("name", item["id"]))
            continue
        email = (item.get("checkout_email") or "").strip().lower()
        if not email:
            skipped.append(item.get("name", item["id"]))
            continue
        groups.setdefault(email, []).append(item)

    sent, errors = [], []
    for email, group in groups.items():
        checkout_user = group[0].get("checkout_user") or "there"
        try:
            msg, all_cc = _build_return_request_msg(email, checkout_user, group, extra_cc, message)
            # Pass extra_cc separately so _smtp_send includes them in RCPT TO but they're already in Cc header
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
                smtp.ehlo()
                if SMTP_USE_TLS:
                    smtp.starttls()
                    smtp.ehlo()
                if SMTP_USER and SMTP_PASSWORD:
                    smtp.login(SMTP_USER, SMTP_PASSWORD)
                all_rcpt = [email] + all_cc
                smtp.sendmail(SMTP_FROM, all_rcpt, msg.as_string())
            sent.append({
                "to": email,
                "user": checkout_user,
                "cc": all_cc,
                "items": [i.get("name") for i in group],
            })
        except Exception as exc:
            errors.append({
                "to": email,
                "user": checkout_user,
                "items": [i.get("name") for i in group],
                "error": str(exc),
            })

    return {"sent": sent, "skipped_no_email": skipped, "errors": errors}


# ── user submission ───────────────────────────────────────────────────────────

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024   # 25 MB — far above any real inventory sheet
_MAX_NOTES_CHARS  = 2000
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")


async def _read_upload(file: UploadFile, limit: int = _MAX_UPLOAD_BYTES) -> bytes:
    """Read an upload in chunks, refusing anything over *limit*.

    A bare file.read() pulls the entire body into memory before anything checks
    it, which makes an oversized upload a cheap way to exhaust the server.
    """
    chunks: list[bytes] = []
    total  = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=413,
                detail=f"File is too large (limit {limit // (1024 * 1024)} MB).",
            )
        chunks.append(chunk)
    if not total:
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")
    return b"".join(chunks)


_SUBMISSION_WINDOW_SEC      = 3600
_MAX_SUBMISSIONS_PER_WINDOW = 20
_submission_times: list[float] = []
_submission_lock = _threading.Lock()


def _rate_limit_submission() -> None:
    """Cap how many submission emails the server will relay per hour.

    This endpoint takes no login and makes the server send mail with an
    attachment, so it needs a ceiling no matter who is calling it.
    """
    now = time.monotonic()
    with _submission_lock:
        _submission_times[:] = [t for t in _submission_times if now - t < _SUBMISSION_WINDOW_SEC]
        if len(_submission_times) >= _MAX_SUBMISSIONS_PER_WINDOW:
            raise HTTPException(
                status_code=429,
                detail="Too many submissions in the last hour. Please try again later.",
            )
        _submission_times.append(now)


@app.post("/api/submit-request")
async def submit_request(
    submitter_name:  str        = Form(...),
    submitter_email: str        = Form(...),
    notes:           str        = Form(""),
    file:            UploadFile = File(...),
):
    """Accept an Excel/CSV file from a user and email it to the admin for review."""
    if not SMTP_HOST:
        raise HTTPException(status_code=422, detail="Email is not configured on the server. Contact your admin.")
    if not ADMIN_EMAIL:
        raise HTTPException(status_code=422, detail="No admin email address configured. Contact your admin.")

    # Keep only the basename: a filename is attacker-controlled and ends up in a
    # Content-Disposition header and in the admin's mail client.
    fname = Path((file.filename or "attachment").strip()).name
    fname = _header_safe(fname).replace('"', "") or "attachment"
    ext   = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext not in ("csv", "xlsx", "xls"):
        raise HTTPException(status_code=422, detail="Only .csv, .xlsx, or .xls files are accepted.")

    submitter_name  = _header_safe(submitter_name)
    submitter_email = _header_safe(submitter_email)
    if not submitter_name:
        raise HTTPException(status_code=422, detail="Please provide your name.")
    if not _EMAIL_RE.fullmatch(submitter_email):
        raise HTTPException(status_code=422, detail="Please provide a valid email address.")
    if len(notes) > _MAX_NOTES_CHARS:
        raise HTTPException(status_code=422, detail=f"Notes are limited to {_MAX_NOTES_CHARS} characters.")

    content = await _read_upload(file)
    _rate_limit_submission()
    submitted_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    body_text = (
        f"A user has submitted an inventory addition request.\n\n"
        f"  Name   : {submitter_name}\n"
        f"  Email  : {submitter_email}\n"
        f"  File   : {fname}\n"
        f"  Sent   : {submitted_at}\n"
        + (f"\nNotes:\n{notes}\n" if notes.strip() else "")
        + "\nThe file is attached. Please review and import it into the inventory system.\n"
    )
    # Every value below is supplied by an unauthenticated caller, so all of it is
    # escaped: otherwise a crafted name or note becomes live markup in the mail
    # the admin opens and trusts.
    body_html = (
        f"<p>A user has submitted an inventory addition request.</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Name</td><td>{_esc(submitter_name)}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Email</td><td>{_esc(submitter_email)}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>File</td><td>{_esc(fname)}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Sent</td><td>{_esc(submitted_at)}</td></tr>"
        + (f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold;vertical-align:top'>Notes</td><td>{_esc(notes)}</td></tr>" if notes.strip() else "")
        + f"</table>"
        f"<p>The file is attached. Please review and import it into the inventory system.</p>"
    )

    msg = MIMEMultipart("mixed")
    # submitter_name / submitter_email are already CR/LF-stripped by _header_safe
    # and the address is regex-validated, so neither can inject extra headers.
    msg["Subject"] = f"[Lab Inventory] Submission from {submitter_name}"
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM}>" if SMTP_FROM_NAME else SMTP_FROM
    msg["To"]      = ADMIN_EMAIL
    msg["Reply-To"] = submitter_email

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(body_text, "plain"))
    alt.attach(MIMEText(body_html, "html"))
    msg.attach(alt)

    # Attach the uploaded file
    mime_type = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if ext == "xlsx"
        else "application/vnd.ms-excel" if ext == "xls"
        else "text/csv"
    )
    part = MIMEBase(*mime_type.split("/", 1))
    part.set_payload(content)
    email_encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
    msg.attach(part)

    try:
        _smtp_send(ADMIN_EMAIL, msg)
    except RuntimeError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {"submitted": True, "to": ADMIN_EMAIL}


# ── Excel template ────────────────────────────────────────────────────────────

TEMPLATE_CATEGORIES = ["DIMMs", "CPU (Silicon)", "Storage", "Systems", "Accessories"]

SAMPLE_ROWS = [
    # vendor, name, part_number, serial_number, rank, speed, capacity, density, dimm_type, rcd, pmic, category, location, tray, team, owner, checkout_user, checkout_email, checkout_date, loan_until, notes
    ("Samsung", "Samsung DDR5-4800 64GB 2Rx4 RDIMM", "PN-D5-64G-4800", "SN-SAM-0001", "2Rx4", "4800 MT/s", "64 GB",  "16Gbits", "CS", "MTC RCD01", "MPS9343", "DIMMs",        "Shelf A1",  "Tray 1", "Lab Team A", "Alice",   "",           "",              "",             "",             "ECC Registered"),
    ("Micron",  "Micron DDR5-5600 96GB 2Rx4 RDIMM",  "PN-D5-96G-5600", "SN-MIC-0001", "2Rx4", "5600 MT/s", "96 GB",  "24Gbits", "ES", "",          "",        "DIMMs",        "Shelf A2",  "",       "Lab Team A", "Alice",   "",           "",              "",             "",             ""),
    ("AMD",     "AMD EPYC 9354 32-Core",             "PN-EPYC-9354",   "SN-AMD-0001", "",     "",          "",       "",        "ES", "",          "",        "CPU (Silicon)", "Shelf B2",  "",       "Lab Team B", "Bob",     "John Doe",   "john@amd.com",  "2026-07-20",   "2026-09-20",   "Genoa generation"),
    ("Samsung", "Samsung 980 Pro 1TB NVMe",          "PN-980P-1TB",    "SN-SAM-0002", "",     "",          "1 TB",   "",        "",   "",          "",        "Storage",       "Shelf C3",  "",       "Lab Team A", "Alice",   "",           "",              "",             "",             "PCIe 4.0"),
    ("Dell",    "Dell PowerEdge R750",               "PN-R750-001",    "SN-DEL-0001", "",     "",          "",       "",        "",   "",          "",        "Systems",       "Rack 1 1U", "Slot 3", "Infra Team", "Charlie", "Jane Smith", "jane@amd.com",  "2026-07-01",   "2026-10-01",   "2U rack server"),
]

COLUMNS = [
    "Vendor",
    "Item Description",
    "Part Number",
    "Serial Number",
    "Rank",
    "Speed",
    "Capacity",
    "Density",
    "Category",
    "Location",
    "Tray / Comment",
    "Team",
    "Owner",
    "Check Out User",
    "Check Out Email",
    "Check Out Date",
    "Loan Until",
    "Notes",
]


@app.post("/api/parse-file", dependencies=[Depends(_require_admin)])
async def parse_file(file: UploadFile = File(...)):
    """Parse an uploaded CSV or xlsx file, decrypting if needed.

    Admin-only: the import flow that calls this is already behind the admin UI,
    and the parsers it reaches (pandas, openpyxl, msoffcrypto) are a large
    attack surface to expose to anyone who can reach the port.

    Returns: {"sheets": [{"name": str, "rows": [[str, ...]]}]}
    Each row is a list of cell strings; row 0 is always the header row.
    """
    try:
        return await _do_parse_file(file)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {exc}")


# Compound File Binary header — an .xlsx that starts with this is not a zip:
# either a legacy .xls, a password-encrypted workbook, or a rights-managed one.
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _rights_managed_label(content: bytes) -> str | None:
    """The sensitivity label id if *content* is rights-managed, else None.

    A label that only classifies (Internal Use Only, as AMD applies it by
    default) leaves the workbook a normal zip carrying extra document
    properties, and parses like any other file. A label that *protects* wraps
    the package in DRM: the bytes become an OLE2 container holding an
    EncryptedPackage whose key comes from Azure Rights Management. There is no
    password to supply, so msoffcrypto cannot open it either — it reports
    "Unrecognized file format", which tells an admin nothing. Detecting the case
    here is what makes the error actionable.
    """
    if not content.startswith(_OLE2_MAGIC) or not _HAS_MSOFFCRYPTO:
        return None
    try:
        ole = msoffcrypto.olefile.OleFileIO(io.BytesIO(content))
        entries = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
        if not any("DRMEncrypted" in e for e in entries):
            return None          # a legacy .xls or password-encrypted file
        try:
            xml = ole.openstream(["\x06DataSpaces", "TransformInfo", "LabelInfo"]).read()
            found = re.search(rb'id="\{?([0-9a-fA-F-]{36})\}?"', xml)
            if found:
                return found.group(1).decode("ascii")
        except Exception:
            pass                 # protected, but the label id is not readable
        return "unknown"
    except Exception:
        return None              # not parseable as OLE2; let the normal path report


async def _do_parse_file(file: UploadFile):
    content = await _read_upload(file)
    fname   = (file.filename or "").lower()

    # ── CSV ──────────────────────────────────────────────────────────────────
    if fname.endswith(".csv"):
        try:
            text = content.decode("utf-8-sig")  # strip BOM if present
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        reader = csv.reader(io.StringIO(text, newline=""))
        rows   = [[str(c) for c in r] for r in reader]
        rows   = [r for r in rows if any(c.strip() for c in r)]
        if not rows:
            raise HTTPException(status_code=422, detail="No data found in CSV file.")
        return {"sheets": [{"name": "CSV", "rows": rows}]}

    # ── XLSX / XLS ────────────────────────────────────────────────────────────
    if not fname.endswith((".xlsx", ".xls")):
        raise HTTPException(status_code=422, detail="Unsupported file type. Upload .csv or .xlsx.")

    label = _rights_managed_label(content)
    if label:
        raise HTTPException(
            status_code=422,
            detail=(
                "This file is encrypted by its sensitivity label"
                + (f" ({label})" if label != "unknown" else "")
                + ", so its contents cannot be read here. The key belongs to Azure "
                "Rights Management, not to a password, so there is nothing to type in.\n\n"
                "In Excel: File → Info → Sensitivity → choose a label that "
                "classifies without protecting (or Remove), save, and upload again. "
                "A label that only classifies — Internal Use Only without "
                "protection — uploads fine and stays on the file."
            ),
        )

    raw = io.BytesIO(content)

    # Decrypt MIP-labelled / password-protected files first if needed.
    def _try_decrypt(buf: io.BytesIO) -> io.BytesIO:
        if not _HAS_MSOFFCRYPTO:
            raise HTTPException(
                status_code=422,
                detail=(
                    "This file appears to be encrypted or labelled, but the decryption "
                    "library is not installed. Run: pip install msoffcrypto-tool"
                ),
            )
        buf.seek(0)
        try:
            office = msoffcrypto.OfficeFile(buf)
            office.load_key(password="")
            out = io.BytesIO()
            office.decrypt(out)
            out.seek(0)
            return out
        except msoffcrypto.exceptions.InvalidKeyError:
            raise HTTPException(
                status_code=422,
                detail=(
                    "This file is password-protected. Remove the password in Excel "
                    "(File → Info → Protect Workbook → Encrypt with Password) and re-upload."
                ),
            )
        except Exception as e:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Could not read this workbook ({e}). If it carries a sensitivity "
                    "label that applies protection, or was saved with encryption, "
                    "save a copy without protection and upload that instead."
                ),
            )

    # Read all sheets with pandas; fall back to decryption on failure.
    engine = "xlrd" if fname.endswith(".xls") else "openpyxl"
    try:
        sheet_dfs = pd.read_excel(
            raw, sheet_name=None, header=None, dtype=str, engine=engine
        )
    except Exception:
        raw = _try_decrypt(raw)
        sheet_dfs = pd.read_excel(
            raw, sheet_name=None, header=None, dtype=str, engine=engine
        )

    sheets = []
    for sheet_name, df in sheet_dfs.items():
        df = df.fillna("").astype(str)
        rows = [
            [cell.strip() for cell in row]
            for row in df.values.tolist()
            if any(cell.strip() for cell in row)   # skip blank rows
        ]
        if rows:
            sheets.append({"name": sheet_name, "rows": rows})

    if not sheets:
        raise HTTPException(status_code=422, detail="No data rows found in the file.")

    return {"sheets": sheets}


_ACTION_VALUES = ["check_out", "check_in", "change_user"]

# The one column list behind both the template and the export, so the two cannot
# drift apart — they already did once, the template marking Check Out Email
# required on one sheet and optional on the other.
#
# (label, field_key, width, is_required, is_date)
_SHEET_COLS = [
    ("Action",                          "action",         14, False, False),
    ("Vendor",                          "vendor",         14, False, False),
    ("Item Description *",              "name",           34, True,  False),
    ("Part Number *",                   "part_number",    20, True,  False),
    ("Serial Number *",                 "serial_number",  20, True,  False),
    ("Rank",                            "rank",           10, False, False),
    ("Speed",                           "speed",          14, False, False),
    ("Capacity",                        "capacity",       12, False, False),
    ("Density",                         "density",        14, False, False),
    ("DIMM Type (ES/CS)",               "dimm_type",      14, False, False),
    ("RCD",                             "rcd",            16, False, False),
    ("PMIC",                            "pmic",           16, False, False),
    ("Condition",                       "condition",      12, False, False),
    ("Condition Note",                  "condition_note", 28, False, False),
    ("Location *",                      "location",       18, True,  False),
    ("Tray / Comment",                  "tray",           18, False, False),
    ("Team *",                          "team",           16, True,  False),
    ("Owner *",                         "owner",          14, True,  False),
    ("Check Out User *",                "checkout_user",  18, True,  False),
    # Required on an Action row (checking an item out to someone unreachable is
    # refused), optional on a new-item row. Left marked because the stricter of
    # the two jobs is the one worth warning about on a blank form, and because
    # an imported loan with no address can never be chased.
    ("Check Out Email *",               "checkout_email", 24, True,  False),
    ("Check Out Date * (YYYY-MM-DD)",   "checkout_date",  18, True,  True),
    ("Loan Until (YYYY-MM-DD)",         "loan_until",     16, False, True),
    ("Notes",                           "notes",          30, False, False),
]

# Columns a category never uses, left off those sheets entirely.
_NO_DIMM_SPECIFIC          = {"rank", "speed", "density", "dimm_type", "rcd", "pmic"}
_NO_DIMM_SPECIFIC_CAPACITY = _NO_DIMM_SPECIFIC | {"capacity"}
_CATEGORY_EXCLUDE: dict[str, set[str]] = {
    "systems":       _NO_DIMM_SPECIFIC_CAPACITY,
    "accessories":   _NO_DIMM_SPECIFIC_CAPACITY,
    "cpu (silicon)": {"rank", "speed", "density", "capacity", "rcd", "pmic"},  # keep dimm_type for ES/CS
    "storage":       _NO_DIMM_SPECIFIC,
}


def _cols_for_category(cat: str) -> list[tuple]:
    exclude = _CATEGORY_EXCLUDE.get(cat.lower().strip(), set())
    return [col for col in _SHEET_COLS if col[1] not in exclude]


def _export_label(label: str) -> str:
    """The same column, labelled for a sheet of real data rather than a form.

    An export is already filled in, so "required" stars and format hints are
    noise at best and misleading at worst. Both parsers strip these anyway —
    "Serial Number *" and "Serial Number" normalise to the same key — so an
    export still uploads to either tab.
    """
    return re.sub(r"\s*\([^)]*\)", "", label).replace("*", "").strip()


def _build_template_workbook():
    """One workbook for both jobs: adding items and checking them in/out.

    A row with a blank Action adds a new item; a row naming an action updates
    whichever item its Serial / Part Number matches. One upload applies both, so
    a sheet can mix parts arriving, parts coming back and loans changing hands
    the way a real one does. There used to be two templates and two
    near-identical generators, which cost an admin a download and a failed
    upload whenever they picked the wrong one — and the pair had already
    drifted: the bulk sheet marked Check Out Email required, the import sheet
    did not, though the server enforces it for both.

    The Action header is deliberately the bare word "Action". The import side
    matches a column by exact alias first and falls back to loose substrings, so
    a chattier label like "Action (blank = add new item)" is safe only while the
    description column is spelled exactly "Item Description". Rename that column
    to "Item Desc" — as an admin editing their own copy well might — and the
    fallback matches "item" inside the Action label instead, mapping every item
    name to the Action column. The explanation belongs in the UI, not the
    header.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    from datetime import date as _dt

    today      = _dt.today().isoformat()
    next_month = _dt.fromordinal(_dt.today().toordinal() + 31).isoformat()

    # Map SAMPLE_ROWS (tuples following COLUMNS order) → list of dicts per category
    col_keys = ["vendor","name","part_number","serial_number","rank","speed",
                "capacity","density","dimm_type","rcd","pmic","category","location","tray","team","owner",
                "checkout_user","checkout_email","checkout_date","loan_until","notes"]
    sample_by_cat: dict[str, list[dict]] = {}
    for row in SAMPLE_ROWS:
        d = dict(zip(col_keys, row))
        sample_by_cat.setdefault(d["category"], []).append(d)

    # Check in / out examples, shown under the new-item examples on every sheet.
    # change_user reassigns an item that is already out, without a check_in first.
    def _action_samples(serial_prefix: str, part: str, name: str, location: str, tray: str) -> list[dict]:
        common = {"part_number": part, "name": name, "location": location, "tray": tray}
        return [
            {**common, "action": "check_out",   "serial_number": f"{serial_prefix}-001",
             "checkout_user": "John Doe",  "checkout_email": "john@amd.com",
             "checkout_date": today, "loan_until": next_month, "notes": "Lab stress test"},
            {**common, "action": "check_in",    "serial_number": f"{serial_prefix}-002"},
            {**common, "action": "change_user", "serial_number": f"{serial_prefix}-003",
             "checkout_user": "Jane Smith", "checkout_email": "jane@amd.com",
             "checkout_date": today, "loan_until": next_month, "notes": "Reassigned"},
        ]

    ACTION_SAMPLES: dict[str, list[dict]] = {
        "DIMMs":         _action_samples("802C06234644DACA", "MTC40F2047S1RC64BBZ", "128GB 2RX4 PC5-6400", "L6-L12-03", "Tray 4"),
        "CPU (Silicon)": _action_samples("CPU-SN", "100-000001234",      "Genoa ES CPU",          "L6-L12-05", "Bin 2"),
        "Storage":       _action_samples("SSD-SN", "MZWLJ3T8HBLS-00007", "3.84TB NVMe SSD",       "L6-L12-07", "Shelf B"),
        "Systems":       _action_samples("SYS-SN", "SYS-PN-001",         "Test Server Platform",  "Rack A1",   ""),
        "Accessories":   _action_samples("ACC-SN", "CBL-PN-001",         "PCIe x16 Riser Cable",  "L6-L12-09", "Drawer 1"),
    }

    def _write_template_sheet(ws, cols: list[tuple], sample_rows: list[dict]) -> None:
        blue_fill = PatternFill("solid", fgColor="2E75B6")
        red_fill  = PatternFill("solid", fgColor="C00000")
        thin      = Side(style="thin", color="FFFFFF")
        border    = Border(left=thin, right=thin, top=thin, bottom=thin)
        ws.freeze_panes = "A2"
        ws.row_dimensions[1].height = 28
        for ci, (label, _, width, is_req, _is_date) in enumerate(cols, start=1):
            cell = ws.cell(row=1, column=ci, value=label)
            cell.font      = Font(bold=True, color="FFFFFF", size=10)
            cell.fill      = red_fill if is_req else blue_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border    = border
            ws.column_dimensions[get_column_letter(ci)].width = width
        for ri, row_dict in enumerate(sample_rows, start=2):
            ws.row_dimensions[ri].height = 16
            for ci, (_label, key, _w, _req, is_date) in enumerate(cols, start=1):
                val = row_dict.get(key, "") or ""
                cell = ws.cell(row=ri, column=ci, value=val if val else None)
                cell.alignment = Alignment(vertical="center")
                if is_date and val:
                    cell.number_format = "@"

        # Blank is allowed and means "add this as a new item".
        action_col = next((i for i, (_l, key, *_r) in enumerate(cols, start=1) if key == "action"), None)
        if action_col:
            dv = DataValidation(type="list", formula1=f'"{",".join(_ACTION_VALUES)}"',
                                allow_blank=True, showDropDown=False, showErrorMessage=True)
            dv.error      = "Leave blank to add a new item, or use one of: " + ", ".join(_ACTION_VALUES)
            dv.errorTitle = "Invalid action"
            ws.add_data_validation(dv)
            dv.add(f"{get_column_letter(action_col)}2:{get_column_letter(action_col)}1000")

    wb = Workbook()
    wb.remove(wb.active)
    for cat in TEMPLATE_CATEGORIES:
        ws   = wb.create_sheet(title=cat[:31])
        cols = _cols_for_category(cat)
        _write_template_sheet(ws, cols, sample_by_cat.get(cat, []) + ACTION_SAMPLES.get(cat, []))

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf.getvalue()


def _template_response() -> Response:
    return Response(
        content=_build_template_workbook(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="inventory_template.xlsx"'},
    )


@app.get("/api/template")
def download_template():
    return _template_response()


@app.get("/api/bulk-template")
def download_bulk_template():
    """The same workbook as /api/template.

    Kept as its own route so existing links, bookmarks and the Bulk Check In/Out
    panel keep working now that one template covers both jobs.
    """
    return _template_response()


class ExportIn(BaseModel):
    ids: list[str] | None = None


@app.post("/api/export")
def export_selected(body: ExportIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    """Export by id, with the ids in the body.

    The GET below takes them as `?ids=` repeated once per item, which is fine
    for a handful and breaks for a selection: an id is 32 hex characters, so
    "select all filtered" on this inventory builds a 349 KB request line. The
    server never sees it — whatever is in front rejects it first, which reaches
    the admin as "Export failed: Bad Gateway".
    """
    return _export_workbook(body.ids, creds)


@app.get("/api/export")
def export_inventory(
    ids: list[str] | None = Query(default=None),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    """Kept for links and bookmarks; the UI posts a selection instead."""
    return _export_workbook(ids, creds)


def _export_workbook(ids: list[str] | None, creds: HTTPAuthorizationCredentials | None):
    # Exporting all items requires admin; exporting specific IDs is public (inventory is public)
    if not ids:
        _require_admin(creds)
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    import re as _re

    # Category column excluded — sheet name carries that information.
    # On re-import the sheet name is used as the category fallback automatically.
    # Columns come from the shared template list: an export an admin edits and
    # uploads has to line up with what the two upload tabs expect.
    def _safe_sheet_name(name: str) -> str:
        name = _re.sub(r'[\\/*?:\[\]]', '_', name).strip() or "Uncategorized"
        return name[:31]

    def _write_sheet(ws, item_rows: list[dict], cols: list[tuple]) -> None:
        header_fill = PatternFill("solid", fgColor="2E75B6")
        ws.row_dimensions[1].height = 24
        ws.freeze_panes = "A2"
        for ci, (label, _key, width, _req, _is_date) in enumerate(cols, start=1):
            cell = ws.cell(row=1, column=ci, value=_export_label(label))
            cell.font      = Font(bold=True, color="FFFFFF", size=10)
            cell.fill      = header_fill
            cell.alignment = Alignment(horizontal="center", vertical="center")
            ws.column_dimensions[get_column_letter(ci)].width = width
        for ri, item in enumerate(item_rows, start=2):
            ws.row_dimensions[ri].height = 16
            for ci, (_label, key, _w, _req, _is_date) in enumerate(cols, start=1):
                # "action" is not a stored field: the column ships empty, for the
                # admin to fill in when they send the sheet back to Bulk Check
                # In/Out. Exporting a filtered set, typing check_in down the
                # column and uploading it is the whole point.
                val = "" if key == "action" else (item.get(key, "") or "")
                cell = ws.cell(row=ri, column=ci, value=val if val != "" else None)
                cell.alignment = Alignment(vertical="center")
                cell.number_format = "@"

        action_col = next((i for i, c in enumerate(cols, start=1) if c[1] == "action"), None)
        if action_col:
            letter = get_column_letter(action_col)
            dv = DataValidation(type="list", formula1=f'"{",".join(_ACTION_VALUES)}"',
                                allow_blank=True, showDropDown=False, showErrorMessage=True)
            dv.error      = "Leave blank to change nothing, or use one of: " + ", ".join(_ACTION_VALUES)
            dv.errorTitle = "Invalid action"
            ws.add_data_validation(dv)
            # Cover the exported rows plus room for anything pasted underneath.
            dv.add(f"{letter}2:{letter}{max(len(item_rows) + 1, 1000)}")

    all_items = _read()
    id_set    = set(ids) if ids else None
    filtered  = [i for i in all_items if id_set is None or i["id"] in id_set]

    # Group by category; blank category → "Uncategorized" (sorted last)
    groups: dict[str, list[dict]] = {}
    for item in filtered:
        cat = (item.get("category") or "").strip() or "Uncategorized"
        groups.setdefault(cat, []).append(item)

    sorted_cats = sorted(k for k in groups if k != "Uncategorized")
    if "Uncategorized" in groups:
        sorted_cats.append("Uncategorized")

    # A workbook with no sheets cannot be saved — openpyxl raises, which reached
    # the admin as a 500 whenever a selection matched nothing (every row in it
    # deleted by someone else, say).
    if not sorted_cats:
        raise HTTPException(
            status_code=404,
            detail="Nothing to export — none of those items are in the inventory."
            if ids else "Nothing to export — the inventory is empty.",
        )

    wb = Workbook()
    wb.remove(wb.active)   # remove default blank sheet
    for cat in sorted_cats:
        ws   = wb.create_sheet(title=_safe_sheet_name(cat))
        cols = _cols_for_category(cat)
        _write_sheet(ws, groups[cat], cols)

    today  = _date.today().isoformat()
    suffix = "_selected" if id_set else "_all"
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="inventory_export{suffix}_{today}.xlsx"'},
    )


# ── serve frontend ────────────────────────────────────────────────────────────

# A part number goes into the upstream URL, so what it may contain is the whole
# of this endpoint's attack surface. Unvalidated, "x?admin=1" adds a query
# string to the internal service and ".." climbs a path segment. Letters,
# digits, dot, dash and underscore cover every real DDR part number
# (MTC40F2047S1RC64BBZ, 100-000001263-02, M321R8GA0BB0-CQKVS). A scanned label's
# country segment arrives attached to the part number and the service has always
# been given it, written either as © or as a literal "(C)" — the inventory holds
# both spellings, so both are allowed. Parentheses cannot steer a URL. Everything
# that can — / ? # % & = : @ and whitespace — stays out.
_PART_NUMBER_RE = re.compile(r"^[A-Za-z0-9._()©-]{1,64}$")

# Answers are stable — a part number decodes to the same thing every time — so
# repeat lookups are served from memory and never leave the server. Misses are
# cached briefly too: without that, a bad part number typed in a loop is an
# amplifier pointed at the internal service.
_DECODE_TTL_SEC      = 24 * 3600
_DECODE_MISS_TTL_SEC = 600
_DECODE_CACHE_MAX    = 2000
_decode_cache: dict[str, tuple[float, dict | None]] = {}

# Only upstream calls are counted, so browsing cached part numbers is never
# limited. The ceiling exists because this endpoint takes no login — the same
# reasoning as _rate_limit_submission.
_DECODE_WINDOW_SEC      = 60
_MAX_DECODES_PER_WINDOW = 30
_decode_times: dict[str, list[float]] = {}
_decode_lock = _threading.Lock()


def _rate_limit_decode(client_ip: str) -> None:
    now = time.monotonic()
    with _decode_lock:
        if len(_decode_times) > 1000:        # keep the bookkeeping bounded
            _decode_times.clear()
        times = [t for t in _decode_times.get(client_ip, []) if now - t < _DECODE_WINDOW_SEC]
        if len(times) >= _MAX_DECODES_PER_WINDOW:
            _decode_times[client_ip] = times
            raise HTTPException(
                status_code=429,
                detail="Too many lookups just now. Wait a minute and try again.",
            )
        times.append(now)
        _decode_times[client_ip] = times


def _decode_cached(pn: str) -> dict | None | str:
    """Cached answer for *pn*: the payload, None for a known miss, "" if unknown."""
    hit = _decode_cache.get(pn)
    if not hit:
        return ""
    stored_at, payload = hit
    ttl = _DECODE_TTL_SEC if payload is not None else _DECODE_MISS_TTL_SEC
    if time.monotonic() - stored_at > ttl:
        _decode_cache.pop(pn, None)
        return ""
    return payload


def _decode_store(pn: str, payload: dict | None) -> None:
    if len(_decode_cache) >= _DECODE_CACHE_MAX:
        _decode_cache.clear()        # cheap eviction; the cache refills by use
    _decode_cache[pn] = (time.monotonic(), payload)


@app.get("/api/lookup-pn/{part_number}")
async def lookup_part_number(part_number: str, request: Request,
                             creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    """Proxy to ddrmpn.amd.com — full decode for a part number.

    Returns the cleaned rcd/pmic vendors plus `raw`, the decoder's whole
    response, which the Decoder tab renders.

    Open to everyone, like the inventory itself: looking up a part number is a
    read anyone in the lab has reason to do. What made it unsafe to leave open
    was not the lookup but the lack of limits around it — an unauthenticated
    passthrough onto an internal service, with the caller choosing the URL. The
    three guards above put that right: the part number is validated, repeat
    lookups never reach the service, and a client can only trigger
    _MAX_DECODES_PER_WINDOW upstream calls a minute. Writes stay admin-only.
    """
    import httpx
    pn = part_number.strip()
    if not pn:
        raise HTTPException(status_code=400, detail="Part number required")
    # ".." is the one traversal the charset would otherwise allow, since a dot is
    # legitimate in a part number; requiring a letter or digit rejects "---" and
    # friends for the same reason.
    if not _PART_NUMBER_RE.match(pn) or ".." in pn or not any(c.isalnum() for c in pn):
        raise HTTPException(
            status_code=400,
            detail="That is not a part number. Use letters, digits, dot, dash or underscore.",
        )

    cached = _decode_cached(pn)
    if cached != "":
        if cached is None:
            raise HTTPException(status_code=404, detail="Part number not found")
        return cached

    # The ceiling is there to stop an anonymous caller hammering an internal
    # service. It must not throttle the app's own work: "Refresh from decoder"
    # asks for every distinct part number at once — 117 of them here — and a
    # limit of _MAX_DECODES_PER_WINDOW silently dropped the rest on the floor,
    # which looked to the admin like the refresh simply not working.
    if not (creds and creds.credentials in _sessions):
        _rate_limit_decode(request.client.host if request.client else "unknown")

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(f"https://ddrmpn.amd.com/api/decode/{pn}")
        if resp.status_code == 404:
            _decode_store(pn, None)
            raise HTTPException(status_code=404, detail="Part number not found")
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Decoder service error")
        data = resp.json()
        rcd_raw  = data.get("RCD Vendor", "") or ""
        pmic_raw = data.get("PMIC Vendor", "") or ""
        # Strip WARNING/ERROR prefixes so only the vendor name is stored
        def _clean(val: str) -> str:
            if "WARNING!" in val or "ERROR!" in val:
                return ""
            return val.strip()
        payload = {"rcd": _clean(rcd_raw), "pmic": _clean(pmic_raw), "raw": data}
        _decode_store(pn, payload)
        return payload
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Decoder service timed out")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach decoder service: {e}")


# ── CPU decoder ───────────────────────────────────────────────────────────────
#
# The PPIN fuse on an AMD CPU encodes the part's serial number. ppin_sn.py holds
# the conversion and doubles as a command-line tool; the endpoints below are the
# same code behind the CPU Decoder tab.

class PpinIn(BaseModel):
    # Either bare PPINs or whole apml_tool output pasted in — the module pulls
    # the values out either way.
    text: str


class SutReadIn(BaseModel):
    host: str
    # None — the default — reads every socket the board answers for, so the
    # caller only has to know the system's name. A number pins one socket.
    socket: int | None = None


# A BMC hostname goes into an SSH connect, so it is held to the shape of a host
# name and nothing else: no spaces, no shell metacharacters, no URL.
_BMC_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_MAX_PPIN_TEXT = 20_000


@app.post("/api/cpu/decode-ppin")
def decode_ppins(body: PpinIn):
    """PPIN → CPU serial number. Open: this is arithmetic, not a lookup.

    Nothing leaves the server and nothing is stored, so there is no service to
    protect behind a login the way /api/lookup-pn needed guards.
    """
    from ppin_sn import DecodeUnavailable, decode_ppin, extract_ppins

    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Paste a PPIN or apml_tool output.")
    if len(text) > _MAX_PPIN_TEXT:
        raise HTTPException(status_code=413, detail="That is more text than apml_tool ever prints.")

    found = extract_ppins(text)
    if not found:
        raise HTTPException(
            status_code=422,
            detail="No PPIN found. A PPIN is 13-16 hex digits, e.g. 0x2b620df48c84013.",
        )

    results = []
    for label, ppin in found:
        try:
            results.append({"label": label, "ppin": ppin, "serial": decode_ppin(ppin)})
        except DecodeUnavailable as exc:
            results.append({"label": label, "ppin": ppin, "error": str(exc)})
    return {"results": results}


# Sockets tried when the caller names only the system. A second socket that is
# not populated makes apml_tool fail, which is an answer rather than an error —
# most boards here are 1P.
_DEFAULT_SOCKETS = (0, 1)

# Which systems this server will SSH to. Empty — the default — means any
# hostname, which is how the lab asked for it: anyone on the network can name a
# SUT and get its CPU serial number without logging in. Set BMC_HOST_ALLOW to a
# comma-separated list of glob patterns (e.g. "seagull-*,eagle-*") and the
# server will refuse everything else, so a stranger cannot point it at a host of
# their choosing. The BMC credentials live here, not in the browser, so without
# a list this endpoint will try them against whatever it is told to.
BMC_HOST_ALLOW = [p.strip().lower() for p in os.getenv("BMC_HOST_ALLOW", "").split(",") if p.strip()]

# Each call is an SSH session and two commands on a BMC, so it is costly in a
# way a decode is not. No login stands between a caller and that.
_SUT_WINDOW_SEC      = 60
_MAX_SUT_PER_WINDOW  = 10
_sut_times: dict[str, list[float]] = {}
_sut_lock = _threading.Lock()


def _rate_limit_sut(client_ip: str) -> None:
    now = time.monotonic()
    with _sut_lock:
        if len(_sut_times) > 1000:
            _sut_times.clear()
        times = [t for t in _sut_times.get(client_ip, []) if now - t < _SUT_WINDOW_SEC]
        if len(times) >= _MAX_SUT_PER_WINDOW:
            _sut_times[client_ip] = times
            raise HTTPException(
                status_code=429,
                detail="Too many systems read just now. Wait a minute and try again.",
            )
        times.append(now)
        _sut_times[client_ip] = times


# apml_tool colours its errors, and the escape codes are noise in a web page.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _apml_complaint(text: str) -> str:
    """The line of apml_tool output that actually says what went wrong.

    Its banners and rules come first, so the first non-blank line is almost
    never the message — on a 1P board it is "===== APML System Management
    Interface =====" rather than "SBRMI module not present".
    """
    for line in _strip_ansi(text).splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) <= set("=-|_ "):
            continue
        if "APML System Management Interface" in stripped or stripped.startswith("End of APML"):
            continue
        return stripped.strip("| ").strip()
    return ""


class SutReadError(Exception):
    """A SUT read failed in a way that has an HTTP status worth reporting.

    Raised by _read_sut_sockets, which has no request to answer and so cannot
    raise HTTPException itself. The endpoint turns this back into one; the
    nightly scan catches it per host instead, so one unreachable BMC does not
    end the run for the other ninety.
    """

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _read_sut_sockets(host: str, sockets: tuple[int, ...]) -> dict:
    """SSH to one BMC, run apml_tool per socket, decode what it prints.

    The actual work behind /api/cpu/read-sut, pulled out so run_audit_scan can
    read a system exactly the way a person asking for one does — same
    timeouts, same "same fuse on both sockets is one CPU" rule, same shape of
    skipped-socket reasons — without the two ever being free to drift apart.
    Raises SutReadError rather than HTTPException, since a background scan has
    no request to attach one to.
    """
    from ppin_sn import DecodeUnavailable, decode_ppin, extract_ppins

    if not BMC_PASSWORD:
        raise SutReadError(
            503, "No BMC password configured. Set BMC_USER / BMC_PASSWORD in .env and restart.")

    try:
        import paramiko
    except ImportError:
        raise SutReadError(
            503, "paramiko is not installed on the server. Run: pip install -r requirements.txt")

    client = paramiko.SSHClient()
    # Lab BMCs regenerate their host keys on reflash, so known_hosts is noise
    # here rather than protection.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=BMC_PORT, username=BMC_USER, password=BMC_PASSWORD,
                       timeout=BMC_TIMEOUT, banner_timeout=BMC_TIMEOUT, auth_timeout=BMC_TIMEOUT,
                       look_for_keys=False, allow_agent=False)
    except paramiko.AuthenticationException:
        raise SutReadError(502, f"{BMC_USER}@{host} refused those credentials.")
    except Exception as exc:
        raise SutReadError(502, f"Could not reach {host}:{BMC_PORT} - {exc}")

    results: list[dict] = []
    raw_by_socket: dict[str, str] = {}
    skipped:  list[dict] = []
    seen_ppins: set[str] = set()
    try:
        for socket_no in sockets:
            command = f"apml_tool {socket_no} --showppinfuse"
            try:
                _in, out, err = client.exec_command(command, timeout=BMC_TIMEOUT)
                raw = _strip_ansi(out.read().decode("utf-8", "replace")
                                  + err.read().decode("utf-8", "replace")).strip()
            except Exception as exc:
                skipped.append({"socket": socket_no, "reason": str(exc)})
                continue

            raw_by_socket[str(socket_no)] = raw
            found = extract_ppins(raw)
            if not found:
                skipped.append({"socket": socket_no,
                                "reason": _apml_complaint(raw) or "no PPIN in the output"})
                continue

            for label, ppin in found:
                # A board that reports the same fuse for both sockets should not
                # be read as two CPUs.
                if ppin in seen_ppins:
                    continue
                seen_ppins.add(ppin)
                row = {"socket": socket_no, "label": label, "ppin": ppin}
                try:
                    row["serial"] = decode_ppin(ppin)
                except DecodeUnavailable as exc:
                    row["error"] = str(exc)
                results.append(row)
    finally:
        client.close()

    if not results:
        detail = f"No CPU serial number came back from {host}."
        if skipped:
            detail += " " + "; ".join(f"socket {s['socket']}: {s['reason']}" for s in skipped)
        raise SutReadError(422, detail)

    return {"host": host, "results": results, "raw": raw_by_socket, "skipped": skipped}


@app.post("/api/cpu/read-sut")
def read_sut_ppin(body: SutReadIn, request: Request):
    """Name a system, get its CPU serial numbers.

    SSHes to the BMC, runs apml_tool per socket, and decodes what it prints —
    one connection for the lot. With no socket given it reads every socket the
    board answers for, so the caller needs to know nothing but the SUT name.

    Open to the lab, like the rest of the app. Worth being clear about what
    that means: the server holds the BMC credentials and will use them against
    the host it is given, so anyone who can reach this port can have it log in
    to a system and read a fuse. BMC_HOST_ALLOW narrows which hosts that can
    be, and the rate limit caps how fast; neither is a substitute for the
    network this runs on being a lab network.

    Credentials come from BMC_USER / BMC_PASSWORD in .env — never from the
    browser, which would put a root password on the wire in clear.
    """
    host = (body.host or "").strip()
    if not _BMC_HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="That is not a hostname.")
    if BMC_HOST_ALLOW and not any(fnmatch(host.lower(), pattern) for pattern in BMC_HOST_ALLOW):
        raise HTTPException(
            status_code=403,
            detail=f"This server only reads {', '.join(BMC_HOST_ALLOW)}.",
        )
    if body.socket is not None and not 0 <= body.socket <= 7:
        raise HTTPException(status_code=400, detail="Socket must be 0-7.")
    _rate_limit_sut(request.client.host if request.client else "unknown")

    sockets = (body.socket,) if body.socket is not None else _DEFAULT_SOCKETS
    try:
        return _read_sut_sockets(host, sockets)
    except SutReadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


# ── nightly CPU audit scan ───────────────────────────────────────────────────
#
# Reads every system in AUDIT_SYSTEMS_CSV, matches each CPU it finds against
# the inventory the same way the CPU Decoder tab's "Against your inventory"
# panel does, and records where and when it was seen — on the item itself
# (the latest sighting) and in cpu_audit_log (every sighting, which is the
# trail a single field cannot hold).

_CPU_SERIAL_SEPARATORS = ("_", "-", " ", ":", "/")


def _find_cpu_by_serial(serial: str, by_serial: dict[str, dict], all_items: list[dict]) -> dict | None:
    """The inventory item a decoded PPIN belongs to, if any.

    Ports _findCpuBySerial from the CPU Decoder panel in static/index.html —
    same rule, so a scan finds exactly what a person reading the same system
    by hand would see on screen. A PPIN decodes to the bare CPU serial, but
    this inventory records CPUs as <serial>_<part number>-<rev>, so an exact
    match is tried first and a stored value that starts with the decoded
    serial and continues with a separator is tried second. The separator is
    required: a different serial that merely starts the same way must not
    match.
    """
    target = (serial or "").strip().lower()
    if not target:
        return None
    exact = by_serial.get(target)
    if exact is not None:
        return exact
    for item in all_items:
        stored = str(item.get("serial_number") or "").strip().lower()
        if (len(stored) > len(target) and stored.startswith(target)
                and stored[len(target)] in _CPU_SERIAL_SEPARATORS):
            return item
    return None


def _record_audit_log(rows: list[dict], kind: str = "cpu") -> None:
    """One row per CPU (or DIMM) a scan looked at, matched or not.

    This is what makes the trail possible: `audit` on the item is overwritten
    on every scan, so by itself it can only ever answer "where was this last
    seen". Kept forever — nothing here prunes it, since thinning out a lab's
    audit trail on its behalf is exactly the kind of decision that should not
    be made silently. `kind` tells the two scans apart in the shared table —
    see the schema-migration comment above _init_db's ALTER TABLE for why this
    is one table with a discriminator rather than two.
    """
    if not rows:
        return
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.executemany(
                "INSERT INTO cpu_audit_log (id, item_id, serial_number, host, found, scanned_at, kind) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(uuid.uuid4().hex, r.get("item_id"), r["serial"], r["host"],
                  1 if r["found"] else 0, _now(), kind) for r in rows],
            )
            conn.commit()


def _record_scan_run(summary: dict, kind: str = "cpu") -> None:
    """One row per completed run, so "what failed last night" survives past
    the one response that first reported it.

    The DIMM scan reuses the same cpus_seen/cpus_matched/cpus_unmatched
    columns for its own per-DIMM counts (see the `kind` column) rather than
    adding dimms_seen/dimms_matched/dimms_unmatched — same numbers, just
    counting a different kind of part; `kind` plus the UI's own label is what
    tells a reader which.
    """
    with _DB_LOCK:
        with _db_connect() as conn:
            conn.execute(
                "INSERT INTO audit_scan_runs "
                "(id, started_at, elapsed_sec, hosts_total, hosts_ok, cpus_seen, "
                " cpus_matched, cpus_unmatched, hosts_failed_json, error, kind) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, summary.get("started_at", _now()), summary.get("elapsed_sec"),
                 summary.get("hosts_total", 0), summary.get("hosts_ok", 0), summary.get("cpus_seen", 0),
                 summary.get("cpus_matched", 0), summary.get("cpus_unmatched", 0),
                 json.dumps(summary.get("hosts_failed", [])), summary.get("error"), kind),
            )
            conn.commit()


def _read_audit_systems_csv(path: str) -> list[str]:
    """Hostnames to scan tonight, one per non-blank line after the header.

    A missing or unreadable file disables the scan with a reason in the
    console log rather than crashing the server at import time or at
    midnight — a typo'd path, or a file that has not been re-exported yet,
    should be a quiet no-op, not an outage.
    """
    hosts: list[str] = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if not row:
                    continue
                name = row[0].strip()
                if not name or name.lower() == "name":
                    continue
                hosts.append(name)
    except OSError as exc:
        print(f"[AUDIT] could not read {path}: {exc}", flush=True)
        return []
    return list(dict.fromkeys(hosts))   # de-duplicate, keep first-seen order


# Guards against the nightly tick and a manual "run now" click overlapping,
# which would have two scans SSH into the same ninety-odd BMCs at once.
_audit_scan_lock = _threading.Lock()


def run_audit_scan() -> dict:
    """Scan every system in AUDIT_SYSTEMS_CSV; return a summary of what happened.

    One bad host — unreachable, wrong credentials, nothing plugged into that
    socket — is recorded as a failure and does not stop the rest of the list;
    with ninety-odd systems, something is always down. Reachable from the
    scheduled loop below and from POST /api/admin/audit-scan/run, so the
    system list can be checked by hand without waiting for the clock.
    """
    if not _audit_scan_lock.acquire(blocking=False):
        return {"error": "An audit scan is already running."}
    try:
        started = time.monotonic()
        hosts = _read_audit_systems_csv(AUDIT_SYSTEMS_CSV)
        today = _date.today().isoformat()
        summary = {
            "started_at": _now(), "hosts_total": len(hosts), "hosts_ok": 0,
            "hosts_failed": [], "cpus_seen": 0, "cpus_matched": 0, "cpus_unmatched": 0,
        }
        if not hosts:
            summary["error"] = f"No hostnames found in {AUDIT_SYSTEMS_CSV}."
            print(f"[AUDIT] {summary['error']}", flush=True)
            _record_scan_run(summary)
            return summary

        # Read once for the whole run rather than per host: matching ninety
        # systems' worth of CPUs against a list re-read each time would be
        # ninety full table scans for data that cannot change mid-run (nothing
        # else writes serial_number while a scan is in progress).
        all_items = _read()
        by_serial: dict[str, dict] = {}
        for it in all_items:
            sn = str(it.get("serial_number") or "").strip().lower()
            if sn:
                by_serial[sn] = it

        for host in hosts:
            if not _BMC_HOST_RE.match(host):
                summary["hosts_failed"].append({"host": host, "error": "not a hostname shape"})
                continue
            if BMC_HOST_ALLOW and not any(fnmatch(host.lower(), p) for p in BMC_HOST_ALLOW):
                summary["hosts_failed"].append({"host": host, "error": "outside BMC_HOST_ALLOW"})
                continue

            try:
                data = _read_sut_sockets(host, _DEFAULT_SOCKETS)
            except SutReadError as exc:
                summary["hosts_failed"].append({"host": host, "error": exc.detail})
                if AUDIT_SCAN_HOST_DELAY_SEC:
                    time.sleep(AUDIT_SCAN_HOST_DELAY_SEC)
                continue

            summary["hosts_ok"] += 1
            matched_ids: list[str] = []
            log_rows: list[dict] = []
            for r in data["results"]:
                serial = r.get("serial")
                if not serial:
                    continue
                summary["cpus_seen"] += 1
                hit = _find_cpu_by_serial(serial, by_serial, all_items)
                if hit:
                    summary["cpus_matched"] += 1
                    matched_ids.append(hit["id"])
                else:
                    summary["cpus_unmatched"] += 1
                log_rows.append({
                    "item_id": hit["id"] if hit else None,
                    "serial": serial, "host": host, "found": bool(hit),
                })

            if matched_ids:
                note = f"{host} · {today}"
                try:
                    _apply_audit_fields(list(dict.fromkeys(matched_ids)), note)
                except _BatchRowsGone as gone:
                    summary["hosts_failed"].append({
                        "host": host,
                        "error": f"{len(gone.ids)} matched item(s) were deleted mid-scan",
                    })
            if log_rows:
                _record_audit_log(log_rows)

            if AUDIT_SCAN_HOST_DELAY_SEC:
                time.sleep(AUDIT_SCAN_HOST_DELAY_SEC)

        summary["elapsed_sec"] = round(time.monotonic() - started, 1)
        print(f"[AUDIT] scan done in {summary['elapsed_sec']}s: "
              f"{summary['hosts_ok']}/{summary['hosts_total']} host(s) ok, "
              f"{summary['cpus_matched']}/{summary['cpus_seen']} CPU(s) matched, "
              f"{len(summary['hosts_failed'])} host(s) failed", flush=True)
        _record_scan_run(summary)
        return summary
    finally:
        _audit_scan_lock.release()


@app.post("/api/admin/audit-scan/run", dependencies=[Depends(_require_admin)])
def trigger_audit_scan():
    """Run the nightly scan now, instead of waiting for 00:30.

    A plain `def` route, so FastAPI runs it in its worker thread pool rather
    than on the event loop — a scan of ninety systems can take a couple of
    minutes, and the rest of the app must stay responsive while it does.
    """
    return run_audit_scan()


async def _audit_scan_loop() -> None:
    """Wake at AUDIT_SCAN_HOUR:AUDIT_SCAN_MINUTE every day and run the scan.

    Recomputes "tomorrow at 00:30" fresh after every wake rather than sleeping
    in one 24-hour block, so a clock change or a scan that overran does not
    leave it waiting a day and a half (or ten minutes) for the next one. If
    the server is not running at 00:30 — the machine is off, or it was
    restarted — that night's scan simply does not happen; nothing here
    catches up on a missed day, since a scan run hours late would record a
    time nobody actually saw those CPUs.
    """
    while True:
        now = datetime.now()
        target = now.replace(hour=AUDIT_SCAN_HOUR, minute=AUDIT_SCAN_MINUTE, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        wait_s = (target - now).total_seconds()
        print(f"[AUDIT] next scan at {target.isoformat(sep=' ', timespec='minutes')} "
              f"({wait_s / 3600:.1f}h)", flush=True)
        await asyncio.sleep(wait_s)
        try:
            # SSH and sqlite calls below are blocking; run_audit_scan in a
            # worker thread so a multi-minute scan does not stall every other
            # request the server is handling meanwhile.
            await asyncio.to_thread(run_audit_scan)
        except Exception as exc:
            print(f"[AUDIT] scan failed: {exc}", flush=True)


# ── nightly DIMM audit scan ──────────────────────────────────────────────────
#
# Twin of the CPU scan above: same CSV, same `audit` column, same per-host
# failure isolation — but for DIMMs, which needs an OS IP that the CPU scan
# never does (apml_tool is read straight off the BMC; dmidecode has to run on
# the OS itself). Ported from two reference scripts — get_os_ip_sol.py
# (SOL-console OS-IP discovery) and check_os_dimm.py (Redfish-first OS-IP
# discovery plus the dmidecode pull) — and the project they both import
# (`FVDDR system information`'s server.py) for the pieces that come from
# there: _DIMM_SCRIPT, _ssh_run_script, the OS credential cascade (see
# _os_credential_cascade), and the legacy-SSH-algorithm options. Adapted to
# run natively here rather than depending on that project at runtime.

try:
    import asyncssh
    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False

# Python 3.14 compatibility: asyncssh's saslprep passes whole strings to
# stringprep.in_table_*/map_table_* functions that now strictly require a
# single character. Patch every affected function in the stringprep module at
# once rather than only the ones a particular login happens to exercise.
try:
    import stringprep as _stringprep

    def _stringprep_patch(fn):
        def _safe(c):
            if len(c) == 1:
                return fn(c)
            results = [fn(ch) for ch in c]
            if results and isinstance(results[0], str):
                return "".join(r if r is not None else ch for r, ch in zip(results, c))
            return any(results)
        return _safe

    for _fn_name in dir(_stringprep):
        if _fn_name.startswith("in_table_") or _fn_name.startswith("map_table_"):
            _orig_fn = getattr(_stringprep, _fn_name)
            if callable(_orig_fn):
                setattr(_stringprep, _fn_name, _stringprep_patch(_orig_fn))
    del _fn_name, _orig_fn
except Exception:
    pass

def _os_credential_cascade() -> list[tuple[str, str]]:
    """OS login(s) tried in order, from OS_LOGIN_1_USER/PASSWORD .. _3_, same
    numbered-slot pattern as the admin accounts above."""
    creds: list[tuple[str, str]] = []
    for u, p in ((OS_LOGIN_1_USER, OS_LOGIN_1_PASSWORD),
                 (OS_LOGIN_2_USER, OS_LOGIN_2_PASSWORD),
                 (OS_LOGIN_3_USER, OS_LOGIN_3_PASSWORD)):
        if u and (u, p) not in creds:
            creds.append((u, p))
    return creds


_LEGACY_SSH_CIPHERS  = ["aes128-cbc", "aes256-cbc", "3des-cbc", "aes128-ctr", "aes256-ctr"]
_LEGACY_SSH_HOSTKEYS = ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512"]


def _legacy_ssh_algs(legacy: list, default_getter) -> list:
    """Legacy algorithms first — what these old embedded SSH servers (BMC
    consoles, dropbear-based shells) actually speak — then asyncssh's own
    defaults appended so a host offering only a modern algorithm is still
    reachable. Naming the list explicitly replaces asyncssh's defaults rather
    than extending them, which is what makes an old box fail the handshake
    otherwise."""
    try:
        defaults = [a.decode() if isinstance(a, bytes) else a for a in default_getter()]
    except Exception:
        return list(legacy)
    return list(legacy) + [a for a in defaults if a not in legacy]


def _build_legacy_ssh_opts() -> dict:
    opts = dict(known_hosts=None, connect_timeout=10,
                preferred_auth=["password", "keyboard-interactive"])
    try:
        from asyncssh.encryption import get_default_encryption_algs
        opts["encryption_algs"] = _legacy_ssh_algs(_LEGACY_SSH_CIPHERS, get_default_encryption_algs)
    except Exception:
        opts["encryption_algs"] = list(_LEGACY_SSH_CIPHERS)
    try:
        from asyncssh.public_key import get_default_public_key_algs
        opts["server_host_key_algs"] = _legacy_ssh_algs(_LEGACY_SSH_HOSTKEYS, get_default_public_key_algs)
    except Exception:
        opts["server_host_key_algs"] = list(_LEGACY_SSH_HOSTKEYS)
    return opts


_LEGACY_SSH_OPTS = _build_legacy_ssh_opts() if HAS_ASYNCSSH else {}


async def _ssh_run_script(ip: str, username: str, password: str, script: str,
                           env: dict | None = None, timeout: float = 60) -> tuple[str, str]:
    """SSH into ip, pipe script to python3 via stdin, return (stdout, stderr)."""
    env_prefix = " ".join(f"{k}={v}" for k, v in (env or {}).items())
    cmd = f"{env_prefix} python3 -" if env_prefix else "python3 -"
    async with asyncssh.connect(ip, username=username, password=password,
                                 **_LEGACY_SSH_OPTS) as conn:
        result = await conn.run(cmd, input=script, timeout=timeout)
        return (result.stdout or ""), (result.stderr or "")


# Remote script, run over SSH on the OS itself. dmidecode-only, by design: the
# original also offered to modprobe an EDAC kernel module when it was not
# already loaded, which is not a read-only operation — that fallback is
# dropped here (see parse_edac), so ce_count/ue_count are simply omitted when
# EDAC isn't already up rather than this server loading a kernel module on
# someone's SUT.
_DIMM_SCRIPT = r'''
import os, re, json, subprocess

def _sysfs(p):
    try: return open(p).read().strip()
    except: return ""

def _cmd(c):
    return subprocess.run(["which",c],capture_output=True).returncode==0

def is_os_booted():
    return (os.path.exists("/sys/firmware/dmi/tables/DMI") or os.path.exists("/dev/mem")) and _cmd("dmidecode")

def parse_dmidecode():
    try: out=subprocess.check_output(["dmidecode","-t","17"],text=True,stderr=subprocess.DEVNULL)
    except: return []
    dimms,cur=[],None
    FM=[("Locator","locator"),("Bank Locator","bank_locator"),
        ("Size","size"),("Speed","speed"),
        ("Configured Memory Speed","configured_speed"),
        ("Configured Clock Speed","configured_speed"),
        ("Configured Speed","configured_speed"),
        ("Manufacturer","manufacturer"),("Part Number","part_number"),
        ("Serial Number","serial"),("Type","dimm_type")]
    all_attrs=list(dict.fromkeys(a for _,a in FM))
    for line in out.splitlines():
        line=line.strip()
        if line=="Memory Device":
            if cur: dimms.append(cur)
            cur={a:"" for a in all_attrs}
            cur.update({"populated":False,"ce_count":0,"ue_count":0,"edac_mc":"","source":"dmidecode"})
            continue
        if cur is None: continue
        for lbl,attr in FM:
            if line.startswith(f"{lbl}:"):
                cur[attr]=line.split(":",1)[1].strip(); break
    if cur: dimms.append(cur)
    for d in dimms:
        d["populated"]=bool(d["size"]) and "No Module" not in d["size"]
        import re as _re
        bl=d.get("bank_locator","").strip()
        m=_re.search(r"[Cc]hannel(\d+)",bl)
        if m:
            d["bank_locator"]=f"Ch {m.group(1)}"
        elif not bl or bl.lower() in ("unknown","not provided","none"):
            m=_re.search(r"DIMM[_ -]?([A-H])\d*",d.get("locator",""),_re.I)
            d["bank_locator"]=f"Ch {m.group(1).upper()}" if m else ""
        if not d.get("configured_speed"):
            d["configured_speed"]=d.get("speed","")
    return dimms

def parse_edac():
    base="/sys/devices/system/edac/mc"
    edac=[]
    if not os.path.isdir(base): return edac
    for mc in sorted(os.listdir(base)):
        mp=os.path.join(base,mc)
        if not mc.startswith("mc") or not os.path.isdir(mp): continue
        for dimm in sorted(os.listdir(mp)):
            dp=os.path.join(mp,dimm)
            if not dimm.startswith("dimm") or not os.path.isdir(dp): continue
            sz=_sysfs(os.path.join(dp,"size"))
            edac.append({"mc":mc,"label":_sysfs(os.path.join(dp,"dimm_label")),
                "ce":int(_sysfs(os.path.join(dp,"dimm_ce_count")) or 0),
                "ue":int(_sysfs(os.path.join(dp,"dimm_ue_count")) or 0),
                "populated":int(sz)>0 if sz.isdigit() else False})
    return edac

def parse_ipmi(bmc_ip,user,pw):
    if not _cmd("ipmitool"): return []
    def run(args):
        base=["ipmitool","-I","lanplus","-H",bmc_ip,"-U",user,"-P",pw] if bmc_ip else ["ipmitool"]
        try: return subprocess.check_output(base+args,text=True,stderr=subprocess.DEVNULL)
        except: return ""
    dimms=[]; cur_fru={}; locator=""
    for line in run(["fru","list"]).splitlines():
        m=re.match(r"FRU Device Description\s*:\s*(.+)",line)
        if m:
            if cur_fru and "DIMM" in locator.upper():
                dimms.append({"locator":locator,"manufacturer":cur_fru.get("Board Mfg",""),
                    "part_number":cur_fru.get("Board Part Number",""),"serial":cur_fru.get("Board Serial",""),
                    "size":"","speed":"","dimm_type":"","populated":True,"source":"ipmi","ce_count":0,"ue_count":0,"edac_mc":""})
            locator=m.group(1).strip(); cur_fru={}
        for k in ["Board Mfg","Board Part Number","Board Serial"]:
            if line.strip().startswith(k+" :"):
                cur_fru[k]=line.split(":",1)[1].strip()
    if cur_fru and "DIMM" in locator.upper():
        dimms.append({"locator":locator,"manufacturer":cur_fru.get("Board Mfg",""),
            "part_number":cur_fru.get("Board Part Number",""),"serial":cur_fru.get("Board Serial",""),
            "size":"","speed":"","dimm_type":"","populated":True,"source":"ipmi","ce_count":0,"ue_count":0,"edac_mc":""})
    return dimms

FORCE_REMOTE=__import__("os").environ.get("DIMM_FORCE_REMOTE","0")=="1"
BMC_IP=__import__("os").environ.get("DIMM_BMC_IP","")
BMC_USER=__import__("os").environ.get("DIMM_BMC_USER","root")
BMC_PASS=__import__("os").environ.get("DIMM_BMC_PASS","")

if not FORCE_REMOTE and is_os_booted():
    dimms=parse_dmidecode()
    edac=parse_edac()
    by_label={e["label"].strip():e for e in edac if e["label"]}
    for d in dimms:
        e=by_label.get(d["locator"].strip())
        if e:
            d["ce_count"]=e["ce"]; d["ue_count"]=e["ue"]; d["edac_mc"]=e["mc"]
            d["source"]="dmidecode+edac"
    method="dmidecode+edac" if edac else "dmidecode"
else:
    dimms=parse_ipmi(BMC_IP,BMC_USER,BMC_PASS)
    method="ipmi"

populated=[d for d in dimms if d["populated"]]
edac_any=any("edac" in d.get("source","") for d in populated)
print(json.dumps({
    "detection_method":method,
    "total_slots":len(dimms),"populated":len(populated),"empty":len(dimms)-len(populated),
    "edac_available":edac_any,
    "ce_errors":sum(d["ce_count"] for d in populated),
    "ue_errors":sum(d["ue_count"] for d in populated),
    "dimms":[{"locator":d["locator"],"bank_locator":d.get("bank_locator",""),
        "size":d["size"],"speed":d["speed"],"configured_speed":d.get("configured_speed",""),
        "manufacturer":d["manufacturer"],"part_number":d["part_number"],
        "serial":d["serial"],"type":d.get("dimm_type",""),"source":d.get("source",""),
        "edac_mc":d["edac_mc"],"ce_count":d["ce_count"],"ue_count":d["ue_count"]} for d in populated]
}))
'''


def _is_routable_ip(addr: str) -> bool:
    return bool(addr) and not addr.startswith("127.") and not addr.startswith("169.254.")


def _bmc_system_resource(client, bmc_ip: str) -> tuple[str, dict]:
    """Return (path, json) of the Redfish ComputerSystem resource.

    Tries dynamic discovery via the Systems collection first, then a few
    fixed paths known to work on this fleet — ported from check_os_dimm.py's
    _system_resource.
    """
    base = f"https://{bmc_ip}"
    candidates = ["/redfish/v1/Systems/system", "/redfish/v1/Systems/Device", "/redfish/v1/Systems/1"]
    try:
        col = client.get(f"{base}/redfish/v1/Systems", timeout=10)
        col.raise_for_status()
        members = col.json().get("Members", [])
        if members:
            first = members[0].get("@odata.id", "")
            if first:
                candidates.insert(0, first)
    except Exception:
        pass
    for path in dict.fromkeys(candidates):
        try:
            r = client.get(f"{base}{path}", timeout=10)
            if r.status_code == 200:
                return path, r.json()
        except Exception:
            continue
    return "", {}


def _discover_os_ip_redfish(host: str) -> tuple[str, str]:
    """(os_ip, power_state) via the BMC's Redfish API, or ("", "?") if the BMC
    itself could not be reached over Redfish.

    Ported from check_os_dimm.py's _system_resource/_discover_os_ip, onto
    httpx (already a dependency here) instead of requests. Same BMC
    credentials the rest of this server already uses.
    """
    import httpx
    with httpx.Client(verify=False, auth=(BMC_USER, BMC_PASSWORD)) as client:
        sys_path, sys_data = _bmc_system_resource(client, host)
        if not sys_path:
            return "", "?"
        power = sys_data.get("PowerState") or "?"
        if power.lower() != "on":
            return "", power

        base = f"https://{host}"
        eth_link = (sys_data.get("EthernetInterfaces") or {}).get("@odata.id", "")
        if not eth_link:
            eth_link = sys_path.rstrip("/") + "/EthernetInterfaces"
        try:
            col = client.get(f"{base}{eth_link}", timeout=10)
            col.raise_for_status()
            members = col.json().get("Members", [])
        except Exception:
            return "", power

        for member in members:
            iface_url = member.get("@odata.id", "")
            if not iface_url:
                continue
            try:
                r = client.get(f"{base}{iface_url}", timeout=10)
                if r.status_code != 200:
                    continue
                data = r.json()
                if (data.get("InterfaceEnabled") is False
                        or (data.get("LinkStatus") or "").lower() == "nolink"):
                    continue
                for entry in (data.get("IPv4Addresses") or []):
                    addr = entry.get("Address", "")
                    if _is_routable_ip(addr):
                        return addr, power
            except Exception:
                continue
        return "", power


# ── SOL-console fallback ──────────────────────────────────────────────────
#
# Only used when DIMM_SOL_FALLBACK_ENABLED is set and Redfish exposed no host
# NIC — real on this fleet (see the user's own screenshots: some boards sit
# at a console login prompt with no IP visible until you log in and read it
# off the OS's own MOTD). Ported from get_os_ip_sol.py.

_SOL_SSH_PORT = 2200
_SOL_BEGIN, _SOL_END = "FVDDRIP_BEGIN", "FVDDRIP_END"
_SOL_PROBE_CMD = (
    'echo FVDDR"IP_BEGIN"; '
    'ip -4 -o addr show scope global 2>/dev/null '
    '|| /sbin/ip -4 -o addr show scope global 2>/dev/null '
    '|| hostname -I 2>/dev/null; '
    'echo FVDDR"IP_END"'
)

_SOL_ANSI_RE      = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][B0]|\r")
_SOL_PROMPT_RE    = re.compile(r"[#$>]\s*$")
_SOL_LOGIN_RE     = re.compile(r"(?:^|\n)[^\n]*login:\s*$", re.I)
_SOL_PASSWORD_RE  = re.compile(r"password:\s*$", re.I)
_SOL_BAD_LOGIN_RE = re.compile(r"login incorrect|authentication failure", re.I)
_SOL_IP_LINE_RE   = re.compile(r"^\s*\d+:\s*(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)")
_SOL_BARE_IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SOL_SKIP_IFACE_RE = re.compile(r"^(lo|docker|virbr|br-|veth|cni|flannel|kube|tun|tap)", re.I)


def _sol_clean(text: str) -> str:
    return _SOL_ANSI_RE.sub("", text)


class _Console:
    """Minimal duplex pipe to a serial console: send/drain/read_until/close.

    Wraps either an asyncssh process (OpenBMC console SSH) or a local
    ipmitool subprocess, so the expect logic below does not care which one
    it got.
    """

    def __init__(self, label: str):
        self.label = label
        self.transcript = ""
        self._buf = ""

    async def _write_raw(self, data: str) -> None:
        raise NotImplementedError

    async def _read_raw(self, timeout: float) -> str:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def send(self, line: str = "", newline: str = "\r") -> None:
        await self._write_raw(line + newline)

    async def drain(self, settle: float = 1.0) -> str:
        out = ""
        while True:
            try:
                chunk = await self._read_raw(settle)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            out += chunk
        self._record(out)
        return out

    async def read_until(self, patterns: list, timeout: float = 15.0) -> tuple[str, int]:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while True:
            for i, pat in enumerate(patterns):
                if pat.search(self._buf):
                    buf, self._buf = self._buf, ""
                    return buf, i
            remaining = deadline - loop.time()
            if remaining <= 0:
                buf, self._buf = self._buf, ""
                return buf, -1
            try:
                chunk = await self._read_raw(min(remaining, 2.0))
            except asyncio.TimeoutError:
                continue
            if not chunk:
                buf, self._buf = self._buf, ""
                return buf, -1
            self._buf += _sol_clean(chunk)
            self._record(chunk)

    def _record(self, chunk: str) -> None:
        if chunk:
            self.transcript += _sol_clean(chunk)
            if len(self.transcript) > 20000:
                self.transcript = self.transcript[-20000:]


class _SshConsole(_Console):
    """SOL over asyncssh — OpenBMC port 2200, or obmc-console-client on 22."""

    def __init__(self, label: str, conn, proc):
        super().__init__(label)
        self._conn, self._proc = conn, proc

    async def _write_raw(self, data: str) -> None:
        self._proc.stdin.write(data)
        await self._proc.stdin.drain()

    async def _read_raw(self, timeout: float) -> str:
        data = await asyncio.wait_for(self._proc.stdout.read(4096), timeout)
        return data if isinstance(data, str) else data.decode("utf-8", "replace")

    async def close(self) -> None:
        for closer in (self._proc.close, self._conn.close):
            try:
                closer()
            except Exception:
                pass
        try:
            await self._conn.wait_closed()
        except Exception:
            pass


class _IpmiConsole(_Console):
    """SOL via a local `ipmitool ... sol activate` subprocess."""

    def __init__(self, label: str, proc):
        super().__init__(label)
        self._proc = proc

    async def _write_raw(self, data: str) -> None:
        self._proc.stdin.write(data.encode())
        await self._proc.stdin.drain()

    async def _read_raw(self, timeout: float) -> str:
        data = await asyncio.wait_for(self._proc.stdout.read(4096), timeout)
        return data.decode("utf-8", "replace")

    async def close(self) -> None:
        try:
            self._proc.stdin.write(b"~.")
            await self._proc.stdin.drain()
            await asyncio.wait_for(self._proc.wait(), 5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


async def _open_ssh_console(bmc_ip: str, port: int, command: str | None, label: str) -> _Console:
    conn = await asyncssh.connect(bmc_ip, port=port, username=BMC_USER,
                                   password=BMC_PASSWORD, **_LEGACY_SSH_OPTS)
    try:
        proc = await conn.create_process(command, term_type="vt100",
                                          term_size=(200, 50), encoding="utf-8")
    except Exception:
        conn.close()
        raise
    return _SshConsole(label, conn, proc)


async def _open_ipmi_console(bmc_ip: str) -> _Console:
    import shutil
    if not shutil.which("ipmitool"):
        raise RuntimeError("ipmitool not on PATH")
    proc = await asyncio.create_subprocess_exec(
        "ipmitool", "-I", "lanplus", "-H", bmc_ip, "-U", BMC_USER,
        "-P", BMC_PASSWORD, "sol", "activate",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT)
    con = _IpmiConsole(f"ipmitool sol activate {bmc_ip}", proc)
    # ipmitool fails fast and loudly (SOL already active, auth, unreachable);
    # give it a moment and treat an early exit as "this transport is out".
    await asyncio.sleep(1.5)
    if proc.returncode is not None:
        out = await proc.stdout.read()
        raise RuntimeError((out.decode("utf-8", "replace").strip() or
                            "ipmitool exited immediately")[:200])
    return con


async def _open_console(bmc_ip: str, log: list) -> _Console:
    """Try the SOL console transports in order; return the first that opens."""
    attempts = [
        ("ssh2200", lambda: _open_ssh_console(bmc_ip, _SOL_SSH_PORT, None,
                                               f"ssh -p {_SOL_SSH_PORT} root@{bmc_ip}")),
        ("obmc",    lambda: _open_ssh_console(bmc_ip, 22, "obmc-console-client",
                                               f"ssh root@{bmc_ip} obmc-console-client")),
        ("ipmi",    lambda: _open_ipmi_console(bmc_ip)),
    ]
    errors = []
    for name, opener in attempts:
        try:
            con = await opener()
            log.append(f"console opened via {name}: {con.label}")
            return con
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            log.append(f"{name} failed — {msg}")
            errors.append(f"{name}: {msg}")
    raise RuntimeError("no console transport worked — " + " | ".join(errors))


async def _reach_shell(con: _Console, creds: list, log: list) -> tuple[bool, bool, str]:
    """Get the console to a shell prompt, logging in if it is sitting at a
    login prompt. Returns (at_shell, we_logged_in, detail) — we_logged_in
    tells the caller whether to log back out afterwards."""
    await con.drain(settle=1.0)
    await con.send("")
    buf, hit = await con.read_until([_SOL_PROMPT_RE, _SOL_PASSWORD_RE, _SOL_LOGIN_RE], timeout=8)

    if hit == 0:
        log.append("console already at a shell prompt")
        return True, False, ""
    if hit == 1:
        log.append("console sitting at a password prompt — resetting it")
        await con.send("")
        buf, hit = await con.read_until([_SOL_PROMPT_RE, _SOL_LOGIN_RE], timeout=8)
        if hit == 0:
            return True, False, ""
        hit = 2 if hit == 1 else -1
    if hit != 2:
        tail = " ".join(buf.split())[-160:]
        log.append(f"no prompt within 8s; console tail: {tail!r}")
        return False, False, (f"console gave no shell or login prompt — last output: {tail!r}"
                               if tail else "console is silent (host powered off, pre-boot, or hung?)")

    for user, pw in creds:
        log.append(f"login attempt as {user}")
        await con.send(user)
        buf, hit = await con.read_until([_SOL_PASSWORD_RE, _SOL_PROMPT_RE, _SOL_BAD_LOGIN_RE], timeout=10)
        if hit == 1:
            log.append(f"logged in as {user} (no password asked)")
            return True, True, ""
        if hit != 0:
            log.append("no password prompt — retrying")
            await con.send("")
            await con.read_until([_SOL_LOGIN_RE], timeout=5)
            continue
        await con.send(pw)
        buf, hit = await con.read_until([_SOL_PROMPT_RE, _SOL_BAD_LOGIN_RE, _SOL_LOGIN_RE], timeout=15)
        if hit == 0:
            log.append(f"logged in as {user}")
            return True, True, ""
        log.append(f"login as {user} rejected")
        await con.read_until([_SOL_LOGIN_RE], timeout=8)
    return False, False, f"console login failed for all credentials ({', '.join(u for u, _ in creds)})"


def _sol_parse_ips(block: str) -> list:
    """Pull (iface, ip, prefix) out of `ip -4 -o addr` output between markers."""
    found = []
    for line in block.splitlines():
        line = line.strip()
        if not line or _SOL_BEGIN in line or _SOL_END in line:
            continue
        m = _SOL_IP_LINE_RE.match(line)
        if m:
            iface, addr, prefix = m.group(1).split("@")[0], m.group(2), m.group(3)
            if _SOL_SKIP_IFACE_RE.match(iface) or not _is_routable_ip(addr):
                continue
            found.append({"iface": iface, "ip": addr, "prefix": int(prefix)})
            continue
        if line.startswith(("ip ", "/sbin/ip ", "echo ")) or 'FVDDR"' in line:
            continue
        for addr in _SOL_BARE_IP_RE.findall(line):
            if _is_routable_ip(addr) and all(f["ip"] != addr for f in found):
                found.append({"iface": "", "ip": addr, "prefix": 0})
    return found


async def _probe_ips(con: _Console, log: list) -> list:
    await con.send(_SOL_PROBE_CMD)
    end_marker = re.compile(re.escape(_SOL_END) + r"[^\n]*\n")
    buf, hit = await con.read_until([end_marker], timeout=25)
    if hit != 0:
        log.append("probe command produced no end marker before timeout")
        tail = " ".join(buf.split())[-200:]
        raise RuntimeError(f"no response to the IP command — console tail: {tail!r}")
    start = buf.find(_SOL_BEGIN)
    block = buf[start + len(_SOL_BEGIN):] if start != -1 else buf
    block = block[:block.find(_SOL_END)] if _SOL_END in block else block
    return _sol_parse_ips(block)


async def _discover_os_ip_sol(bmc_ip: str) -> str:
    """OS IP via a SOL console login — the fallback for boards Redfish does
    not expose a host NIC for.

    Opens the console, logs in with the same OS credential cascade the DIMM
    script itself uses, reads the address off `ip -4 -o addr show scope
    global`, and logs back out so nothing is left sitting at a root shell on
    a shared, stateful console.
    """
    log: list = []
    con = None
    try:
        con = await _open_console(bmc_ip, log)
        at_shell, logged_in, _detail = await _reach_shell(con, _os_credential_cascade(), log)
        if not at_shell:
            return ""
        try:
            ips = await _probe_ips(con, log)
        finally:
            if logged_in:
                try:
                    await con.send("exit")
                    await con.read_until([_SOL_LOGIN_RE], timeout=8)
                except Exception:
                    pass
        return ips[0]["ip"] if ips else ""
    except Exception as exc:
        print(f"[DIMM AUDIT] SOL console fallback on {bmc_ip} failed: {exc}", flush=True)
        return ""
    finally:
        if con is not None:
            await con.close()


def _discover_os_ip(host: str) -> tuple[str, str]:
    """(os_ip, detail) for one host: Redfish first, SOL console only if
    enabled and Redfish came back empty.

    A non-empty detail that starts with "redfish-empty:" is a signal to the
    caller to try the SOL fallback, not a final failure reason — the text
    after the colon is the Redfish-side reason, kept so it can still be
    reported if the SOL fallback also comes up empty.
    """
    os_ip, power = _discover_os_ip_redfish(host)
    if os_ip:
        return os_ip, ""
    if power == "?":
        reason = "BMC not reachable over Redfish"
    elif power.lower() != "on":
        reason = f"not in OS state (PowerState={power})"
    else:
        reason = "PowerState=On but Redfish exposed no host IP"
    if not DIMM_SOL_FALLBACK_ENABLED:
        return "", f"{reason} (DIMM_SOL_FALLBACK_ENABLED is off)"
    return "", f"redfish-empty:{reason}"


# ── DIMM serial matching ──────────────────────────────────────────────────
#
# Ports parseBarcode/itemSerial from the DIMM barcode-matching logic in
# static/index.html (index.html:1897-1917). Simpler here than the frontend's
# serialMatches: dmidecode always reports a bare serial, so only the
# barcode-to-bare-serial direction is needed.

def _parse_barcode_serial(code: str) -> str:
    raw = (code or "").strip()
    if not raw:
        return ""
    m = re.search(r"\(S\)(.*?)(?=\((?:L|S|P|C)\)|©|$)", raw, re.I)
    return m.group(1).strip() if m else ""


def _item_serial(item: dict) -> str:
    raw = str(item.get("serial_number") or "").strip()
    return (_parse_barcode_serial(raw) or raw).lower()


def _find_dimm_by_serial(serial: str, by_serial: dict[str, dict]) -> dict | None:
    """The inventory DIMM a dmidecode-reported serial belongs to, if any."""
    target = (serial or "").strip().lower()
    if not target:
        return None
    return by_serial.get(target)


_dimm_scan_lock = _threading.Lock()


def run_dimm_audit_scan() -> dict:
    """Scan every system in AUDIT_SYSTEMS_CSV for DIMMs: auto-grab the OS IP,
    SSH in, run the dmidecode-based DIMM script, match what it finds against
    the inventory. Twin of run_audit_scan — reachable from the scheduled loop
    below and from POST /api/admin/dimm-scan/run.
    """
    if not _dimm_scan_lock.acquire(blocking=False):
        return {"error": "A DIMM audit scan is already running."}
    try:
        if not HAS_ASYNCSSH:
            summary = {
                "started_at": _now(), "hosts_total": 0, "hosts_ok": 0, "hosts_failed": [],
                "cpus_seen": 0, "cpus_matched": 0, "cpus_unmatched": 0,
                "error": "asyncssh is not installed. Run: pip install -r requirements.txt",
            }
            _record_scan_run(summary, kind="dimm")
            return summary
        return asyncio.run(_run_dimm_audit_scan_async())
    finally:
        _dimm_scan_lock.release()


async def _run_dimm_audit_scan_async() -> dict:
    # Reuses the same hosts_total/hosts_ok/cpus_seen/cpus_matched/
    # cpus_unmatched columns audit_scan_runs already has for the CPU scan —
    # same numbers, just counting DIMMs instead of CPUs — rather than adding
    # a parallel set of dimm-named columns. `kind` plus the UI's own label is
    # what tells a reader which scan a row belongs to.
    started = time.monotonic()
    hosts = _read_audit_systems_csv(AUDIT_SYSTEMS_CSV)
    today = _date.today().isoformat()
    summary = {
        "started_at": _now(), "hosts_total": len(hosts), "hosts_ok": 0,
        "hosts_failed": [], "cpus_seen": 0, "cpus_matched": 0, "cpus_unmatched": 0,
    }
    if not hosts:
        summary["error"] = f"No hostnames found in {AUDIT_SYSTEMS_CSV}."
        print(f"[DIMM AUDIT] {summary['error']}", flush=True)
        _record_scan_run(summary, kind="dimm")
        return summary

    all_items = _read()
    by_serial: dict[str, dict] = {}
    for it in all_items:
        if str(it.get("category") or "") != "DIMMs":
            continue
        key = _item_serial(it)
        if key:
            by_serial[key] = it

    creds = _os_credential_cascade()

    for host in hosts:
        if not _BMC_HOST_RE.match(host):
            summary["hosts_failed"].append({"host": host, "error": "not a hostname shape"})
            continue
        if BMC_HOST_ALLOW and not any(fnmatch(host.lower(), p) for p in BMC_HOST_ALLOW):
            summary["hosts_failed"].append({"host": host, "error": "outside BMC_HOST_ALLOW"})
            continue

        os_ip, detail = _discover_os_ip(host)
        if not os_ip and detail.startswith("redfish-empty:"):
            redfish_reason = detail.split(":", 1)[1]
            os_ip = await _discover_os_ip_sol(host)
            if not os_ip:
                detail = f"{redfish_reason}, and the SOL console fallback found no OS IP either"
        if not os_ip:
            summary["hosts_failed"].append({"host": host, "error": detail})
            if DIMM_SCAN_HOST_DELAY_SEC:
                await asyncio.sleep(DIMM_SCAN_HOST_DELAY_SEC)
            continue

        last_err = "no credentials tried"
        dimm_data = None
        for user, pw in creds:
            try:
                out, err = await _ssh_run_script(os_ip, user, pw, _DIMM_SCRIPT)
                for line in out.splitlines():
                    if line.strip().startswith("{"):
                        dimm_data = json.loads(line.strip())
                        break
                if dimm_data is not None:
                    break
                last_err = f"no JSON in output (stderr: {err.strip()[:200]})"
            except Exception as exc:
                last_err = str(exc)
        if dimm_data is None:
            summary["hosts_failed"].append({"host": host, "error": f"OS IP {os_ip} found but {last_err}"})
            if DIMM_SCAN_HOST_DELAY_SEC:
                await asyncio.sleep(DIMM_SCAN_HOST_DELAY_SEC)
            continue

        summary["hosts_ok"] += 1
        matched_ids: list[str] = []
        log_rows: list[dict] = []
        for d in dimm_data.get("dimms", []):
            serial = d.get("serial")
            if not serial:
                continue
            summary["cpus_seen"] += 1
            hit = _find_dimm_by_serial(serial, by_serial)
            if hit:
                summary["cpus_matched"] += 1
                matched_ids.append(hit["id"])
            else:
                summary["cpus_unmatched"] += 1
            log_rows.append({
                "item_id": hit["id"] if hit else None,
                "serial": serial, "host": host, "found": bool(hit),
            })

        if matched_ids:
            note = f"{host} · {today}"
            try:
                _apply_audit_fields(list(dict.fromkeys(matched_ids)), note)
            except _BatchRowsGone as gone:
                summary["hosts_failed"].append({
                    "host": host,
                    "error": f"{len(gone.ids)} matched item(s) were deleted mid-scan",
                })
        if log_rows:
            _record_audit_log(log_rows, kind="dimm")

        if DIMM_SCAN_HOST_DELAY_SEC:
            await asyncio.sleep(DIMM_SCAN_HOST_DELAY_SEC)

    summary["elapsed_sec"] = round(time.monotonic() - started, 1)
    print(f"[DIMM AUDIT] scan done in {summary['elapsed_sec']}s: "
          f"{summary['hosts_ok']}/{summary['hosts_total']} host(s) ok, "
          f"{summary['cpus_matched']}/{summary['cpus_seen']} DIMM(s) matched, "
          f"{len(summary['hosts_failed'])} host(s) failed", flush=True)
    _record_scan_run(summary, kind="dimm")
    return summary


class DimmSutReadIn(BaseModel):
    host: str


@app.post("/api/dimm/read-sut")
async def read_sut_dimms(body: DimmSutReadIn, request: Request):
    """Name a system, get its DIMM info — the DIMM twin of /api/cpu/read-sut.

    Auto-grabs the OS IP (Redfish first, then a SOL console login if
    DIMM_SOL_FALLBACK_ENABLED), SSHes into the OS with the built-in OS
    credential cascade, and runs the dmidecode-based DIMM script. Open to the
    lab like the CPU read — it is still just a read, and the credentials
    never leave the server. Writing what it found to the inventory's audit
    trail stays admin-only, via /api/items/audit.
    """
    host = (body.host or "").strip()
    if not _BMC_HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="That is not a hostname.")
    if BMC_HOST_ALLOW and not any(fnmatch(host.lower(), pattern) for pattern in BMC_HOST_ALLOW):
        raise HTTPException(
            status_code=403,
            detail=f"This server only reads {', '.join(BMC_HOST_ALLOW)}.",
        )
    _rate_limit_sut(request.client.host if request.client else "unknown")

    if not HAS_ASYNCSSH:
        raise HTTPException(
            status_code=503,
            detail="asyncssh is not installed on the server. Run: pip install -r requirements.txt")

    # _discover_os_ip does blocking httpx calls; off the event loop so one
    # slow/unreachable BMC does not stall every other request meanwhile.
    os_ip, detail = await asyncio.to_thread(_discover_os_ip, host)
    if not os_ip and detail.startswith("redfish-empty:"):
        redfish_reason = detail.split(":", 1)[1]
        if DIMM_SOL_FALLBACK_ENABLED:
            os_ip = await _discover_os_ip_sol(host)
        if not os_ip:
            detail = (f"{redfish_reason}, and the SOL console fallback found no OS IP either"
                      if DIMM_SOL_FALLBACK_ENABLED else
                      f"{redfish_reason} (DIMM_SOL_FALLBACK_ENABLED is off)")
    if not os_ip:
        raise HTTPException(status_code=422, detail=f"{host}: {detail}")

    last_err = "no credentials tried"
    dimm_data = None
    used_user = None
    for user, pw in _os_credential_cascade():
        try:
            out, err = await _ssh_run_script(os_ip, user, pw, _DIMM_SCRIPT)
            for line in out.splitlines():
                if line.strip().startswith("{"):
                    dimm_data = json.loads(line.strip())
                    used_user = user
                    break
            if dimm_data is not None:
                break
            last_err = f"no JSON in output (stderr: {err.strip()[:200]})"
        except Exception as exc:
            last_err = str(exc)
    if dimm_data is None:
        raise HTTPException(status_code=502, detail=f"OS IP {os_ip} found for {host}, but {last_err}")

    dimm_data["host"] = host
    dimm_data["os_ip"] = os_ip
    dimm_data["ssh_user"] = used_user
    return dimm_data


@app.post("/api/admin/dimm-scan/run", dependencies=[Depends(_require_admin)])
def trigger_dimm_scan():
    """Run the nightly DIMM scan now, instead of waiting for its scheduled time.

    A plain `def` route, same reason as /api/admin/audit-scan/run: this can
    take a couple of minutes across ninety systems and must not block the
    event loop.
    """
    return run_dimm_audit_scan()


async def _dimm_scan_loop() -> None:
    """Wake at DIMM_SCAN_HOUR:DIMM_SCAN_MINUTE every day and run the DIMM scan.

    Twin of _audit_scan_loop — see its docstring for why a missed day is not
    caught up on.
    """
    while True:
        now = datetime.now()
        target = now.replace(hour=DIMM_SCAN_HOUR, minute=DIMM_SCAN_MINUTE, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        wait_s = (target - now).total_seconds()
        print(f"[DIMM AUDIT] next scan at {target.isoformat(sep=' ', timespec='minutes')} "
              f"({wait_s / 3600:.1f}h)", flush=True)
        await asyncio.sleep(wait_s)
        try:
            await asyncio.to_thread(run_dimm_audit_scan)
        except Exception as exc:
            print(f"[DIMM AUDIT] scan failed: {exc}", flush=True)


@app.get("/")
def index():
    return FileResponse("static/index.html")


app.mount("/", StaticFiles(directory="static", html=True), name="static")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    # _init_db() / _migrate_from_json() already ran at import.
    configured = str(_CONFIGURED_DIR)
    actual     = str(DATA_DIR.resolve())
    print(f"  Data dir  : {actual}" + (" (FALLBACK — shared drive unavailable)" if actual != str(_CONFIGURED_DIR.resolve()) else ""))
    print(f"  Database  : {DB_FILE}")
    print(f"  Admins    : {', '.join(ADMIN_CREDENTIALS.keys())}")
    print(f"  Serving   : http://{HOST}:{PORT}")
    uvicorn.run("server:app", host=HOST, port=PORT, reload=False)
