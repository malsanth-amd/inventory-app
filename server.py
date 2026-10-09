"""
FVDDR Inventory Management — FastAPI backend
Reads/writes inventory.json from a configurable shared drive path.
Admin-only writes: POST/PUT/DELETE require a valid session token.
"""

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import smtplib
import uuid
from datetime import datetime, timezone, date as _date
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
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

_CONFIGURED_DIR = Path(os.getenv("INVENTORY_DATA_DIR", "./data"))
_FALLBACK_DIR   = Path("./data")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

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
        u = os.getenv("ADMIN_USERNAME", "admin").strip()
        p = os.getenv("ADMIN_PASSWORD", "changeme").strip()
        creds[u] = p
    return creds

ADMIN_CREDENTIALS: dict[str, str] = _load_admin_credentials()
SUPER_ADMIN_USERNAME: str = os.getenv("SUPER_ADMIN_USERNAME", "FVDDR_Admin").strip()
DEVELOPER_USERNAME: str = "FVDDR_Dev"
DEVELOPER_DEFAULT_PASSWORD: str = "Developer"

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
    Always ensures the developer account exists."""
    admins: list[dict] = []
    first_run = not (ADMINS_FILE.exists() and ADMINS_FILE.stat().st_size > 2)

    if first_run:
        admins = [{"username": u, "hash": _hash_password(p)} for u, p in ADMIN_CREDENTIALS.items()]
        print(f"  Admin credentials bootstrapped → {ADMINS_FILE}")
        print(f"  Plain-text passwords in .env are no longer used.")
    else:
        admins = _read_admins()

    if not any(a["username"] == DEVELOPER_USERNAME for a in admins):
        admins.append({"username": DEVELOPER_USERNAME, "hash": _hash_password(DEVELOPER_DEFAULT_PASSWORD)})
        print(f"  Developer account bootstrapped: {DEVELOPER_USERNAME}")

    if first_run or not any(a["username"] == DEVELOPER_USERNAME for a in _read_admins()):
        _write_admins(admins)


_bootstrap_admins()


def _check_credentials(username: str, password: str) -> bool:
    for admin in _read_admins():
        if admin["username"] == username:
            return _verify_password(password, admin["hash"])
    # Fallback to .env plain text (e.g. admins.json was deleted)
    stored = ADMIN_CREDENTIALS.get(username)
    return hmac.compare_digest(password, stored) if stored else False


# In-memory session store: token → username
# Tokens are invalidated when the server restarts.
_sessions: dict[str, str] = {}

app = FastAPI(title="FVDDR Inventory Management")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer(auto_error=False)


# ── auth helpers ──────────────────────────────────────────────────────────────



def _get_role(username: str) -> str:
    if username == DEVELOPER_USERNAME:
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
    if _sessions[creds.credentials] not in (SUPER_ADMIN_USERNAME, DEVELOPER_USERNAME):
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
    "location", "tray", "team", "owner",
    "checkout_user", "checkout_email", "checkout_date", "loan_until",
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
        # Schema migrations — add new columns to existing databases (idempotent)
        for col, definition in [
            ("dimm_type", "TEXT NOT NULL DEFAULT ''"),
            ("rcd",       "TEXT NOT NULL DEFAULT ''"),
            ("pmic",      "TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                conn.execute(f"ALTER TABLE items ADD COLUMN {col} {definition}")
            except _sqlite3.OperationalError:
                pass  # column already exists
        conn.commit()


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


def _read() -> list[dict]:
    """Return all items ordered newest-first, with category normalised."""
    with _db_connect() as conn:
        rows = conn.execute(
            f"SELECT {_COLS_SQL} FROM items ORDER BY createdAt DESC"
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["category"] = _normalize_category(item.get("category", ""))
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
    merged["category"] = _normalize_category(merged.get("category", ""))
    return merged


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


# ── schemas ───────────────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    username: str
    password: str


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
    notes: str | None = ""


class BatchIn(BaseModel):
    items: list[ItemIn]


# ── auth routes ───────────────────────────────────────────────────────────────

@app.post("/api/login")
def login(body: LoginIn):
    if not _check_credentials(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = secrets.token_hex(32)
    _sessions[token] = body.username
    return {"token": token, "username": body.username, "is_superadmin": body.username in (SUPER_ADMIN_USERNAME, DEVELOPER_USERNAME), "role": _get_role(body.username)}


@app.post("/api/logout", status_code=204)
def logout(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if creds and creds.credentials in _sessions:
        del _sessions[creds.credentials]


@app.get("/api/me")
def me(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if creds and creds.credentials in _sessions:
        uname = _sessions[creds.credentials]
        return {"authenticated": True, "username": uname, "is_superadmin": uname in (SUPER_ADMIN_USERNAME, DEVELOPER_USERNAME), "role": _get_role(uname)}
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
    if username == DEVELOPER_USERNAME:
        raise HTTPException(status_code=400, detail="Developer account credentials are fixed and cannot be changed.")
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

@app.get("/api/items")
def list_items():
    return _read()


@app.post("/api/items", status_code=201)
def create_item(body: ItemIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    item = {
        "id": uuid.uuid4().hex,
        "createdAt": _now(),
        "updatedAt": _now(),
        **body.model_dump(),
    }
    if actor and actor != DEVELOPER_USERNAME:
        item["modified_by"] = actor
    _insert_items([item])
    item["category"] = _normalize_category(item.get("category", ""))
    return item


@app.post("/api/items/batch", status_code=201)
def create_items_batch(body: BatchIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    created = []
    for item_in in body.items:
        item = {
            "id": uuid.uuid4().hex,
            "createdAt": _now(),
            "updatedAt": _now(),
            **item_in.model_dump(),
        }
        if actor and actor != DEVELOPER_USERNAME:
            item["modified_by"] = actor
        created.append(item)
    _insert_items(created)
    return {"imported": len(created)}


@app.put("/api/items/{item_id}")
def update_item(item_id: str, body: ItemIn, creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    _require_admin(creds)
    actor = _sessions.get(creds.credentials, "") if creds else ""
    changes = {**body.model_dump(), "updatedAt": _now()}
    if actor and actor != DEVELOPER_USERNAME:
        changes["modified_by"] = actor
    updated = _update_item_row(item_id, changes)
    if updated is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated


@app.delete("/api/items/{item_id}", status_code=204, dependencies=[Depends(_require_admin)])
def delete_item(item_id: str):
    if _delete_ids([item_id]) == 0:
        raise HTTPException(status_code=404, detail="Item not found")


class BatchDeleteIn(BaseModel):
    ids: list[str]

@app.post("/api/items/batch-delete", status_code=200, dependencies=[Depends(_require_admin)])
def batch_delete_items(body: BatchDeleteIn):
    # dict.fromkeys de-duplicates while keeping the caller's order
    return {"deleted": _delete_ids(list(dict.fromkeys(body.ids)))}


# ── email reminders ───────────────────────────────────────────────────────────

class ReminderIn(BaseModel):
    subject: str | None = None
    message: str | None = None
    ids:     list[str] | None = None   # if set, only send for these item IDs


class ReturnRequestIn(BaseModel):
    ids:     list[str]
    cc:      list[str] | None = None   # extra CC addresses chosen by admin
    message: str | None = None


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
        sn_cell   = f"<br><span style='color:#777;font-size:0.9em'>S/N: {item['serial_number']}</span>" if item.get("serial_number") else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{item.get('name','—')}{sn_cell}</td>"
            f"<td style='padding:6px 0;color:#555'>{due_label}: {due_cell}</td>"
            f"</tr>"
        )

    intro = (
        "you have checked out the following item from the lab inventory:"
        if count == 1
        else f"you have <strong>{count} items</strong> checked out from the lab inventory:"
    )
    body_html = (
        f"<p>Hi {checkout_user},</p>"
        f"<p>This is a reminder that {intro}</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>{rows_html}</table>"
        f"<p>Please <strong>return</strong> each item as soon as it is no longer needed or <strong>reply</strong> to this email if require to extend loan period.</p>"
        + (f"<p>{extra_message}</p>" if extra_message else "")
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
        sn = f"<br><span style='color:#777;font-size:0.9em'>S/N: {item['serial_number']}</span>" if item.get("serial_number") else ""
        pn = f"<br><span style='color:#777;font-size:0.9em'>PN: {item['part_number']}</span>"   if item.get("part_number")  else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{item.get('name','—')}{sn}{pn}</td>"
            f"<td style='padding:6px 0;color:#555'>{due_label}: {due}</td>"
            f"</tr>"
        )
    body_html = (
        f"<p>Hi {checkout_user},</p>"
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
        sn  = f"<br><span style='color:#777;font-size:0.85em'>S/N: {item['serial_number']}</span>" if item.get("serial_number") else ""
        pn  = f"<br><span style='color:#777;font-size:0.85em'>PN: {item['part_number']}</span>"   if item.get("part_number")  else ""
        loc = f"<br><span style='color:#777;font-size:0.85em'>Location: {item['location']}</span>" if item.get("location") else ""
        cat = f"<span style='color:#777;font-size:0.85em'>{item['category']}</span>" if item.get("category") else ""
        rows_html += (
            f"<tr style='border-top:1px solid #e0e0e0'>"
            f"<td style='padding:6px 16px 6px 0;font-weight:bold'>{item.get('name','—')}{sn}{pn}{loc}</td>"
            f"<td style='padding:6px 8px 6px 0;color:#555'>{cat}</td>"
            f"<td style='padding:6px 0;color:#555;white-space:nowrap'>{due_label}: {due_cell}</td>"
            f"</tr>"
        )

    intro = (
        "the FVDDR Lab Admin is requesting that you return the following item:"
        if count == 1
        else f"the FVDDR Lab Admin is requesting that you return the following <strong>{count} items</strong>:"
    )
    msg_block = f"<p style='background:#fffbe6;border-left:3px solid #f59e0b;padding:10px 14px;border-radius:4px;margin:12px 0'><strong>Note from Admin:</strong><br>{message}</p>" if message else ""
    body_html = (
        f"<p>Hi {checkout_user},</p>"
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

    fname = (file.filename or "attachment").strip()
    ext   = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext not in ("csv", "xlsx", "xls"):
        raise HTTPException(status_code=422, detail="Only .csv, .xlsx, or .xls files are accepted.")

    content = await file.read()
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
    body_html = (
        f"<p>A user has submitted an inventory addition request.</p>"
        f"<table style='border-collapse:collapse;margin:8px 0'>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Name</td><td>{submitter_name}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Email</td><td>{submitter_email}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>File</td><td>{fname}</td></tr>"
        f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold'>Sent</td><td>{submitted_at}</td></tr>"
        + (f"<tr><td style='padding:3px 14px 3px 0;font-weight:bold;vertical-align:top'>Notes</td><td>{notes}</td></tr>" if notes.strip() else "")
        + f"</table>"
        f"<p>The file is attached. Please review and import it into the inventory system.</p>"
    )

    msg = MIMEMultipart("mixed")
    msg["Subject"] = f"[Lab Inventory] Submission from {submitter_name}"
    msg["From"]    = f"{SMTP_FROM_NAME} <{SMTP_FROM}>" if SMTP_FROM_NAME else SMTP_FROM
    msg["To"]      = ADMIN_EMAIL
    if submitter_email:
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


@app.post("/api/parse-file")
async def parse_file(file: UploadFile = File(...)):
    """Parse an uploaded CSV or xlsx file, decrypting if needed.

    Returns: {"sheets": [{"name": str, "rows": [[str, ...]]}]}
    Each row is a list of cell strings; row 0 is always the header row.
    """
    try:
        return await _do_parse_file(file)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {exc}")


async def _do_parse_file(file: UploadFile):
    content = await file.read()
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
            raise HTTPException(status_code=422, detail=f"Could not decrypt file: {e}")

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


@app.get("/api/template")
def download_template():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    import re as _re

    # (label, field_key, width, is_required, is_date)
    BASE_TEMPLATE_COLS = [
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
        ("Location *",                      "location",       18, True,  False),
        ("Tray / Comment",                  "tray",           18, False, False),
        ("Team *",                          "team",           16, True,  False),
        ("Owner *",                         "owner",          14, True,  False),
        ("Check Out User *",                "checkout_user",  18, True,  False),
        ("Check Out Email",                 "checkout_email", 24, False, False),
        ("Check Out Date * (YYYY-MM-DD)",   "checkout_date",  18, True,  True),
        ("Loan Until (YYYY-MM-DD)",         "loan_until",     16, False, True),
        ("Notes",                           "notes",          30, False, False),
    ]

    _NO_DIMM_SPECIFIC               = {"rank", "speed", "density", "dimm_type", "rcd", "pmic"}
    _NO_DIMM_SPECIFIC_CAPACITY      = {"rank", "speed", "density", "capacity", "dimm_type", "rcd", "pmic"}
    CATEGORY_EXCLUDE: dict[str, set[str]] = {
        "systems":       _NO_DIMM_SPECIFIC_CAPACITY,
        "accessories":   _NO_DIMM_SPECIFIC_CAPACITY,
        "cpu (silicon)": {"rank", "speed", "density", "capacity", "rcd", "pmic"},  # keep dimm_type for ES/CS
        "storage":       _NO_DIMM_SPECIFIC,
    }

    # Map SAMPLE_ROWS (tuples following COLUMNS order) → list of dicts per category
    col_keys = ["vendor","name","part_number","serial_number","rank","speed",
                "capacity","density","dimm_type","rcd","pmic","category","location","tray","team","owner",
                "checkout_user","checkout_email","checkout_date","loan_until","notes"]
    sample_by_cat: dict[str, list[dict]] = {}
    for row in SAMPLE_ROWS:
        d = dict(zip(col_keys, row))
        sample_by_cat.setdefault(d["category"], []).append(d)

    def _cols_for(cat: str) -> list[tuple]:
        exclude = CATEGORY_EXCLUDE.get(cat.lower().strip(), set())
        return [(lbl, key, w, req, is_date)
                for lbl, key, w, req, is_date in BASE_TEMPLATE_COLS
                if key not in exclude]

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

    wb = Workbook()
    wb.remove(wb.active)
    for cat in TEMPLATE_CATEGORIES:
        ws   = wb.create_sheet(title=cat[:31])
        cols = _cols_for(cat)
        _write_template_sheet(ws, cols, sample_by_cat.get(cat, []))

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="inventory_template.xlsx"'},
    )


@app.get("/api/bulk-template")
def download_bulk_template():
    """XLSX template for Bulk Check In / Check Out — one sheet per category, same styling as import template."""
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation
    from datetime import date as _dt

    today      = _dt.today().isoformat()
    next_month = _dt.fromordinal(_dt.today().toordinal() + 31).isoformat()

    ACTION_VALUES = ["check_out", "check_in", "change_user"]

    # (label, key, width, is_required, is_date)
    BULK_COLS = [
        ("Action *",                       "action",         14, True,  False),
        ("Serial Number *",                "serial_number",  22, True,  False),
        ("Part Number",                    "part_number",    22, False, False),
        ("Item Name (reference only)",     "name",           34, False, False),
        ("Location",                       "location",       18, False, False),
        ("Tray / Comment",                 "tray",           18, False, False),
        ("Check Out User",                 "checkout_user",  20, False, False),
        ("Check Out Email",                "checkout_email", 26, False, False),
        ("Check Out Date (YYYY-MM-DD)",    "checkout_date",  20, False, True),
        ("Loan Until (YYYY-MM-DD)",        "loan_until",     18, False, True),
        ("Notes",                          "notes",          30, False, False),
    ]

    # Sample rows keyed by category; demonstrates check_out, check_in, and change_user
    # (change_user reassigns an item that is already checked out to a different user
    # without needing a check_in first).
    BULK_SAMPLES: dict[str, list[dict]] = {
        "DIMMs":        [
            {"action": "check_out",  "serial_number": "802C06234644DACAAE", "part_number": "MTC40F2047S1RC64BBZ", "name": "128GB 2RX4 PC5-6400",  "location": "L6-L12-03", "tray": "Tray 4",  "checkout_user": "John Doe",  "checkout_email": "john@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": "Lab stress test"},
            {"action": "check_in",   "serial_number": "802C06234644DACBA1", "part_number": "MTC40F2047S1RC64BBZ", "name": "128GB 2RX4 PC5-6400",  "location": "L6-L12-03", "tray": "Tray 4",  "checkout_user": "",          "checkout_email": "",              "checkout_date": "",         "loan_until": "",         "notes": ""},
            {"action": "change_user","serial_number": "802C06234644DACCA2", "part_number": "MTC40F2047S1RC64BBZ", "name": "128GB 2RX4 PC5-6400",  "location": "L6-L12-03", "tray": "Tray 4",  "checkout_user": "Jane Smith","checkout_email": "jane@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": "Reassigned"},
        ],
        "CPU (Silicon)": [
            {"action": "check_out",  "serial_number": "CPU-SN-001", "part_number": "100-000001234",      "name": "Genoa ES CPU",              "location": "L6-L12-05", "tray": "Bin 2",   "checkout_user": "Jane Smith", "checkout_email": "jane@amd.com", "checkout_date": today,      "loan_until": next_month, "notes": ""},
            {"action": "check_in",   "serial_number": "CPU-SN-002", "part_number": "100-000001234",      "name": "Genoa ES CPU",              "location": "L6-L12-05", "tray": "Bin 2",   "checkout_user": "",           "checkout_email": "",             "checkout_date": "",         "loan_until": "",         "notes": ""},
            {"action": "change_user","serial_number": "CPU-SN-003", "part_number": "100-000001234",      "name": "Genoa ES CPU",              "location": "L6-L12-05", "tray": "Bin 2",   "checkout_user": "John Doe",   "checkout_email": "john@amd.com", "checkout_date": today,      "loan_until": next_month, "notes": "Reassigned"},
        ],
        "Storage":      [
            {"action": "check_out",  "serial_number": "SSD-SN-001", "part_number": "MZWLJ3T8HBLS-00007", "name": "3.84TB NVMe SSD",          "location": "L6-L12-07", "tray": "Shelf B", "checkout_user": "John Doe",  "checkout_email": "john@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": ""},
            {"action": "check_in",   "serial_number": "SSD-SN-002", "part_number": "MZWLJ3T8HBLS-00007", "name": "3.84TB NVMe SSD",          "location": "L6-L12-07", "tray": "Shelf B", "checkout_user": "",          "checkout_email": "",              "checkout_date": "",         "loan_until": "",         "notes": ""},
            {"action": "change_user","serial_number": "SSD-SN-003", "part_number": "MZWLJ3T8HBLS-00007", "name": "3.84TB NVMe SSD",          "location": "L6-L12-07", "tray": "Shelf B", "checkout_user": "Jane Smith","checkout_email": "jane@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": "Reassigned"},
        ],
        "Systems":      [
            {"action": "check_out",  "serial_number": "SYS-SN-001", "part_number": "SYS-PN-001",         "name": "Test Server Platform",     "location": "Rack A1",   "tray": "",        "checkout_user": "Jane Smith", "checkout_email": "jane@amd.com", "checkout_date": today,      "loan_until": next_month, "notes": ""},
            {"action": "check_in",   "serial_number": "SYS-SN-002", "part_number": "SYS-PN-001",         "name": "Test Server Platform",     "location": "Rack A1",   "tray": "",        "checkout_user": "",           "checkout_email": "",             "checkout_date": "",         "loan_until": "",         "notes": ""},
            {"action": "change_user","serial_number": "SYS-SN-003", "part_number": "SYS-PN-001",         "name": "Test Server Platform",     "location": "Rack A1",   "tray": "",        "checkout_user": "John Doe",   "checkout_email": "john@amd.com", "checkout_date": today,      "loan_until": next_month, "notes": "Reassigned"},
        ],
        "Accessories":  [
            {"action": "check_out",  "serial_number": "ACC-SN-001", "part_number": "CBL-PN-001",         "name": "PCIe x16 Riser Cable",     "location": "L6-L12-09", "tray": "Drawer 1","checkout_user": "John Doe",  "checkout_email": "john@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": ""},
            {"action": "check_in",   "serial_number": "ACC-SN-002", "part_number": "CBL-PN-001",         "name": "PCIe x16 Riser Cable",     "location": "L6-L12-09", "tray": "Drawer 1","checkout_user": "",          "checkout_email": "",              "checkout_date": "",         "loan_until": "",         "notes": ""},
            {"action": "change_user","serial_number": "ACC-SN-003", "part_number": "CBL-PN-001",         "name": "PCIe x16 Riser Cable",     "location": "L6-L12-09", "tray": "Drawer 1","checkout_user": "Jane Smith","checkout_email": "jane@amd.com",  "checkout_date": today,      "loan_until": next_month, "notes": "Reassigned"},
        ],
    }

    blue_fill = PatternFill("solid", fgColor="2E75B6")
    red_fill  = PatternFill("solid", fgColor="C00000")
    thin      = Side(style="thin", color="FFFFFF")
    border    = Border(left=thin, right=thin, top=thin, bottom=thin)

    def _write_bulk_sheet(ws, sample_rows):
        ws.freeze_panes = "A2"
        ws.row_dimensions[1].height = 28
        for ci, (label, _, width, is_req, _) in enumerate(BULK_COLS, start=1):
            cell = ws.cell(row=1, column=ci, value=label)
            cell.font      = Font(bold=True, color="FFFFFF", size=10)
            cell.fill      = red_fill if is_req else blue_fill
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border    = border
            ws.column_dimensions[get_column_letter(ci)].width = width
        for ri, row_dict in enumerate(sample_rows, start=2):
            ws.row_dimensions[ri].height = 16
            for ci, (_, key, _, _, is_date) in enumerate(BULK_COLS, start=1):
                val  = row_dict.get(key, "") or ""
                cell = ws.cell(row=ri, column=ci, value=val if val else None)
                cell.alignment = Alignment(vertical="center")
                if is_date and val:
                    cell.number_format = "@"
        # Dropdown restricting the Action column to the three recognized values.
        dv = DataValidation(type="list", formula1=f'"{",".join(ACTION_VALUES)}"', allow_blank=True, showDropDown=False, showErrorMessage=True)
        dv.error = "Use one of: " + ", ".join(ACTION_VALUES)
        dv.errorTitle = "Invalid action"
        ws.add_data_validation(dv)
        dv.add(f"A2:A1000")

    wb = Workbook()
    wb.remove(wb.active)
    for cat in TEMPLATE_CATEGORIES:
        ws = wb.create_sheet(title=cat[:31])
        _write_bulk_sheet(ws, BULK_SAMPLES.get(cat, []))

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="bulk_checkinout_template.xlsx"'},
    )


@app.get("/api/export")
def export_inventory(
    ids: list[str] | None = Query(default=None),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    # Exporting all items requires admin; exporting specific IDs is public (inventory is public)
    if not ids:
        _require_admin(creds)
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    import re as _re

    # Category column excluded — sheet name carries that information.
    # On re-import the sheet name is used as the category fallback automatically.
    BASE_COLS = [
        ("Vendor",           "vendor",         14),
        ("Item Description", "name",           34),
        ("Part Number",      "part_number",    20),
        ("Serial Number",    "serial_number",  20),
        ("Rank",             "rank",           10),
        ("Speed",            "speed",          14),
        ("Capacity",         "capacity",       12),
        ("Density",          "density",        14),
        ("DIMM Type",        "dimm_type",      12),
        ("RCD",              "rcd",            16),
        ("PMIC",             "pmic",           16),
        ("Location",         "location",       18),
        ("Tray / Comment",   "tray",           18),
        ("Team",             "team",           16),
        ("Owner",            "owner",          14),
        ("Check Out User",   "checkout_user",  18),
        ("Check Out Email",  "checkout_email", 24),
        ("Check Out Date",   "checkout_date",  18),
        ("Loan Until",       "loan_until",     16),
        ("Notes",            "notes",          30),
    ]

    # Fields irrelevant to specific categories — excluded from those sheets.
    _NO_DIMM_SPECIFIC          = {"rank", "speed", "density", "dimm_type", "rcd", "pmic"}
    _NO_DIMM_SPECIFIC_CAPACITY = {"rank", "speed", "density", "capacity", "dimm_type", "rcd", "pmic"}
    CATEGORY_EXCLUDE: dict[str, set[str]] = {
        "systems":       _NO_DIMM_SPECIFIC_CAPACITY,
        "accessories":   _NO_DIMM_SPECIFIC_CAPACITY,
        "cpu (silicon)": {"rank", "speed", "density", "capacity", "rcd", "pmic"},
        "storage":       _NO_DIMM_SPECIFIC,
    }

    def _cols_for_category(cat: str) -> list[tuple]:
        exclude = CATEGORY_EXCLUDE.get(cat.lower().strip(), set())
        return [(label, key, width) for label, key, width in BASE_COLS if key not in exclude]

    def _safe_sheet_name(name: str) -> str:
        name = _re.sub(r'[\\/*?:\[\]]', '_', name).strip() or "Uncategorized"
        return name[:31]

    def _write_sheet(ws, item_rows: list[dict], cols: list[tuple]) -> None:
        header_fill = PatternFill("solid", fgColor="2E75B6")
        ws.row_dimensions[1].height = 24
        ws.freeze_panes = "A2"
        for ci, (label, _, width) in enumerate(cols, start=1):
            cell = ws.cell(row=1, column=ci, value=label)
            cell.font      = Font(bold=True, color="FFFFFF", size=10)
            cell.fill      = header_fill
            cell.alignment = Alignment(horizontal="center", vertical="center")
            ws.column_dimensions[get_column_letter(ci)].width = width
        for ri, item in enumerate(item_rows, start=2):
            ws.row_dimensions[ri].height = 16
            for ci, (_, key, _) in enumerate(cols, start=1):
                val = item.get(key, "") or ""
                cell = ws.cell(row=ri, column=ci, value=val if val != "" else None)
                cell.alignment = Alignment(vertical="center")
                cell.number_format = "@"

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

@app.get("/api/lookup-pn/{part_number}")
async def lookup_part_number(part_number: str):
    """Proxy to ddrmpn.amd.com — returns rcd and pmic vendor for a given part number."""
    import httpx
    pn = part_number.strip()
    if not pn:
        raise HTTPException(status_code=400, detail="Part number required")
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(f"https://ddrmpn.amd.com/api/decode/{pn}")
        if resp.status_code == 404:
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
        return {"rcd": _clean(rcd_raw), "pmic": _clean(pmic_raw), "raw": data}
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Decoder service timed out")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Could not reach decoder service: {e}")


@app.get("/")
def index():
    return FileResponse("static/index.html")


app.mount("/", StaticFiles(directory="static", html=True), name="static")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    _init_db()
    _migrate_from_json()
    configured = str(_CONFIGURED_DIR)
    actual     = str(DATA_DIR.resolve())
    print(f"  Data dir  : {actual}" + (" (FALLBACK — shared drive unavailable)" if actual != str(_CONFIGURED_DIR.resolve()) else ""))
    print(f"  Database  : {DB_FILE}")
    print(f"  Admins    : {', '.join(ADMIN_CREDENTIALS.keys())}")
    print(f"  Serving   : http://{HOST}:{PORT}")
    uvicorn.run("server:app", host=HOST, port=PORT, reload=False)
