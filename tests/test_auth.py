"""Authentication, authorisation and credential handling.

The lockout these cover is a real one: removing the .env plain-text fallback
locked out a superadmin that existed only in .env and not in admins.json.
test_env_only_account_migrates_on_first_login is that regression.
"""

from __future__ import annotations

import json

from conftest import TEST_ADMIN, TEST_PASSWORD


# ── the retired hardcoded account ─────────────────────────────────────────────

def test_legacy_developer_credential_is_rejected(client):
    """FVDDR_Dev / "Developer" used to be a superadmin compiled into server.py."""
    resp = client.post(
        "/api/login", json={"username": "FVDDR_Dev", "password": "Developer"}
    )
    assert resp.status_code == 401


def test_legacy_developer_name_grants_nothing(app_module):
    assert app_module._is_superadmin("FVDDR_Dev") is False


def test_empty_developer_username_never_matches(app_module):
    """DEVELOPER_USERNAME defaults to "", which must not match an empty session."""
    assert app_module.DEVELOPER_USERNAME == ""
    assert app_module._is_superadmin("") is False


def test_no_account_is_bootstrapped_beyond_configuration(app_module):
    names = {a["username"] for a in app_module._read_admins()}
    assert names == {TEST_ADMIN}


# ── login ─────────────────────────────────────────────────────────────────────

def test_configured_superadmin_can_log_in(client):
    resp = client.post(
        "/api/login", json={"username": TEST_ADMIN, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_superadmin"] is True
    assert body["role"] == "superadmin"


def test_wrong_password_is_rejected(client):
    resp = client.post(
        "/api/login", json={"username": TEST_ADMIN, "password": "nope"}
    )
    assert resp.status_code == 401


def test_unknown_user_is_rejected(client):
    resp = client.post(
        "/api/login", json={"username": "nobody", "password": TEST_PASSWORD}
    )
    assert resp.status_code == 401


def test_placeholder_admin_changeme_is_not_a_login(client):
    resp = client.post("/api/login", json={"username": "admin", "password": "changeme"})
    assert resp.status_code == 401


def test_env_only_account_migrates_on_first_login(app_module, tmp_path, monkeypatch):
    """Regression: an account in .env but absent from admins.json must still work.

    Removing the plain-text fallback outright locked out exactly this case — a
    superadmin that had never been written into admins.json. It is accepted once
    against .env, then stored as a hash so the plain-text value stops mattering.
    """
    admins_file = tmp_path / "admins.json"
    admins_file.write_text(
        json.dumps([{"username": "SomebodyElse", "hash": "x"}]), encoding="utf-8"
    )
    monkeypatch.setattr(app_module, "ADMINS_FILE", admins_file)
    monkeypatch.setattr(
        app_module, "ADMIN_CREDENTIALS", {"EnvOnly": "env-password-123"}
    )
    monkeypatch.setattr(app_module, "_ADMIN_CREDS_ARE_PLACEHOLDER", False)

    assert app_module._check_credentials("EnvOnly", "env-password-123") is True

    stored = json.loads(admins_file.read_text(encoding="utf-8"))
    entry = next(a for a in stored if a["username"] == "EnvOnly")
    assert entry["hash"].startswith("pbkdf2:")
    # The hash path now serves this account, and a wrong password still fails.
    assert app_module._check_credentials("EnvOnly", "env-password-123") is True
    assert app_module._check_credentials("EnvOnly", "wrong") is False


def test_placeholder_credentials_never_migrate(app_module, tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "ADMINS_FILE", tmp_path / "admins.json")
    monkeypatch.setattr(app_module, "ADMIN_CREDENTIALS", {"admin": "changeme"})
    monkeypatch.setattr(app_module, "_ADMIN_CREDS_ARE_PLACEHOLDER", True)
    assert app_module._check_credentials("admin", "changeme") is False


# ── endpoint protection ───────────────────────────────────────────────────────

def test_parse_file_requires_admin(client):
    resp = client.post(
        "/api/parse-file", files={"file": ("a.csv", b"col\nvalue\n", "text/csv")}
    )
    assert resp.status_code == 401


def test_parse_file_works_for_admin(client, auth):
    resp = client.post(
        "/api/parse-file",
        files={"file": ("a.csv", b"Item Description\nwidget\n", "text/csv")},
        headers=auth,
    )
    assert resp.status_code == 200
    assert len(resp.json()["sheets"]) == 1


def test_write_endpoints_require_admin(client):
    assert client.post("/api/items", json={"name": "x"}).status_code == 401
    assert client.post("/api/items/batch", json={"items": []}).status_code == 401
    assert client.post(
        "/api/items/bulk-rcd-pmic", json={"updates": {}}
    ).status_code == 401
    assert client.post("/api/items/batch-delete", json={"ids": []}).status_code == 401


def test_bad_token_is_rejected(client):
    resp = client.post(
        "/api/items", json={"name": "x"}, headers={"Authorization": "Bearer bogus"}
    )
    assert resp.status_code == 401


def test_upload_size_is_capped(client, auth, app_module):
    oversized = b"x" * (app_module._MAX_UPLOAD_BYTES + 1024)
    resp = client.post(
        "/api/parse-file",
        files={"file": ("big.csv", oversized, "text/csv")},
        headers=auth,
    )
    assert resp.status_code == 413
