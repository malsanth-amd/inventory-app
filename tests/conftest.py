"""Shared fixtures.

server.py does its work at import time — it resolves the data directory, opens
the database and bootstraps admins.json — so the environment has to be set up
*before* the import. That is why this module configures os.environ at the top,
rather than in a fixture.

Every run gets its own throwaway data directory, so tests never touch the real
inventory and can be run on a developer machine that also has the app running.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

TEST_ADMIN = "TestSuperAdmin"
TEST_PASSWORD = "test-password-123"

_DATA_DIR = Path(tempfile.mkdtemp(prefix="inventory-tests-"))

os.environ["INVENTORY_DATA_DIR"] = str(_DATA_DIR)
os.environ["ADMIN_1_USERNAME"] = TEST_ADMIN
os.environ["ADMIN_1_PASSWORD"] = TEST_PASSWORD
os.environ["SUPER_ADMIN_USERNAME"] = TEST_ADMIN
os.environ["DEVELOPER_USERNAME"] = ""
# load_dotenv() does not override variables already in the environment, so
# blanking these here keeps the run independent of whatever .env the developer
# happens to have. Without it, their ADMIN_2/ADMIN_3 accounts get bootstrapped
# into the test database and account-set assertions fail confusingly.
for _slot in (2, 3):
    os.environ[f"ADMIN_{_slot}_USERNAME"] = ""
    os.environ[f"ADMIN_{_slot}_PASSWORD"] = ""
os.environ["ADMIN_USERNAME"] = ""
os.environ["ADMIN_PASSWORD"] = ""
# Leave SMTP unset by default so nothing can send mail during a test run.
os.environ["SMTP_HOST"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import server  # noqa: E402

server._init_db()


@pytest.fixture(scope="session")
def app_module():
    return server


@pytest.fixture(scope="session")
def client():
    return TestClient(server.app)


@pytest.fixture(scope="session")
def token(client):
    resp = client.post(
        "/api/login", json={"username": TEST_ADMIN, "password": TEST_PASSWORD}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


@pytest.fixture(scope="session")
def auth(token):
    """Authorization header for the superadmin account."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def make_item(client, auth):
    """Create items and guarantee they are removed when the test finishes."""
    created: list[str] = []

    def _make(**fields):
        payload = {"name": "test item", "category": "DIMMs", **fields}
        resp = client.post("/api/items", json=payload, headers=auth)
        if resp.status_code == 201:
            created.append(resp.json()["id"])
        return resp

    yield _make

    for item_id in created:
        client.delete(f"/api/items/{item_id}", headers=auth)


def strip_server_fields(item: dict) -> dict:
    """Drop the fields the API assigns, leaving a valid ItemIn body."""
    body = dict(item)
    for key in ("id", "createdAt", "updatedAt", "modified_by"):
        body.pop(key, None)
    return body
