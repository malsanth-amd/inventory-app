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
# The nightly audit scan must never start on its own during a test run: it
# would SSH to whatever AUDIT_SYSTEMS_CSV points at (a real path by default)
# every time any test module imports server. Tests that exercise the scan
# call run_audit_scan() directly, or monkeypatch this back to "true".
os.environ["AUDIT_SCAN_ENABLED"] = "false"
os.environ["DIMM_SCAN_ENABLED"] = "false"
# Forced off regardless of the developer's real .env: a test that forgets to
# monkeypatch _discover_os_ip_sol must fail loudly on a mocked call, not
# silently open a real console session to a real BMC. This is not
# hypothetical — a real .env with this left on once made the DIMM scan test
# suite do exactly that.
os.environ["DIMM_SOL_FALLBACK_ENABLED"] = "false"
# A fixed, obviously-fake OS login cascade for the DIMM scan tests — never the
# developer's real .env values, and never the lab's actual OS credentials.
os.environ["OS_LOGIN_1_USER"]     = "root"
os.environ["OS_LOGIN_1_PASSWORD"] = "test-os-password-1"
os.environ["OS_LOGIN_2_USER"]     = "amd"
os.environ["OS_LOGIN_2_PASSWORD"] = "test-os-password-1"
os.environ["OS_LOGIN_3_USER"]     = ""
os.environ["OS_LOGIN_3_PASSWORD"] = ""

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


@pytest.fixture(autouse=True)
def _reset_decoder_state():
    """Decoder lookups are cached and rate limited per client.

    Both are process-global, so without this one test's lookup answers the
    next one's — and a file with more than _MAX_DECODES_PER_WINDOW lookups
    would start returning 429 partway through.
    """
    server._decode_cache.clear()
    server._decode_times.clear()
    server._sut_times.clear()
    yield


def strip_server_fields(item: dict) -> dict:
    """Drop the fields the API assigns, leaving a valid ItemIn body."""
    body = dict(item)
    for key in ("id", "createdAt", "updatedAt", "modified_by"):
        body.pop(key, None)
    return body


# ── a BMC that never leaves this process ──────────────────────────────────────
#
# Shared by test_ppin.py (the /api/cpu/read-sut endpoint) and test_audit_scan.py
# (the nightly scan that reads the same way). Lives here, not in either test
# module, so both can use it without one importing fixtures out of the other.

class _FakeChannel:
    def __init__(self, text: str):
        self._text = text.encode()

    def read(self):
        return self._text


class _FakeSSH:
    """A BMC that answers apml_tool per socket from a canned map.

    by_host, when given, maps hostname -> per_socket dict and is resolved once
    .connect(host, ...) reveals which host this instance is standing in for —
    which is what lets one fake serve a whole scan over several systems rather
    than just the one /api/cpu/read-sut talks to at a time. An entry's
    "_connect_error" key, if present, is raised from connect() instead of a
    per_socket map being used.
    """

    instances: list["_FakeSSH"] = []

    def __init__(self, per_socket: dict[int, str] | None = None, connect_error=None,
                 by_host: dict[str, dict] | None = None):
        self.per_socket    = per_socket if per_socket is not None else {}
        self.connect_error = connect_error
        self.by_host       = by_host
        self.host          = None
        self.commands: list[str] = []
        self.connects  = 0
        self.closed    = False
        _FakeSSH.instances.append(self)

    def set_missing_host_key_policy(self, _policy): pass

    def connect(self, host, *a, **k):
        self.connects += 1
        self.host = host
        if self.by_host is not None:
            entry = self.by_host.get(host, {})
            err = entry.get("_connect_error")
            if err:
                raise err
            self.per_socket = {k: v for k, v in entry.items() if k != "_connect_error"}
        elif self.connect_error:
            raise self.connect_error

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        socket_no = int(command.split()[1])
        if socket_no not in self.per_socket:
            raise OSError(f"apml_tool: socket {socket_no} not present")
        return None, _FakeChannel(self.per_socket[socket_no]), _FakeChannel("")

    def close(self):
        self.closed = True


@pytest.fixture
def fake_bmc(monkeypatch, app_module):
    """install(per_socket=None, connect_error=None, by_host=None) patches
    paramiko.SSHClient for the duration of one test.

    by_host maps hostname -> {socket: output} (plus an optional
    "_connect_error" entry), for tests that read more than one system in a
    single call — the nightly scan, chiefly. Without it every host gets the
    same per_socket/connect_error, which is all the single-host
    /api/cpu/read-sut tests need.
    """
    import paramiko
    monkeypatch.setattr(app_module, "BMC_PASSWORD", "test-bmc-password")

    def install(per_socket=None, connect_error=None, by_host=None):
        _FakeSSH.instances.clear()
        monkeypatch.setattr(
            paramiko, "SSHClient",
            lambda: _FakeSSH(per_socket, connect_error, by_host))
        return _FakeSSH

    return install


DUAL = {
    0: "| Socket 0 PPIN FUSE | 0x2b620df48c84013 |",
    1: "| Socket 1 PPIN FUSE | 0x831a421659c02b |",
}
