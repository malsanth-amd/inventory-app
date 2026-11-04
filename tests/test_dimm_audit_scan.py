"""The nightly DIMM audit scan: auto-grab each system's OS IP, SSH in, run a
dmidecode-based DIMM read, and match what it finds against the inventory —
the DIMM twin of test_audit_scan.py's CPU scan.

What matters most here, in order: a host with no OS IP (or no SSH login) must
not abort the other systems, the bare-serial-vs-barcode matching must agree
with what a person scanning the same DIMM by hand would see on screen, CPU and
DIMM runs must stay separated by `kind` in the shared cpu_audit_log/
audit_scan_runs tables, and every write path stays admin-only.
"""

from __future__ import annotations

import csv
from pathlib import Path


def _write_csv(tmp_path, names: list[str]):
    path = tmp_path / "systems.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["name"])
        for n in names:
            w.writerow([n])
    return str(path)


def _log_rows(app_module, host: str) -> list[dict]:
    with app_module._db_connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM cpu_audit_log WHERE host = ? AND kind = 'dimm' ORDER BY scanned_at", (host,)
        ).fetchall()]


def _no_delay(monkeypatch, app_module):
    monkeypatch.setattr(app_module, "DIMM_SCAN_HOST_DELAY_SEC", 0)
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)


def _dimm_json(serials: list[str]) -> str:
    import json
    return json.dumps({
        "detection_method": "dmidecode", "total_slots": len(serials), "populated": len(serials),
        "empty": 0, "edac_available": False, "ce_errors": 0, "ue_errors": 0,
        "dimms": [{"locator": f"DIMM{i}", "bank_locator": "", "size": "16 GB", "speed": "",
                   "configured_speed": "", "manufacturer": "", "part_number": "PN123",
                   "serial": s, "type": "", "source": "dmidecode", "edac_mc": "",
                   "ce_count": 0, "ue_count": 0} for i, s in enumerate(serials)],
    })


def _fake_discover_redfish(by_host: dict):
    """by_host maps hostname -> ("ip", "On"/"Off"/"?")."""
    def fn(host):
        return by_host.get(host, ("", "?"))
    return fn


def _fake_ssh_run_script(by_ip_creds: dict, calls: list | None = None):
    """by_ip_creds maps ip -> {(user, pw): ("stdout", "stderr")} or an
    Exception instance to raise for that credential pair."""
    async def fn(ip, username, password, script, env=None, timeout=60):
        if calls is not None:
            calls.append((ip, username, password))
        entry = by_ip_creds.get(ip, {})
        result = entry.get((username, password), Exception("all credentials refused"))
        if isinstance(result, Exception):
            raise result
        return result
    return fn


# ── DIMM serial matching ──────────────────────────────────────────────────────

def test_exact_bare_serial_matches(app_module):
    item = {"id": "x", "serial_number": "ABC123"}
    by_serial = {app_module._item_serial(item): item}
    assert app_module._find_dimm_by_serial("ABC123", by_serial) is item


def test_a_barcode_wrapped_stored_serial_matches_the_bare_dmidecode_serial(app_module):
    """97% of stored serial_number values are a full barcode; dmidecode always
    reports the bare serial, so the scan has to decode the stored side."""
    item = {"id": "x", "serial_number": "(L)Desc(S)SER456(P)PN789"}
    by_serial = {}
    key = app_module._item_serial(item)
    by_serial[key] = item
    assert key == "ser456"
    assert app_module._find_dimm_by_serial("SER456", by_serial) is item


def test_nothing_matches_an_absent_serial(app_module):
    assert app_module._find_dimm_by_serial("ZZZZZZ", {}) is None


def test_a_bare_serial_with_no_s_segment_parses_as_itself(app_module):
    assert app_module._parse_barcode_serial("JUST-A-SERIAL") == ""
    assert app_module._item_serial({"serial_number": "JUST-A-SERIAL"}) == "just-a-serial"


# ── one scan, several systems ─────────────────────────────────────────────────

def test_a_run_matches_logs_and_stamps_each_host_it_can_read(
        tmp_path, monkeypatch, app_module, make_item):
    _no_delay(monkeypatch, app_module)
    held = make_item(name="dimm held", category="DIMMs",
                     serial_number="(L)Desc(S)SER111(P)PN1").json()

    monkeypatch.setattr(app_module, "_discover_os_ip_redfish", _fake_discover_redfish({
        "eagle-0291": ("10.0.0.1", "On"),
        "eagle-0292": ("10.0.0.2", "On"),
        "eagle-0293": ("", "Off"),
    }))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.1": {("root", "test-os-password-1"): (_dimm_json(["SER111"]), "")},
        "10.0.0.2": {("root", "test-os-password-1"): (_dimm_json(["SER999"]), "")},   # matches nothing
    }))

    path = _write_csv(tmp_path, ["eagle-0291", "eagle-0292", "eagle-0293"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    summary = app_module.run_dimm_audit_scan()

    assert summary["hosts_total"] == 3
    assert summary["hosts_ok"] == 2
    assert len(summary["hosts_failed"]) == 1
    assert summary["hosts_failed"][0]["host"] == "eagle-0293"
    assert "not in OS state" in summary["hosts_failed"][0]["error"]
    assert summary["cpus_seen"] == 2
    assert summary["cpus_matched"] == 1
    assert summary["cpus_unmatched"] == 1

    held_now = next(i for i in app_module._read() if i["id"] == held["id"])
    assert held_now["audit"].startswith("eagle-0291 · ")

    matched_log = _log_rows(app_module, "eagle-0291")
    assert len(matched_log) == 1
    assert matched_log[0]["item_id"] == held["id"]
    assert matched_log[0]["found"] == 1
    assert matched_log[0]["kind"] == "dimm"

    unmatched_log = _log_rows(app_module, "eagle-0292")
    assert len(unmatched_log) == 1
    assert unmatched_log[0]["item_id"] is None
    assert unmatched_log[0]["serial_number"] == "SER999"

    assert _log_rows(app_module, "eagle-0293") == []


def test_credential_cascade_tries_both_os_default_pairs_in_order(
        tmp_path, monkeypatch, app_module):
    _no_delay(monkeypatch, app_module)
    calls: list = []
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0700": ("10.0.0.7", "On")}))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.7": {("amd", "test-os-password-1"): (_dimm_json([]), "")},
    }, calls=calls))

    path = _write_csv(tmp_path, ["eagle-0700"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    summary = app_module.run_dimm_audit_scan()
    assert summary["hosts_ok"] == 1
    assert calls == [("10.0.0.7", "root", "test-os-password-1"), ("10.0.0.7", "amd", "test-os-password-1")]


def test_a_third_credential_pair_is_tried_after_the_other_two(
        tmp_path, monkeypatch, app_module):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "OS_LOGIN_3_USER", "labuser")
    monkeypatch.setattr(app_module, "OS_LOGIN_3_PASSWORD", "labpass")
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0701": ("10.0.0.8", "On")}))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.8": {("labuser", "labpass"): (_dimm_json([]), "")},
    }))

    path = _write_csv(tmp_path, ["eagle-0701"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()
    assert summary["hosts_ok"] == 1


def test_ssh_failure_on_every_credential_is_a_failed_host_not_a_crash(
        tmp_path, monkeypatch, app_module):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0702": ("10.0.0.9", "On")}))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({}))

    path = _write_csv(tmp_path, ["eagle-0702"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()

    assert summary["hosts_ok"] == 0
    assert len(summary["hosts_failed"]) == 1
    assert "10.0.0.9" in summary["hosts_failed"][0]["error"]


def test_no_os_ip_and_sol_fallback_disabled_is_a_clean_failure(
        tmp_path, monkeypatch, app_module):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "DIMM_SOL_FALLBACK_ENABLED", False)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0703": ("", "On")}))

    path = _write_csv(tmp_path, ["eagle-0703"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()

    assert summary["hosts_failed"][0]["host"] == "eagle-0703"
    assert "DIMM_SOL_FALLBACK_ENABLED is off" in summary["hosts_failed"][0]["error"]


def test_sol_fallback_is_used_only_when_enabled_and_redfish_came_back_empty(
        tmp_path, monkeypatch, app_module):
    """Never a real console login in a test — the fake simply proves the
    fallback path is reached and its result used."""
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "DIMM_SOL_FALLBACK_ENABLED", True)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0704": ("", "On")}))

    async def fake_sol(bmc_ip):
        assert bmc_ip == "eagle-0704"
        return "10.0.0.11"
    monkeypatch.setattr(app_module, "_discover_os_ip_sol", fake_sol)
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.11": {("root", "test-os-password-1"): (_dimm_json([]), "")},
    }))

    path = _write_csv(tmp_path, ["eagle-0704"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()
    assert summary["hosts_ok"] == 1


def test_sol_fallback_also_failing_reports_both_reasons(
        tmp_path, monkeypatch, app_module):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "DIMM_SOL_FALLBACK_ENABLED", True)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0705": ("", "On")}))

    async def fake_sol(bmc_ip):
        return ""
    monkeypatch.setattr(app_module, "_discover_os_ip_sol", fake_sol)

    path = _write_csv(tmp_path, ["eagle-0705"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()
    error = summary["hosts_failed"][0]["error"]
    assert "Redfish" in error and "SOL console fallback" in error


def test_asyncssh_missing_is_reported_not_crashed(tmp_path, monkeypatch, app_module):
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", False)
    path = _write_csv(tmp_path, ["eagle-0706"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_dimm_audit_scan()
    assert "asyncssh is not installed" in summary["error"]


def test_concurrent_runs_are_refused_rather_than_queued(app_module):
    assert app_module._dimm_scan_lock.acquire(blocking=False)
    try:
        assert app_module.run_dimm_audit_scan() == {"error": "A DIMM audit scan is already running."}
    finally:
        app_module._dimm_scan_lock.release()


def test_an_empty_csv_is_reported_as_an_error_not_a_silent_no_op(
        tmp_path, monkeypatch, app_module):
    path = _write_csv(tmp_path, [])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)
    summary = app_module.run_dimm_audit_scan()
    assert "error" in summary
    assert summary["hosts_total"] == 0


# ── kind separates the two scans in the shared tables ─────────────────────────

def test_cpu_and_dimm_runs_stay_on_their_own_endpoints(
        tmp_path, monkeypatch, app_module, client, auth):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "AUDIT_SCAN_HOST_DELAY_SEC", 0)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish", _fake_discover_redfish({}))

    cpu_path = str(tmp_path / "cpu-systems.csv")
    dimm_path = str(tmp_path / "dimm-systems.csv")
    Path(cpu_path).write_text("name\r\n", encoding="utf-8")
    Path(dimm_path).write_text("name\r\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", cpu_path)
    app_module.run_audit_scan()
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", dimm_path)
    app_module.run_dimm_audit_scan()

    cpu_runs = client.get("/api/admin/audit-scan/runs?limit=100", headers=auth).json()["runs"]
    dimm_runs = client.get("/api/admin/dimm-scan/runs?limit=100", headers=auth).json()["runs"]
    assert all(r["kind"] == "cpu" for r in cpu_runs)
    assert all(r["kind"] == "dimm" for r in dimm_runs)
    assert dimm_path in dimm_runs[0]["error"]
    assert cpu_path in cpu_runs[0]["error"]


def test_dimm_scan_runs_endpoint_requires_admin(client):
    assert client.get("/api/admin/dimm-scan/runs").status_code == 401


def test_dimm_scan_manual_trigger_requires_admin(client):
    assert client.post("/api/admin/dimm-scan/run").status_code == 401


def test_dimm_scan_manual_trigger_runs_the_scan(
        tmp_path, monkeypatch, app_module, client, auth):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish", _fake_discover_redfish({}))
    path = _write_csv(tmp_path, ["eagle-0800"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    resp = client.post("/api/admin/dimm-scan/run", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json()["hosts_total"] == 1


# ── schema migration ───────────────────────────────────────────────────────────

def test_kind_column_migration_is_idempotent(app_module):
    """_init_db() runs again here the way it already has at import time;
    re-running it must not raise and must not disturb existing rows."""
    before = app_module._db_connect().execute(
        "SELECT COUNT(*) FROM audit_scan_runs").fetchone()[0]
    app_module._init_db()
    after = app_module._db_connect().execute(
        "SELECT COUNT(*) FROM audit_scan_runs").fetchone()[0]
    assert before == after


# ── single-system lookup: POST /api/dimm/read-sut ─────────────────────────────
#
# The DIMM twin of /api/cpu/read-sut in test_ppin.py: open to the lab (it is a
# read, and the credentials never leave the server), a different host shape
# is a 400, an unreachable OS IP or failed SSH login is reported rather than
# crashing, and a good read returns the parsed DIMM list.

def test_read_sut_is_open_to_the_lab_not_admin_gated(
        tmp_path, monkeypatch, app_module, client):
    """No auth header at all — matches /api/cpu/read-sut's own boundary."""
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)
    monkeypatch.setattr(app_module, "_discover_os_ip", lambda host: ("", "not in OS state (PowerState=Off)"))
    resp = client.post("/api/dimm/read-sut", json={"host": "eagle-0900"})
    assert resp.status_code == 422, resp.text   # reached the handler, just found nothing
    assert "not in OS state" in resp.json()["detail"]


def test_read_sut_rejects_a_bad_hostname_shape(client):
    resp = client.post("/api/dimm/read-sut", json={"host": "not a host!"})
    assert resp.status_code == 400


def test_read_sut_reports_asyncssh_missing_rather_than_crashing(monkeypatch, app_module, client):
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", False)
    resp = client.post("/api/dimm/read-sut", json={"host": "eagle-0901"})
    assert resp.status_code == 503
    assert "asyncssh" in resp.json()["detail"]


def test_read_sut_reports_ssh_failure_rather_than_crashing(monkeypatch, app_module, client):
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)
    monkeypatch.setattr(app_module, "_discover_os_ip", lambda host: ("10.0.0.50", ""))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({}))
    resp = client.post("/api/dimm/read-sut", json={"host": "eagle-0902"})
    assert resp.status_code == 502
    assert "10.0.0.50" in resp.json()["detail"]


def test_read_sut_returns_the_parsed_dimm_list_on_success(monkeypatch, app_module, client):
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)
    monkeypatch.setattr(app_module, "_discover_os_ip", lambda host: ("10.0.0.51", ""))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.51": {("root", "test-os-password-1"): (_dimm_json(["SER777"]), "")},
    }))
    resp = client.post("/api/dimm/read-sut", json={"host": "eagle-0903"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["host"] == "eagle-0903"
    assert data["os_ip"] == "10.0.0.51"
    assert data["ssh_user"] == "root"
    assert data["dimms"][0]["serial"] == "SER777"


def test_read_sut_tries_sol_fallback_only_when_enabled(monkeypatch, app_module, client):
    monkeypatch.setattr(app_module, "HAS_ASYNCSSH", True)
    monkeypatch.setattr(app_module, "DIMM_SOL_FALLBACK_ENABLED", False)
    monkeypatch.setattr(app_module, "_discover_os_ip",
                        lambda host: ("", "redfish-empty:PowerState=On but Redfish exposed no host IP"))

    async def fail_if_called(bmc_ip):
        raise AssertionError("SOL fallback must not run when disabled")
    monkeypatch.setattr(app_module, "_discover_os_ip_sol", fail_if_called)

    resp = client.post("/api/dimm/read-sut", json={"host": "eagle-0904"})
    assert resp.status_code == 422
    assert "DIMM_SOL_FALLBACK_ENABLED is off" in resp.json()["detail"]


# ── combined audit log export ──────────────────────────────────────────────────

def test_audit_log_export_requires_admin(client):
    assert client.get("/api/admin/audit-log/export").status_code == 401


def _parse_csv_rows(text: str) -> list[dict]:
    import csv as _csv
    import io as _io
    reader = _csv.DictReader(_io.StringIO(text))
    return list(reader)


def test_audit_log_export_includes_both_kinds_as_one_csv(
        tmp_path, monkeypatch, app_module, client, auth, make_item):
    _no_delay(monkeypatch, app_module)
    item = make_item(name="dimm exported", category="DIMMs", serial_number="SER-EXPORT-1").json()
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish",
                        _fake_discover_redfish({"eagle-0950": ("10.0.0.95", "On")}))
    monkeypatch.setattr(app_module, "_ssh_run_script", _fake_ssh_run_script({
        "10.0.0.95": {("root", "test-os-password-1"): (_dimm_json(["SER-EXPORT-1"]), "")},
    }))
    dimm_path = str(tmp_path / "dimm-export.csv")
    Path(dimm_path).write_text("name\r\neagle-0950\r\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", dimm_path)
    app_module.run_dimm_audit_scan()

    resp = client.get("/api/admin/audit-log/export", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    rows = _parse_csv_rows(resp.text)
    match = next(r for r in rows if r["serial_number"] == "SER-EXPORT-1")
    assert match["kind"] == "dimm"
    assert match["host"] == "eagle-0950"
    assert match["item_id"] == item["id"]
    assert match["item_name"] == "dimm exported"


def test_audit_log_export_can_filter_by_kind(tmp_path, monkeypatch, app_module, client, auth):
    _no_delay(monkeypatch, app_module)
    monkeypatch.setattr(app_module, "_discover_os_ip_redfish", _fake_discover_redfish({}))
    path = str(tmp_path / "empty.csv")
    Path(path).write_text("name\r\n", encoding="utf-8")
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    resp = client.get("/api/admin/audit-log/export?kind=dimm", headers=auth)
    assert resp.status_code == 200
    rows = _parse_csv_rows(resp.text)
    assert rows   # earlier tests in this module already produced dimm-kind rows
    assert all(r["kind"] == "dimm" for r in rows)


# ── /api/items/audit's kind tag ────────────────────────────────────────────────
#
# Regression coverage for a real bug: this endpoint is shared by the CPU and
# DIMM single-host lookups' "record what was just found" step, and used to
# hardcode kind="cpu" regardless of which one called it — every manual DIMM
# read was logging into the trail mislabeled as a CPU sighting.

def test_record_audit_defaults_to_cpu_kind(client, auth, make_item):
    item = make_item(name="cpu for audit", category="CPU (Silicon)", serial_number="CPUSER1").json()
    resp = client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "some-host",
    }, headers=auth)
    assert resp.status_code == 200, resp.text
    with_kind = client.get(f"/api/items/{item['id']}/audit-history", headers=auth).json()["history"]
    assert with_kind[0]["found"] == 1

    export = _parse_csv_rows(client.get("/api/admin/audit-log/export", headers=auth).text)
    row = next(r for r in export if r["item_id"] == item["id"])
    assert row["kind"] == "cpu"


def test_record_audit_accepts_dimm_kind(client, auth, make_item):
    item = make_item(name="dimm for audit", category="DIMMs", serial_number="DIMMSER1").json()
    resp = client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "some-host", "kind": "dimm",
    }, headers=auth)
    assert resp.status_code == 200, resp.text

    export = _parse_csv_rows(client.get("/api/admin/audit-log/export", headers=auth).text)
    row = next(r for r in export if r["item_id"] == item["id"])
    assert row["kind"] == "dimm"


def test_record_audit_rejects_an_unknown_kind(client, auth, make_item):
    item = make_item(name="audit kind validation", category="DIMMs").json()
    resp = client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "some-host", "kind": "gpu",
    }, headers=auth)
    assert resp.status_code == 422


# ── audit log export: full item serial + latest-date-only ─────────────────────

def test_export_includes_the_items_own_full_serial_number(client, auth, make_item):
    item = make_item(name="cpu with composite serial", category="CPU (Silicon)",
                     serial_number="F430935S60026_100-000001263-01").json()
    client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "some-host",
    }, headers=auth)

    rows = _parse_csv_rows(client.get("/api/admin/audit-log/export", headers=auth).text)
    row = next(r for r in rows if r["item_id"] == item["id"])
    assert row["item_serial_number"] == "F430935S60026_100-000001263-01"


def test_latest_only_keeps_each_systems_own_most_recent_date(app_module, client, auth, make_item):
    """Per system, not one global date: a system last touched long ago still
    shows its own latest entry, and a system read twice on different dates
    only shows the newer one for that system."""
    item = make_item(name="latest-only probe", category="CPU (Silicon)",
                     serial_number="LATESTPROBE").json()
    with app_module._db_connect() as conn:
        import uuid as _uuid
        # "repeat-host" has an old sighting and a today sighting -- only
        # today's should survive latest_only for this host.
        conn.execute(
            "INSERT INTO cpu_audit_log (id, item_id, serial_number, host, found, scanned_at, kind) "
            "VALUES (?, ?, ?, ?, 1, ?, 'cpu')",
            (_uuid.uuid4().hex, item["id"], "LATESTPROBE", "repeat-host", "2020-01-01T00:00:00+00:00"),
        )
        # "stale-host" was only ever scanned long ago -- that is still its
        # own latest, so it must still appear.
        conn.execute(
            "INSERT INTO cpu_audit_log (id, item_id, serial_number, host, found, scanned_at, kind) "
            "VALUES (?, ?, ?, ?, 1, ?, 'cpu')",
            (_uuid.uuid4().hex, item["id"], "LATESTPROBE", "stale-host", "2020-01-01T00:00:00+00:00"),
        )
        conn.commit()
    client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "repeat-host",
    }, headers=auth)

    latest = _parse_csv_rows(client.get("/api/admin/audit-log/export?latest_only=true", headers=auth).text)
    rows_for_item = [r for r in latest if r["item_id"] == item["id"]]
    hosts_seen = {r["host"] for r in rows_for_item}
    assert hosts_seen == {"repeat-host", "stale-host"}
    # And only the recent one of repeat-host's two dated entries survived.
    repeat_dates = {r["scanned_at"][:10] for r in rows_for_item if r["host"] == "repeat-host"}
    assert "2020-01-01" not in repeat_dates

    everything = _parse_csv_rows(client.get("/api/admin/audit-log/export", headers=auth).text)
    all_rows_for_item = [r for r in everything if r["item_id"] == item["id"]]
    assert len(all_rows_for_item) == 3   # nothing lost from the unfiltered export


def test_latest_only_groups_hosts_case_insensitively(app_module, client, auth, make_item):
    item = make_item(name="case probe", category="CPU (Silicon)", serial_number="CASEPROBE").json()
    with app_module._db_connect() as conn:
        import uuid as _uuid
        conn.execute(
            "INSERT INTO cpu_audit_log (id, item_id, serial_number, host, found, scanned_at, kind) "
            "VALUES (?, ?, ?, ?, 1, ?, 'cpu')",
            (_uuid.uuid4().hex, item["id"], "CASEPROBE", "Case-Host", "2020-01-01T00:00:00+00:00"),
        )
        conn.commit()
    client.post("/api/items/audit", json={
        "ids": [item["id"]], "audit": "note", "host": "case-host",
    }, headers=auth)

    latest = _parse_csv_rows(client.get("/api/admin/audit-log/export?latest_only=true", headers=auth).text)
    rows_for_item = [r for r in latest if r["item_id"] == item["id"]]
    # Only today's lowercase-hostname row -- the 2020 "Case-Host" row is the
    # same system under different casing, and is not this system's latest.
    assert len(rows_for_item) == 1
    assert rows_for_item[0]["host"] == "case-host"
