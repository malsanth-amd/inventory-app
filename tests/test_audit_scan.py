"""The nightly CPU audit scan: read every system in a CSV, match what each one
reports against the inventory, and keep a trail of where each CPU has been
seen — not just the latest sighting.

Three things matter most here, in order: a bad host must not abort the other
ninety, the audit field and the log it feeds must actually agree with what
_find_cpu_by_serial decided, and the write side (/api/items/audit,
/api/admin/audit-scan/run, the history endpoint) must stay admin-only, since
reading a system is open to the whole lab but writing to inventory is not.
"""

from __future__ import annotations

import csv

from ppin_sn import decode_ppin

PPIN_A = "0x2b620df48c84013"   # decodes to 9KR5736P30019
PPIN_B = "0x831a421659c02b"    # decodes to F405504W30043
SERIAL_A = decode_ppin(PPIN_A)
SERIAL_B = decode_ppin(PPIN_B)


def _socket_line(ppin: str, socket: int = 0) -> str:
    return f"| Socket {socket} PPIN FUSE | {ppin} |"


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
            "SELECT * FROM cpu_audit_log WHERE host = ? ORDER BY scanned_at", (host,)
        ).fetchall()]


def _no_delay(monkeypatch, app_module):
    """97 real systems want a pause between each; a handful of fake ones in a
    test do not — keep the suite fast and deterministic."""
    monkeypatch.setattr(app_module, "AUDIT_SCAN_HOST_DELAY_SEC", 0)


# ── reading the CSV ───────────────────────────────────────────────────────────

def test_reads_hostnames_skipping_header_and_blanks(tmp_path, app_module):
    path = tmp_path / "systems.csv"
    path.write_text("name\r\nEagle-0291\r\n\r\nEagle-0292\r\n", encoding="utf-8")
    assert app_module._read_audit_systems_csv(str(path)) == ["Eagle-0291", "Eagle-0292"]


def test_de_duplicates_keeping_first_seen_order(tmp_path, app_module):
    path = _write_csv(tmp_path, ["Eagle-0291", "Falcon-01", "Eagle-0291"])
    assert app_module._read_audit_systems_csv(path) == ["Eagle-0291", "Falcon-01"]


def test_a_missing_file_is_reported_not_raised(tmp_path, app_module, capsys):
    missing = str(tmp_path / "does-not-exist.csv")
    assert app_module._read_audit_systems_csv(missing) == []
    assert "could not read" in capsys.readouterr().out.lower()


# ── matching a decoded serial to a stored item ────────────────────────────────

def test_exact_serial_matches(app_module):
    item = {"id": "x", "serial_number": "F427529U60099"}
    by_serial = {"f427529u60099": item}
    assert app_module._find_cpu_by_serial("F427529U60099", by_serial, [item]) is item


def test_matches_the_composite_format_this_inventory_stores_cpus_in(app_module):
    """A PPIN decodes to the bare serial; CPUs here are stored as
    <serial>_<part number>-<rev>. This is the gap the CPU Decoder panel's
    "Not in this inventory" bug came from — the scan must not repeat it."""
    item = {"id": "x", "serial_number": "F427529U60021_100-000001263-04"}
    assert app_module._find_cpu_by_serial("F427529U60021", {}, [item]) is item


def test_a_bare_prefix_without_a_separator_is_not_a_match(app_module):
    """F427529U600219 merely starts with F427529U60021; it is a different chip."""
    item = {"id": "x", "serial_number": "F427529U600219"}
    assert app_module._find_cpu_by_serial("F427529U60021", {}, [item]) is None


def test_nothing_matches_an_absent_serial(app_module):
    assert app_module._find_cpu_by_serial("ZZZZZZZZZZZZZ", {}, []) is None


# ── one scan, several systems ─────────────────────────────────────────────────

def test_a_run_matches_logs_and_stamps_each_host_it_can_read(
        tmp_path, monkeypatch, app_module, fake_bmc, make_item):
    _no_delay(monkeypatch, app_module)
    held = make_item(name="cpu held", category="CPU (Silicon)",
                     serial_number=f"{SERIAL_A}_100-000001263-04").json()

    fake_bmc(by_host={
        "eagle-0291": {0: _socket_line(PPIN_A)},          # matches `held`
        "eagle-0292": {0: _socket_line(PPIN_B)},           # decodes, matches nothing
        "eagle-0293": {"_connect_error": OSError("No route to host")},
    })
    path = _write_csv(tmp_path, ["eagle-0291", "eagle-0292", "eagle-0293"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    summary = app_module.run_audit_scan()

    assert summary["hosts_total"] == 3
    assert summary["hosts_ok"] == 2                      # 0291 and 0292 both answered
    assert len(summary["hosts_failed"]) == 1
    assert summary["hosts_failed"][0]["host"] == "eagle-0293"
    assert summary["cpus_seen"] == 2
    assert summary["cpus_matched"] == 1
    assert summary["cpus_unmatched"] == 1

    held_now = next(i for i in app_module._read() if i["id"] == held["id"])
    assert held_now["audit"].startswith("eagle-0291 · ")

    matched_log = _log_rows(app_module, "eagle-0291")
    assert len(matched_log) == 1
    assert matched_log[0]["item_id"] == held["id"]
    assert matched_log[0]["found"] == 1

    unmatched_log = _log_rows(app_module, "eagle-0292")
    assert len(unmatched_log) == 1
    assert unmatched_log[0]["item_id"] is None
    assert unmatched_log[0]["found"] == 0
    assert unmatched_log[0]["serial_number"] == SERIAL_B

    # The host that never connected gets no log rows at all — there was
    # nothing to report seeing.
    assert _log_rows(app_module, "eagle-0293") == []


def test_a_second_scan_overwrites_the_field_but_the_log_keeps_both(
        tmp_path, monkeypatch, app_module, fake_bmc, make_item):
    _no_delay(monkeypatch, app_module)
    item = make_item(name="cpu rescanned", category="CPU (Silicon)",
                     serial_number=f"{SERIAL_A}_100-000001263-04").json()

    fake_bmc(by_host={"eagle-0400": {0: _socket_line(PPIN_A)}})
    path = _write_csv(tmp_path, ["eagle-0400"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    app_module.run_audit_scan()
    app_module.run_audit_scan()

    rows = _log_rows(app_module, "eagle-0400")
    # Only this test's own item/host pair is asserted on, so a second scan
    # really did add a second row rather than there being two from elsewhere.
    assert len(rows) == 2
    assert all(r["item_id"] == item["id"] for r in rows)


def test_an_unknown_hostname_shape_in_the_csv_is_a_failure_not_a_crash(
        tmp_path, monkeypatch, app_module, fake_bmc):
    _no_delay(monkeypatch, app_module)
    fake_bmc(by_host={})
    path = _write_csv(tmp_path, ["not a hostname!"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    summary = app_module.run_audit_scan()
    assert summary["hosts_failed"][0]["error"] == "not a hostname shape"
    assert summary["hosts_ok"] == 0


def test_an_empty_csv_is_reported_as_an_error_not_a_silent_no_op(
        tmp_path, monkeypatch, app_module):
    path = _write_csv(tmp_path, [])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    summary = app_module.run_audit_scan()
    assert "error" in summary
    assert summary["hosts_total"] == 0


def test_concurrent_runs_are_refused_rather_than_queued(app_module):
    """The nightly tick and a manual 'run now' click must not SSH into the
    same ninety-odd BMCs twice at once."""
    assert app_module._audit_scan_lock.acquire(blocking=False)
    try:
        assert app_module.run_audit_scan() == {"error": "An audit scan is already running."}
    finally:
        app_module._audit_scan_lock.release()


# ── the admin boundary ────────────────────────────────────────────────────────

def test_manual_trigger_requires_admin(client):
    assert client.post("/api/admin/audit-scan/run").status_code == 401


def test_manual_trigger_runs_the_scan(tmp_path, monkeypatch, app_module, client, auth, fake_bmc):
    _no_delay(monkeypatch, app_module)
    fake_bmc(by_host={})
    path = _write_csv(tmp_path, ["eagle-0500"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    resp = client.post("/api/admin/audit-scan/run", headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json()["hosts_total"] == 1


def test_history_requires_admin(client, make_item):
    item = make_item(name="cpu guarded", category="CPU (Silicon)").json()
    assert client.get(f"/api/items/{item['id']}/audit-history").status_code == 401


def test_history_lists_scans_newest_first(
        tmp_path, monkeypatch, app_module, client, auth, fake_bmc, make_item):
    _no_delay(monkeypatch, app_module)
    item = make_item(name="cpu with history", category="CPU (Silicon)",
                     serial_number=f"{SERIAL_A}_100-000001263-04").json()
    fake_bmc(by_host={"eagle-0600": {0: _socket_line(PPIN_A)}})
    path = _write_csv(tmp_path, ["eagle-0600"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    app_module.run_audit_scan()
    app_module.run_audit_scan()

    resp = client.get(f"/api/items/{item['id']}/audit-history", headers=auth)
    assert resp.status_code == 200, resp.text
    history = resp.json()["history"]
    assert len(history) == 2
    assert all(h["host"] == "eagle-0600" and h["found"] == 1 for h in history)


def test_history_is_empty_for_an_item_never_scanned(client, auth, make_item):
    item = make_item(name="cpu untouched", category="CPU (Silicon)").json()
    resp = client.get(f"/api/items/{item['id']}/audit-history", headers=auth)
    assert resp.status_code == 200
    assert resp.json()["history"] == []


# ── which systems failed, after the fact ──────────────────────────────────────
#
# The gap this closes: a real run found 19 of 97 systems had not answered, and
# the only way to learn that was a one-off read-only query against the live
# database, because the failed-host list only ever existed in the HTTP
# response of the request that triggered the scan. These pin that the list
# survives past that response, for both the manual trigger and an unattended
# 00:30 run that nobody was watching.

def test_a_run_is_recorded_with_its_failed_hosts(
        tmp_path, monkeypatch, app_module, fake_bmc, client, auth):
    _no_delay(monkeypatch, app_module)
    fake_bmc(by_host={
        "eagle-0100": {0: _socket_line(PPIN_A)},
        "eagle-0101": {"_connect_error": OSError("No route to host")},
    })
    path = _write_csv(tmp_path, ["eagle-0100", "eagle-0101"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    live_summary = app_module.run_audit_scan()

    resp = client.get("/api/admin/audit-scan/runs", headers=auth)
    assert resp.status_code == 200, resp.text
    runs = resp.json()["runs"]
    assert runs[0]["hosts_total"] == 2
    assert runs[0]["hosts_ok"] == 1
    assert runs[0]["hosts_failed"] == live_summary["hosts_failed"]
    assert runs[0]["hosts_failed"][0]["host"] == "eagle-0101"
    assert "No route to host" in runs[0]["hosts_failed"][0]["error"]


def test_an_unattended_run_is_recorded_the_same_way(
        tmp_path, monkeypatch, app_module, fake_bmc, client, auth):
    """The scheduled loop calls run_audit_scan() with nobody watching the
    response; the run must still be findable afterward through the endpoint,
    exactly as a manual run is."""
    _no_delay(monkeypatch, app_module)
    fake_bmc(by_host={"eagle-0200": {"_connect_error": OSError("timed out")}})
    path = _write_csv(tmp_path, ["eagle-0200"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    app_module.run_audit_scan()   # nothing reads the return value — as the loop does

    runs = client.get("/api/admin/audit-scan/runs", headers=auth).json()["runs"]
    assert runs[0]["hosts_failed"][0]["host"] == "eagle-0200"


def test_runs_are_newest_first_and_each_is_its_own_row(
        tmp_path, monkeypatch, app_module, fake_bmc, client, auth):
    _no_delay(monkeypatch, app_module)
    fake_bmc(by_host={})
    path = _write_csv(tmp_path, ["eagle-0300"])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)

    before = len(client.get("/api/admin/audit-scan/runs?limit=100", headers=auth).json()["runs"])
    app_module.run_audit_scan()
    app_module.run_audit_scan()
    runs = client.get("/api/admin/audit-scan/runs?limit=100", headers=auth).json()["runs"]

    assert len(runs) == before + 2
    assert runs[0]["started_at"] >= runs[1]["started_at"]


def test_an_empty_csv_is_still_recorded_as_a_run(tmp_path, monkeypatch, app_module, client, auth):
    """A misconfigured path is itself worth finding after the fact, not only
    in whichever terminal happened to be open when it first went wrong."""
    path = _write_csv(tmp_path, [])
    monkeypatch.setattr(app_module, "AUDIT_SYSTEMS_CSV", path)
    app_module.run_audit_scan()

    runs = client.get("/api/admin/audit-scan/runs", headers=auth).json()["runs"]
    assert runs[0]["hosts_total"] == 0
    assert "No hostnames found" in runs[0]["error"]


def test_a_refused_concurrent_run_is_not_recorded(app_module, client, auth):
    """'Someone else is already scanning' is not an outcome — logging it as a
    run would make the history noisy with events that did nothing."""
    before = len(client.get("/api/admin/audit-scan/runs?limit=100", headers=auth).json()["runs"])
    assert app_module._audit_scan_lock.acquire(blocking=False)
    try:
        app_module.run_audit_scan()
    finally:
        app_module._audit_scan_lock.release()
    after = len(client.get("/api/admin/audit-scan/runs?limit=100", headers=auth).json()["runs"])
    assert after == before


def test_runs_endpoint_requires_admin(client):
    assert client.get("/api/admin/audit-scan/runs").status_code == 401
