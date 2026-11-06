"""The audit field: where a CPU was last actually seen.

Written by the CPU decoder when it reads a system, so the inventory records
not just where an item is filed but where it was found. The permission check
is the one that matters most here: /api/cpu/read-sut is deliberately open to
the lab, so the write that follows a scan must not be.
"""

from __future__ import annotations

from conftest import strip_server_fields

NOTE = "seagull-0152 · 2026-11-01"


def _fetch(client, item_id: str) -> dict:
    return next(i for i in client.get("/api/items").json() if i["id"] == item_id)


def test_records_the_note_on_each_item(client, auth, make_item):
    a = make_item(name="cpu a", category="CPU (Silicon)").json()
    b = make_item(name="cpu b", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [a["id"], b["id"]], "audit": NOTE})
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == 2
    assert _fetch(client, a["id"])["audit"] == NOTE
    assert _fetch(client, b["id"])["audit"] == NOTE


def test_requires_admin(client, make_item):
    """The scan is open to anyone; the write it triggers is not."""
    item = make_item(name="cpu guarded", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit",
                       json={"ids": [item["id"]], "audit": NOTE})
    assert resp.status_code == 401
    assert _fetch(client, item["id"])["audit"] == ""


def test_a_later_scan_replaces_the_earlier_one(client, auth, make_item):
    """The field is "last seen", not a history."""
    item = make_item(name="cpu moved", category="CPU (Silicon)").json()
    client.post("/api/items/audit", headers=auth,
                json={"ids": [item["id"]], "audit": "seagull-0100 · 2026-10-01"})
    client.post("/api/items/audit", headers=auth,
                json={"ids": [item["id"]], "audit": NOTE})
    assert _fetch(client, item["id"])["audit"] == NOTE


def test_missing_items_are_refused(client, auth, make_item):
    item = make_item(name="cpu present", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [item["id"], "no-such-id"], "audit": NOTE})
    assert resp.status_code == 404, resp.text
    # Nothing applied — the whole call is refused, as elsewhere.
    assert _fetch(client, item["id"])["audit"] == ""


def test_empty_id_list_is_a_no_op(client, auth):
    resp = client.post("/api/items/audit", headers=auth, json={"ids": [], "audit": NOTE})
    assert resp.status_code == 200
    assert resp.json()["updated"] == 0


def test_duplicate_ids_are_collapsed(client, auth, make_item):
    """Two sockets can resolve to one stored row; that is one update, not two."""
    item = make_item(name="cpu twice", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [item["id"], item["id"]], "audit": NOTE})
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == 1


def test_long_notes_are_capped(client, auth, make_item, app_module):
    item = make_item(name="cpu long", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [item["id"]], "audit": "x" * 500})
    assert resp.status_code == 200, resp.text
    assert len(_fetch(client, item["id"])["audit"]) == app_module._MAX_AUDIT_LEN


def test_editing_an_item_does_not_clear_the_audit(client, auth, make_item):
    """The field is maintained by scans, and is not part of the edit form — a
    normal save must leave it alone rather than blanking it."""
    item = make_item(name="cpu edited", category="CPU (Silicon)").json()
    client.post("/api/items/audit", headers=auth,
                json={"ids": [item["id"]], "audit": NOTE})
    fresh = _fetch(client, item["id"])
    body = {**strip_server_fields(fresh), "location": "L6-L12-09"}
    body.pop("audit", None)                      # the UI never sends it
    resp = client.put(f"/api/items/{item['id']}", json=body, headers=auth)
    assert resp.status_code == 200, resp.text
    after = _fetch(client, item["id"])
    assert after["location"] == "L6-L12-09"
    assert after["audit"] == NOTE


def test_audit_changes_the_items_etag(client, auth, make_item):
    """Otherwise other tabs would not see the scan's result until something
    else happened to change the inventory."""
    item = make_item(name="cpu etag", category="CPU (Silicon)").json()
    before = client.get("/api/items").headers["ETag"]
    client.post("/api/items/audit", headers=auth,
                json={"ids": [item["id"]], "audit": NOTE})
    assert client.get("/api/items").headers["ETag"] != before


# ── this endpoint is also how a one-off "Get CPU Serial Number" read gets its
# CPU into the trail, not only the nightly batch scan ───────────────────────
#
# Found the hard way: 49 real items had a current `audit` value from months
# of single-system reads, and cpu_audit_log had zero rows for any of them —
# this endpoint stamped the field but, without a host, had nothing to log.

def _log_rows_for(app_module, item_id: str) -> list[dict]:
    with app_module._db_connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM cpu_audit_log WHERE item_id = ?", (item_id,)
        ).fetchall()]


def test_a_host_in_the_request_logs_a_history_row(client, auth, app_module, make_item):
    item = make_item(name="cpu with host", category="CPU (Silicon)",
                     serial_number="F427529U60021").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [item["id"]], "audit": NOTE, "host": "seagull-0152"})
    assert resp.status_code == 200, resp.text

    rows = _log_rows_for(app_module, item["id"])
    assert len(rows) == 1
    assert rows[0]["host"] == "seagull-0152"
    assert rows[0]["found"] == 1
    assert rows[0]["serial_number"] == "F427529U60021"


def test_no_host_means_no_log_row(client, auth, app_module, make_item):
    """Back-compat: a caller that only ever sent ids/audit (no such caller
    exists in this codebase anymore, but the field is optional) must not start
    failing, and must not have rows invented for it either."""
    item = make_item(name="cpu without host", category="CPU (Silicon)").json()
    resp = client.post("/api/items/audit", headers=auth,
                       json={"ids": [item["id"]], "audit": NOTE})
    assert resp.status_code == 200, resp.text
    assert _log_rows_for(app_module, item["id"]) == []


def test_repeated_single_system_reads_each_add_a_row(client, auth, app_module, make_item):
    """The scenario that exposed the gap: the same system read by hand, night
    after night, with nothing ever moving. Every read should still add to the
    trail, not just refresh the one-line field."""
    item = make_item(name="cpu read repeatedly", category="CPU (Silicon)").json()
    for _ in range(3):
        client.post("/api/items/audit", headers=auth,
                    json={"ids": [item["id"]], "audit": NOTE, "host": "seagull-0152"})
    assert len(_log_rows_for(app_module, item["id"])) == 3
