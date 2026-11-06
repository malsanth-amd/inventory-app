"""One upload that both adds items and checks them in/out.

A real spreadsheet is rarely all one thing — some parts arriving, some coming
back, a loan changing hands. /api/items/batch takes both halves and commits them
as a single transaction, so the interesting assertions here are the ones about
what happens when part of the file is bad: nothing at all may land, or the admin
is left reconciling a half-applied sheet with no way to tell which half.
"""

from __future__ import annotations

from conftest import strip_server_fields


def _row(item: dict, **changes) -> dict:
    """An update row carrying the item's current version, as the UI sends it."""
    return {
        "id": item["id"],
        "item": {**strip_server_fields(item), **changes},
        "expected_updated_at": item["updatedAt"],
    }


def _new(name: str, **fields) -> dict:
    return {"name": name, "category": "DIMMs", **fields}


def _fetch(client, item_id: str) -> dict:
    return next(i for i in client.get("/api/items").json() if i["id"] == item_id)


def _count(client) -> int:
    return len(client.get("/api/items").json())


def _cleanup(client, auth, resp):
    """Delete whatever a raw (fixture-less) batch call created."""
    if resp.status_code != 201:
        return
    names = {"combined new", "combined new 2", "rolled back", "capped"}
    ids = [i["id"] for i in client.get("/api/items").json() if i["name"] in names]
    if ids:
        client.post("/api/items/batch-delete", json={"ids": ids}, headers=auth)


# ── back-compat: the creates-only shape the import always sent ────────────────

def test_items_only_still_works(client, auth):
    """A payload with no `updates` key behaves exactly as it did before."""
    resp = client.post("/api/items/batch", headers=auth,
                       json={"items": [_new("combined new"), _new("combined new 2")]})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["imported"] == 2
    assert body["updated"] == 0
    assert body["items"] == []
    _cleanup(client, auth, resp)


def test_updates_only(client, auth, make_item):
    item = make_item(name="returning", checkout_user="Mega",
                     checkout_email="mega@amd.com", checkout_date="2026-10-01").json()
    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [],
        "updates": [_row(item, checkout_user="", checkout_email="",
                         checkout_date="", loan_until="")],
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["updated"] == 1
    assert _fetch(client, item["id"])["checkout_user"] == ""


# ── the point of the change: both halves, one call ────────────────────────────

def test_mixed_sheet_applies_both_halves(client, auth, make_item):
    out    = make_item(name="going out").json()
    back   = make_item(name="coming back", checkout_user="Mega",
                       checkout_email="mega@amd.com", checkout_date="2026-10-01").json()
    reassigned = make_item(name="changing hands", checkout_user="Mega",
                           checkout_email="mega@amd.com", checkout_date="2026-10-01").json()

    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("combined new")],
        "updates": [
            _row(out, checkout_user="Ava", checkout_email="ava@amd.com",
                 checkout_date="2026-10-20"),
            _row(back, checkout_user="", checkout_email="",
                 checkout_date="", loan_until=""),
            _row(reassigned, checkout_user="Noor", checkout_email="noor@amd.com",
                 checkout_date="2026-10-20"),
        ],
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["imported"] == 1
    assert body["updated"] == 3
    # The response carries the stored rows, so the caller can patch its copy.
    assert {i["id"] for i in body["items"]} == {out["id"], back["id"], reassigned["id"]}

    assert _fetch(client, out["id"])["checkout_user"] == "Ava"
    assert _fetch(client, back["id"])["checkout_user"] == ""
    assert _fetch(client, reassigned["id"])["checkout_user"] == "Noor"
    _cleanup(client, auth, resp)


# ── all-or-nothing ────────────────────────────────────────────────────────────

def test_a_bad_update_row_stops_the_new_items_landing(client, auth, make_item):
    """The whole reason both halves share one transaction.

    Applied as two requests, the creates would already be in the table by the
    time the bad update row was found, leaving an admin to work out which rows
    of their file had taken effect.
    """
    good = make_item(name="fine").json()
    before = _count(client)

    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("rolled back"), _new("rolled back")],
        "updates": [
            _row(good, location="Lab A"),
            {"id": "does-not-exist", "item": _new("ghost"), "expected_updated_at": None},
        ],
    })
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert "nothing was changed" in detail["message"]
    assert any("not found" in r["error"] for r in detail["rows"])

    assert _count(client) == before                      # no new items
    assert _fetch(client, good["id"])["location"] != "Lab A"   # no update either


def test_every_bad_row_is_reported_at_once(client, auth):
    """One retry should be able to fix the whole file, not one row per attempt."""
    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [],
        "updates": [
            {"id": f"missing-{n}", "item": _new(f"ghost {n}"), "expected_updated_at": None}
            for n in range(3)
        ],
    })
    assert resp.status_code == 422, resp.text
    assert len(resp.json()["detail"]["rows"]) == 3


def test_same_item_twice_in_one_file_is_refused(client, auth, make_item):
    item = make_item(name="listed twice").json()
    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [],
        "updates": [_row(item, location="Lab A"), _row(item, location="Lab B")],
    })
    assert resp.status_code == 422, resp.text
    assert any("twice" in r["error"] for r in resp.json()["detail"]["rows"])


def test_stale_version_is_a_conflict(client, auth, make_item):
    item = make_item(name="raced").json()
    # Someone else edits it after the file was matched against the inventory.
    client.post("/api/items/batch", headers=auth,
                json={"items": [], "updates": [_row(item, location="Lab A")]})

    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("rolled back")],
        "updates": [_row(item, location="Lab B")],   # carries the pre-edit version
    })
    assert resp.status_code == 409, resp.text
    assert "Reload" in resp.json()["detail"]["rows"][0]["error"]
    assert _fetch(client, item["id"])["location"] == "Lab A"


# ── the import exemption applies to new rows only ─────────────────────────────

def test_borrower_without_email_is_allowed_on_a_new_row(client, auth):
    """Imported history often predates anyone recording an address.

    Refusing the file would mean inventing addresses or not recording the loans
    at all, and the second is what actually happened. Reports counts these.
    """
    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("combined new", checkout_user="Mega", checkout_date="2026-10-01")],
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported"] == 1
    _cleanup(client, auth, resp)


def test_borrower_without_email_is_refused_on_an_action_row(client, auth, make_item):
    """Checking an item out by sheet is the same act as the check-out modal."""
    item = make_item(name="on the shelf").json()
    before = _count(client)

    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("rolled back")],
        "updates": [_row(item, checkout_user="Mega", checkout_date="2026-10-01")],
    })
    assert resp.status_code == 422, resp.text
    assert "Check Out Email is required" in resp.json()["detail"]["rows"][0]["error"]
    assert _count(client) == before
    assert _fetch(client, item["id"])["checkout_user"] == ""


def test_legacy_loan_stays_editable(client, auth, make_item):
    """A row stored without an address before the rule must still be editable.

    Only *naming a new borrower* without an address is refused; correcting
    another field on such a row, or checking it in, still works.
    """
    created = client.post("/api/items/batch", headers=auth, json={
        "items": [_new("combined new", checkout_user="Mega", checkout_date="2026-10-01")],
    })
    assert created.status_code == 201
    item = next(i for i in client.get("/api/items").json()
                if i["name"] == "combined new" and i["checkout_user"] == "Mega")

    resp = client.post("/api/items/batch", headers=auth,
                       json={"items": [], "updates": [_row(item, location="Lab C")]})
    assert resp.status_code == 201, resp.text
    assert _fetch(client, item["id"])["location"] == "Lab C"
    client.post("/api/items/batch-delete", json={"ids": [item["id"]]}, headers=auth)


# ── limits and auth ───────────────────────────────────────────────────────────

def test_a_whole_inventory_of_new_rows_is_allowed(client, auth, app_module):
    """Importing more new rows than the bulk-edit limit must work.

    This is how the system gets populated — a real file ran to 9,006 rows — and
    for a while it was refused with "Too many rows in one batch (9006); limit is
    5000", because the check in/out cap had been applied to inserts as well.
    Inserting is one executemany with nothing to validate against; it is not
    what that cap was protecting.
    """
    n = app_module._MAX_BATCH_UPDATE + 500
    resp = client.post("/api/items/batch", headers=auth,
                       json={"items": [_new("bulk insert") for _ in range(n)]})
    assert resp.status_code == 201, resp.text[:300]
    assert resp.json()["imported"] == n

    ids = [i["id"] for i in client.get("/api/items").json() if i["name"] == "bulk insert"]
    assert len(ids) == n
    for chunk in (ids[i:i + 400] for i in range(0, len(ids), 400)):
        client.post("/api/items/batch-delete", json={"ids": chunk}, headers=auth)


def test_action_rows_keep_the_tighter_cap(client, auth, app_module):
    """Updates are validated and merged row by row with the lock held, so their
    own limit still applies even when the new rows are well within theirs."""
    over = app_module._MAX_BATCH_UPDATE + 1
    resp = client.post("/api/items/batch", headers=auth, json={
        "items": [],
        "updates": [
            {"id": f"x-{n}", "item": _new("capped"), "expected_updated_at": None}
            for n in range(over)
        ],
    })
    assert resp.status_code == 413, resp.text
    detail = resp.json()["detail"]
    assert "check in/out" in detail
    assert str(app_module._MAX_BATCH_UPDATE) in detail


def test_the_whole_file_still_has_a_ceiling(client, auth, app_module, monkeypatch):
    """Bounded so one request cannot carry an unlimited body."""
    monkeypatch.setattr(app_module, "_MAX_IMPORT_ROWS", 10)
    resp = client.post("/api/items/batch", headers=auth,
                       json={"items": [_new("capped") for _ in range(11)]})
    assert resp.status_code == 413, resp.text
    assert "Split the spreadsheet" in resp.json()["detail"]


def test_requires_admin(client, make_item):
    item = make_item(name="guarded").json()
    resp = client.post("/api/items/batch",
                       json={"items": [], "updates": [_row(item, location="Lab A")]})
    assert resp.status_code == 401
    assert _fetch(client, item["id"])["location"] != "Lab A"
