"""The all-or-nothing bulk edit behind Bulk Check In/Out.

The point of the endpoint is not only that one request beats one PUT per row —
it is that a bad row can no longer leave half the sheet applied. Most of these
tests assert the "nothing changed" half.
"""

from __future__ import annotations

from conftest import strip_server_fields


def _row(item: dict, **changes) -> dict:
    """A batch row carrying the item's current version, as the UI sends it."""
    return {
        "id": item["id"],
        "item": {**strip_server_fields(item), **changes},
        "expected_updated_at": item["updatedAt"],
    }


def _fetch(client, item_id: str) -> dict:
    return next(i for i in client.get("/api/items").json() if i["id"] == item_id)


def test_applies_every_row_in_one_call(client, auth, make_item):
    items = [make_item(name=f"batch {n}").json() for n in range(5)]
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(it, checkout_user="Mega", checkout_email="mega@amd.com",
             checkout_date="2026-10-13", loan_until="2026-11-13")
        for it in items
    ]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated"] == 5
    # The response carries the stored rows, so the caller need not re-read.
    assert {i["id"] for i in body["items"]} == {i["id"] for i in items}
    assert all(i["checkout_user"] == "Mega" for i in body["items"])
    assert all(_fetch(client, i["id"])["checkout_user"] == "Mega" for i in items)


def test_check_in_clears_the_borrower(client, auth, make_item):
    item = make_item(name="to return", checkout_user="Mega",
                     checkout_email="mega@amd.com", checkout_date="2026-10-01").json()
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(item, checkout_user="", checkout_email="", checkout_date="", loan_until="")
    ]})
    assert resp.status_code == 200, resp.text
    assert _fetch(client, item["id"])["checkout_user"] == ""


def test_a_stale_row_rejects_the_whole_batch(client, auth, make_item):
    first, second = make_item(name="stale a").json(), make_item(name="stale b").json()
    # Someone else saves `second` after the sheet was matched.
    client.put(f"/api/items/{second['id']}", headers=auth,
               json={**strip_server_fields(second), "location": "Shelf Q"})

    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(first, location="Lab A"),
        _row(second, location="Lab A"),     # carries the version read before the edit
    ]})
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "nothing was changed" in detail["message"]
    assert [r["name"] for r in detail["rows"]] == ["stale b"]
    # The good row must not have been applied either.
    assert _fetch(client, first["id"])["location"] == ""
    assert _fetch(client, second["id"])["location"] == "Shelf Q"


def test_unknown_id_rejects_the_whole_batch(client, auth, make_item):
    item = make_item(name="present").json()
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(item, location="Lab A"),
        {"id": "does-not-exist", "item": {"name": "ghost", "category": "DIMMs"}},
    ]})
    assert resp.status_code == 422
    assert "not found" in resp.json()["detail"]["rows"][0]["error"]
    assert _fetch(client, item["id"])["location"] == ""


def test_borrower_without_an_email_rejects_the_whole_batch(client, auth, make_item):
    good, bad = make_item(name="good row").json(), make_item(name="bad row").json()
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(good, checkout_user="Mega", checkout_email="mega@amd.com"),
        _row(bad, checkout_user="Nobody"),          # no address
    ]})
    assert resp.status_code == 422
    assert [r["name"] for r in resp.json()["detail"]["rows"]] == ["bad row"]
    assert _fetch(client, good["id"])["checkout_user"] == ""


def test_every_bad_row_is_reported_at_once(client, auth, make_item):
    rows = [make_item(name=f"bad {n}").json() for n in range(3)]
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(it, checkout_user="Nobody") for it in rows
    ]})
    assert resp.status_code == 422
    # An importer fixing a sheet wants the whole list, not one row per attempt.
    assert len(resp.json()["detail"]["rows"]) == 3


def test_the_same_item_twice_is_refused(client, auth, make_item):
    item = make_item(name="twice").json()
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        _row(item, location="Lab A"),
        _row(item, location="Lab B"),
    ]})
    assert resp.status_code == 422
    assert "twice" in resp.json()["detail"]["rows"][0]["error"]
    assert _fetch(client, item["id"])["location"] == ""


def test_edits_are_attributed(client, auth, make_item, app_module):
    item = make_item(name="attributed bulk").json()
    client.post("/api/items/batch-update", headers=auth,
                json={"updates": [_row(item, location="Lab C")]})
    stored = _fetch(client, item["id"])
    assert stored["modified_by"] != ""
    assert stored["updatedAt"] != item["updatedAt"]


def test_missing_expected_version_still_applies(client, auth, make_item):
    """The header is optional on PUT; omitting it here means the same thing."""
    item = make_item(name="no version").json()
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [
        {"id": item["id"], "item": {**strip_server_fields(item), "location": "Lab D"}}
    ]})
    assert resp.status_code == 200, resp.text
    assert _fetch(client, item["id"])["location"] == "Lab D"


def test_empty_batch_is_a_no_op(client, auth):
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": []})
    assert resp.status_code == 200
    assert resp.json() == {"updated": 0, "items": []}


def test_oversized_batch_is_refused(client, auth, app_module):
    one = {"id": "x", "item": {"name": "n", "category": "DIMMs"}}
    resp = client.post("/api/items/batch-update", headers=auth,
                       json={"updates": [one] * (app_module._MAX_BATCH_UPDATE + 1)})
    assert resp.status_code == 413


def test_requires_admin(client, make_item):
    item = make_item(name="guarded").json()
    resp = client.post("/api/items/batch-update", json={"updates": [_row(item, location="Lab A")]})
    assert resp.status_code in (401, 403)
    assert _fetch(client, item["id"])["location"] == ""
