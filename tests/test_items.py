"""Item CRUD, the bulk RCD/PMIC fill, transport and spreadsheet round-trips."""

from __future__ import annotations

import json

from conftest import TEST_ADMIN, strip_server_fields

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


# ── CRUD and attribution ──────────────────────────────────────────────────────

def test_create_read_update_delete(client, auth):
    created = client.post(
        "/api/items", json={"name": "crud item", "category": "Storage"}, headers=auth
    ).json()

    stored = next(i for i in client.get("/api/items").json() if i["id"] == created["id"])
    assert stored["name"] == "crud item"

    body = strip_server_fields(stored)
    updated = client.put(
        f"/api/items/{created['id']}", json={**body, "location": "Shelf Z"}, headers=auth
    )
    assert updated.status_code == 200
    assert updated.json()["location"] == "Shelf Z"

    assert client.delete(f"/api/items/{created['id']}", headers=auth).status_code == 204
    assert all(i["id"] != created["id"] for i in client.get("/api/items").json())


def test_edits_are_attributed(make_item):
    """Every write records who made it.

    The retired developer account was explicitly skipped here, so its edits
    left no trace at all. Nothing is exempt now.
    """
    assert make_item(name="attributed").json()["modified_by"] == TEST_ADMIN


def test_update_of_missing_item_is_404(client, auth):
    resp = client.put("/api/items/does-not-exist",
                      json={"name": "x", "category": "DIMMs"}, headers=auth)
    assert resp.status_code == 404


def test_batch_delete_deduplicates(client, auth):
    ids = [
        client.post("/api/items", json={"name": f"bulk del {n}", "category": "DIMMs"},
                    headers=auth).json()["id"]
        for n in range(3)
    ]
    resp = client.post("/api/items/batch-delete",
                       json={"ids": ids + [ids[0]]}, headers=auth)
    assert resp.json()["deleted"] == 3


# ── bulk RCD/PMIC ─────────────────────────────────────────────────────────────

def test_bulk_fill_sets_both_columns(client, auth, make_item):
    pn = "TEST-PN-BULK-0001"
    make_item(name="bulk fill a", part_number=pn, category="DIMMs")
    make_item(name="bulk fill b", part_number=pn, category="DIMMs")

    resp = client.post(
        "/api/items/bulk-rcd-pmic",
        json={"updates": {pn: {"rcd": "Montage A0", "pmic": "Richtek B3"}}},
        headers=auth,
    )
    assert resp.status_code == 200
    assert resp.json()["updated"] == 2

    rows = [i for i in client.get("/api/items").json() if i["part_number"] == pn]
    assert all(r["rcd"] == "Montage A0" and r["pmic"] == "Richtek B3" for r in rows)


def test_bulk_fill_is_idempotent(client, auth, make_item):
    pn = "TEST-PN-BULK-0002"
    make_item(name="idempotent", part_number=pn, category="DIMMs")
    payload = {"updates": {pn: {"rcd": "Renesas B1", "pmic": "MPS R1.4S"}}}

    assert client.post("/api/items/bulk-rcd-pmic", json=payload,
                       headers=auth).json()["updated"] == 1
    assert client.post("/api/items/bulk-rcd-pmic", json=payload,
                       headers=auth).json()["updated"] == 0


def test_bulk_fill_does_not_overwrite_by_default(client, auth, make_item):
    """A vendor an admin corrected by hand survives the background auto-fill."""
    pn = "TEST-PN-BULK-0003"
    make_item(name="hand edited", part_number=pn, category="DIMMs", rcd="HAND-EDITED")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"rcd": "Decoder", "pmic": "Decoder PMIC"}}},
                headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["rcd"] == "HAND-EDITED"   # kept
    assert row["pmic"] == "Decoder PMIC"  # the blank column was filled


def test_bulk_fill_overwrite_mode_replaces(client, auth, make_item):
    """The manual Lookup button is a refresh and has always replaced values."""
    pn = "TEST-PN-BULK-0004"
    make_item(name="refresh me", part_number=pn, category="DIMMs", rcd="STALE")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"rcd": "Fresh", "pmic": "Fresh PMIC"}},
                      "overwrite": True},
                headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["rcd"] == "Fresh"


def test_bulk_fill_ignores_non_dimms(client, auth, make_item):
    pn = "TEST-PN-BULK-0005"
    make_item(name="an accessory", part_number=pn, category="Accessories")
    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {pn: {"rcd": "X", "pmic": "Y"}}}, headers=auth)
    assert resp.json()["updated"] == 0


def test_bulk_fill_never_blanks_a_column(client, auth, make_item):
    pn = "TEST-PN-BULK-0006"
    make_item(name="keep values", part_number=pn, category="DIMMs",
              rcd="Existing", pmic="Existing")
    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {pn: {"rcd": "", "pmic": ""}}}, headers=auth)
    assert resp.json()["updated"] == 0


def test_bulk_fill_trims_part_number_keys(client, auth, make_item):
    pn = "TEST-PN-BULK-0007"
    make_item(name="padded key", part_number=pn, category="DIMMs")
    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {f"  {pn}  ": {"rcd": "Trimmed", "pmic": "T"}}},
                       headers=auth)
    assert resp.json()["updated"] == 1


def test_bulk_fill_rejects_oversized_payload(client, auth, app_module):
    updates = {f"PN{n}": {"rcd": "x"} for n in range(app_module._MAX_BULK_PNS + 1)}
    resp = client.post("/api/items/bulk-rcd-pmic", json={"updates": updates},
                       headers=auth)
    assert resp.status_code == 422


# ── transport ─────────────────────────────────────────────────────────────────

def test_items_response_is_compressed(client, auth, make_item):
    """/api/items is polled twice a minute per tab; uncompressed it is ~6 MB.

    GZipMiddleware has a minimum_size threshold, so the response has to be
    bigger than a near-empty test database to exercise it.
    """
    for n in range(25):
        make_item(name=f"compressible item number {n}", category="DIMMs",
                  notes="padding " * 20)

    resp = client.get("/api/items", headers={"Accept-Encoding": "gzip"})
    assert len(resp.content) > 1024, "test data too small to trigger compression"
    assert resp.headers.get("content-encoding") == "gzip"


# ── spreadsheets ──────────────────────────────────────────────────────────────

def test_templates_round_trip_through_the_parser(client, auth):
    for endpoint in ("/api/template", "/api/bulk-template"):
        template = client.get(endpoint)
        assert template.status_code == 200

        parsed = client.post("/api/parse-file",
                             files={"file": ("t.xlsx", template.content, XLSX_MIME)},
                             headers=auth)
        assert parsed.status_code == 200, f"{endpoint} did not parse back"
        headers = parsed.json()["sheets"][0]["rows"][0]
        assert any("email" in str(h).lower() for h in headers)


def test_export_round_trips(client, auth, make_item):
    make_item(name="exported item", category="DIMMs")
    export = client.get("/api/export", headers=auth)
    assert export.status_code == 200

    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", export.content, XLSX_MIME)},
                         headers=auth)
    assert parsed.status_code == 200
    assert parsed.json()["sheets"]


def test_export_of_everything_requires_admin(client):
    assert client.get("/api/export").status_code == 401


def test_csv_parsing(client, auth):
    csv_bytes = b"Item Description,Part Number\nWidget,PN-1\n"
    resp = client.post("/api/parse-file",
                       files={"file": ("a.csv", csv_bytes, "text/csv")}, headers=auth)
    rows = resp.json()["sheets"][0]["rows"]
    assert rows[0] == ["Item Description", "Part Number"]
    assert rows[1] == ["Widget", "PN-1"]
