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


def test_export_columns_lists_every_sheet_column(client):
    """Open to everyone — it only names columns, carries no data — and is
    the picker's one source of truth, shared with the server's own sheets."""
    resp = client.get("/api/export/columns")
    assert resp.status_code == 200
    cols = resp.json()["columns"]
    keys = {c["key"] for c in cols}
    assert {"name", "part_number", "serial_number", "location", "notes"} <= keys
    # Labelled for a filled-in sheet, not a blank form.
    assert all("*" not in c["label"] for c in cols)


def test_export_honors_a_chosen_column_subset(client, auth, make_item):
    make_item(name="narrow export item", category="DIMMs", part_number="PN-NARROW")
    resp = client.post("/api/export", json={
        "ids": None, "columns": ["name", "part_number"],
    }, headers=auth)
    assert resp.status_code == 200, resp.text

    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", resp.content, XLSX_MIME)},
                         headers=auth)
    assert parsed.status_code == 200
    dimm_sheet = next(s for s in parsed.json()["sheets"] if s["name"] == "DIMMs")
    header = dimm_sheet["rows"][0]
    assert header == ["Item Description", "Part Number"]


def test_export_audit_column_shows_the_latest_sighting(app_module, client, auth, make_item):
    """Audit is overwritten (not appended to) on every scan, so whatever the
    export shows is already the latest sighting — confirms that still holds
    once Audit is actually picked for export."""
    item = make_item(name="audited export item", category="DIMMs").json()
    app_module._apply_audit_fields([item["id"]], "Eagle-0291 · 2026-11-02")
    app_module._apply_audit_fields([item["id"]], "Eagle-0291 · 2026-11-04")   # the later scan

    resp = client.post("/api/export", json={
        "ids": None, "columns": ["name", "audit"],
    }, headers=auth)
    assert resp.status_code == 200, resp.text

    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", resp.content, XLSX_MIME)},
                         headers=auth)
    dimm_sheet = next(s for s in parsed.json()["sheets"] if s["name"] == "DIMMs")
    header = dimm_sheet["rows"][0]
    assert header == ["Item Description", "Audit"]
    row = next(r for r in dimm_sheet["rows"][1:] if r[0] == "audited export item")
    assert row[1] == "Eagle-0291 · 2026-11-04"


def test_export_with_no_columns_param_keeps_every_column(client, auth, make_item):
    """Backward compatible: an old bookmark/script that never sends `columns`
    must still get the full sheet it always did."""
    make_item(name="full export item", category="DIMMs")
    resp = client.post("/api/export", json={"ids": None}, headers=auth)
    assert resp.status_code == 200

    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", resp.content, XLSX_MIME)},
                         headers=auth)
    dimm_sheet = next(s for s in parsed.json()["sheets"] if s["name"] == "DIMMs")
    header = dimm_sheet["rows"][0]
    assert len(header) > 2
    assert "Location" in header


def test_csv_parsing(client, auth):
    csv_bytes = b"Item Description,Part Number\nWidget,PN-1\n"
    resp = client.post("/api/parse-file",
                       files={"file": ("a.csv", csv_bytes, "text/csv")}, headers=auth)
    rows = resp.json()["sheets"][0]["rows"]
    assert rows[0] == ["Item Description", "Part Number"]
    assert rows[1] == ["Widget", "PN-1"]


# ── speed from the decoder ────────────────────────────────────────────────────
#
# Speed joined rcd/pmic in this path later: the decoder derives it from the part
# number, and the stored column disagreed with it on every DIMM in the table —
# 4800/5600 against a decoder that reads 12800 off the part number.

def test_bulk_fill_writes_speed_into_a_blank_column(client, auth, make_item):
    pn = "TEST-PN-SPEED-0001"
    make_item(name="no speed", part_number=pn, category="DIMMs")

    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {pn: {"speed": "12800"}}}, headers=auth)
    assert resp.json()["updated"] == 1

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    # The column reads "4800 MT/s" everywhere else; a bare number gains the unit.
    assert row["speed"] == "12800 MT/s"


def test_bulk_fill_leaves_a_stored_speed_alone(client, auth, make_item):
    """Fill mode is what the background auto-fill runs; it must not rewrite."""
    pn = "TEST-PN-SPEED-0002"
    make_item(name="has speed", part_number=pn, category="DIMMs", speed="4800 MT/s")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"speed": "12800"}}}, headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["speed"] == "4800 MT/s"


def test_overwrite_replaces_a_stored_speed(client, auth, make_item):
    """What the Refresh from decoder button is for."""
    pn = "TEST-PN-SPEED-0003"
    make_item(name="stale speed", part_number=pn, category="DIMMs", speed="4800 MT/s")

    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {pn: {"speed": "12800"}}, "overwrite": True},
                       headers=auth)
    assert resp.json()["updated"] == 1

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["speed"] == "12800 MT/s"


def test_speed_only_update_is_idempotent(client, auth, make_item):
    pn = "TEST-PN-SPEED-0004"
    make_item(name="twice", part_number=pn, category="DIMMs", speed="4800 MT/s")
    payload = {"updates": {pn: {"speed": "12800"}}, "overwrite": True}

    assert client.post("/api/items/bulk-rcd-pmic", json=payload, headers=auth).json()["updated"] == 1
    assert client.post("/api/items/bulk-rcd-pmic", json=payload, headers=auth).json()["updated"] == 0


def test_a_speed_that_already_carries_units_is_stored_as_given(client, auth, make_item):
    pn = "TEST-PN-SPEED-0005"
    make_item(name="units given", part_number=pn, category="DIMMs")
    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"speed": "6400 MT/s"}}}, headers=auth)
    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["speed"] == "6400 MT/s"


def test_speed_is_written_for_dimms_only(client, auth, make_item):
    """The statement is scoped to DIMMs; a CPU sharing a part number is not touched."""
    pn = "TEST-PN-SPEED-0006"
    make_item(name="a dimm", part_number=pn, category="DIMMs")
    make_item(name="not a dimm", part_number=pn, category="CPU (Silicon)")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"speed": "12800"}}, "overwrite": True}, headers=auth)

    rows = {i["name"]: i for i in client.get("/api/items").json() if i["part_number"] == pn}
    assert rows["a dimm"]["speed"] == "12800 MT/s"
    assert rows["not a dimm"]["speed"] == ""


def test_speed_travels_with_rcd_and_pmic(client, auth, make_item):
    pn = "TEST-PN-SPEED-0007"
    make_item(name="all three", part_number=pn, category="DIMMs",
              rcd="STALE", pmic="STALE", speed="4800 MT/s")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"rcd": "Montage B0", "pmic": "Richtek B3",
                                       "speed": "12800"}},
                      "overwrite": True},
                headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert (row["rcd"], row["pmic"], row["speed"]) == ("Montage B0", "Richtek B3", "12800 MT/s")


# ── exporting a selection ─────────────────────────────────────────────────────
#
# Ids used to travel as repeated `?ids=` query parameters. An id is 32 hex
# characters, so selecting the whole table built a request line of a third of a
# megabyte, which never reached the server: the admin saw "Export failed: Bad
# Gateway". They go in the body now.

def test_export_of_a_selection_posts_the_ids(client, auth, make_item):
    ids = [make_item(name=f"posted {n}", category="DIMMs").json()["id"] for n in range(3)]
    resp = client.post("/api/export", json={"ids": ids}, headers=auth)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == XLSX_MIME
    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", resp.content, XLSX_MIME)}, headers=auth)
    assert parsed.status_code == 200


def test_a_selection_too_large_for_a_url_still_exports(client, auth, make_item):
    """The case that failed: more ids than a request line can carry."""
    real = make_item(name="one real row", category="DIMMs").json()["id"]
    # 5,000 ids is ~180 KB as a query string; as a body it is unremarkable.
    ids = [real] + [f"{n:032x}" for n in range(5000)]
    resp = client.post("/api/export", json={"ids": ids}, headers=auth)
    assert resp.status_code == 200
    assert len(resp.content) > 0


def test_exporting_a_selection_that_matches_nothing_says_so(client, auth):
    """It used to be a 500: openpyxl cannot save a workbook with no sheets."""
    resp = client.post("/api/export", json={"ids": ["gone-1", "gone-2"]}, headers=auth)
    assert resp.status_code == 404
    assert "none of those items" in resp.json()["detail"]


def test_the_get_form_still_works(client, auth, make_item):
    """Links and bookmarks that carry a few ids keep working."""
    item_id = make_item(name="get export", category="DIMMs").json()["id"]
    assert client.get(f"/api/export?ids={item_id}").status_code == 200


def test_exporting_everything_still_requires_admin(client):
    assert client.post("/api/export", json={"ids": None}).status_code == 401
    assert client.post("/api/export", json={}).status_code == 401


def test_bulk_fill_writes_dimm_type(client, auth, make_item):
    """MRDIMM / RDIMM, which the import never filled — blank on every row."""
    pn = "TEST-PN-TYPE-0001"
    make_item(name="no type", part_number=pn, category="DIMMs")

    resp = client.post("/api/items/bulk-rcd-pmic",
                       json={"updates": {pn: {"dimm_type": "MRDIMM"}}}, headers=auth)
    assert resp.json()["updated"] == 1
    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["dimm_type"] == "MRDIMM"


def test_dimm_type_follows_the_same_fill_and_overwrite_rules(client, auth, make_item):
    pn = "TEST-PN-TYPE-0002"
    make_item(name="typed by hand", part_number=pn, category="DIMMs", dimm_type="ES")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"dimm_type": "MRDIMM"}}}, headers=auth)
    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["dimm_type"] == "ES", "fill mode overwrote a hand-entered value"

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"dimm_type": "MRDIMM"}}, "overwrite": True},
                headers=auth)
    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["dimm_type"] == "MRDIMM"


def test_all_four_decoder_columns_travel_together(client, auth, make_item, app_module):
    """One statement writes the lot; a parameter miscount would cross them over."""
    assert app_module._DECODER_COLUMNS == ("rcd", "pmic", "speed", "dimm_type")
    pn = "TEST-PN-ALL-0001"
    make_item(name="all four", part_number=pn, category="DIMMs",
              rcd="old", pmic="old", speed="4800 MT/s", dimm_type="old")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"rcd": "Montage B0", "pmic": "Richtek B3",
                                       "speed": "12800", "dimm_type": "MRDIMM"}},
                      "overwrite": True},
                headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert row["rcd"] == "Montage B0"
    assert row["pmic"] == "Richtek B3"
    assert row["speed"] == "12800 MT/s"
    assert row["dimm_type"] == "MRDIMM"


def test_a_decoder_update_of_one_column_leaves_the_others_alone(client, auth, make_item):
    pn = "TEST-PN-ALL-0002"
    make_item(name="only type", part_number=pn, category="DIMMs",
              rcd="keep", pmic="keep", speed="4800 MT/s")

    client.post("/api/items/bulk-rcd-pmic",
                json={"updates": {pn: {"dimm_type": "RDIMM"}}, "overwrite": True},
                headers=auth)

    row = next(i for i in client.get("/api/items").json() if i["part_number"] == pn)
    assert (row["rcd"], row["pmic"], row["speed"]) == ("keep", "keep", "4800 MT/s")
    assert row["dimm_type"] == "RDIMM"
