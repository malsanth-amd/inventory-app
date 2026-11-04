"""One template for both jobs: adding items and checking them in/out.

There used to be two workbooks and two generators. They drifted — the bulk
sheet marked Check Out Email required, the import sheet did not — and an admin
who downloaded the wrong one got a failed upload. These tests pin the single
template's shape and the column names both parsers rely on.
"""

from __future__ import annotations

import io

import openpyxl
import pytest

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

ENDPOINTS = ("/api/template", "/api/bulk-template")


def _sheets(client, endpoint: str):
    resp = client.get(endpoint)
    assert resp.status_code == 200
    return openpyxl.load_workbook(io.BytesIO(resp.content))


def _headers(ws) -> list[str]:
    return [str(c.value or "") for c in ws[1]]


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_every_sheet_leads_with_action(client, endpoint):
    wb = _sheets(client, endpoint)
    assert wb.sheetnames, "template has no sheets"
    for name in wb.sheetnames:
        assert _headers(wb[name])[0] == "Action", f"{name} does not lead with Action"


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_action_header_cannot_capture_another_column(client, endpoint):
    """The import side falls back to loose substring matching.

    A longer label such as "Action (blank = add new item)" survives only while
    the description column is spelled exactly "Item Description"; once an admin
    renames it to something like "Item Desc", the fallback matches "item" inside
    the Action label and every item name maps to the Action column.
    """
    wb = _sheets(client, endpoint)
    for name in wb.sheetnames:
        header = _headers(wb[name])[0].lower()
        assert header == "action"
        for word in ("item", "name", "part", "serial", "note", "comment", "loc"):
            assert word not in header


def test_both_routes_serve_the_same_template(client):
    one, two = (_sheets(client, e) for e in ENDPOINTS)
    assert one.sheetnames == two.sheetnames
    for name in one.sheetnames:
        assert _headers(one[name]) == _headers(two[name])


def test_the_sheet_carries_both_kinds_of_row(client):
    """An admin should see what each job looks like without reading docs."""
    wb = _sheets(client, "/api/template")
    ws = wb["DIMMs"]
    actions = [str(r[0].value or "") for r in ws.iter_rows(min_row=2, max_row=ws.max_row)]
    assert "" in actions, "no blank-Action row showing how to add an item"
    assert {"check_out", "check_in", "change_user"} <= set(actions)


def test_action_column_offers_a_dropdown_that_allows_blank(client):
    wb = _sheets(client, "/api/template")
    for name in wb.sheetnames:
        dvs = wb[name].data_validations.dataValidation
        assert len(dvs) == 1, f"{name} should validate exactly the Action column"
        dv = dvs[0]
        assert "A2" in str(dv.sqref)
        assert dv.formula1 == '"check_out,check_in,change_user"'
        # Blank is a meaningful value: it means "add this as a new item".
        assert dv.allow_blank


def test_check_out_email_is_marked_required(client):
    """The server refuses a named borrower with no address, on either job."""
    wb = _sheets(client, "/api/template")
    for name in wb.sheetnames:
        email = next(h for h in _headers(wb[name]) if "Email" in h)
        assert email.endswith("*"), f"{name} does not mark Check Out Email required"


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_template_round_trips_through_the_parser(client, auth, endpoint):
    template = client.get(endpoint)
    parsed = client.post("/api/parse-file",
                         files={"file": ("t.xlsx", template.content, XLSX_MIME)},
                         headers=auth)
    assert parsed.status_code == 200, f"{endpoint} did not parse back"
    headers = [str(h).lower() for h in parsed.json()["sheets"][0]["rows"][0]]
    # The columns each side keys on.
    assert headers[0] == "action"
    assert any("serial" in h for h in headers)
    assert any("part" in h for h in headers)
    assert any("email" in h for h in headers)


# ── the export is the same sheet, filled in ───────────────────────────────────

def _export(client, auth):
    resp = client.get("/api/export", headers=auth)
    assert resp.status_code == 200
    return openpyxl.load_workbook(io.BytesIO(resp.content))


def test_export_columns_come_from_the_template(client, auth, make_item, app_module):
    """One column list behind both, so they cannot drift apart again."""
    make_item(name="exported dimm", category="DIMMs")
    exported, template = _export(client, auth), _sheets(client, "/api/template")
    for name in exported.sheetnames:
        if name not in template.sheetnames:
            continue           # a custom category has no template sheet
        assert _headers(exported[name]) == [
            app_module._export_label(h) for h in _headers(template[name])
        ], f"{name} headers differ from the template"


def test_export_leads_with_an_empty_action_column(client, auth, make_item):
    """Filled in, the export becomes a Bulk Check In/Out sheet.

    Export what someone holds, type check_in down column A, upload. Without the
    column the admin has to add it by hand and spell the header exactly right.
    """
    make_item(name="held item", category="DIMMs",
              checkout_user="Mega", checkout_email="mega@amd.com")
    wb = _export(client, auth)
    for name in wb.sheetnames:
        ws = wb[name]
        assert _headers(ws)[0] == "Action"
        actions = [r[0].value for r in ws.iter_rows(min_row=2, max_row=ws.max_row)]
        # Blank, because it is an instruction the admin has not given yet.
        assert all(a in (None, "") for a in actions), f"{name} pre-filled Action"


def test_export_offers_the_same_dropdown(client, auth, make_item):
    make_item(name="dropdown item", category="DIMMs")
    wb = _export(client, auth)
    dvs = wb[wb.sheetnames[0]].data_validations.dataValidation
    assert len(dvs) == 1
    assert dvs[0].formula1 == '"check_out,check_in,change_user"'
    assert dvs[0].allow_blank


def test_export_drops_the_markers_but_stays_readable_to_both_parsers(client, auth, make_item):
    make_item(name="marker item", category="DIMMs")
    headers = _headers(_export(client, auth)["DIMMs"])
    assert "Serial Number" in headers and "Serial Number *" not in headers
    assert "Check Out Date" in headers                      # no (YYYY-MM-DD) hint
    assert "Tray / Comment" in headers                      # a real slash survives


@pytest.mark.parametrize("label,expected", [
    ("Item Description *",            "Item Description"),
    ("Check Out Date * (YYYY-MM-DD)", "Check Out Date"),
    ("DIMM Type (ES/CS)",             "DIMM Type"),
    ("Tray / Comment",                "Tray / Comment"),
    ("Action",                        "Action"),
])
def test_export_label_strips_only_form_markup(label, expected, app_module):
    assert app_module._export_label(label) == expected


def test_export_still_round_trips_through_the_parser(client, auth, make_item):
    make_item(name="round trip item", category="DIMMs")
    export = client.get("/api/export", headers=auth)
    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", export.content, XLSX_MIME)},
                         headers=auth)
    assert parsed.status_code == 200
    rows = parsed.json()["sheets"][0]["rows"]
    assert rows[0][0].lower() == "action"
    # Every data row carries a blank Action, so the Import tab still treats an
    # exported sheet as new items rather than silently skipping it.
    assert all((r[0] or "").strip() == "" for r in rows[1:])


def test_category_specific_columns_survive_the_merge(client):
    """DIMM-only columns stay off the sheets that never use them."""
    wb = _sheets(client, "/api/template")
    dimm = _headers(wb["DIMMs"])
    assert any("RCD" == h for h in dimm) and any("Rank" == h for h in dimm)
    for name in ("Systems", "Accessories"):
        headers = _headers(wb[name])
        assert "RCD" not in headers and "Rank" not in headers
