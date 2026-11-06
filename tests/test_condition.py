"""Condition: Good / Suspect / Bad, tracked separately from check-out state.

An item can be both checked out and faulty — that is usually how a fault is
found — so this is its own field rather than a third value of the status badge.
"""

from __future__ import annotations

import pytest

from conftest import strip_server_fields

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def put(client, auth, item, **changes):
    body = {**strip_server_fields(item), **changes}
    return client.put(f"/api/items/{item['id']}", json=body, headers=auth)


# ── defaults and normalisation ────────────────────────────────────────────────

def test_new_items_are_good_by_default(make_item):
    assert make_item(name="default condition").json()["condition"] == "Good"


def test_blank_condition_reads_as_good(app_module):
    """9.7k rows predate the column and store ''; none of them needed a backfill."""
    assert app_module._normalize_condition("") == "Good"
    assert app_module._normalize_condition(None) == "Good"


@pytest.mark.parametrize("supplied,expected",
                         [("bad", "Bad"), ("BAD", "Bad"), ("  suspect ", "Suspect"),
                          ("Good", "Good")])
def test_condition_is_normalised(make_item, supplied, expected):
    resp = make_item(condition=supplied, condition_note="a reason")
    assert resp.status_code == 201, resp.text
    assert resp.json()["condition"] == expected


def test_unknown_condition_is_rejected(make_item):
    assert make_item(condition="Broken", condition_note="x").status_code == 422


# ── the reason is mandatory ───────────────────────────────────────────────────

@pytest.mark.parametrize("condition", ["Bad", "Suspect"])
def test_fault_requires_a_reason(make_item, condition):
    """A bare "Bad" ages into a mystery; the reason is the whole value."""
    resp = make_item(condition=condition)
    assert resp.status_code == 422
    assert "reason" in resp.text.lower()


def test_fault_with_a_reason_is_accepted(make_item):
    resp = make_item(condition="Bad", condition_note="failed MemTest at 4800, bank 3")
    assert resp.status_code == 201
    assert resp.json()["condition_note"] == "failed MemTest at 4800, bank 3"


def test_good_needs_no_reason(make_item):
    assert make_item(condition="Good").status_code == 201


def test_reason_length_is_capped(make_item):
    assert make_item(condition="Bad", condition_note="x" * 2000).status_code == 422


# ── independent of check-out ──────────────────────────────────────────────────

def test_item_can_be_both_checked_out_and_bad(client, auth, make_item):
    created = make_item(name="fails in the field").json()
    resp = put(client, auth, created,
               condition="Bad", condition_note="DIMM training failure",
               checkout_user="Debugger", checkout_email="d@amd.com",
               checkout_date="2026-10-12")
    assert resp.status_code == 200
    assert resp.json()["condition"] == "Bad"
    assert resp.json()["checkout_user"] == "Debugger"


def test_checking_in_keeps_the_fault(client, auth, make_item):
    """Returning a part must not quietly clear what is wrong with it."""
    created = make_item(name="returned faulty", condition="Bad",
                        condition_note="bent pins", checkout_user="A",
                        checkout_email="a@amd.com").json()
    resp = put(client, auth, created, checkout_user="", checkout_email="")
    assert resp.status_code == 200
    assert resp.json()["condition"] == "Bad"
    assert resp.json()["condition_note"] == "bent pins"


def test_clearing_a_fault_works(client, auth, make_item):
    created = make_item(name="repaired", condition="Bad",
                        condition_note="reseated, retested ok").json()
    resp = put(client, auth, created, condition="Good", condition_note="")
    assert resp.status_code == 200
    assert resp.json()["condition"] == "Good"


# ── reporting ─────────────────────────────────────────────────────────────────

def test_bad_items_are_not_counted_as_available(client, auth, make_item):
    before = client.get("/api/reports/summary", headers=auth).json()["totals"]
    make_item(name="not stock", condition="Bad", condition_note="dead")
    after = client.get("/api/reports/summary", headers=auth).json()["totals"]

    assert after["items"] == before["items"] + 1
    assert after["bad"] == before["bad"] + 1
    assert after["available"] == before["available"], "a faulty unit is not spare stock"


def test_suspect_items_remain_available(client, auth, make_item):
    before = client.get("/api/reports/summary", headers=auth).json()["totals"]
    make_item(name="needs retest", condition="Suspect", condition_note="intermittent")
    after = client.get("/api/reports/summary", headers=auth).json()["totals"]

    assert after["suspect"] == before["suspect"] + 1
    assert after["available"] == before["available"] + 1


def test_low_stock_excludes_faulty_units(client, auth, make_item):
    pn = "COND-PN-STOCK"
    make_item(name="spare ok", part_number=pn, category="DIMMs")
    make_item(name="spare dead", part_number=pn, category="DIMMs",
              condition="Bad", condition_note="no POST")

    data = client.get("/api/reports/summary", params={"low_stock_threshold": 5},
                      headers=auth).json()
    entry = next(s for s in data["low_stock"] if s["part_number"] == pn)
    assert entry["total"] == 2
    assert entry["available"] == 1
    assert entry["bad"] == 1


def test_failures_are_grouped_by_part_and_vendor(client, auth, make_item):
    pn = "COND-PN-FAULTS"
    for n in range(3):
        make_item(name=f"faulty {n}", part_number=pn, vendor="TestVendor",
                  category="DIMMs", condition="Bad", condition_note="training failure")
    make_item(name="healthy", part_number=pn, vendor="TestVendor", category="DIMMs")

    data = client.get("/api/reports/summary", headers=auth).json()
    part = next(f for f in data["faults_by_part"] if f["part_number"] == pn)
    assert part["bad"] == 3 and part["total"] == 4

    vendor = next(f for f in data["faults_by_vendor"] if f["vendor"] == "TestVendor")
    assert vendor["bad"] == 3

    flagged = {f["name"] for f in data["faulty"]}
    assert "faulty 0" in flagged and "healthy" not in flagged


# ── spreadsheets ──────────────────────────────────────────────────────────────

def test_condition_survives_export(client, auth, make_item):
    make_item(name="exported faulty", condition="Bad", condition_note="cracked PCB")
    export = client.get("/api/export", headers=auth)
    parsed = client.post("/api/parse-file",
                         files={"file": ("e.xlsx", export.content, XLSX_MIME)},
                         headers=auth)
    headers = [str(h).lower() for h in parsed.json()["sheets"][0]["rows"][0]]
    assert any("condition" in h for h in headers)


def test_template_offers_the_columns(client, auth):
    template = client.get("/api/template")
    parsed = client.post("/api/parse-file",
                         files={"file": ("t.xlsx", template.content, XLSX_MIME)},
                         headers=auth)
    headers = [str(h).lower() for h in parsed.json()["sheets"][0]["rows"][0]]
    assert any(h == "condition" for h in headers)
    assert any("condition note" in h for h in headers)


def test_batch_import_validates_conditions(client, auth):
    rows = [{"name": "import faulty", "category": "DIMMs", "condition": "Bad"}]
    assert client.post("/api/items/batch", json={"items": rows},
                       headers=auth).status_code == 422
