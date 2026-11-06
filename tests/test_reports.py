"""The reporting summary — whole-table questions the UI could not answer."""

from __future__ import annotations


def summary(client, auth, **params):
    resp = client.get("/api/reports/summary", params=params, headers=auth)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_requires_admin(client):
    assert client.get("/api/reports/summary").status_code == 401


def test_totals_add_up(client, auth, make_item):
    make_item(name="report available", category="DIMMs")
    make_item(name="report checked out", category="DIMMs",
              checkout_user="Someone", checkout_email="someone@amd.com")

    data = summary(client, auth)
    totals = data["totals"]
    assert totals["items"] == totals["available"] + totals["checked_out"]
    assert totals["checked_out"] >= 1


def test_category_rows_are_consistent(client, auth, make_item):
    make_item(name="cat storage", category="Storage")
    data = summary(client, auth)

    for row in data["by_category"]:
        assert row["total"] == row["available"] + row["checked_out"]
    assert sum(r["total"] for r in data["by_category"]) == data["totals"]["items"]
    assert "Storage" in {r["category"] for r in data["by_category"]}


def test_borrowers_report_contactability(client, auth, make_item, app_module):
    created = make_item(name="uncontactable loan").json()
    # Write the legacy state directly, as the old import path could.
    app_module._update_item_row(
        created["id"], {"checkout_user": "NoEmailPerson", "checkout_email": ""}
    )
    make_item(name="contactable loan", checkout_user="HasEmail",
              checkout_email="has@amd.com")

    borrowers = {b["checkout_user"]: b for b in summary(client, auth)["borrowers"]}
    assert borrowers["NoEmailPerson"]["without_email"] == borrowers["NoEmailPerson"]["items"]
    assert borrowers["HasEmail"]["without_email"] == 0
    assert borrowers["HasEmail"]["email"] == "has@amd.com"


def test_low_stock_respects_threshold(client, auth, make_item):
    pn = "REPORT-PN-LOWSTOCK"
    make_item(name="scarce part", part_number=pn, category="DIMMs",
              checkout_user="A", checkout_email="a@amd.com")

    data = summary(client, auth, low_stock_threshold=0)
    assert data["low_stock_threshold"] == 0
    entry = next(s for s in data["low_stock"] if s["part_number"] == pn)
    assert entry["available"] == 0
    assert entry["total"] == 1

    # Raising the threshold cannot shrink the list.
    wider = summary(client, auth, low_stock_threshold=5)
    assert len(wider["low_stock"]) >= len(data["low_stock"])


def test_low_stock_threshold_is_bounded(client, auth):
    assert client.get("/api/reports/summary", params={"low_stock_threshold": -1},
                      headers=auth).status_code == 422
    assert client.get("/api/reports/summary", params={"low_stock_threshold": 99999},
                      headers=auth).status_code == 422


def test_overdue_lists_only_past_due_dates(client, auth, make_item):
    make_item(name="overdue item", checkout_user="Late", checkout_email="late@amd.com",
              checkout_date="2020-01-01", loan_until="2020-02-01")
    make_item(name="future item", checkout_user="Fine", checkout_email="fine@amd.com",
              checkout_date="2020-01-01", loan_until="2099-01-01")

    names = {o["name"] for o in summary(client, auth)["overdue"]}
    assert "overdue item" in names
    assert "future item" not in names


def test_gaps_are_counted(client, auth, make_item, app_module):
    created = make_item(name="gap row", category="DIMMs").json()
    app_module._update_item_row(
        created["id"], {"checkout_user": "Nobody", "checkout_email": "", "location": ""}
    )

    gaps = summary(client, auth)["gaps"]
    for key in ("no_location", "dimms_without_rcd", "dimms_without_speed",
                "checkout_without_email", "checkout_without_date",
                "checkout_without_due", "no_part_number", "no_serial"):
        assert key in gaps and gaps[key] >= 0
    assert gaps["checkout_without_email"] >= 1
    assert gaps["no_location"] >= 1
