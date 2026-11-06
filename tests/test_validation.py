"""ItemIn validation — the single gate every write path shares.

Validation used to live in the UI and only in the check-out modal, so the
import path enforced nothing. That is how 192 of 193 check-outs ended up with
no email and no date, leaving the reminder system with nothing to work from.
"""

from __future__ import annotations

import pytest

from conftest import strip_server_fields


# ── email ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("address", ["john@amd.com", "a.b-c@sub.example.co.uk"])
def test_valid_emails_are_accepted(make_item, address):
    resp = make_item(checkout_user="Someone", checkout_email=address)
    assert resp.status_code == 201


@pytest.mark.parametrize("address", ["not-an-email", "a@b", "a b@c.com", "@amd.com"])
def test_invalid_emails_are_rejected(make_item, address):
    assert make_item(checkout_email=address).status_code == 422


def test_blank_email_is_allowed_when_nobody_is_named(make_item):
    assert make_item(checkout_email="").status_code == 201


# ── dates ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "supplied,expected",
    [
        ("2026-03-05", "2026-03-05"),              # ISO, already correct
        ("2026-03-05 00:00:00", "2026-03-05"),     # pandas/Excel datetime
        ("2026-03-05T09:30:00", "2026-03-05"),     # ISO with time
        ("2026/03/05", "2026-03-05"),              # slashes
        ("05-Mar-2026", "2026-03-05"),             # unambiguous text month
        ("05 Mar 2026", "2026-03-05"),             # space-separated text month
        ("Mar 05, 2026", "2026-03-05"),            # month-first text month
        ("05 Mar 2026 00:00:00", "2026-03-05"),    # ...and with a time on it
        ("46086", "2026-03-05"),                   # Excel serial day number
        ("", ""),
    ],
)
def test_dates_are_normalised(make_item, supplied, expected):
    resp = make_item(checkout_date=supplied)
    assert resp.status_code == 201, resp.text
    assert resp.json()["checkout_date"] == expected


@pytest.mark.parametrize("supplied", ["05/01/2026", "tomorrow", "2026-13-45", "5th March"])
def test_unreadable_dates_are_rejected(make_item, supplied):
    """05/01/2026 is ambiguous (May or January?) and is refused, not guessed at."""
    assert make_item(checkout_date=supplied).status_code == 422


def test_loan_until_before_checkout_is_rejected(make_item):
    resp = make_item(checkout_date="2026-03-05", loan_until="2026-01-01")
    assert resp.status_code == 422


def test_loan_until_on_checkout_date_is_allowed(make_item):
    resp = make_item(checkout_date="2026-03-05", loan_until="2026-03-05",
                     checkout_user="A", checkout_email="a@amd.com")
    assert resp.status_code == 201


# ── category ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "supplied,expected",
    [
        ("DIMMs", "DIMMs"),
        ("dimms", "DIMMs"),
        ("CPU (Silicon)", "CPU (Silicon)"),
        ("cpusilicon", "CPU (Silicon)"),
        ("", ""),
    ],
)
def test_categories_are_normalised(make_item, supplied, expected):
    resp = make_item(category=supplied)
    assert resp.status_code == 201, resp.text
    assert resp.json()["category"] == expected


def test_unknown_category_is_rejected(make_item):
    assert make_item(category="Widgets").status_code == 422


# ── text handling ─────────────────────────────────────────────────────────────

def test_whitespace_is_trimmed(make_item):
    resp = make_item(vendor="   SK Hynix   ", location="  Shelf A  ")
    assert resp.json()["vendor"] == "SK Hynix"
    assert resp.json()["location"] == "Shelf A"


def test_blank_name_is_rejected(client, auth):
    resp = client.post("/api/items", json={"name": "   ", "category": "DIMMs"},
                       headers=auth)
    assert resp.status_code == 422


def test_overlong_values_are_rejected(make_item):
    assert make_item(notes="x" * 5000).status_code == 422
    assert make_item(location="x" * 500).status_code == 422


def test_realistic_barcode_serial_fits(make_item):
    """Stored serials are full 2D barcode dumps; the cap must not reject them."""
    barcode = "(L)96GB 4Rx8 PC5-128/64B-MC1-1312-XT(S)80AD0125181289006B(P)HMCGM8AHJMB869N"
    assert make_item(serial_number=barcode).status_code == 201


# ── borrower must be contactable (ratchet) ────────────────────────────────────

def test_new_checkout_without_email_is_rejected(make_item):
    resp = make_item(checkout_user="Mega")
    assert resp.status_code == 422
    assert "email" in resp.json()["detail"].lower()


def test_new_checkout_with_email_is_accepted(make_item):
    assert make_item(checkout_user="Mega", checkout_email="mega@amd.com").status_code == 201


def test_legacy_row_stays_editable(client, auth, app_module, make_item):
    """A check-out stored before this rule must remain editable and returnable.

    Enforcing the rule unconditionally would have made all 192 pre-existing
    check-outs impossible to correct without first inventing an address.
    """
    created = make_item(name="legacy row").json()
    # Write the uncontactable state directly, as the old import path would have.
    app_module._update_item_row(
        created["id"], {"checkout_user": "Eng Loong", "checkout_email": ""}
    )
    stored = next(i for i in client.get("/api/items").json() if i["id"] == created["id"])
    body = strip_server_fields(stored)

    # 1. an unrelated edit still works
    resp = client.put(f"/api/items/{created['id']}", json={**body, "tray": "Tray 9"},
                      headers=auth)
    assert resp.status_code == 200, resp.text

    # 2. the item can be checked back in
    resp = client.put(
        f"/api/items/{created['id']}",
        json={**body, "checkout_user": "", "checkout_email": ""},
        headers=auth,
    )
    assert resp.status_code == 200


def test_changing_borrower_requires_an_email(client, auth, app_module, make_item):
    created = make_item(name="legacy reassign").json()
    app_module._update_item_row(
        created["id"], {"checkout_user": "Eng Loong", "checkout_email": ""}
    )
    stored = next(i for i in client.get("/api/items").json() if i["id"] == created["id"])
    body = strip_server_fields(stored)

    resp = client.put(f"/api/items/{created['id']}",
                      json={**body, "checkout_user": "Someone New"}, headers=auth)
    assert resp.status_code == 422


# ── batch import ──────────────────────────────────────────────────────────────

def test_import_accepts_a_borrower_without_an_email(client, auth):
    """Import is the one path that may record an uncontactable check-out.

    A spreadsheet is usually a record of loans that already happened, with no
    address ever captured. Refusing the file meant inventing addresses or not
    recording the loans, and the second is what happened.
    """
    rows = [
        {"name": "imported no email 1", "category": "DIMMs", "checkout_user": "Mega"},
        {"name": "imported with email", "category": "DIMMs",
         "checkout_user": "Z", "checkout_email": "z@amd.com"},
        {"name": "imported no email 2", "category": "DIMMs", "checkout_user": "Mega/Jackie"},
    ]
    resp = client.post("/api/items/batch", json={"items": rows}, headers=auth)
    assert resp.status_code == 201, resp.text
    assert resp.json()["imported"] == 3

    stored = {i["name"]: i for i in client.get("/api/items").json()}
    assert stored["imported no email 1"]["checkout_user"]  == "Mega"
    assert stored["imported no email 1"]["checkout_email"] == ""

    ids = [stored[r["name"]]["id"] for r in rows]
    client.post("/api/items/batch-delete", json={"ids": ids}, headers=auth)


def test_hand_entry_still_requires_an_email(client, auth, make_item):
    """The exemption is import-only — naming a borrower by hand still costs one field."""
    # single create
    assert make_item(checkout_user="Mega").status_code == 422

    # bulk check in/out, which is a batch-update and not an import
    created = make_item(name="bulk co target").json()
    resp = client.post(
        "/api/items/batch-update",
        json={"updates": [{
            "id": created["id"],
            "item": {**strip_server_fields(created), "checkout_user": "Mega",
                     "checkout_email": "", "checkout_date": "2026-10-01"},
            "expected_updated_at": created["updatedAt"],
        }]},
        headers=auth,
    )
    assert resp.status_code == 422, resp.text


def test_clean_batch_imports(client, auth):
    rows = [
        {"name": "batch ok 1", "category": "DIMMs"},
        {"name": "batch ok 2", "category": "Storage",
         "checkout_user": "Z", "checkout_email": "z@amd.com"},
    ]
    resp = client.post("/api/items/batch", json={"items": rows}, headers=auth)
    assert resp.status_code == 201
    assert resp.json()["imported"] == 2

    ids = [i["id"] for i in client.get("/api/items").json()
           if i["name"].startswith("batch ok")]
    client.post("/api/items/batch-delete", json={"ids": ids}, headers=auth)
