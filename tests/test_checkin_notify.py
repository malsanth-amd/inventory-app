"""POST /api/items/notify-checkin — the Check In modal's "let someone know
it's back" email, sent to addresses the admin typed in rather than the
item's own checkout_email (the returning borrower is not who asked to hear
about it).
"""

from __future__ import annotations


def test_requires_admin(client, make_item):
    item = make_item(name="checkin notify guarded").json()
    resp = client.post("/api/items/notify-checkin",
                       json={"ids": [item["id"]], "emails": ["someone@amd.com"]})
    assert resp.status_code == 401


def test_no_recipients_is_a_quiet_no_op(client, auth, make_item):
    item = make_item(name="checkin notify no recipients").json()
    resp = client.post("/api/items/notify-checkin",
                       json={"ids": [item["id"]], "emails": []}, headers=auth)
    assert resp.status_code == 200
    assert resp.json() == {"sent": 0, "skipped": 0, "note": "No recipient addresses given"}


def test_reports_smtp_not_configured_rather_than_failing(client, auth, make_item):
    """conftest.py leaves SMTP_HOST blank for the whole test run, same as
    notify-checkout's own untested-but-equivalent path — this is the
    deterministic branch reachable without a real mail server."""
    item = make_item(name="checkin notify no smtp").json()
    resp = client.post("/api/items/notify-checkin",
                       json={"ids": [item["id"]], "emails": ["someone@amd.com"]}, headers=auth)
    assert resp.status_code == 200
    body = resp.json()
    assert body["sent"] == 0
    assert body["skipped"] == 1
    assert body["note"] == "SMTP not configured"


def test_sends_one_message_per_recipient_for_matching_items(
        monkeypatch, app_module, client, auth, make_item):
    monkeypatch.setattr(app_module, "SMTP_HOST", "smtp.example.com")
    sent_to: list[str] = []
    monkeypatch.setattr(app_module, "_smtp_send",
                        lambda to_addr, msg, extra_cc=None: sent_to.append(to_addr))

    item = make_item(name="checkin notify sent", part_number="PN1", location="L1").json()
    resp = client.post("/api/items/notify-checkin", json={
        "ids": [item["id"]], "emails": ["a@amd.com", "b@amd.com"],
    }, headers=auth)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"sent": 2, "skipped": 0}
    assert sorted(sent_to) == ["a@amd.com", "b@amd.com"]


def test_no_matching_items_is_reported_not_sent(monkeypatch, app_module, client, auth):
    monkeypatch.setattr(app_module, "SMTP_HOST", "smtp.example.com")
    resp = client.post("/api/items/notify-checkin",
                       json={"ids": ["does-not-exist"], "emails": ["someone@amd.com"]}, headers=auth)
    assert resp.status_code == 200
    assert resp.json() == {"sent": 0, "skipped": 1, "note": "No matching items"}
