"""Conditional GET on /api/items.

Every open tab re-asks for the whole inventory every 30 seconds. Answering that
unconditionally means a full table scan, a per-row normalise, a JSON serialise
and a gzip — almost always to produce the bytes the browser already holds. The
ETag turns the common case into an empty 304, so what these tests guard is
twofold: that an unchanged table really does answer 304, and that the token
moves for *every* kind of write, since a stale token would hide real edits from
every client until something else happened to change it.
"""

from __future__ import annotations

from conftest import strip_server_fields


def _etag(client) -> str:
    resp = client.get("/api/items")
    assert resp.status_code == 200, resp.text
    tag = resp.headers.get("ETag")
    assert tag, "no ETag on /api/items"
    return tag


def test_first_request_carries_an_etag(client):
    resp = client.get("/api/items")
    assert resp.status_code == 200
    assert resp.headers.get("ETag")
    # no-cache means "revalidate", which is what keeps the browser asking
    # conditionally rather than serving a stale inventory from memory.
    assert resp.headers.get("Cache-Control") == "no-cache"


def test_unchanged_table_answers_304_with_no_body(client):
    tag = _etag(client)
    resp = client.get("/api/items", headers={"If-None-Match": tag})
    assert resp.status_code == 304, resp.text
    assert resp.content == b""
    assert resp.headers.get("ETag") == tag


def test_a_stale_token_gets_the_full_list(client, make_item):
    make_item(name="etag stale probe")
    resp = client.get("/api/items", headers={"If-None-Match": '"not-the-current-token"'})
    assert resp.status_code == 200
    assert any(i["name"] == "etag stale probe" for i in resp.json())


def test_weak_tag_is_recognised(client):
    """A proxy may weaken the tag in transit; W/"x" is still version x."""
    tag = _etag(client)
    resp = client.get("/api/items", headers={"If-None-Match": f"W/{tag}"})
    assert resp.status_code == 304


# ── the token has to move for every write path ────────────────────────────────

def test_create_changes_the_token(client, make_item):
    before = _etag(client)
    make_item(name="etag create")
    assert _etag(client) != before


def test_update_changes_the_token(client, auth, make_item):
    item = make_item(name="etag update").json()
    before = _etag(client)
    body = {**strip_server_fields(item), "location": "Lab Z"}
    assert client.put(f"/api/items/{item['id']}", json=body, headers=auth).status_code == 200
    assert _etag(client) != before


def test_delete_changes_the_token(client, auth, make_item):
    item = make_item(name="etag delete").json()
    before = _etag(client)
    assert client.delete(f"/api/items/{item['id']}", headers=auth).status_code == 204
    assert _etag(client) != before


def test_import_changes_the_token(client, auth):
    """The combined import writes through _apply_import, not _insert_items."""
    before = _etag(client)
    resp = client.post("/api/items/batch", headers=auth,
                       json={"items": [{"name": "etag import", "category": "DIMMs"}]})
    assert resp.status_code == 201, resp.text
    after = _etag(client)
    assert after != before

    ids = [i["id"] for i in client.get("/api/items").json() if i["name"] == "etag import"]
    client.post("/api/items/batch-delete", json={"ids": ids}, headers=auth)


def test_check_in_through_batch_update_changes_the_token(client, auth, make_item):
    item = make_item(name="etag checkin", checkout_user="Mega",
                     checkout_email="mega@amd.com", checkout_date="2026-10-01").json()
    before = _etag(client)
    resp = client.post("/api/items/batch-update", headers=auth, json={"updates": [{
        "id": item["id"],
        "item": {**strip_server_fields(item), "checkout_user": "", "checkout_email": "",
                 "checkout_date": "", "loan_until": ""},
        "expected_updated_at": item["updatedAt"],
    }]})
    assert resp.status_code == 200, resp.text
    assert _etag(client) != before


def test_token_is_stable_when_nothing_happens(client):
    """Otherwise every poll would still ship the whole inventory."""
    assert _etag(client) == _etag(client) == _etag(client)
