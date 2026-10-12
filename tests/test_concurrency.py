"""Optimistic concurrency on PUT /api/items/{id}.

Every PUT carries the client's whole copy of the row, so without a version
check the second of two concurrent saves silently discards the first — even
when the two admins edited completely different fields.
"""

from __future__ import annotations

from conftest import strip_server_fields


def current(client, item_id: str) -> dict:
    return next(i for i in client.get("/api/items").json() if i["id"] == item_id)


def test_stale_write_is_refused(client, auth, make_item):
    """The scenario that used to lose data, now caught."""
    created = make_item(name="conflict demo", location="Shelf A", tray="Tray 1").json()

    # Both admins load the same version.
    alice = strip_server_fields(created)
    bob = strip_server_fields(created)
    version = created["updatedAt"]

    first = client.put(
        f"/api/items/{created['id']}",
        json={**alice, "location": "Shelf B"},
        headers={**auth, "X-Expected-Updated-At": version},
    )
    assert first.status_code == 200

    # Bob edits a *different* field, from his now-stale snapshot.
    second = client.put(
        f"/api/items/{created['id']}",
        json={**bob, "tray": "Tray 9"},
        headers={**auth, "X-Expected-Updated-At": version},
    )
    assert second.status_code == 409

    row = current(client, created["id"])
    assert row["location"] == "Shelf B", "the first admin's change must survive"
    assert row["tray"] == "Tray 1", "the stale write must not have applied"


def test_conflict_message_names_the_other_editor(client, auth, make_item):
    created = make_item(name="who changed it").json()
    version = created["updatedAt"]
    client.put(f"/api/items/{created['id']}",
               json={**strip_server_fields(created), "notes": "first"},
               headers={**auth, "X-Expected-Updated-At": version})

    resp = client.put(f"/api/items/{created['id']}",
                      json={**strip_server_fields(created), "notes": "second"},
                      headers={**auth, "X-Expected-Updated-At": version})
    assert resp.status_code == 409
    assert "changed by" in resp.json()["detail"]


def test_fresh_version_succeeds(client, auth, make_item):
    created = make_item(name="sequential edits").json()

    for value in ("one", "two", "three"):
        row = current(client, created["id"])
        resp = client.put(
            f"/api/items/{created['id']}",
            json={**strip_server_fields(row), "notes": value},
            headers={**auth, "X-Expected-Updated-At": row["updatedAt"]},
        )
        assert resp.status_code == 200

    assert current(client, created["id"])["notes"] == "three"


def test_header_is_optional(client, auth, make_item):
    """Omitting the header keeps the old last-write-wins behaviour.

    Callers that genuinely want to force a write (and any client that has not
    been updated) are not broken by the check being added.
    """
    created = make_item(name="no header").json()
    resp = client.put(f"/api/items/{created['id']}",
                      json={**strip_server_fields(created), "notes": "forced"},
                      headers=auth)
    assert resp.status_code == 200


def test_conflict_check_runs_before_validation(client, auth, make_item):
    """A conflict is reported as a conflict, not as a validation error."""
    created = make_item(name="ordering").json()
    version = created["updatedAt"]
    client.put(f"/api/items/{created['id']}",
               json={**strip_server_fields(created), "notes": "bump"},
               headers={**auth, "X-Expected-Updated-At": version})

    resp = client.put(
        f"/api/items/{created['id']}",
        json={**strip_server_fields(created), "checkout_user": "NoEmailPerson"},
        headers={**auth, "X-Expected-Updated-At": version},
    )
    assert resp.status_code == 409


def test_missing_item_is_404_even_with_a_version(client, auth):
    resp = client.put("/api/items/nope",
                      json={"name": "x", "category": "DIMMs"},
                      headers={**auth, "X-Expected-Updated-At": "2026-01-01T00:00:00+00:00"})
    assert resp.status_code == 404
