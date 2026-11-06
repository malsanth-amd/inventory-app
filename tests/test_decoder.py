"""The ddrmpn.amd.com proxy behind the Decoder tab.

The network is stubbed: these assert how the endpoint behaves, not what AMD's
service returns. A live call is covered separately and skipped when offline.
"""

from __future__ import annotations

import os

import httpx
import pytest

SAMPLE = {
    "Part Number": "HMCG88CHJMA863N",
    "Manufacturer": "Hynix",
    "RCD Vendor": "Montage A0",
    "PMIC Vendor": "Richtek B3",
    "DIMM Info": "12800 MRDIMM 2Rx8 16Gb 32GB",
    "DIMM Speed": "12800",
    "DIMM Type": "MRDIMM",
    "DIMM Config": "2Rx8",
    "DRAM Density": "16Gb",
}


@pytest.fixture
def stub_decoder(monkeypatch):
    """Replace the outbound httpx call with a canned response."""
    def install(payload=SAMPLE, status=200):
        class _Response:
            status_code = status
            def json(self):
                return payload

        class _Client:
            def __init__(self, *a, **k): pass
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def get(self, url, *a, **k):
                install.requested_url = url
                return _Response()

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        return install

    return install


def test_anyone_may_look_up_a_part_number(client, stub_decoder):
    """Open on purpose: reading a part number is not a privileged act.

    It was closed because it was an unauthenticated passthrough onto an
    internal service with the caller choosing the URL. The guards below are
    what make it safe to leave open; writes are still admin-only.
    """
    stub_decoder()
    resp = client.get("/api/lookup-pn/HMCG88CHJMA863N")
    assert resp.status_code == 200
    assert resp.json()["rcd"] == "Montage A0"


# ── the guards that let it stay open ──────────────────────────────────────────

@pytest.mark.parametrize("bad,why", [
    ("x%3Fadmin%3D1", "a query string on the internal service"),
    ("%2E%2E", "climbing a path segment"),
    ("a%20b", "whitespace"),
    ("x%26y", "an extra parameter"),
    ("x%25', 'percent", "double encoding"),
    ("x" * 65, "absurd length"),
])
def test_part_numbers_that_could_steer_the_upstream_url_are_refused(client, stub_decoder, bad, why):
    install = stub_decoder()
    resp = client.get(f"/api/lookup-pn/{bad}")
    assert resp.status_code == 400, f"{why} was accepted"
    # Nothing left the server.
    assert not hasattr(install, "requested_url"), f"{why} reached ddrmpn.amd.com"


def test_a_repeat_lookup_never_leaves_the_server(client, stub_decoder, app_module):
    install = stub_decoder()
    first = client.get("/api/lookup-pn/HMCG88CHJMA863N")
    assert first.status_code == 200
    del install.requested_url                      # forget the first call

    second = client.get("/api/lookup-pn/HMCG88CHJMA863N")
    assert second.status_code == 200
    assert second.json() == first.json()
    assert not hasattr(install, "requested_url"), "a cached part number still called upstream"


def test_an_unknown_part_number_is_remembered_too(client, stub_decoder):
    """Otherwise a bad part number typed in a loop is an amplifier."""
    install = stub_decoder(status=404)
    assert client.get("/api/lookup-pn/NOSUCHPN").status_code == 404
    del install.requested_url
    assert client.get("/api/lookup-pn/NOSUCHPN").status_code == 404
    assert not hasattr(install, "requested_url")


def test_a_client_cannot_hammer_the_internal_service(client, stub_decoder, app_module):
    stub_decoder()
    limit = app_module._MAX_DECODES_PER_WINDOW
    # Distinct part numbers, so every one is a cache miss and a real call.
    for n in range(limit):
        assert client.get(f"/api/lookup-pn/PN-{n}").status_code == 200, f"refused at {n}"
    assert client.get(f"/api/lookup-pn/PN-{limit}").status_code == 429


def test_cached_lookups_do_not_count_against_the_limit(client, stub_decoder, app_module):
    stub_decoder()
    assert client.get("/api/lookup-pn/SAME").status_code == 200
    for _ in range(app_module._MAX_DECODES_PER_WINDOW * 2):
        assert client.get("/api/lookup-pn/SAME").status_code == 200


def test_returns_rcd_pmic_and_the_full_payload(client, auth, stub_decoder):
    stub_decoder()
    body = client.get("/api/lookup-pn/HMCG88CHJMA863N", headers=auth).json()

    assert body["rcd"] == "Montage A0"
    assert body["pmic"] == "Richtek B3"
    # The Decoder tab renders everything, not just the two fields the rest uses.
    assert body["raw"]["DIMM Speed"] == "12800"
    assert body["raw"]["CAS Latency" if "CAS Latency" in body["raw"] else "DIMM Type"]


def test_warning_values_are_cleaned_out_of_rcd_pmic(client, auth, stub_decoder):
    stub_decoder({
        **SAMPLE,
        "RCD Vendor": "WARNING! RCD Process code not provided in part number.",
        "PMIC Vendor": "ERROR! unknown",
    })
    body = client.get("/api/lookup-pn/X", headers=auth).json()

    assert body["rcd"] == "" and body["pmic"] == ""
    # ...but the raw payload keeps them, so the tab can show what was said.
    assert body["raw"]["RCD Vendor"].startswith("WARNING!")


def test_unknown_part_number_is_404(client, auth, stub_decoder):
    stub_decoder(status=404)
    assert client.get("/api/lookup-pn/NOPE", headers=auth).status_code == 404


def test_upstream_error_is_502(client, auth, stub_decoder):
    stub_decoder(status=500)
    assert client.get("/api/lookup-pn/X", headers=auth).status_code == 502


def test_blank_part_number_is_rejected(client, auth, stub_decoder):
    stub_decoder()
    assert client.get("/api/lookup-pn/%20%20", headers=auth).status_code == 400


def test_part_numbers_with_odd_characters_pass_through(client, auth, stub_decoder):
    """Scanned part numbers carry a (C) country segment rendered as ©."""
    install = stub_decoder()
    assert client.get("/api/lookup-pn/HMCG94CHJMAA0EN%C2%A9KR",
                      headers=auth).status_code == 200
    assert "HMCG94CHJMAA0EN" in install.requested_url


def test_timeout_is_504(client, auth, monkeypatch):
    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): raise httpx.TimeoutException("slow")

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    assert client.get("/api/lookup-pn/X", headers=auth).status_code == 504


def test_unreachable_service_is_502(client, auth, monkeypatch):
    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    assert client.get("/api/lookup-pn/X", headers=auth).status_code == 502


@pytest.mark.skipif(os.getenv("RUN_LIVE_DECODER") != "1",
                    reason="set RUN_LIVE_DECODER=1 to call ddrmpn.amd.com for real")
def test_live_decode(client, auth):
    body = client.get("/api/lookup-pn/HMCG88CHJMA863N", headers=auth).json()
    assert body["raw"]["Part Number"] == "HMCG88CHJMA863N"
    assert body["rcd"] and body["pmic"]


def test_an_admin_is_not_throttled(client, auth, stub_decoder, app_module):
    """The limit protects an internal service from anonymous callers.

    It must not throttle the app's own work: "Refresh from decoder" looks up
    every distinct part number at once — 117 in the live inventory — and a cap
    of _MAX_DECODES_PER_WINDOW silently dropped most of them, which reached the
    admin as the refresh quietly not working.
    """
    stub_decoder()
    over = app_module._MAX_DECODES_PER_WINDOW * 4
    for n in range(over):
        resp = client.get(f"/api/lookup-pn/ADMIN-PN-{n}", headers=auth)
        assert resp.status_code == 200, f"throttled at {n} with a token"


def test_an_anonymous_caller_is_still_throttled(client, stub_decoder, app_module):
    stub_decoder()
    limit = app_module._MAX_DECODES_PER_WINDOW
    for n in range(limit):
        assert client.get(f"/api/lookup-pn/ANON-PN-{n}").status_code == 200
    assert client.get(f"/api/lookup-pn/ANON-PN-{limit}").status_code == 429


def test_a_bad_token_is_treated_as_anonymous(client, stub_decoder, app_module):
    stub_decoder()
    bad = {"Authorization": "Bearer not-a-real-token"}
    limit = app_module._MAX_DECODES_PER_WINDOW
    for n in range(limit):
        assert client.get(f"/api/lookup-pn/BAD-PN-{n}", headers=bad).status_code == 200
    assert client.get(f"/api/lookup-pn/BAD-PN-{limit}", headers=bad).status_code == 429


@pytest.mark.parametrize("pn", [
    "HMCGP4AHJMF870N(C)KR",     # the country segment written literally
    "HMCG94CHJMAA0PN©KR",       # ...and as the symbol; the table holds both
    "MTC40F2047S1RC64BBZ",
    "100-000001263-02",
    "M321R8GA0BB0-CQKVS",
])
def test_part_numbers_the_inventory_actually_holds_are_accepted(client, stub_decoder, pn):
    """One rejected part number in a 117-part sweep raised a page-wide error."""
    stub_decoder()
    resp = client.get(f"/api/lookup-pn/{pn}")
    assert resp.status_code == 200, f"{pn} was refused"


@pytest.mark.parametrize("bad", ["x%3Fy", "a%20b", "x%26y", "%2E%2E"])
def test_parentheses_did_not_open_the_door_to_url_steering(client, stub_decoder, bad):
    stub_decoder()
    assert client.get(f"/api/lookup-pn/{bad}").status_code == 400
