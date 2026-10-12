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


def test_requires_admin(client, stub_decoder):
    stub_decoder()
    assert client.get("/api/lookup-pn/HMCG88CHJMA863N").status_code == 401


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
