"""PPIN fuse parsing — apml_tool's output shape varies by BMC firmware."""

import pytest

from ppin_sn import DecodeUnavailable, decode_ppin, extract_ppins, parse_ppin


def test_parses_boxed_table_output():
    out = """
\t ------------------------------------------------
\t | PPIN FUSE\t | 0x1234567890abcdef \t |
\t ------------------------------------------------
"""
    assert parse_ppin(out) == "1234567890ABCDEF"


def test_parses_plain_label_output():
    assert parse_ppin("PPIN Fuse: 00ab89cd6745ef23\n") == "00AB89CD6745EF23"


def test_parses_bare_value_without_a_label():
    assert parse_ppin("\n0xDEADBEEF00001111\n") == "DEADBEEF00001111"


def test_prefers_the_value_on_the_ppin_line():
    # The socket/module banner can carry its own 16-digit hex blob; the labelled
    # line is the one that matters.
    out = "Module: aaaabbbbccccdddd\nPPIN FUSE | 0x1111222233334444 |\n"
    assert parse_ppin(out) == "1111222233334444"


def test_reports_an_unfused_part_rather_than_hiding_it():
    assert parse_ppin("PPIN FUSE | 0x0000000000000000 |") == "0000000000000000"


# The register drops leading zeros, so a short print is normal. Both examples
# are the ones the Confluence page itself gives.
@pytest.mark.parametrize("printed,padded", [
    ("0x831a421659c02b",  "00831A421659C02B"),
    ("0x2b620df48c84013", "02B620DF48C84013"),
])
def test_left_pads_a_short_ppin_to_16_digits(printed, padded):
    assert parse_ppin(f"PPIN FUSE | {printed} |") == padded


def test_pads_a_short_ppin_without_the_0x_prefix():
    assert parse_ppin("PPIN Fuse: 831a421659c02b\n") == "00831A421659C02B"


@pytest.mark.parametrize("out", [
    "",
    "apml_tool: command not found",
    "Socket 0 ready, 12 cores",       # no PPIN label, nothing hex-shaped
])
def test_rejects_output_without_a_ppin(out):
    with pytest.raises(ValueError):
        parse_ppin(out)


# ── PPIN → serial number ──────────────────────────────────────────────────────

def test_decodes_the_fields_the_fuse_packs():
    """Built from known field values rather than a captured answer.

    lot number 1 → base-37 digits 0000001 → "@@@@@@A" (0 is '@', 1 is 'A')
    date code 35 → 'P' (77 + 35 // 10) then '5'
    unit 19      → "0019"
    """
    ppin = (1 << 21) | (35 << 14) | 19
    assert decode_ppin(f"{ppin:016x}") == "@@@@@@AP50019"


def test_lot_digits_above_26_are_numerals():
    """The alphabet is not plain base-36: 0 is '@', 27 maps to '0', 36 to '9'."""
    # The lot is the first seven characters; its last digit is the ones place.
    assert decode_ppin(f"{(27 << 21):016x}")[:7] == "@@@@@@0"
    assert decode_ppin(f"{(36 << 21):016x}")[:7] == "@@@@@@9"


@pytest.mark.parametrize("ppin,serial", [
    # The two examples the Confluence page prints, pinned so a change to the
    # decode has to be deliberate.
    ("0x831a421659c02b",  "F405504W30043"),
    ("0x2b620df48c84013", "9KR5736P30019"),
])
def test_known_ppins(ppin, serial):
    assert decode_ppin(ppin) == serial


def test_leading_zeros_and_prefix_do_not_change_the_answer():
    assert decode_ppin("00831A421659C02B") == decode_ppin("0x831a421659c02b")
    assert decode_ppin("831a421659c02b") == decode_ppin("0X831A421659C02B")


@pytest.mark.parametrize("bad", ["", "   ", "0x", "not-hex", "12g4"])
def test_rejects_anything_that_is_not_hex(bad):
    with pytest.raises(DecodeUnavailable):
        decode_ppin(bad)


def test_extracts_one_ppin_per_socket():
    out = (
        "\t ------------------------------------------------\n"
        "\t | Socket 0 PPIN FUSE\t | 0x2b620df48c84013 \t |\n"
        "\t | Socket 1 PPIN FUSE\t | 0x831a421659c02b  \t |\n"
    )
    found = extract_ppins(out)
    assert [label for label, _ in found] == ["Socket 0 PPIN FUSE", "Socket 1 PPIN FUSE"]
    assert [decode_ppin(p) for _, p in found] == ["9KR5736P30019", "F405504W30043"]


def test_extraction_pads_short_values():
    assert extract_ppins("PPIN: 0x2b620df48c84013")[0][1] == "02B620DF48C84013"


# ── the CPU Decoder tab's endpoints ───────────────────────────────────────────

def test_decode_endpoint_is_open_to_everyone(client):
    """Arithmetic, not a lookup: nothing leaves the server, nothing is stored."""
    resp = client.post("/api/cpu/decode-ppin", json={"text": "PPIN: 0x2b620df48c84013"})
    assert resp.status_code == 200
    assert resp.json()["results"] == [
        {"label": "PPIN", "ppin": "02B620DF48C84013", "serial": "9KR5736P30019"}
    ]


def test_decode_endpoint_handles_a_whole_apml_dump(client):
    dump = ("\t | Socket 0 PPIN FUSE\t | 0x2b620df48c84013 \t |\n"
            "\t | Socket 1 PPIN FUSE\t | 0x831a421659c02b  \t |\n")
    results = client.post("/api/cpu/decode-ppin", json={"text": dump}).json()["results"]
    assert [r["serial"] for r in results] == ["9KR5736P30019", "F405504W30043"]


@pytest.mark.parametrize("text,status", [
    ("",        400),
    ("   ",     400),
    ("hello",   422),      # nothing PPIN-shaped
    ("x" * 20_001, 413),
])
def test_decode_endpoint_rejects_junk(client, text, status):
    assert client.post("/api/cpu/decode-ppin", json={"text": text}).status_code == status


def test_reading_a_sut_needs_no_login(client, fake_bmc):
    """Open to the lab, like the rest of the app.

    The guards that come with that are BMC_HOST_ALLOW and the rate limit
    below — not a login.
    """
    fake_bmc(DUAL)
    resp = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"})
    assert resp.status_code == 200
    assert resp.json()["results"][0]["serial"] == "9KR5736P30019"


@pytest.mark.parametrize("host", [
    "a host",            # whitespace
    "sut; rm -rf /",     # shell metacharacters
    "http://sut/",       # a URL
    "",
    "x" * 64,
])
def test_sut_hostnames_are_held_to_a_hostname_shape(client, auth, host):
    resp = client.post("/api/cpu/read-sut", json={"host": host}, headers=auth)
    assert resp.status_code == 400


def test_socket_is_bounded(client, auth):
    assert client.post("/api/cpu/read-sut", json={"host": "seagull-0112", "socket": 99},
                       headers=auth).status_code == 400


def test_missing_bmc_password_says_so_instead_of_hanging(client, auth, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "BMC_PASSWORD", "")
    resp = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth)
    assert resp.status_code == 503
    assert "BMC_PASSWORD" in resp.json()["detail"]


# ── naming a system is the whole input ────────────────────────────────────────
#
# _FakeSSH and the fake_bmc fixture that installs it live in conftest.py now:
# test_audit_scan.py reads several systems in one call and needed the same
# fake, just handed a map of host -> output instead of one fixed map.

from conftest import DUAL, _FakeSSH  # noqa: E402


def test_a_system_name_is_the_only_input_needed(client, auth, fake_bmc):
    fake_bmc(DUAL)
    resp = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [r["serial"] for r in body["results"]] == ["9KR5736P30019", "F405504W30043"]
    assert [r["socket"] for r in body["results"]] == [0, 1]


def test_both_sockets_are_read_over_one_connection(client, auth, fake_bmc):
    fake_bmc(DUAL)
    client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth)
    ssh = _FakeSSH.instances[0]
    assert ssh.connects == 1, "reconnected per socket"
    assert ssh.commands == ["apml_tool 0 --showppinfuse", "apml_tool 1 --showppinfuse"]
    assert ssh.closed


def test_a_single_socket_board_still_answers(client, auth, fake_bmc):
    """Socket 1 failing on a 1P board is an answer, not an error."""
    fake_bmc({0: DUAL[0]})
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth).json()
    assert [r["serial"] for r in body["results"]] == ["9KR5736P30019"]
    assert body["skipped"][0]["socket"] == 1


def test_a_board_reporting_one_fuse_twice_is_one_cpu(client, auth, fake_bmc):
    fake_bmc({0: DUAL[0], 1: DUAL[0]})
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth).json()
    assert len(body["results"]) == 1


def test_a_named_socket_is_the_only_one_read(client, auth, fake_bmc):
    fake_bmc(DUAL)
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112", "socket": 1},
                       headers=auth).json()
    assert [r["socket"] for r in body["results"]] == [1]
    assert _FakeSSH.instances[0].commands == ["apml_tool 1 --showppinfuse"]


def test_no_socket_answering_reports_what_each_said(client, auth, fake_bmc):
    fake_bmc({})
    resp = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "socket 0" in detail and "socket 1" in detail


def test_an_unreachable_bmc_is_reported_as_such(client, auth, fake_bmc):
    fake_bmc(connect_error=OSError("No route to host"))
    resp = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}, headers=auth)
    assert resp.status_code == 502
    assert "No route to host" in resp.json()["detail"]


# apml_tool's real output, from seagull-0112: a 1P board, colour codes and all.
REAL_SOCKET_0 = """=============================== APML System Management Interface ==========================
-------------------------------------------------------------------------
| PPIN Fuse | 0x8324cac0f5802d                                            |
-------------------------------------------------------------------------

=============================== End of APML SMI =========================="""

REAL_SOCKET_1 = ("=============================== APML System Management Interface ==========================\n"
                 "\x1b[31m SBRMI module not present.Please install the module\x1b[0m\n\n"
                 "=============================== End of APML SMI ==========================")


def test_real_apml_output_decodes(client, fake_bmc):
    fake_bmc({0: REAL_SOCKET_0, 1: REAL_SOCKET_1})
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}).json()
    assert [r["serial"] for r in body["results"]] == ["F433669U60045"]
    assert body["results"][0]["ppin"] == "008324CAC0F5802D"


def test_the_skipped_socket_says_what_apml_said(client, fake_bmc):
    """Not the banner: the first non-blank line is a row of '=' signs."""
    fake_bmc({0: REAL_SOCKET_0, 1: REAL_SOCKET_1})
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}).json()
    assert body["skipped"] == [{"socket": 1, "reason": "SBRMI module not present.Please install the module"}]


def test_colour_codes_do_not_reach_the_page(client, fake_bmc):
    fake_bmc({0: REAL_SOCKET_0, 1: REAL_SOCKET_1})
    body = client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}).json()
    assert "\x1b" not in "".join(body["raw"].values())


def test_an_allowlist_refuses_hosts_outside_the_lab(client, fake_bmc, app_module, monkeypatch):
    fake_bmc(DUAL)
    monkeypatch.setattr(app_module, "BMC_HOST_ALLOW", ["seagull-*", "eagle-*"])
    assert client.post("/api/cpu/read-sut", json={"host": "seagull-0112"}).status_code == 200
    assert client.post("/api/cpu/read-sut", json={"host": "eagle-7"}).status_code == 200

    blocked = client.post("/api/cpu/read-sut", json={"host": "someone-elses-box"})
    assert blocked.status_code == 403
    assert "seagull-*" in blocked.json()["detail"]
    # Nothing was dialled.
    assert len(_FakeSSH.instances) == 2


def test_no_allowlist_means_any_host(client, fake_bmc, app_module, monkeypatch):
    """The lab asked for it open; the list is how a site narrows it."""
    fake_bmc(DUAL)
    monkeypatch.setattr(app_module, "BMC_HOST_ALLOW", [])
    assert client.post("/api/cpu/read-sut", json={"host": "anything-at-all"}).status_code == 200


def test_a_caller_cannot_sweep_the_network(client, fake_bmc, app_module):
    fake_bmc(DUAL)
    limit = app_module._MAX_SUT_PER_WINDOW
    for n in range(limit):
        assert client.post("/api/cpu/read-sut", json={"host": f"seagull-{n:04d}"}).status_code == 200
    refused = client.post("/api/cpu/read-sut", json={"host": "seagull-9999"})
    assert refused.status_code == 429
    assert len(_FakeSSH.instances) == limit, "the refused call still connected"
