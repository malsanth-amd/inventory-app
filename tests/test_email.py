"""Email construction: escaping, header safety and the submission endpoint.

Item names and serial numbers come from uploaded spreadsheets, and the
submission form takes no login at all, so everything these templates
interpolate is attacker-reachable.
"""

from __future__ import annotations

import pytest

HOSTILE = '<script>alert(1)</script><a href="http://evil.example">click</a>'


def html_part(message) -> str:
    part = next(p for p in message.walk() if p.get_content_type() == "text/html")
    return part.get_payload(decode=True).decode()


# ── escaping in the four builders ─────────────────────────────────────────────

def test_reminder_email_escapes_every_value(app_module):
    msg = app_module._build_reminder_msg(
        "someone@amd.com",
        HOSTILE,
        [{"name": HOSTILE, "serial_number": HOSTILE, "loan_until": "2026-01-01"}],
        HOSTILE,
    )
    body = html_part(msg)
    assert "<script>" not in body
    assert 'href="http://evil.example"' not in body
    assert "&lt;script&gt;" in body


def test_checkout_notification_escapes_every_value(app_module):
    msg = app_module._build_checkout_msg(
        "someone@amd.com",
        HOSTILE,
        [{"name": HOSTILE, "serial_number": HOSTILE, "part_number": HOSTILE}],
    )
    body = html_part(msg)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


def test_return_request_escapes_every_value(app_module):
    msg, _cc = app_module._build_return_request_msg(
        "someone@amd.com",
        HOSTILE,
        [{"name": HOSTILE, "serial_number": HOSTILE, "location": HOSTILE,
          "category": HOSTILE}],
        extra_cc=[],
        message=HOSTILE,
    )
    body = html_part(msg)
    assert "<script>" not in body
    assert 'href="http://evil.example"' not in body


# ── helpers ───────────────────────────────────────────────────────────────────

def test_esc_handles_none_and_numbers(app_module):
    assert app_module._esc(None) == ""
    assert app_module._esc(42) == "42"
    assert app_module._esc("a & b") == "a &amp; b"


def test_header_safe_strips_newlines(app_module):
    cleaned = app_module._header_safe("Alice\r\nBcc: attacker@evil.example")
    assert "\n" not in cleaned and "\r" not in cleaned


def test_header_safe_bounds_length(app_module):
    assert len(app_module._header_safe("x" * 1000)) <= 200


@pytest.mark.parametrize("address", ["a@b.com", "first.last@sub.amd.com"])
def test_email_regex_accepts_real_addresses(app_module, address):
    assert app_module._EMAIL_RE.fullmatch(address)


@pytest.mark.parametrize("address", ["not an email", "a@b", "a@@b.com", ""])
def test_email_regex_rejects_junk(app_module, address):
    assert app_module._EMAIL_RE.fullmatch(address) is None


# ── the unauthenticated submission endpoint ───────────────────────────────────

@pytest.fixture
def captured_mail(app_module, monkeypatch):
    """Intercept outgoing mail and enable the endpoint without a real relay."""
    box: dict = {}
    monkeypatch.setattr(app_module, "SMTP_HOST", "smtp.invalid")
    monkeypatch.setattr(app_module, "ADMIN_EMAIL", "admin@lab.test")
    monkeypatch.setattr(
        app_module, "_smtp_send", lambda to, msg, extra_cc=None: box.update(msg=msg)
    )
    monkeypatch.setattr(app_module, "_rate_limit_submission", lambda: None)
    return box


def submit(client, **overrides):
    data = {"submitter_name": "Alice", "submitter_email": "alice@amd.com", "notes": ""}
    data.update(overrides)
    return client.post(
        "/api/submit-request", data=data,
        files={"file": ("sheet.csv", b"col\nvalue\n", "text/csv")},
    )


def test_submission_rejects_invalid_email(client, captured_mail):
    assert submit(client, submitter_email="not-an-email").status_code == 422


def test_submission_rejects_blank_name(client, captured_mail):
    assert submit(client, submitter_name="   ").status_code == 422


def test_submission_rejects_oversized_notes(client, captured_mail, app_module):
    resp = submit(client, notes="x" * (app_module._MAX_NOTES_CHARS + 1))
    assert resp.status_code == 422


def test_submission_rejects_unexpected_file_types(client, captured_mail):
    resp = client.post(
        "/api/submit-request",
        data={"submitter_name": "A", "submitter_email": "a@b.com", "notes": ""},
        files={"file": ("payload.exe", b"MZ", "application/octet-stream")},
    )
    assert resp.status_code == 422


def test_submission_escapes_html_in_notes(client, captured_mail):
    assert submit(client, notes=HOSTILE).status_code == 200
    body = html_part(captured_mail["msg"])
    assert 'href="http://evil.example"' not in body
    assert "&lt;a href=" in body


def test_submission_strips_header_injection(client, captured_mail):
    assert submit(client, submitter_name="Alice\r\nBcc: attacker@evil.example").status_code == 200
    msg = captured_mail["msg"]
    assert "\n" not in str(msg["Subject"])
    assert "Bcc" not in msg.keys()


def test_submission_strips_path_from_filename(client, captured_mail):
    client.post(
        "/api/submit-request",
        data={"submitter_name": "A", "submitter_email": "a@b.com", "notes": ""},
        files={"file": ("../../../etc/passwd.csv", b"a\n", "text/csv")},
    )
    attachment = next(p for p in captured_mail["msg"].walk() if p.get_filename())
    name = attachment.get_filename()
    assert "/" not in name and ".." not in name


def test_submission_rate_limit(client, app_module, monkeypatch):
    monkeypatch.setattr(app_module, "SMTP_HOST", "smtp.invalid")
    monkeypatch.setattr(app_module, "ADMIN_EMAIL", "admin@lab.test")
    monkeypatch.setattr(app_module, "_smtp_send", lambda *a, **k: None)
    monkeypatch.setattr(app_module, "_submission_times", [])

    statuses = [submit(client).status_code
                for _ in range(app_module._MAX_SUBMISSIONS_PER_WINDOW + 2)]
    assert 429 in statuses
