"""Sensitivity-labelled workbooks.

A label that only classifies (Internal Use Only, as applied by default) leaves
the file a normal zip and must keep working. A label that *protects* wraps the
package in Azure Rights Management encryption, which nothing here can open —
msoffcrypto reports "Unrecognized file format", which told an admin nothing.
These tests pin both halves.
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

LABEL_ID = "b86ed9a8-cb14-47c1-b0a5-71632fe823d9"
LABEL_XML = (
    b'<?xml version="1.0" encoding="utf-8" standalone="yes"?>'
    b'<clbl:labelList xmlns:clbl="http://schemas.microsoft.com/office/2020/mipLabelMetadata">'
    b'<clbl:label id="{' + LABEL_ID.encode() + b'}" enabled="1" method="Privileged" '
    b'siteId="{3dd8961f-e488-4e60-8e11-a82d994e183d}" contentBits="9" removed="0" />'
    b"</clbl:labelList>"
)


# ── a label that only classifies ──────────────────────────────────────────────

def _stamp_label(xlsx: bytes) -> bytes:
    """Add the parts a non-encrypting MIP label writes into a workbook."""
    props = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"'
        ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        '<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2"'
        f' name="MSIP_Label_{LABEL_ID}_Name"><vt:lpwstr>AMD Internal Use Only</vt:lpwstr></property>'
        "</Properties>"
    )
    src = zipfile.ZipFile(io.BytesIO(xlsx))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "[Content_Types].xml":
                data = data.replace(
                    b"</Types>",
                    b'<Override PartName="/docProps/custom.xml" ContentType='
                    b'"application/vnd.openxmlformats-officedocument.custom-properties+xml"/></Types>')
            elif info.filename == "_rels/.rels":
                data = data.replace(
                    b"</Relationships>",
                    b'<Relationship Id="rIdMSIP" Type="http://schemas.openxmlformats.org/'
                    b'officeDocument/2006/relationships/custom-properties" '
                    b'Target="docProps/custom.xml"/></Relationships>')
            z.writestr(info, data)
        z.writestr("docProps/custom.xml", props)
    return out.getvalue()


def test_a_classifying_label_still_imports(client, auth):
    """The ordinary case: the label is metadata, the workbook is still a zip."""
    labelled = _stamp_label(client.get("/api/template").content)
    resp = client.post("/api/parse-file",
                       files={"file": ("labelled.xlsx", labelled, XLSX_MIME)}, headers=auth)
    assert resp.status_code == 200, resp.text
    sheets = resp.json()["sheets"]
    assert sheets[0]["rows"][0][0] == "Action"
    # The label is untouched — uploading does not strip it from the admin's copy.
    assert b"MSIP_Label" in zipfile.ZipFile(io.BytesIO(labelled)).read("docProps/custom.xml")


# ── a label that protects ─────────────────────────────────────────────────────

class _FakeOle:
    """Stands in for olefile: a rights-managed container's directory."""

    def __init__(self, entries, label: bytes | None):
        self._entries, self._label = entries, label

    def listdir(self, streams=True, storages=True):
        return self._entries

    def openstream(self, path):
        if self._label is None:
            raise OSError("file not found")
        return io.BytesIO(self._label)


DRM_ENTRIES = [
    ["\x06DataSpaces", "DataSpaceInfo", "DRMEncryptedDataSpace"],
    ["\x06DataSpaces", "TransformInfo", "DRMEncryptedTransform", "Primary"],
    ["\x06DataSpaces", "TransformInfo", "LabelInfo"],
    ["EncryptedPackage"],
]


@pytest.fixture
def fake_ole(monkeypatch, app_module):
    def _install(entries, label):
        monkeypatch.setattr(app_module.msoffcrypto, "olefile",
                            type("m", (), {"OleFileIO": lambda _buf: _FakeOle(entries, label)}))
    return _install


def test_detects_a_rights_managed_file_and_names_the_label(fake_ole, app_module):
    fake_ole(DRM_ENTRIES, LABEL_XML)
    assert app_module._rights_managed_label(OLE2_MAGIC + b"rest") == LABEL_ID


def test_protected_file_without_a_readable_label_is_still_detected(fake_ole, app_module):
    fake_ole(DRM_ENTRIES, None)
    assert app_module._rights_managed_label(OLE2_MAGIC + b"rest") == "unknown"


def test_a_legacy_xls_is_not_mistaken_for_a_protected_file(fake_ole, app_module):
    """Old .xls files are OLE2 too — only the DRM streams mean rights managed."""
    fake_ole([["Workbook"], ["SummaryInformation"]], None)
    assert app_module._rights_managed_label(OLE2_MAGIC + b"rest") is None


@pytest.mark.parametrize("content", [
    b"PK\x03\x04 ordinary xlsx zip",
    b"name,qty\nwidget,2\n",
    b"",
])
def test_non_ole2_content_is_left_alone(content, app_module):
    assert app_module._rights_managed_label(content) is None


def test_unparseable_ole2_bytes_do_not_raise(app_module):
    assert app_module._rights_managed_label(OLE2_MAGIC + os.urandom(512)) is None


def test_upload_of_a_protected_file_explains_what_to_do(client, auth, monkeypatch, app_module):
    monkeypatch.setattr(app_module, "_rights_managed_label", lambda content: LABEL_ID)
    resp = client.post("/api/parse-file",
                       files={"file": ("protected.xlsx", OLE2_MAGIC + b"x", XLSX_MIME)},
                       headers=auth)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert LABEL_ID in detail                      # which label did it
    assert "Sensitivity" in detail                 # where to change it
    # The old message blamed decryption and offered a password that cannot exist.
    assert "password-protected" not in detail
