from bs4 import BeautifulSoup
import refresh_recipe_bkc_page as m

# Hand-built HTML matching the REAL screenshot's layout: a filenames row
# (BIOS | REAV0080I/TEAV0080I | RHOV0080I/THOV0080I | RFAV0080I/TFAV0080I |
# RSGV0080I/TSGV0080I) followed by a SEPARATE row holding one shared
# Artifactory "Index of ..." link spanning all boards - NOT embedded per
# board cell (that wrong assumption was the original bug: BIOS silently
# never resolved, leaving recipe.yaml's old "weekly" BIOS entries intact).
BIOS_SECTION_HTML = """
<table>
  <tr>
    <td>BIOS</td>
    <td><strong>REAV0080I</strong> / <strong>TEAV0080I</strong></td>
    <td><strong>RHOV0080I</strong> / <strong>THOV0080I</strong></td>
    <td><strong>RFAV0080I</strong> / <strong>TFAV0080I</strong></td>
    <td><strong>RSGV0080I</strong> / <strong>TSGV0080I</strong></td>
  </tr>
  <tr>
    <td colspan="5">
      <a href="https://mkmartifactory.amd.com:8443/artifactory/fw-bios-dev-local/PlatformBIOS/Venicesp8/pi/0080I">Index of fw-bios-dev-local/PlatformBIOS/Venicesp8/pi/0080I</a>
    </td>
  </tr>
</table>
"""


def test_find_bios_section_shared_link():
    cells, folder_url = m.find_bios_section(BIOS_SECTION_HTML)
    assert len(cells) == 4, cells
    assert folder_url == (
        "https://mkmartifactory.amd.com:8443/artifactory/fw-bios-dev-local/PlatformBIOS/Venicesp8/pi/0080I"
    ), folder_url
    print("PASS: find_bios_section locates the shared Artifactory link in the NEXT row, not per-board-cell")


def test_extract_bios_filenames_per_board():
    cells, _ = m.find_bios_section(BIOS_SECTION_HTML)
    for cell, expected in zip(cells, [
        ["REAV0080I", "TEAV0080I"],
        ["RHOV0080I", "THOV0080I"],
        ["RFAV0080I", "TFAV0080I"],
        ["RSGV0080I", "TSGV0080I"],
    ]):
        assert m.extract_bios_filenames(cell) == expected, (cell, expected)
    print("PASS: extract_bios_filenames pulls the right filenames out of each board's own cell")


def test_find_bios_section_no_link_returns_none_url():
    html = "<table><tr><td>BIOS</td><td>REAV0080I / TEAV0080I (no link anywhere)</td></tr></table>"
    cells, folder_url = m.find_bios_section(html)
    assert folder_url is None
    print("PASS: find_bios_section returns a None folder_url when no Artifactory/Index link exists nearby")


def test_extract_bios_filenames_no_match_returns_none():
    soup = BeautifulSoup("<td>nothing bios-shaped here</td>", "html.parser")
    cell = soup.find("td")
    assert m.extract_bios_filenames(cell) is None
    print("PASS: extract_bios_filenames returns None without a filename match")


# AMD switched this release's BIOS row to a "weekly/<rev>" Artifactory feed
# with a new version-body shape ("6A28N": digit+letter+digits+letter, not
# the older pure-digits-plus-one-letter "0080I" shape) - confirmed on the
# real live page. resolve_bios_artifact()/find_bios_section() are already
# folder-URL-driven and needed no change; only BIOS_FILENAME_RE had to
# widen to match this new shape too.
WEEKLY_BIOS_SECTION_HTML = """
<table>
  <tr>
    <td>BIOS</td>
    <td><strong>WEAV6A28N</strong></td>
    <td><strong>WHOV6A28N</strong></td>
    <td><strong>WFAV6A28N</strong></td>
    <td><strong>WSGV6A28N</strong></td>
  </tr>
  <tr>
    <td colspan="5">
      <a href="https://mkmartifactory.amd.com/artifactory/fw-bios-dev-local/PlatformBIOS/Venicesp8/weekly/6A28N/GCC/">Index of fw-bios-dev-local/PlatformBIOS/Venicesp8/weekly/6A28N/GCC</a>
    </td>
  </tr>
</table>
"""


def test_extract_bios_filenames_weekly_format():
    cells, folder_url = m.find_bios_section(WEEKLY_BIOS_SECTION_HTML)
    assert folder_url.endswith("/weekly/6A28N/GCC/"), folder_url
    for cell, expected in zip(cells, [["WEAV6A28N"], ["WHOV6A28N"], ["WFAV6A28N"], ["WSGV6A28N"]]):
        assert m.extract_bios_filenames(cell) == expected, (cell, expected)
    print("PASS: extract_bios_filenames also matches the newer 'weekly' version-body shape (e.g. WEAV6A28N)")


# Hand-built HTML shaped like the screenshot's BMC FW row - a single shared
# cell/link+version across all boards (\\atlcorpnetfs\...\v2.18.0.100I).
BMC_CELL_HTML = """
<table>
  <tr>
    <td>BMC FW</td>
    <td><a href="file://atlcorpnetfs/BiosOnly/BMC_Release/sp7/v2.18.0.100I">\\atlcorpnetfs\\BiosOnly\\BMC_Release\\sp7\\v2.18.0.100I</a></td>
    <td>sp7_v2.18.0.100I</td>
  </tr>
</table>
"""


def test_extract_bmc_version_from_page():
    version = m.extract_bmc_version_from_page(BMC_CELL_HTML)
    assert version == "2.18.0.100I", version
    print("PASS: extract_bmc_version_from_page reads the page-pinned BMC version, not the share's latest-mtime folder")


def test_extract_bmc_version_from_page_missing_row():
    try:
        m.extract_bmc_version_from_page("<table><tr><td>Unrelated</td><td>nothing here</td></tr></table>")
        assert False, "should have raised ValueError for a missing BMC row"
    except ValueError:
        print("PASS: extract_bmc_version_from_page raises when no BMC row is found")


def test_resolve_bmc_at_version_picks_exact_folder(tmp_path=None):
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        share_root = Path(tmp)
        # The page-pinned version (should be picked)...
        pinned = share_root / "v2.18.0.100I" / "BMC"
        pinned.mkdir(parents=True)
        (pinned / "obmc-phosphor-image-sp7_v2.18.0.100I.static.mtd.tar").write_bytes(b"x")
        # ...and a NEWER-by-mtime but NOT page-pinned build, simulating the
        # real incident (share has a newer WIP build than the page lists).
        import time
        newer = share_root / "v3.0.0.101C" / "BMC"
        newer.mkdir(parents=True)
        newer_file = newer / "obmc-phosphor-image-sp7_v3.0.0.101C.static.mtd.tar"
        newer_file.write_bytes(b"y")
        os.utime(newer_file, (time.time() + 1000, time.time() + 1000))

        share_uri = "file:///" + str(share_root.resolve()).replace("\\", "/")
        with patch.object(m, "_probe_host_reachable", return_value=True):
            result = m.resolve_bmc_at_version(share_uri, "2.18.0.100I")

        assert result["version_folder"] == "v2.18.0.100I", result["version_folder"]
        assert "100I" in result["path"].name, result["path"].name
        print("PASS: resolve_bmc_at_version picks the page-pinned version, ignoring a newer-by-mtime build elsewhere on the share")


if __name__ == "__main__":
    import os
    from unittest.mock import patch

    test_find_bios_section_shared_link()
    test_extract_bios_filenames_per_board()
    test_find_bios_section_no_link_returns_none_url()
    test_extract_bios_filenames_no_match_returns_none()
    test_extract_bios_filenames_weekly_format()
    test_extract_bmc_version_from_page()
    test_extract_bmc_version_from_page_missing_row()
    test_resolve_bmc_at_version_picks_exact_folder()
    print("\nALL PASS")
