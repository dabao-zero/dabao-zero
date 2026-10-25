from __future__ import annotations

import json
from pathlib import Path

import pytest

from dabao.vex import VexStatement, build_openvex, package_url, to_json

STATEMENT = VexStatement(
    advisory_id="CVE-2022-48303",
    stream="debian",
    packages=(("tar", "1.34+dfsg-1.2+dabao1"), ("tar-scripts", "1.34+dfsg-1.2+dabao1")),
    upstream_ref="https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
    patch_sha256="a" * 64,
)
NOW = 1_792_800_000.0


def test_package_urls_have_no_qualifiers_and_encode_the_awkward_characters() -> None:
    # Plain package URLs are what both scanners matched in the 2026-10-23 experiment (ADR-0010).
    assert package_url("debian", "tar", "1.34+dfsg-1.2+dabao1") == (
        "pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdabao1"
    )
    assert package_url("debian", "libcap2", "1:2.66-4") == "pkg:deb/debian/libcap2@1%3A2.66-4"
    assert package_url("alpine", "brotli-libs", "1.2.1-r0") == "pkg:apk/alpine/brotli-libs@1.2.1-r0"


def test_an_unknown_stream_has_no_package_url() -> None:
    with pytest.raises(ValueError, match="stream"):
        package_url("wolfi", "x", "1")


def test_the_document_says_fixed_for_each_package_of_the_one_cve() -> None:
    doc = build_openvex([STATEMENT], timestamp=NOW)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["version"] == 1 and doc["author"] == "dabao-zero gate runner"
    assert doc["timestamp"] == "2026-10-24T00:00:00Z"
    (st,) = doc["statements"]
    assert st["vulnerability"] == {"name": "CVE-2022-48303"}
    assert [p["@id"] for p in st["products"]] == [
        "pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdabao1",
        "pkg:deb/debian/tar-scripts@1.34%2Bdfsg-1.2%2Bdabao1",
    ]
    assert st["status"] == "fixed"
    assert STATEMENT.upstream_ref in st["status_notes"] and "a" * 64 in st["status_notes"]


def test_the_same_inputs_give_the_same_bytes_and_a_content_derived_id() -> None:
    a = to_json(build_openvex([STATEMENT], timestamp=NOW))
    b = to_json(build_openvex([STATEMENT], timestamp=NOW))
    assert a == b and json.loads(a)["@id"].startswith(
        "https://github.com/dabao-zero/dabao-zero/vex/"
    )
    other = VexStatement(**{**STATEMENT.__dict__, "advisory_id": "CVE-2023-39804"})
    assert json.loads(to_json(build_openvex([other], timestamp=NOW)))["@id"] != json.loads(a)["@id"]


def test_there_is_nothing_to_say_without_a_statement() -> None:
    with pytest.raises(ValueError, match="no statements"):
        build_openvex([], timestamp=NOW)


def test_a_statement_without_packages_is_refused() -> None:
    empty = VexStatement(**{**STATEMENT.__dict__, "packages": ()})
    with pytest.raises(ValueError, match="packages"):
        build_openvex([empty], timestamp=NOW)


def test_the_document_can_be_written_for_a_scanner(tmp_path: Path) -> None:
    from dabao.vex import write_openvex

    path = write_openvex(tmp_path / "v.json", [STATEMENT], timestamp=NOW)
    assert json.loads(path.read_text())["statements"][0]["status"] == "fixed"
