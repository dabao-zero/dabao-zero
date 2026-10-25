"""Canary: do the pinned scanners still honour our VEX statements? (ADR-0010 decision 7)

Needs `trivy` and `grype` on PATH and network access. Run with `make test-scanners`; the scheduled
workflow `scanner-canary` runs it with pinned scanner versions. If a scanner upgrade stops honouring
a plain-package-URL `fixed` statement, or starts clearing more than the one CVE named, this fails.

Both images are pinned by digest, so only the scanners and their databases can change the outcome.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from dabao.live import GrypeScanner, ImageSource, TrivyScanner
from dabao.vex import VexStatement, write_openvex

pytestmark = pytest.mark.scanners

NOW = 1_792_800_000.0
ALPINE = ImageSource(
    base_digest="sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417",
    base_ref="mirror.gcr.io/library/nginx",
)
DEBIAN = ImageSource(
    base_digest="sha256:f4a83aa865a2b4a064ff142aa91c713180df9fcb86ce676b5de2981029379c37",
    base_ref="debian",
)


@pytest.fixture(autouse=True)
def need_scanners() -> None:
    if shutil.which("trivy") is None or shutil.which("grype") is None:
        pytest.skip("trivy and grype are needed")


def ids(scanner: TrivyScanner | GrypeScanner, digest: str) -> set[str]:
    return {f.advisory_id for f in scanner.scan(digest)}


def vex(tmp_path: Path, **kw: object) -> Path:
    s = VexStatement(upstream_ref="https://example.invalid/fix", patch_sha256="0" * 64, **kw)  # type: ignore[arg-type]
    return write_openvex(tmp_path / "vex.json", [s], timestamp=NOW)


ScannerFactory = Callable[[ImageSource], TrivyScanner | GrypeScanner]
SCANNERS: list[ScannerFactory] = [TrivyScanner, GrypeScanner]


@pytest.mark.parametrize("make", SCANNERS, ids=["trivy", "grype"])
def test_alpine_a_fixed_statement_clears_the_cve_and_only_that_one(
    make: ScannerFactory, tmp_path: Path
) -> None:
    plain = make(ALPINE)
    before = ids(plain, ALPINE.base_digest)
    assert "CVE-2026-111497" in before  # nginx:alpine ships brotli-libs 1.2.0-r1
    path = vex(
        tmp_path,
        advisory_id="CVE-2026-111497",
        stream="alpine",
        packages=(("brotli-libs", "1.2.0-r1"),),
    )
    after = ids(plain.with_vex(path), ALPINE.base_digest)
    assert before - after == {"CVE-2026-111497"}
    assert after - before == set()


@pytest.mark.parametrize("make", SCANNERS, ids=["trivy", "grype"])
def test_debian_a_patch_for_one_cve_does_not_clear_its_sibling_in_the_same_upload(
    make: ScannerFactory, tmp_path: Path
) -> None:
    plain = make(DEBIAN)
    before = ids(plain, DEBIAN.base_digest)
    assert {
        "CVE-2022-48303",
        "CVE-2023-39804",
    } <= before  # tar 1.34+dfsg-1.2, both fixed in +deb12u1
    path = vex(
        tmp_path,
        advisory_id="CVE-2022-48303",
        stream="debian",
        packages=(("tar", "1.34+dfsg-1.2"), ("tar-scripts", "1.34+dfsg-1.2")),
    )
    after = ids(plain.with_vex(path), DEBIAN.base_digest)
    assert before - after == {"CVE-2022-48303"}
    assert (
        "CVE-2023-39804" in after
    )  # the version bump that clears both is exactly what ADR-0010 refuses
