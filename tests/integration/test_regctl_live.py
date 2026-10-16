"""Live registry smoke test. Needs `regctl` on PATH and network access to mirror.gcr.io."""

from __future__ import annotations

import shutil

import pytest

from dabao.inventory import Regctl, inventory

pytestmark = pytest.mark.integration


@pytest.mark.skipif(shutil.which("regctl") is None, reason="regctl not installed")
def test_reads_debian_package_database_from_a_real_image() -> None:
    stream, pkgs = inventory(Regctl(), "mirror.gcr.io/library/nginx:1.27")
    assert stream == "debian"
    assert "libc6" in pkgs and len(pkgs) > 50
