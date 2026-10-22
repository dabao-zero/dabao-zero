"""Builds a real patched image. Needs Docker with buildx and network access to snapshot.debian.org.

Slow (about three minutes per build), so it has its own marker and is not part of `make check` or CI:
run it with `make test-docker`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from dabao.debian import DebianAdapter, DebianBase
from dabao.models import Component, Patch, PatchSource

pytestmark = pytest.mark.docker

BASE = DebianBase(
    image="debian:bookworm-20240110-slim",
    digest="sha256:f4a83aa865a2b4a064ff142aa91c713180df9fcb86ce676b5de2981029379c37",
    snapshot="20240110T000000Z",
    source_date_epoch=1704844800,
)
COMP = Component(stream="debian", package="tar", version="1.34+dfsg-1.2")
FIX = Path(__file__).parent / "fixtures" / "tar-CVE-2022-48303.diff"
BUILDER = "dabao-itest"


@pytest.fixture(scope="module")
def builder() -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.skip("docker not installed")
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("no Docker daemon")
    made = (
        subprocess.run(
            ["docker", "buildx", "create", "--name", BUILDER, "--driver", "docker-container"],
            capture_output=True,
        ).returncode
        == 0
    )
    yield BUILDER
    if made:
        subprocess.run(["docker", "buildx", "rm", BUILDER], capture_output=True)


def patch(diff: str) -> Patch:
    return Patch(
        advisory_id="CVE-2022-48303",
        component=COMP,
        source=PatchSource.UPSTREAM_DERIVED,
        upstream_ref="https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
        diff=diff,
    )


def installed_version(oci: Path, package: str) -> str | None:
    """The package's version from the newest layer that carries dpkg's status file."""
    index = json.loads((oci / "index.json").read_text())
    manifest = json.loads((oci / "blobs/sha256" / index["manifests"][0]["digest"][7:]).read_text())
    for layer in reversed(manifest["layers"]):
        with tarfile.open(oci / "blobs/sha256" / layer["digest"][7:]) as t:
            if "var/lib/dpkg/status" not in t.getnames():
                continue
            member = t.extractfile("var/lib/dpkg/status")
            assert member is not None
            for block in member.read().decode().split("\n\n"):
                lines = dict(ln.split(": ", 1) for ln in block.splitlines() if ": " in ln)
                if lines.get("Package") == package:
                    return lines.get("Version")
    return None


def test_a_real_patched_build_is_installed_and_reproducible(builder: str, tmp_path: Path) -> None:
    diff = FIX.read_text()
    first = DebianAdapter(BASE, tmp_path / "a", builder=builder)
    second = DebianAdapter(BASE, tmp_path / "b", builder=builder)
    digest = first.build_image(COMP, patch(diff))
    assert digest.startswith("sha256:") and digest != BASE.digest
    assert installed_version(first.archives[digest], "tar") == "1.34+dfsg-1.2+dabao1"
    assert second.build_image(COMP, patch(diff)) == digest  # same inputs, same digest


def test_a_patch_that_does_not_apply_fails_the_build_and_ships_nothing(
    builder: str, tmp_path: Path
) -> None:
    from dabao.debian import DebianBuildError

    bad = "--- a/src/nope.c\n+++ b/src/nope.c\n@@ -1 +1 @@\n-x\n+y\n"
    adapter = DebianAdapter(BASE, tmp_path, builder=builder)
    with pytest.raises(DebianBuildError):
        adapter.build_image(COMP, patch(bad))
    assert adapter.archives == {}
