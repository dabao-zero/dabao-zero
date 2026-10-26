"""Builds a real patched Alpine image. Needs Docker with buildx and network access to gitlab.alpinelinux.org.

Slow (a couple of minutes per build), so it has its own marker and is not part of `make check` or CI:
run it with `make test-docker`. The patch is a one-line README note (no behaviour change): the point is
that the recipe applies it, the package is rebuilt as the next revision and installed, and the same
inputs give the same digest.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from dabao.alpine import AlpineAdapter, AlpineBase, AlpineBuildError
from dabao.models import Component, Patch, PatchSource

pytestmark = pytest.mark.docker

BASE = AlpineBase(
    image="mirror.gcr.io/library/nginx:alpine",
    digest="sha256:a3554c0d0b48177b1413c26e01f695334428020d9df01243fbae3e11cfd17417",
    builder_image="mirror.gcr.io/library/alpine:3.24",
    builder_digest="sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
    release="3.24",
    source_date_epoch=1792800000,
)
COMP = Component(stream="alpine", package="brotli", version="1.2.0-r1")
FIX = Path(__file__).parent / "fixtures" / "brotli-readme-note.diff"
BUILDER = "dabao-itest-alpine"


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
        advisory_id="CVE-2026-111497",
        component=COMP,
        source=PatchSource.UPSTREAM_DERIVED,
        upstream_ref="https://github.com/google/brotli/commit/abc123",
        diff=diff,
    )


def installed_version(oci: Path, package: str) -> str | None:
    """The package's version from the newest layer that carries apk's installed database."""
    index = json.loads((oci / "index.json").read_text())
    manifest = json.loads((oci / "blobs/sha256" / index["manifests"][0]["digest"][7:]).read_text())
    for layer in reversed(manifest["layers"]):
        with tarfile.open(oci / "blobs/sha256" / layer["digest"][7:]) as t:
            if "lib/apk/db/installed" not in t.getnames():
                continue
            member = t.extractfile("lib/apk/db/installed")
            assert member is not None
            for block in member.read().decode().split("\n\n"):
                fields = {ln[0]: ln[2:] for ln in block.splitlines() if len(ln) > 2}
                if fields.get("P") == package:
                    return fields.get("V")
    return None


def added_keys(oci: Path) -> list[str]:
    """Signing keys present in the layer our build added (the last one); there must be none."""
    index = json.loads((oci / "index.json").read_text())
    manifest = json.loads((oci / "blobs/sha256" / index["manifests"][0]["digest"][7:]).read_text())
    found: list[str] = []
    for layer in manifest["layers"][-1:]:
        with tarfile.open(oci / "blobs/sha256" / layer["digest"][7:]) as t:
            found += [n for n in t.getnames() if n.endswith(".rsa.pub") and "apk/keys" in n]
    return found


def test_a_real_patched_build_is_installed_as_the_next_revision_and_reproducible(
    builder: str, tmp_path: Path
) -> None:
    diff = FIX.read_text()
    first = AlpineAdapter(BASE, tmp_path / "a", builder=builder)
    second = AlpineAdapter(BASE, tmp_path / "b", builder=builder)
    digest = first.build_image(COMP, patch(diff))
    assert digest.startswith("sha256:") and digest != BASE.digest
    assert installed_version(first.archives[digest], "brotli-libs") == "1.2.0-r2"
    assert added_keys(first.archives[digest]) == []  # the throwaway key must not stay in the image
    assert second.build_image(COMP, patch(diff)) == digest  # same inputs, same digest


def test_a_patch_that_does_not_apply_fails_the_build_and_ships_nothing(
    builder: str, tmp_path: Path
) -> None:
    bad = "--- a/nope.c\n+++ b/nope.c\n@@ -1 +1 @@\n-x\n+y\n"
    adapter = AlpineAdapter(BASE, tmp_path, builder=builder)
    with pytest.raises(AlpineBuildError):
        adapter.build_image(COMP, patch(bad))
    assert adapter.archives == {}


def test_a_version_no_recipe_ever_had_fails_with_a_clear_message(
    builder: str, tmp_path: Path
) -> None:
    comp = COMP.model_copy(update={"version": "9.9.9-r0"})
    adapter = AlpineAdapter(BASE, tmp_path, builder=builder)
    with pytest.raises(AlpineBuildError, match="no aports commit has brotli 9.9.9-r0"):
        adapter.build_image(comp, patch(FIX.read_text()).model_copy(update={"component": comp}))
