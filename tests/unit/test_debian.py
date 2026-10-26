from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dabao.debian import (
    DebianAdapter,
    DebianBase,
    DebianBuildError,
    changelog_entry,
    render_dockerfile,
)
from dabao.models import Component, Patch, PatchSource

BASE = DebianBase(
    image="debian:bookworm-20240110-slim",
    digest="sha256:" + "a" * 64,
    snapshot="20240110T000000Z",
    source_date_epoch=1704844800,
)
COMP = Component(stream="debian", package="tar", version="1.34+dfsg-1.2")
DIFF = "--- a/src/list.c\n+++ b/src/list.c\n@@ -1 +1 @@\n-a\n+b\n"
PATCH = Patch(
    advisory_id="CVE-2022-48303",
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref="https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
    diff=DIFF,
)
OUT_DIGEST = "sha256:" + "b" * 64


class FakeDocker:
    """Records the command; on success writes the OCI layout buildx would have written."""

    def __init__(self, rc: int = 0, err: str = "") -> None:
        self.calls: list[list[str]] = []
        self.rc, self.err = rc, err

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(args)
        if self.rc == 0:
            spec = args[args.index("--output") + 1]
            dest = Path(dict(kv.split("=", 1) for kv in spec.split(",") if "=" in kv)["dest"])
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "index.json").write_text(json.dumps({"manifests": [{"digest": OUT_DIGEST}]}))
        return subprocess.CompletedProcess(args, self.rc, b"", self.err.encode())


def adapter(tmp_path: Path, docker: FakeDocker) -> DebianAdapter:
    return DebianAdapter(BASE, tmp_path, runner=docker, builder="b1")


def test_unpatched_build_is_the_official_image_and_runs_nothing(tmp_path: Path) -> None:
    docker = FakeDocker()
    assert adapter(tmp_path, docker).build_image(COMP, None) == BASE.digest
    assert docker.calls == []


def test_patched_build_runs_buildx_once_and_returns_the_manifest_digest(tmp_path: Path) -> None:
    docker = FakeDocker()
    assert adapter(tmp_path, docker).build_image(COMP, PATCH) == OUT_DIGEST
    (cmd,) = docker.calls
    assert cmd[:3] == ["docker", "buildx", "build"]
    assert cmd[cmd.index("--builder") + 1] == "b1"
    out = cmd[cmd.index("--output") + 1]
    assert out.startswith("type=oci,") and "rewrite-timestamp=true" in out and "tar=false" in out
    assert "SOURCE_DATE_EPOCH=1704844800" in cmd and "--no-cache" in cmd


def test_build_context_holds_the_patch_and_a_pinned_dockerfile(tmp_path: Path) -> None:
    docker = FakeDocker()
    adapter(tmp_path, docker).build_image(COMP, PATCH)
    (cmd,) = docker.calls
    ctx = Path(cmd[-1])
    assert (ctx / "patch.diff").read_text() == DIFF
    df = (ctx / "Dockerfile").read_text()
    assert f"FROM {BASE.image}@{BASE.digest}" in df
    assert "snapshot.debian.org/archive/debian/20240110T000000Z/" in df
    assert "tar=1.34+dfsg-1.2" in df
    assert (ctx / "changelog.entry").read_text() == changelog_entry(COMP, PATCH, BASE)


def test_changelog_is_deterministic_and_bumps_with_a_dabao_suffix() -> None:
    entry = changelog_entry(COMP, PATCH, BASE)
    assert entry.startswith("tar (1.34+dfsg-1.2+dabao1) bookworm; urgency=medium\n")
    assert "CVE-2022-48303" in entry and PATCH.upstream_ref in entry
    assert entry.rstrip().endswith("Wed, 10 Jan 2024 00:00:00 +0000")
    assert entry == changelog_entry(COMP, PATCH, BASE)


def test_dockerfile_fails_the_build_if_the_patch_does_not_apply() -> None:
    df = render_dockerfile(COMP, BASE)
    assert "patch -p1 --no-backup-if-mismatch" in df
    assert "set -eu" in df  # a rejected hunk must stop the build, not ship an unpatched image
    assert "--log=/dev/null" in df  # dpkg's own log would make the image differ run to run


def test_the_package_is_built_as_a_normal_user_not_root() -> None:
    df = render_dockerfile(COMP, BASE)  # tar's configure refuses to run as root
    assert "useradd" in df and "runuser -u builder" in df and "chown -R builder" in df
    assert df.index("patch -p1") < df.index("chown -R builder") < df.index("runuser -u builder")


def test_logs_with_timestamps_are_removed_so_the_digest_is_stable() -> None:
    df = render_dockerfile(COMP, BASE)  # found by comparing two real builds of tar
    assert "rm -f /var/log/alternatives.log" in df
    assert df.index("dpkg --log=/dev/null -i") < df.index("rm -f /var/log/alternatives.log")


def test_same_inputs_render_the_same_dockerfile() -> None:
    assert render_dockerfile(COMP, BASE) == render_dockerfile(COMP, BASE)


def test_only_debian_and_a_matching_component_are_accepted(tmp_path: Path) -> None:
    a = adapter(tmp_path, FakeDocker())
    with pytest.raises(ValueError, match="debian"):
        a.build_image(COMP.model_copy(update={"stream": "alpine"}), PATCH)
    other = COMP.model_copy(update={"version": "9"})
    with pytest.raises(ValueError, match="does not match"):
        a.build_image(other, PATCH)


def test_a_failed_build_raises_with_the_tail_of_the_error(tmp_path: Path) -> None:
    docker = FakeDocker(rc=1, err="x" * 3000 + "patch: **** malformed")
    with pytest.raises(DebianBuildError, match="malformed"):
        adapter(tmp_path, docker).build_image(COMP, PATCH)


def test_a_manifest_digest_that_is_not_there_is_an_error(tmp_path: Path) -> None:
    class Empty(FakeDocker):
        def __call__(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
            res = super().__call__(args)
            ctx_out = Path(args[args.index("--output") + 1].split("dest=")[1].split(",")[0])
            (ctx_out / "index.json").write_text(json.dumps({"manifests": []}))
            return res

    with pytest.raises(DebianBuildError, match="digest"):
        adapter(tmp_path, Empty()).build_image(COMP, PATCH)


@pytest.mark.parametrize("bad", ["x; rm -rf /", "a b", "$(id)", "../x", "UPPER", "", "-flag"])
def test_package_names_that_could_inject_shell_are_refused(tmp_path: Path, bad: str) -> None:
    comp = COMP.model_copy(update={"package": bad})
    patch = PATCH.model_copy(update={"component": comp})
    with pytest.raises(ValueError, match="package name"):
        adapter(tmp_path, FakeDocker()).build_image(comp, patch)


@pytest.mark.parametrize("bad", ["1.0; id", "1.0 x", "$(id)", "1.0`id`", "", "1.0\n2"])
def test_versions_that_could_inject_shell_are_refused(tmp_path: Path, bad: str) -> None:
    comp = COMP.model_copy(update={"version": bad})
    patch = PATCH.model_copy(update={"component": comp})
    with pytest.raises(ValueError, match="version"):
        adapter(tmp_path, FakeDocker()).build_image(comp, patch)


def test_real_debian_versions_are_accepted(tmp_path: Path) -> None:
    for v in ["1.34+dfsg-1.2", "1:2.66-4+deb12u1", "3.0.11-1~deb12u2", "4.19.0-2+deb12u1"]:
        comp = COMP.model_copy(update={"version": v})
        patch = PATCH.model_copy(update={"component": comp})
        adapter(tmp_path, FakeDocker()).build_image(comp, patch)
