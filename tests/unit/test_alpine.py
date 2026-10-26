from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from dabao.alpine import (
    AlpineAdapter,
    AlpineBase,
    AlpineBuildError,
    rebuilt_version,
    render_dockerfile,
)
from dabao.models import Component, Patch, PatchSource

BASE = AlpineBase(
    image="nginx:alpine",
    digest="sha256:" + "a" * 64,
    builder_image="alpine:3.24",
    builder_digest="sha256:" + "c" * 64,
    release="3.24",
    source_date_epoch=1792800000,
)
COMP = Component(stream="alpine", package="brotli", version="1.2.0-r1")
DIFF = "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n"
PATCH = Patch(
    advisory_id="CVE-2026-111497",
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref="https://github.com/google/brotli/commit/abc123",
    diff=DIFF,
)
OUT_DIGEST = "sha256:" + "b" * 64


class FakeDocker:
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


def adapter(tmp_path: Path, docker: FakeDocker) -> AlpineAdapter:
    return AlpineAdapter(BASE, tmp_path, runner=docker, builder="b1")


def test_the_unpatched_build_is_the_official_image_and_runs_nothing(tmp_path: Path) -> None:
    docker = FakeDocker()
    assert adapter(tmp_path, docker).build_image(COMP, None) == BASE.digest
    assert docker.calls == []


def test_a_patched_build_runs_buildx_once_and_returns_the_manifest_digest(tmp_path: Path) -> None:
    docker = FakeDocker()
    a = adapter(tmp_path, docker)
    assert a.build_image(COMP, PATCH) == OUT_DIGEST
    (cmd,) = docker.calls
    assert cmd[:3] == ["docker", "buildx", "build"] and cmd[cmd.index("--builder") + 1] == "b1"
    out = cmd[cmd.index("--output") + 1]
    assert out.startswith("type=oci,") and "rewrite-timestamp=true" in out and "tar=false" in out
    assert "SOURCE_DATE_EPOCH=1792800000" in cmd and "--no-cache" in cmd
    assert OUT_DIGEST in a.archives


def test_the_rebuilt_version_is_the_next_revision() -> None:
    assert rebuilt_version("1.2.0-r1") == "1.2.0-r2"
    assert rebuilt_version("3.0.11-r9") == "3.0.11-r10"
    with pytest.raises(ValueError, match="revision"):
        rebuilt_version("1.2.0")


def test_the_context_holds_the_patch_and_a_pinned_dockerfile(tmp_path: Path) -> None:
    docker = FakeDocker()
    adapter(tmp_path, docker).build_image(COMP, PATCH)
    ctx = Path(docker.calls[0][-1])
    assert (ctx / "patch.diff").read_text() == DIFF
    df = (ctx / "Dockerfile").read_text()
    assert f"FROM {BASE.builder_image}@{BASE.builder_digest} AS build" in df
    assert f"FROM {BASE.image}@{BASE.digest}" in df
    assert "--branch 3.24-stable" in df and "gitlab.alpinelinux.org/alpine/aports.git" in df


def test_the_recipe_commit_is_found_by_version_and_the_build_fails_if_there_is_none() -> None:
    df = render_dockerfile(COMP, BASE)
    assert 'WANT="1.2.0-r1"' in df and "git log" in df
    assert "no aports commit has" in df and "exit 1" in df


def test_the_patch_is_added_as_a_source_with_a_new_checksum_and_revision() -> None:
    df = render_dockerfile(COMP, BASE)
    assert 'source="$source dabao-fix.patch"' in df and "pkgrel=2" in df
    assert "abuild checksum" in df


def test_a_patch_the_recipe_never_applies_fails_the_build() -> None:
    df = render_dockerfile(COMP, BASE)  # a recipe whose prepare() skips default_prepare ignores it
    assert "abuild unpack prepare" in df and "patch -R -p1 --dry-run" in df
    assert "set -eu" in df


def test_packages_are_built_as_a_normal_user_with_a_throwaway_key() -> None:
    df = render_dockerfile(COMP, BASE)
    assert "adduser -D builder" in df and "USER builder" in df and "abuild-keygen" in df


def _final_stage(df: str) -> str:
    return df.split(f"FROM {BASE.image}@{BASE.digest}")[1]


def test_the_image_gets_only_packages_it_already_had_and_keeps_its_world() -> None:
    final = _final_stage(render_dockerfile(COMP, BASE))
    assert "apk info -e" in final and "cp /etc/apk/world" in final


def test_the_final_image_never_trusts_or_keeps_a_signing_key() -> None:
    # Found by building twice: the per-build key made every build differ, and a cleanup that
    # guessed the key's name left it in the image. Packages now lose their signature before the
    # install and are installed untrusted, so no key ever reaches the final stage.
    df = render_dockerfile(COMP, BASE)
    final = _final_stage(df)
    assert "/etc/apk/keys" not in final and ".rsa.pub" not in final
    assert "--allow-untrusted" in final
    assert "unused_data" in df  # the signature is the first gzip member of an apk; it is dropped


def test_built_packages_are_mounted_not_copied_so_no_layer_holds_them() -> None:
    # Found by building twice: every package of the recipe was copied into a layer, and one of them
    # (the static libraries, built with LTO) differs from build to build although the one that is
    # installed does not. Mounting the build stage keeps the packages out of the image entirely.
    final = _final_stage(render_dockerfile(COMP, BASE))
    assert "--mount=type=bind,from=build,source=/out,target=/tmp/dabao-apk" in final
    assert "COPY --from=build" not in final


def test_apk_logs_with_timestamps_are_put_back_so_the_digest_is_stable() -> None:
    final = _final_stage(render_dockerfile(COMP, BASE))  # `apk add` logs the time of the install
    assert "/var/log/apk.log" in final and "apk.log.keep" in final
    assert final.index("apk add") < final.rindex("apk.log.keep")


def test_same_inputs_render_the_same_dockerfile() -> None:
    assert render_dockerfile(COMP, BASE) == render_dockerfile(COMP, BASE)


@pytest.mark.parametrize(
    "bad",
    ["x; rm -rf /", "a b", "$(id)", "../x", "UPPER", "", "-flag"],
)
def test_package_names_that_could_inject_shell_are_refused(tmp_path: Path, bad: str) -> None:
    comp = COMP.model_copy(update={"package": bad})
    with pytest.raises(ValueError, match="package name"):
        adapter(tmp_path, FakeDocker()).build_image(
            comp, PATCH.model_copy(update={"component": comp})
        )


@pytest.mark.parametrize("bad", ["1.2.0-r1; id", "1.2.0-r1 x", "1.2.0", "$(id)-r1", "-r1"])
def test_versions_that_could_inject_shell_are_refused(tmp_path: Path, bad: str) -> None:
    comp = COMP.model_copy(update={"version": bad})
    with pytest.raises(ValueError, match="version"):
        adapter(tmp_path, FakeDocker()).build_image(
            comp, PATCH.model_copy(update={"component": comp})
        )


def test_only_alpine_and_a_matching_component_are_accepted(tmp_path: Path) -> None:
    a = adapter(tmp_path, FakeDocker())
    with pytest.raises(ValueError, match="alpine"):
        a.build_image(COMP.model_copy(update={"stream": "debian"}), PATCH)
    with pytest.raises(ValueError, match="does not match"):
        a.build_image(COMP.model_copy(update={"version": "9.9-r0"}), PATCH)


def test_a_failed_build_raises_with_the_tail_of_the_error(tmp_path: Path) -> None:
    docker = FakeDocker(rc=1, err="x" * 3000 + "patch: **** malformed")
    with pytest.raises(AlpineBuildError, match="malformed"):
        adapter(tmp_path, docker).build_image(COMP, PATCH)


def test_a_manifest_digest_that_is_not_there_is_an_error(tmp_path: Path) -> None:
    class Empty(FakeDocker):
        def __call__(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
            res = super().__call__(args)
            dest = Path(args[args.index("--output") + 1].split("dest=")[1].split(",")[0])
            (dest / "index.json").write_text(json.dumps({"manifests": []}))
            return res

    with pytest.raises(AlpineBuildError, match="digest"):
        adapter(tmp_path, Empty()).build_image(COMP, PATCH)
