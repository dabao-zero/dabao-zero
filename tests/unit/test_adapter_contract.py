"""One contract every DistroAdapter must satisfy (DAB-31, ADR-0004).

ADR-0004 freezes the adapter interface only after two real distros pass the same suite. Each case
below runs once per adapter; a third distro (Wolfi) is added by writing one more `Case`.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from dabao import alpine, debian
from dabao.buildx import BuildError
from dabao.models import Component, Patch, PatchSource
from dabao.seams import DistroAdapter

OUT_DIGEST = "sha256:" + "b" * 64


class FakeDocker:
    """Records every command; on success writes the OCI layout buildx would have written."""

    def __init__(self, rc: int = 0, err: str = "", digests: bool = True) -> None:
        self.calls: list[list[str]] = []
        self.rc, self.err, self.digests = rc, err, digests

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(args)
        if self.rc == 0:
            spec = args[args.index("--output") + 1]
            dest = Path(dict(kv.split("=", 1) for kv in spec.split(",") if "=" in kv)["dest"])
            dest.mkdir(parents=True, exist_ok=True)
            manifests = [{"digest": OUT_DIGEST}] if self.digests else []
            (dest / "index.json").write_text(json.dumps({"manifests": manifests}))
        return subprocess.CompletedProcess(args, self.rc, b"", self.err.encode())


@dataclass(frozen=True)
class Case:
    name: str
    stream: str
    other_stream: str
    base_digest: str
    component: Component
    make: Callable[[Path, FakeDocker], DistroAdapter]
    dockerfile: Callable[[Component], str]
    errors: type[BuildError]


def _patch(component: Component) -> Patch:
    return Patch(
        advisory_id="CVE-2099-0001",
        component=component,
        source=PatchSource.UPSTREAM_DERIVED,
        upstream_ref="https://example.org/fix",
        diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
    )


DEBIAN_BASE = debian.DebianBase(
    image="debian:bookworm-slim",
    digest="sha256:" + "a" * 64,
    snapshot="20240110T000000Z",
    source_date_epoch=1704844800,
)
ALPINE_BASE = alpine.AlpineBase(
    image="nginx:alpine",
    digest="sha256:" + "d" * 64,
    builder_image="alpine:3.24",
    builder_digest="sha256:" + "c" * 64,
    release="3.24",
    source_date_epoch=1792800000,
)
CASES = [
    Case(
        "debian",
        "debian",
        "alpine",
        DEBIAN_BASE.digest,
        Component(stream="debian", package="tar", version="1.34+dfsg-1.2"),
        lambda d, r: debian.DebianAdapter(DEBIAN_BASE, d, runner=r, builder="b"),
        lambda c: debian.render_dockerfile(c, DEBIAN_BASE),
        debian.DebianBuildError,
    ),
    Case(
        "alpine",
        "alpine",
        "debian",
        ALPINE_BASE.digest,
        Component(stream="alpine", package="brotli", version="1.2.0-r1"),
        lambda d, r: alpine.AlpineAdapter(ALPINE_BASE, d, runner=r, builder="b"),
        lambda c: alpine.render_dockerfile(c, ALPINE_BASE),
        alpine.AlpineBuildError,
    ),
]
ids = [c.name for c in CASES]


@pytest.fixture(params=CASES, ids=ids)
def case(request: pytest.FixtureRequest) -> Case:
    return request.param  # type: ignore[no-any-return]


def test_the_unpatched_build_is_the_official_image_and_runs_nothing(
    case: Case, tmp_path: Path
) -> None:
    docker = FakeDocker()
    assert case.make(tmp_path, docker).build_image(case.component, None) == case.base_digest
    assert docker.calls == []


def test_a_patched_build_runs_one_build_and_returns_its_manifest_digest(
    case: Case, tmp_path: Path
) -> None:
    docker = FakeDocker()
    a = case.make(tmp_path, docker)
    assert a.build_image(case.component, _patch(case.component)) == OUT_DIGEST
    assert len(docker.calls) == 1 and docker.calls[0][:3] == ["docker", "buildx", "build"]
    assert OUT_DIGEST in a.archives  # type: ignore[attr-defined]


def test_the_build_is_reproducible_by_construction(case: Case, tmp_path: Path) -> None:
    docker = FakeDocker()
    case.make(tmp_path, docker).build_image(case.component, _patch(case.component))
    (cmd,) = docker.calls
    assert any(a.startswith("SOURCE_DATE_EPOCH=") for a in cmd)
    assert "--no-cache" in cmd and "rewrite-timestamp=true" in cmd[cmd.index("--output") + 1]


def test_every_base_is_pinned_by_digest_and_a_rejected_patch_stops_the_build(case: Case) -> None:
    df = case.dockerfile(case.component)
    froms = [ln for ln in df.splitlines() if ln.startswith("FROM ")]
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}", ln) for ln in froms)
    assert "set -eu" in df  # a hunk that does not apply must fail the build, not ship unpatched


def test_the_dockerfile_asks_for_no_privilege_and_carries_no_credential(case: Case) -> None:
    df = case.dockerfile(case.component).lower()
    assert "privileged" not in df and "--network=host" not in df
    assert not re.search(r"(token|secret|password|api_key)", df)


def test_the_same_inputs_render_the_same_dockerfile(case: Case) -> None:
    assert case.dockerfile(case.component) == case.dockerfile(case.component)


def test_a_component_of_another_stream_is_refused(case: Case, tmp_path: Path) -> None:
    foreign = case.component.model_copy(update={"stream": case.other_stream})
    with pytest.raises(ValueError, match=case.stream):
        case.make(tmp_path, FakeDocker()).build_image(foreign, _patch(foreign))


def test_a_patch_for_another_component_is_refused(case: Case, tmp_path: Path) -> None:
    other = case.component.model_copy(update={"package": "someother"})
    with pytest.raises(ValueError, match="does not match"):
        case.make(tmp_path, FakeDocker()).build_image(case.component, _patch(other))


@pytest.mark.parametrize("bad", ["x; rm -rf /", "$(id)", "a b", "../x", "UPPER"])
def test_a_package_name_that_could_inject_shell_is_refused(
    case: Case, tmp_path: Path, bad: str
) -> None:
    c = case.component.model_copy(update={"package": bad})
    with pytest.raises(ValueError, match="package name"):
        case.make(tmp_path, FakeDocker()).build_image(c, _patch(c))


@pytest.mark.parametrize("bad", ["1.0; id", "$(id)", "1 2", "`id`"])
def test_a_version_that_could_inject_shell_is_refused(case: Case, tmp_path: Path, bad: str) -> None:
    c = case.component.model_copy(update={"version": bad})
    with pytest.raises(ValueError, match="version"):
        case.make(tmp_path, FakeDocker()).build_image(c, _patch(c))


def test_a_failed_build_raises_the_adapters_error_with_the_message(
    case: Case, tmp_path: Path
) -> None:
    docker = FakeDocker(rc=1, err="#7 0.1 hunk 2 FAILED\n")
    with pytest.raises(case.errors, match="hunk 2 FAILED") as exc:
        case.make(tmp_path, docker).build_image(case.component, _patch(case.component))
    assert isinstance(exc.value, BuildError)


def test_a_failed_build_leaves_no_archive_behind(case: Case, tmp_path: Path) -> None:
    a = case.make(tmp_path, FakeDocker(rc=1, err="boom"))
    with pytest.raises(BuildError):
        a.build_image(case.component, _patch(case.component))
    assert a.archives == {}  # type: ignore[attr-defined]


def test_a_build_that_wrote_no_digest_is_an_error(case: Case, tmp_path: Path) -> None:
    a = case.make(tmp_path, FakeDocker(digests=False))
    with pytest.raises(case.errors, match="digest"):
        a.build_image(case.component, _patch(case.component))
