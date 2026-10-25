from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from dabao.live import (
    GrypeScanner,
    ImageSource,
    OciDiffer,
    SmokeSuiteRunner,
    TrivyScanner,
)
from dabao.models import Finding

BASE = "sha256:" + "a" * 64
AFTER = "sha256:" + "b" * 64


def done(out: str = "", rc: int = 0, err: str = "") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], rc, out.encode(), err.encode())


def source(tmp_path: Path) -> ImageSource:
    return ImageSource(base_digest=BASE, base_ref="debian:slim", archives={AFTER: tmp_path})


TRIVY_JSON = json.dumps(
    {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-48303",
                        "PkgName": "tar",
                        "FixedVersion": "1.2",
                        "Severity": "HIGH",
                    },
                    {"VulnerabilityID": "CVE-2022-48303", "PkgName": "tar-scripts"},
                    {"VulnerabilityID": "CVE-2024-12133", "PkgName": "libtasn1-6"},
                ]
            },
            {"Vulnerabilities": None},
        ]
    }
)
GRYPE_JSON = json.dumps(
    {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2022-48303",
                    "severity": "High",
                    "fix": {"state": "fixed"},
                },
                "artifact": {"name": "tar"},
            },
            {
                "vulnerability": {
                    "id": "GHSA-xxxx",
                    "severity": "Low",
                    "fix": {"state": "not-fixed"},
                },
                "artifact": {"name": "x"},
            },
        ]
    }
)


def test_trivy_scans_a_built_image_from_its_oci_layout_and_parses_findings(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return done(TRIVY_JSON)

    found = TrivyScanner(source(tmp_path), runner=run).scan(AFTER)
    assert (
        Finding(advisory_id="CVE-2022-48303", package="tar", severity="HIGH", fix_state="fixed")
        in found
    )
    unfixed = [f for f in found if f.package == "libtasn1-6"]
    assert [f.fix_state for f in unfixed] == ["unfixed"]
    assert len(found) == 3
    assert calls[0][:3] == ["trivy", "image", "--quiet"] and "--input" in calls[0]
    assert str(tmp_path) in calls[0]


def test_trivy_scans_the_base_image_by_pinned_reference() -> None:
    calls: list[list[str]] = []

    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return done(TRIVY_JSON)

    TrivyScanner(ImageSource(BASE, "debian:slim"), runner=run).scan(BASE)
    assert calls[0][-1] == f"debian:slim@{BASE}" and "--input" not in calls[0]


def test_grype_parses_matches(tmp_path: Path) -> None:
    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        assert args[0] == "grype" and args[1] == f"oci-dir:{tmp_path}"
        return done(GRYPE_JSON)

    found = GrypeScanner(source(tmp_path), runner=run).scan(AFTER)
    assert {f.advisory_id for f in found} == {"CVE-2022-48303", "GHSA-xxxx"}
    by_id = {f.advisory_id: f for f in found}
    assert (by_id["CVE-2022-48303"].fix_state, by_id["CVE-2022-48303"].severity) == (
        "fixed",
        "High",
    )
    assert by_id["GHSA-xxxx"].fix_state == "unfixed"


@pytest.mark.parametrize("cls", [TrivyScanner, GrypeScanner])
def test_a_scanner_that_fails_raises_rather_than_reporting_clean(
    cls: type[TrivyScanner | GrypeScanner], tmp_path: Path
) -> None:
    from dabao.live import ScannerError

    scanner = cls(source(tmp_path), runner=lambda a: done("", 2, "db error"))
    with pytest.raises(ScannerError, match="db error"):
        scanner.scan(AFTER)


def test_scanner_names_are_distinct(tmp_path: Path) -> None:
    src = source(tmp_path)
    assert {TrivyScanner(src).name, GrypeScanner(src).name} == {"trivy", "grype"}


# --- OciDiffer -------------------------------------------------------------------------------


def layer(files: dict[str, bytes], whiteouts: tuple[str, ...] = ()) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        for w in whiteouts:
            t.addfile(tarfile.TarInfo(w))
    return buf.getvalue()


def write_oci(root: Path, layers: list[bytes]) -> str:
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    import hashlib

    descs = []
    for data in layers:
        h = hashlib.sha256(data).hexdigest()
        (blobs / h).write_bytes(data)
        descs.append({"digest": f"sha256:{h}"})
    manifest = json.dumps({"layers": descs}).encode()
    mh = hashlib.sha256(manifest).hexdigest()
    (blobs / mh).write_bytes(manifest)
    (root / "index.json").write_text(json.dumps({"manifests": [{"digest": f"sha256:{mh}"}]}))
    return f"sha256:{mh}"


STATUS = (
    b"Package: tar\nStatus: install ok installed\nVersion: 1.34+dfsg-1.2+dabao1\n\n"
    b"Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2\n"
)


def rebuilt_layout(tmp_path: Path, extra: dict[str, bytes] | None = None) -> str:
    return write_oci(
        tmp_path,
        [
            layer({"bin/sh": b"base"}),  # the base image's layer
            layer({"tmp/dabao-debs/tar.deb": b"x"}),  # the staging COPY
            layer(
                {
                    "usr/bin/tar": b"new",
                    "usr/share/doc/tar/copyright": b"c",
                    "var/lib/dpkg/status": STATUS,
                    # Debian lists /bin/tar; on a merged-usr image it lands at usr/bin/tar
                    "var/lib/dpkg/info/tar.list": b"/.\n/bin/tar\n/usr/share/doc/tar/copyright\n",
                    **(extra or {}),
                },
                ("tmp/.wh.dabao-debs",),
            ),
        ],
    )


def test_differ_reports_nothing_when_every_change_belongs_to_a_rebuilt_package(
    tmp_path: Path,
) -> None:
    digest = rebuilt_layout(tmp_path)
    src = ImageSource(BASE, "debian:slim", {digest: tmp_path})
    assert OciDiffer(src, base_layers=1).changed_files(BASE, digest) == []


def test_differ_reports_a_change_nothing_rebuilt_can_explain(tmp_path: Path) -> None:
    digest = rebuilt_layout(tmp_path, {"usr/bin/evil": b"!", "etc/passwd": b"root::0:0"})
    src = ImageSource(BASE, "debian:slim", {digest: tmp_path})
    assert OciDiffer(src, base_layers=1).changed_files(BASE, digest) == [
        "etc/passwd",
        "usr/bin/evil",
    ]


def test_differ_returns_none_when_it_cannot_read_the_image(tmp_path: Path) -> None:
    src = ImageSource(BASE, "debian:slim", {})
    assert OciDiffer(src).changed_files(BASE, AFTER) is None


# --- SmokeSuiteRunner ------------------------------------------------------------------------


def test_smoke_suite_runs_each_command_inside_the_built_image(tmp_path: Path) -> None:
    ran: list[tuple[list[str], str]] = []

    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        ctx = Path(args[-1])
        ran.append((args, (ctx / "Dockerfile").read_text()))
        return done("", 0)

    runner = SmokeSuiteRunner(source(tmp_path), ["tar --version", "true"], runner=run, builder="b1")
    result = runner.run(AFTER)
    assert result is not None and result.passed
    assert len(ran) == 2
    args, dockerfile = ran[0]
    assert args[:3] == ["docker", "buildx", "build"] and args[args.index("--builder") + 1] == "b1"
    assert f"patched=oci-layout://{tmp_path}@{AFTER}" in args
    assert dockerfile == "FROM patched\nRUN tar --version\n"


def test_smoke_suite_fails_and_names_the_failing_command(tmp_path: Path) -> None:
    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        if "RUN false" in (Path(args[-1]) / "Dockerfile").read_text():
            return done("", 1, 'process "/bin/sh -c false" did not complete successfully')
        return done()

    result = SmokeSuiteRunner(source(tmp_path), ["true", "false"], runner=run).run(AFTER)
    assert result is not None and not result.passed and "false" in result.details


def test_smoke_suite_returns_none_when_the_image_cannot_be_reached(tmp_path: Path) -> None:
    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return done("", 1, "failed to read oci-layout: no such directory")

    assert SmokeSuiteRunner(source(tmp_path), ["true"], runner=run).run(AFTER) is None


def test_smoke_suite_cannot_test_the_base_image_it_has_no_layout_for() -> None:
    assert SmokeSuiteRunner(ImageSource(BASE, "debian:slim"), ["true"]).run(BASE) is None


def test_a_scanner_given_a_vex_passes_it_on_and_the_original_is_unchanged(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        seen.append(args)
        return done(TRIVY_JSON if args[0] == "trivy" else GRYPE_JSON)

    vex = tmp_path / "v.json"
    for plain in (
        TrivyScanner(source(tmp_path), runner=run),
        GrypeScanner(source(tmp_path), runner=run),
    ):
        with_vex = plain.with_vex(vex)
        plain.scan(AFTER)
        with_vex.scan(AFTER)
        assert "--vex" not in seen[-2]
        assert seen[-1][seen[-1].index("--vex") + 1] == str(vex)
        assert with_vex.name == plain.name


# --- OciDiffer on an Alpine image ------------------------------------------------------------

APK_BASE = (
    b"C:Q1aaa=\nP:busybox\nV:1.37.0-r31\nF:bin\nR:busybox\n\n"
    b"C:Q1bbb=\nP:brotli-libs\nV:1.2.0-r1\nF:usr/lib\nR:libbrotlicommon.so.1.2.0\n\n"
)
APK_AFTER = (
    b"C:Q1aaa=\nP:busybox\nV:1.37.0-r31\nF:bin\nR:busybox\n\n"
    b"C:Q1ccc=\nP:brotli-libs\nV:1.2.0-r2\nF:usr/lib\nR:libbrotlicommon.so.1.2.0\n\n"
)


def apk_layout(tmp_path: Path, extra: dict[str, bytes] | None = None) -> str:
    return write_oci(
        tmp_path,
        [
            layer({"lib/apk/db/installed": APK_BASE, "bin/busybox": b"b"}),  # the base
            layer({"tmp/dabao-apk/brotli-libs-1.2.0-r2.apk": b"x"}),  # the staging COPY
            layer(
                {
                    "usr/lib/libbrotlicommon.so.1.2.0": b"new",
                    "lib/apk/db/installed": APK_AFTER,
                    "etc/apk/world": b"brotli-libs\n",
                    "var/log/apk.log": b"log",
                    **(extra or {}),
                },
                ("tmp/.wh.dabao-apk",),
            ),
        ],
    )


def test_apk_differ_reports_nothing_when_every_change_belongs_to_a_rebuilt_package(
    tmp_path: Path,
) -> None:
    digest = apk_layout(tmp_path)
    differ = OciDiffer(ImageSource(BASE, "nginx", {digest: tmp_path}), added_layers=2)
    assert differ.changed_files(BASE, digest) == []


def test_apk_differ_reports_a_change_no_rebuilt_package_explains(tmp_path: Path) -> None:
    digest = apk_layout(tmp_path, {"usr/bin/evil": b"!", "etc/passwd": b"root::0:0"})
    differ = OciDiffer(ImageSource(BASE, "nginx", {digest: tmp_path}), added_layers=2)
    assert differ.changed_files(BASE, digest) == ["etc/passwd", "usr/bin/evil"]


def test_a_package_that_did_not_change_version_explains_nothing(tmp_path: Path) -> None:
    digest = apk_layout(tmp_path, {"bin/busybox": b"tampered"})  # busybox kept its version
    differ = OciDiffer(ImageSource(BASE, "nginx", {digest: tmp_path}), added_layers=2)
    assert differ.changed_files(BASE, digest) == ["bin/busybox"]


def test_rebuilt_packages_are_the_ones_whose_version_changed_in_an_apk_image(
    tmp_path: Path,
) -> None:
    digest = apk_layout(tmp_path)
    differ = OciDiffer(ImageSource(BASE, "nginx", {digest: tmp_path}), added_layers=2)
    assert differ.rebuilt_packages(digest) == [("brotli-libs", "1.2.0-r2")]


def test_rebuilt_packages_are_the_marked_ones_in_a_debian_image(tmp_path: Path) -> None:
    digest = rebuilt_layout(tmp_path)
    differ = OciDiffer(ImageSource(BASE, "debian:slim", {digest: tmp_path}), base_layers=1)
    assert differ.rebuilt_packages(digest) == [("tar", "1.34+dfsg-1.2+dabao1")]


def test_rebuilt_packages_is_none_when_the_image_cannot_be_read(tmp_path: Path) -> None:
    assert OciDiffer(ImageSource(BASE, "x", {})).rebuilt_packages(AFTER) is None


def test_added_layers_says_how_many_layers_the_build_put_on_top(tmp_path: Path) -> None:
    digest = apk_layout(tmp_path, {"usr/bin/evil": b"!"})  # three layers: one base, two added
    src = ImageSource(BASE, "nginx", {digest: tmp_path})
    # counting only the last layer as the build's still sees the change that is in it
    assert OciDiffer(src, added_layers=1).changed_files(BASE, digest) == ["usr/bin/evil"]
