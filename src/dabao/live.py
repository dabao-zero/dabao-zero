"""Live gate components for the Debian stream: scanners, a build differ and a smoke-test runner.

Each shells out through an injectable runner, so unit tests need no binaries, no Docker and no
network. A tool that fails raises or returns None; none of them ever reports "clean" on failure.
"""

from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from dabao.models import Finding
from dabao.seams import SuiteResult

Runner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


class ScannerError(Exception):
    pass


def _run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=1800, check=False)


@dataclass(frozen=True)
class ImageSource:
    """Where each image digest can be found: built ones as OCI layouts, the base by reference."""

    base_digest: str
    base_ref: str  # e.g. debian:bookworm-20240110-slim; used as `<ref>@<digest>`
    archives: Mapping[str, Path] = field(default_factory=dict)

    def layout(self, digest: str) -> Path | None:
        return self.archives.get(digest)

    def reference(self, digest: str) -> str:
        return f"{self.base_ref}@{digest}"


def _fail(tool: str, res: subprocess.CompletedProcess[bytes]) -> ScannerError:
    return ScannerError(
        f"{tool} failed ({res.returncode}): {res.stderr.decode(errors='replace')[-500:]}"
    )


@dataclass
class TrivyScanner:
    source: ImageSource
    runner: Runner = _run
    name: str = "trivy"
    vex_path: Path | None = None

    def with_vex(self, path: Path) -> TrivyScanner:
        """The same scanner, told to apply an OpenVEX document (ADR-0010). This one is unchanged."""
        return replace(self, vex_path=path)

    def scan(self, image_digest: str) -> list[Finding]:
        layout = self.source.layout(image_digest)
        target = ["--input", str(layout)] if layout else [self.source.reference(image_digest)]
        cmd = ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln"]
        if self.vex_path is not None:
            cmd += ["--vex", str(self.vex_path)]
        res = self.runner([*cmd, "--pkg-types", "os", *target])
        if res.returncode != 0:
            raise _fail("trivy", res)
        data = json.loads(res.stdout or b"{}")
        return [
            Finding(
                advisory_id=v["VulnerabilityID"],
                package=v.get("PkgName", ""),
                severity=v.get("Severity", ""),
                fix_state="fixed" if v.get("FixedVersion") else "unfixed",
            )
            for r in data.get("Results", [])
            for v in r.get("Vulnerabilities") or []
        ]


def _grype_fix_state(vulnerability: dict[str, Any]) -> str:
    state = (vulnerability.get("fix") or {}).get("state", "unknown")
    return "fixed" if state == "fixed" else "unknown" if state == "unknown" else "unfixed"


@dataclass
class GrypeScanner:
    source: ImageSource
    runner: Runner = _run
    name: str = "grype"
    vex_path: Path | None = None

    def with_vex(self, path: Path) -> GrypeScanner:
        """The same scanner, told to apply an OpenVEX document (ADR-0010). This one is unchanged."""
        return replace(self, vex_path=path)

    def scan(self, image_digest: str) -> list[Finding]:
        layout = self.source.layout(image_digest)
        target = f"oci-dir:{layout}" if layout else self.source.reference(image_digest)
        cmd = ["grype", target, "-o", "json", "-q"]
        if self.vex_path is not None:
            cmd += ["--vex", str(self.vex_path)]
        res = self.runner(cmd)
        if res.returncode != 0:
            raise _fail("grype", res)
        data = json.loads(res.stdout or b"{}")
        return [
            Finding(
                advisory_id=m["vulnerability"]["id"],
                package=m["artifact"]["name"],
                severity=m["vulnerability"].get("severity", ""),
                fix_state=_grype_fix_state(m["vulnerability"]),
            )
            for m in data.get("matches", [])
        ]


def _blob(layout: Path, digest: str) -> Path:
    return layout / "blobs" / "sha256" / digest.removeprefix("sha256:")


DPKG_BOOKKEEPING = (
    "var/lib/dpkg/",
    "etc/alternatives/",
    "etc/rmt",
    "var/cache/ldconfig/",
    "etc/ld.so.cache",
)


def _merged_usr(path: str) -> str:
    """Debian lists /bin/tar; on a merged-usr image the file lands at usr/bin/tar."""
    path = path.lstrip("/")
    return f"usr/{path}" if path.split("/", 1)[0] in ("bin", "sbin", "lib", "lib64") else path


def _installed_versions(status: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for block in status.split("\n\n"):
        fields = dict(ln.split(": ", 1) for ln in block.splitlines() if ": " in ln)
        if "Package" in fields and "Version" in fields:
            out[fields["Package"]] = fields["Version"]
    return out


@dataclass
class OciDiffer:
    """Files the build changed that no rebuilt package or dpkg bookkeeping explains.

    A rebuilt package legitimately changes its own binaries, so "changed" is judged against the file
    lists of the packages the build re-versioned (suffix `+dabao1`), plus dpkg's own state. Anything
    else the build touched, say /etc/passwd or a binary of another package, is returned and the
    build_diff gate fails on it.
    """

    source: ImageSource
    base_layers: int = 1  # layers the base image already has (debian slim has one)
    ignore_prefixes: tuple[str, ...] = ("tmp/dabao-debs",)  # build staging, removed again
    rebuilt_marker: str = "+dabao1"
    bookkeeping: tuple[str, ...] = DPKG_BOOKKEEPING

    def changed_files(self, before_digest: str, after_digest: str) -> list[str] | None:
        layout = self.source.layout(after_digest)
        if layout is None:
            return None
        try:
            index = json.loads((layout / "index.json").read_text())
            manifest = json.loads(_blob(layout, index["manifests"][0]["digest"]).read_text())
            changed: set[str] = set()
            texts: dict[str, str] = {}
            for layer in manifest["layers"][self.base_layers :]:
                with tarfile.open(_blob(layout, layer["digest"])) as t:
                    for member in t:
                        name = member.name.removeprefix("./")
                        if member.isdir() or "/.wh." in f"/{name}" or name.startswith(".wh."):
                            continue
                        if name.startswith(self.ignore_prefixes):
                            continue
                        changed.add(name)
                        is_meta = name == "var/lib/dpkg/status" or name.endswith(".list")
                        if is_meta and name.startswith("var/lib/dpkg/"):
                            fh = t.extractfile(member)
                            texts[name] = fh.read().decode(errors="replace") if fh else ""
            versions = _installed_versions(texts.get("var/lib/dpkg/status", ""))
            explained: set[str] = set()
            for pkg, version in versions.items():
                if version.endswith(self.rebuilt_marker):
                    listing = texts.get(f"var/lib/dpkg/info/{pkg}.list", "")
                    explained |= {_merged_usr(ln) for ln in listing.splitlines()}
            return sorted(
                f for f in changed if f not in explained and not f.startswith(self.bookkeeping)
            )
        except (OSError, KeyError, IndexError, tarfile.TarError, ValueError):
            return None


@dataclass
class SmokeSuiteRunner:
    """Runs shell commands inside the built image, as RUN steps of a throwaway build.

    This is a smoke test, not the official image's own suite (which the Debian image does not ship
    in a runnable form). Commands run in the image through an `oci-layout` build context, so the
    image never has to be loaded into the Docker daemon.
    """

    source: ImageSource
    commands: list[str]
    runner: Runner = _run
    builder: str = "dabao-builder"

    def run(self, image_digest: str) -> SuiteResult | None:
        layout = self.source.layout(image_digest)
        if layout is None:
            return None
        for command in self.commands:
            with tempfile.TemporaryDirectory(prefix="dabao-smoke-") as ctx:
                (Path(ctx) / "Dockerfile").write_text(f"FROM patched\nRUN {command}\n")
                res = self.runner(
                    [
                        "docker",
                        "buildx",
                        "build",
                        "--builder",
                        self.builder,
                        "--no-cache",
                        "--build-context",
                        f"patched=oci-layout://{layout}@{image_digest}",
                        "--output",
                        "type=cacheonly",
                        ctx,
                    ]  # fmt: skip
                )
            if res.returncode != 0:
                err = res.stderr.decode(errors="replace")
                if "did not complete successfully" in err:
                    return SuiteResult(False, f"command failed: {command}")
                return None  # the build itself could not run; that is not a failing test
        return SuiteResult(True, f"{len(self.commands)} smoke command(s) passed")
