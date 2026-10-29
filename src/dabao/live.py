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
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from dabao.ingest import parse_debian_notes
from dabao.models import Finding
from dabao.seams import SuiteResult
from dabao.upstream import patch_url

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
APK_BOOKKEEPING = ("lib/apk/db/", "etc/apk/world", "var/log/apk.log", "var/cache/apk/")
DPKG_STATUS_FILE = "var/lib/dpkg/status"
APK_DB_FILE = "lib/apk/db/installed"


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


def _apk_packages(db: str) -> dict[str, tuple[str, list[str]]]:
    """apk's installed database: package -> (version, files). `F:` sets the directory and each
    `R:` names a file in it."""
    out: dict[str, tuple[str, list[str]]] = {}
    for block in db.split("\n\n"):
        name = version = ""
        files: list[str] = []
        directory = ""
        for line in block.splitlines():
            if line.startswith("P:"):
                name = line[2:]
            elif line.startswith("V:"):
                version = line[2:]
            elif line.startswith("F:"):
                directory = line[2:]
            elif line.startswith("R:"):
                files.append(f"{directory}/{line[2:]}" if directory else line[2:])
        if name:
            out[name] = (version, files)
    return out


@dataclass
class _Scan:
    changed: set[str]  # files the added layers wrote
    texts: dict[str, str]  # package databases and file lists the added layers wrote
    base_texts: dict[str, str]  # the same files as the base image had them


@dataclass
class OciDiffer:
    """Files the build changed that no rebuilt package or package-manager bookkeeping explains.

    A rebuilt package legitimately changes its own files, so "changed" is judged against the file
    lists of the packages the build re-versioned, plus the package manager's own state. Anything
    else the build touched, say /etc/passwd or a binary of another package, is returned and the
    build_diff gate fails on it. Works on Debian (packages marked `+dabao1`) and Alpine (packages
    whose version differs from the base image's).

    Layers beyond the base are the build's: give `added_layers` (our builds add two) or, for a base
    with a known layer count, `base_layers`.
    """

    source: ImageSource
    base_layers: int = 1  # layers the base image already has (debian slim has one)
    added_layers: int | None = None  # overrides base_layers: the last N layers are the build's
    ignore_prefixes: tuple[str, ...] = ("tmp/dabao-debs", "tmp/dabao-apk")  # staging, removed again
    rebuilt_marker: str = "+dabao1"
    bookkeeping: tuple[str, ...] = DPKG_BOOKKEEPING

    def _read(self, digest: str) -> _Scan | None:
        layout = self.source.layout(digest)
        if layout is None:
            return None
        try:
            index = json.loads((layout / "index.json").read_text())
            manifest = json.loads(_blob(layout, index["manifests"][0]["digest"]).read_text())
            layers = manifest["layers"]
            n_base = len(layers) - self.added_layers if self.added_layers else self.base_layers
            scan = _Scan(set(), {}, {})
            for i, layer in enumerate(layers):
                added = i >= n_base
                with tarfile.open(_blob(layout, layer["digest"])) as t:
                    for member in t:
                        name = member.name.removeprefix("./")
                        if member.isdir() or "/.wh." in f"/{name}" or name.startswith(".wh."):
                            continue
                        is_db = (
                            name in (DPKG_STATUS_FILE, APK_DB_FILE)
                            or (name.startswith("var/lib/dpkg/") and name.endswith(".list"))
                        )  # fmt: skip
                        if is_db:
                            fh = t.extractfile(member)
                            text = fh.read().decode(errors="replace") if fh else ""
                            (scan.texts if added else scan.base_texts)[name] = text
                        if added and not name.startswith(self.ignore_prefixes):
                            scan.changed.add(name)
            return scan
        except (OSError, KeyError, IndexError, tarfile.TarError, ValueError):
            return None

    def _rebuilt(self, scan: _Scan) -> dict[str, tuple[str, list[str]]]:
        """Rebuilt package -> (version, files), for whichever package manager the image uses."""
        if APK_DB_FILE in scan.texts:
            before = _apk_packages(scan.base_texts.get(APK_DB_FILE, ""))
            return {
                n: (v, files)
                for n, (v, files) in _apk_packages(scan.texts[APK_DB_FILE]).items()
                if before.get(n, ("", []))[0] != v
            }
        out: dict[str, tuple[str, list[str]]] = {}
        for pkg, version in _installed_versions(scan.texts.get(DPKG_STATUS_FILE, "")).items():
            if version.endswith(self.rebuilt_marker):
                listing = scan.texts.get(f"var/lib/dpkg/info/{pkg}.list", "")
                out[pkg] = (version, [_merged_usr(ln) for ln in listing.splitlines()])
        return out

    def changed_files(self, before_digest: str, after_digest: str) -> list[str] | None:
        scan = self._read(after_digest)
        if scan is None:
            return None
        explained = {f for _, files in self._rebuilt(scan).values() for f in files}
        bookkeeping = APK_BOOKKEEPING if APK_DB_FILE in scan.texts else self.bookkeeping
        return sorted(
            f for f in scan.changed if f not in explained and not f.startswith(bookkeeping)
        )

    def rebuilt_packages(self, digest: str) -> list[tuple[str, str]] | None:
        """(binary package, version) of what the build re-versioned: what a VEX statement names."""
        scan = self._read(digest)
        if scan is None:
            return None
        return sorted((n, v) for n, (v, _) in self._rebuilt(scan).items())


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


MAX_UPSTREAM_BYTES = 2_000_000


def _site(host: str) -> str:
    """The last two labels of a host: enough to tell savannah.gnu.org from an unrelated redirect."""
    return ".".join(host.lower().split(".")[-2:])


@dataclass
class HttpUpstreamFetcher:
    """Reads the raw patch of an upstream commit, only from hosts on the provenance allow-list.

    Anything it cannot read (unknown host, error, redirect to another site, oversized answer) is
    None, which the gate treats as a failure (ADR-0010 check 2).
    """

    allowlist: tuple[str, ...]
    timeout_s: float = 60.0  # savannah answers slowly under load
    opener: Callable[[str, float], tuple[str, bytes]] | None = (
        None  # (url, timeout) -> (final url, body)
    )

    def _open(self, url: str) -> tuple[str, bytes]:
        if self.opener is not None:
            return self.opener(url, self.timeout_s)
        req = Request(url, headers={"User-Agent": "dabao-zero-gate"})  # noqa: S310 - https only, below
        with urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310
            return resp.geturl(), resp.read(MAX_UPSTREAM_BYTES + 1)

    def commit_diff(self, ref: str) -> str | None:
        if not any(ref.startswith(p) for p in self.allowlist):
            return None
        url = patch_url(ref)
        if url is None or urlsplit(url).scheme != "https":
            return None
        try:
            final, body = self._open(url)
        except OSError:
            return None
        if _site(urlsplit(final).netloc) != _site(urlsplit(url).netloc):
            return None
        if len(body) > MAX_UPSTREAM_BYTES:
            return None
        try:
            return body.decode()
        except UnicodeDecodeError:
            return None


DEBIAN_CVE_LIST = (
    "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/CVE/list"
)


def fetch_debian_fix_refs(
    ids: set[str], url: str = DEBIAN_CVE_LIST, timeout_s: float = 300.0
) -> dict[str, tuple[str, ...]]:
    """Fix commits the Debian tracker names for `ids`, streamed from its CVE list.

    Stops reading once every id has been seen. Any failure gives no references, which the gate then
    treats as "the feed names no fix reference" and refuses a VEX (ADR-0010 check 1).
    """
    if urlsplit(url).scheme != "https":
        return {}
    try:
        with urlopen(Request(url, headers={"User-Agent": "dabao-zero"}), timeout=timeout_s) as resp:  # noqa: S310
            lines = (raw.decode(errors="replace") for raw in resp)
            return parse_debian_notes(lines, wanted=set(ids))
    except OSError:
        return {}
