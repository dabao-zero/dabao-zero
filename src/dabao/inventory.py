"""Read package inventories out of OCI images with `regctl`, with no Docker daemon.

`regctl` is run through an injectable runner so unit tests need no binary and no network.
Only the package database file is pulled from the image, never the whole image.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass

Runner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]

DPKG_STATUS = "var/lib/dpkg/status"
APK_INSTALLED = "lib/apk/db/installed"


class RegctlError(Exception):
    pass


def _run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=300, check=False)


class Regctl:
    def __init__(self, binary: str = "regctl", runner: Runner = _run) -> None:
        self._binary, self._runner = binary, runner

    def digest(self, image: str) -> str:
        res = self._runner([self._binary, "image", "digest", image])
        if res.returncode != 0:
            raise RegctlError(res.stderr.decode(errors="replace").strip())
        return res.stdout.decode().strip()

    def get_file(self, image: str, path: str) -> bytes | None:
        """File contents from the image's merged layers, or None if it does not exist."""
        res = self._runner([self._binary, "image", "get-file", image, path])
        if res.returncode == 0:
            return res.stdout
        err = res.stderr.decode(errors="replace")
        if "not found" in err:
            return None
        raise RegctlError(err.strip())


def parse_dpkg_status(text: str) -> dict[str, str]:
    """Installed packages from a dpkg status file: name -> version."""
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue  # continuation line
            key, _, value = line.partition(":")
            fields[key] = value.strip()
        pkg, ver = fields.get("Package"), fields.get("Version")
        if pkg and ver and fields.get("Status", "").endswith("installed"):
            out[pkg] = ver
    return out


def parse_apk_installed(text: str) -> dict[str, str]:
    """Installed packages from an apk database: name -> version."""
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        name = ver = None
        for line in block.splitlines():
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                ver = line[2:].strip()
        if name and ver:
            out[name] = ver
    return out


def parse_apk_origins(text: str) -> dict[str, str]:
    """Source packages in an apk database: origin name -> version.

    Advisory feeds name the source package (`brotli`), while the database lists binaries
    (`brotli-libs`); every binary of one origin carries the same version."""
    out: dict[str, str] = {}
    for block in text.split("\n\n"):
        name = ver = origin = None
        for line in block.splitlines():
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                ver = line[2:].strip()
            elif line.startswith("o:"):
                origin = line[2:].strip()
        if name and ver:
            out[origin or name] = ver
    return out


def inventory(regctl: Regctl, image: str) -> tuple[str, dict[str, str]]:
    """(stream, packages) for an image; stream is 'debian' (dpkg) or 'alpine' (apk)."""
    dpkg = regctl.get_file(image, DPKG_STATUS)
    if dpkg is not None:
        return "debian", parse_dpkg_status(dpkg.decode(errors="replace"))
    apk = regctl.get_file(image, APK_INSTALLED)
    if apk is not None:
        return "alpine", parse_apk_installed(apk.decode(errors="replace"))
    raise RegctlError(f"{image}: no dpkg or apk package database found")


@dataclass(frozen=True)
class PackageDiff:
    added: dict[str, str]
    removed: dict[str, str]
    changed: dict[str, tuple[str, str]]  # name -> (before, after)

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def diff_inventories(before: dict[str, str], after: dict[str, str]) -> PackageDiff:
    return PackageDiff(
        added={k: v for k, v in after.items() if k not in before},
        removed={k: v for k, v in before.items() if k not in after},
        changed={
            k: (before[k], after[k]) for k in before.keys() & after.keys() if before[k] != after[k]
        },
    )
