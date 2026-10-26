"""One reproducible `docker buildx build` to an OCI layout, shared by the distro adapters.

A build writes an OCI layout directory with rewritten timestamps, so the same inputs give the same
manifest digest. Docker runs through an injectable runner so unit tests need no daemon.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

Runner = Callable[[list[str]], "subprocess.CompletedProcess[bytes]"]

# Names and versions end up inside generated Dockerfile shell lines. Refuse anything outside the
# characters distro packages really use, so a feed entry can never inject a command.
_NAME = re.compile(r"^[a-z0-9][a-z0-9.+_-]*$")


class BuildError(Exception):
    pass


def default_runner(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=3600, check=False)


def check_name(package: str) -> None:
    if not _NAME.match(package):
        raise ValueError(f"not a safe package name: {package!r}")


_DEBIAN_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+~:-]*$")
_APK_VERSION = re.compile(r"^[0-9][0-9A-Za-z._~]*-r[0-9]+$")


def check_debian_version(version: str) -> None:
    if not _DEBIAN_VERSION.match(version):
        raise ValueError(f"not a safe version: {version!r}")


def check_apk_version(version: str) -> None:
    if not _APK_VERSION.match(version):
        raise ValueError(f"not a safe version (expected X-rN): {version!r}")


_STEP_OUTPUT = re.compile(r"^#(\d+) \d+\.\d+ (.*)$")
_FAILED_STEP = re.compile(r"^#(\d+) ERROR: ")


def _why(stderr: bytes) -> str:
    """What the failing step printed, else the last step output, else the tail of stderr.

    BuildKit builds stages in parallel and interleaves their logs, so the last lines may belong to a
    step that succeeded: the failing step is the one named in the `#N ERROR:` line. The tail alone
    is usually the Dockerfile excerpt BuildKit prints last, hiding the message."""
    text = stderr.decode(errors="replace")
    lines = text.splitlines()
    failed = next((m.group(1) for ln in lines if (m := _FAILED_STEP.match(ln))), None)
    steps = [(m.group(1), m.group(2)) for ln in lines if (m := _STEP_OUTPUT.match(ln))]
    own = [msg for n, msg in steps if n == failed] if failed else []
    chosen = own or [msg for _, msg in steps]
    if chosen:
        return "\n".join(chosen[-20:])[-1500:]
    return text[-1500:]


def build_oci(runner: Runner, builder: str, ctx: Path, out: Path, source_date_epoch: int) -> str:
    """Build `ctx/Dockerfile` into the OCI layout at `out` and return the image manifest digest."""
    cmd = [
        "docker", "buildx", "build",
        "--builder", builder,
        "--no-cache", "--provenance=false", "--sbom=false",
        "--build-arg", f"SOURCE_DATE_EPOCH={source_date_epoch}",
        "--output", f"type=oci,tar=false,dest={out},rewrite-timestamp=true",
        str(ctx),
    ]  # fmt: skip
    res = runner(cmd)
    if res.returncode != 0:
        raise BuildError(f"docker build failed ({res.returncode}): {_why(res.stderr)}")
    manifests = json.loads((out / "index.json").read_text()).get("manifests", [])
    if not manifests:
        raise BuildError("the build wrote no image digest")
    return str(manifests[0]["digest"])
