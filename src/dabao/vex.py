"""OpenVEX statements for rebuilt packages (ADR-0010).

The gate runner, never the agent, writes these, and only after the evidence checks of ADR-0010
pass. A statement says: for these rebuilt binary packages, this one CVE is `fixed`. The packages
are named by plain package URL with no qualifiers: that is the form Trivy 0.70.0 and Grype 0.121.0
both matched in the 2026-10-23 experiment. Naming the image with the packages as subcomponents
matched in neither.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

CONTEXT = "https://openvex.dev/ns/v0.2.0"
AUTHOR = "dabao-zero gate runner"
ID_PREFIX = "https://github.com/dabao-zero/dabao-zero/vex/"

_PURL = {"debian": "pkg:deb/debian", "alpine": "pkg:apk/alpine"}


@dataclass(frozen=True)
class VexStatement:
    """One CVE fixed in the listed rebuilt packages, with what the fix was derived from."""

    advisory_id: str
    stream: str
    packages: tuple[tuple[str, str], ...]  # (binary package name, installed version)
    upstream_ref: str
    patch_sha256: str


def package_url(stream: str, name: str, version: str) -> str:
    base = _PURL.get(stream)
    if base is None:
        raise ValueError(f"no package URL for stream {stream!r}")
    return f"{base}/{quote(name, safe='')}@{quote(version, safe='')}"


def _statement(s: VexStatement) -> dict[str, Any]:
    if not s.packages:
        raise ValueError(f"statement for {s.advisory_id} names no packages")
    return {
        "vulnerability": {"name": s.advisory_id},
        "products": [{"@id": package_url(s.stream, n, v)} for n, v in s.packages],
        "status": "fixed",
        "status_notes": (
            f"Fix derived from {s.upstream_ref}; patch sha256:{s.patch_sha256}. "
            "Issued by the dabao-zero gate runner after its evidence checks (ADR-0010)."
        ),
    }


def build_openvex(statements: Sequence[VexStatement], timestamp: float) -> dict[str, Any]:
    """A document whose id is derived from its statements, so equal inputs give equal bytes."""
    if not statements:
        raise ValueError("no statements to publish")
    body = [_statement(s) for s in statements]
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:32]
    return {
        "@context": CONTEXT,
        "@id": f"{ID_PREFIX}{digest}",
        "author": AUTHOR,
        "timestamp": datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 1,
        "statements": body,
    }


def to_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def write_openvex(path: Path, statements: Sequence[VexStatement], timestamp: float) -> Path:
    path.write_text(to_json(build_openvex(statements, timestamp)))
    return path
