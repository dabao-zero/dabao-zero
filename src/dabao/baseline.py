"""Summarise stock-scanner output for the baseline in docs/baseline-scan.md (DAB-74, ADR-0011).

Only operating-system packages are counted (`deb`, `apk`): language ecosystems are out of scope for
this milestone (PLAN). "Fixable" means the scanner's own data names a fix; everything else is a CVE
nobody has fixed, which no rebuild or version can clear on a stock scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

OS_PACKAGE_TYPES = {"deb", "apk"}


@dataclass(frozen=True)
class Counts:
    total: int
    fixable: int
    unfixable: int
    fixable_high: int  # fixable and HIGH or CRITICAL
    critical_or_high: int


def _counts(rows: list[tuple[str, str, bool, str]]) -> Counts:
    """rows: (vulnerability id, package, fixable, severity); distinct (id, package) pairs."""
    seen: dict[tuple[str, str], tuple[bool, str]] = {}
    for vid, pkg, fixable, severity in rows:
        seen[(vid, pkg)] = (fixable, severity.upper())
    high = {"HIGH", "CRITICAL"}
    return Counts(
        total=len(seen),
        fixable=sum(1 for f, _ in seen.values() if f),
        unfixable=sum(1 for f, _ in seen.values() if not f),
        fixable_high=sum(1 for f, s in seen.values() if f and s in high),
        critical_or_high=sum(1 for _, s in seen.values() if s in high),
    )


def summarise_trivy(text: str) -> tuple[Counts, str, str]:
    """Counts, base ("debian 12.7") and the image digest, from `trivy image --format json`."""
    data = json.loads(text or "{}")
    rows = [
        (
            v["VulnerabilityID"],
            v.get("PkgName", ""),
            bool(v.get("FixedVersion")),
            v.get("Severity", ""),
        )
        for r in data.get("Results", [])
        if r.get("Class") == "os-pkgs"
        for v in r.get("Vulnerabilities") or []
    ]
    meta = data.get("Metadata", {})
    os_info = meta.get("OS") or {}
    base = f"{os_info.get('Family', '?')} {os_info.get('Name', '')}".strip()
    digests = meta.get("RepoDigests") or []
    digest = digests[0].split("@", 1)[1] if digests else ""
    return _counts(rows), base, digest


def summarise_grype(text: str) -> Counts:
    data = json.loads(text or "{}")
    rows = [
        (
            m["vulnerability"]["id"],
            m["artifact"]["name"],
            (m["vulnerability"].get("fix") or {}).get("state") == "fixed",
            m["vulnerability"].get("severity", ""),
        )
        for m in data.get("matches", [])
        if m["artifact"].get("type") in OS_PACKAGE_TYPES
    ]
    return _counts(rows)
