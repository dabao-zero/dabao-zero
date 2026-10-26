"""Advisory ingestion (PLAN S1, T4.1): feed records -> `affected` rows for our images' packages.

Pure parsing is separate from the database step. Ingest is idempotent: re-running it creates
no duplicates and never resets the status of a row that is already being worked on.
Debian and Alpine streams are handled; the stream picks the version ordering.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from dabao.orm import AdvisoryRow, AffectedRow
from dabao.versions import compare_apk, compare_dpkg

DEBIAN_RELEASES = {"12": "bookworm", "11": "bullseye"}


@dataclass(frozen=True)
class FeedRecord:
    id: str
    aliases: tuple[str, ...]
    package: str
    fixed_version: str | None  # None: no fix available yet, every version is affected
    fix_refs: tuple[str, ...] = ()  # the feed's own links to the fix (OSV references of type FIX)


def canonical_id(ids: list[str]) -> str:
    """CVE id if there is one (lowest, for determinism), else the first id given."""
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else ids[0]


def _osv_fix_refs(rec: dict[str, Any]) -> tuple[str, ...]:
    refs = rec.get("references")
    if not isinstance(refs, list):
        return ()
    urls = {
        r["url"].strip()
        for r in refs
        if isinstance(r, dict) and r.get("type") == "FIX" and isinstance(r.get("url"), str)
    }
    return tuple(sorted(u for u in urls if u))


def parse_osv(records: list[dict[str, Any]], ecosystem: str = "Debian:12") -> list[FeedRecord]:
    """OSV records -> one FeedRecord per affected package in `ecosystem`.

    Malformed records are skipped.
    """
    out: list[FeedRecord] = []
    for rec in records:
        affected = rec.get("affected")
        rid = rec.get("id")
        if not isinstance(rid, str) or not isinstance(affected, list):
            continue
        ids = [rid, *[a for a in rec.get("aliases", []) if isinstance(a, str)]]
        canon = canonical_id(ids)
        aliases = tuple(sorted(set(ids) - {canon}))
        fix_refs = _osv_fix_refs(rec)
        for aff in affected:
            pkg = aff.get("package", {}) if isinstance(aff, dict) else {}
            if pkg.get("ecosystem") != ecosystem or not pkg.get("name"):
                continue
            fixed: str | None = None
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed = event["fixed"]
            out.append(FeedRecord(canon, aliases, pkg["name"], fixed, fix_refs))
    return out


def parse_debian_tracker(data: dict[str, Any], release: str = "bookworm") -> list[FeedRecord]:
    """Debian security tracker JSON -> FeedRecords for one release.

    Skips entries fixed in version "0" (not affected) or absent from the release.
    """
    out: list[FeedRecord] = []
    for package, cves in data.items():
        for cve, entry in cves.items():
            rel = entry.get("releases", {}).get(release)
            if rel is None:
                continue
            status, fixed = rel.get("status"), rel.get("fixed_version")
            if status == "open":
                out.append(FeedRecord(cve, (), package, None))
            elif status == "resolved" and fixed and fixed != "0":
                out.append(FeedRecord(cve, (), package, fixed))
    return out


def parse_alpine_secdb(data: dict[str, Any]) -> list[FeedRecord]:
    """Alpine secdb JSON (one repository of one release) -> FeedRecords.

    Alpine lists only vulnerabilities that have a fix, keyed by the version that fixes them;
    version "0" means "not affected" and is skipped. A value may hold several ids in one string.
    """
    out: list[FeedRecord] = []
    for item in data.get("packages", []):
        pkg = item["pkg"]
        for fixed, cves in pkg.get("secfixes", {}).items():
            if fixed == "0":
                continue
            for entry in cves:
                for cve in entry.split():
                    out.append(FeedRecord(cve, (), pkg["name"], fixed))
    return out


_COMPARE = {"debian": compare_dpkg, "alpine": compare_apk}


def is_vulnerable(installed: str, fixed: str | None, stream: str = "debian") -> bool:
    return fixed is None or _COMPARE[stream](installed, fixed) < 0


def _find_advisory(session: Session, ids: set[str]) -> AdvisoryRow | None:
    for row in session.scalars(select(AdvisoryRow)):
        if ids & ({row.id} | {a for a in row.aliases.split("\n") if a}):
            return row
    return None


def ingest(
    session: Session,
    records: list[FeedRecord],
    images: dict[str, dict[str, str]],  # image name -> {package: installed version}
    now: float,
    stream: str = "debian",
) -> dict[str, int]:
    """Create advisories and PENDING rows for vulnerable installed packages. Returns counts."""
    counts = {"advisories": 0, "affected": 0, "skipped_not_installed": 0, "skipped_fixed": 0}
    for rec in records:
        ids = {rec.id, *rec.aliases}
        adv = _find_advisory(session, ids)
        for image, packages in sorted(images.items()):
            installed = packages.get(rec.package)
            if installed is None:
                counts["skipped_not_installed"] += 1
                continue
            if not is_vulnerable(installed, rec.fixed_version, stream):
                counts["skipped_fixed"] += 1
                continue
            if adv is None:
                adv = AdvisoryRow(
                    id=rec.id,
                    aliases="\n".join(sorted(rec.aliases)),
                    fix_refs="\n".join(sorted(rec.fix_refs)),
                )
                session.add(adv)
                session.flush()
                counts["advisories"] += 1
            else:  # merge any newly learned aliases
                known = {a for a in adv.aliases.split("\n") if a}
                extra = (ids - {adv.id}) - known
                if extra:
                    adv.aliases = "\n".join(sorted(known | extra))
                refs = {r for r in adv.fix_refs.split("\n") if r}
                if set(rec.fix_refs) - refs:
                    adv.fix_refs = "\n".join(sorted(refs | set(rec.fix_refs)))
            exists = session.scalar(
                select(AffectedRow.id).where(
                    AffectedRow.advisory_id == adv.id,
                    AffectedRow.stream == stream,
                    AffectedRow.image == image,
                    AffectedRow.package == rec.package,
                    AffectedRow.version == installed,
                )
            )
            if exists is None:
                session.add(
                    AffectedRow(
                        advisory_id=adv.id,
                        stream=stream,
                        image=image,
                        package=rec.package,
                        version=installed,
                        created_at=now,
                    )
                )
                counts["affected"] += 1
    session.commit()
    return counts
