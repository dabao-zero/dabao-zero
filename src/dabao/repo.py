"""Queries and the few writes the API needs. Everything else is written by the orchestrator."""

from __future__ import annotations

import statistics

from sqlalchemy import select
from sqlalchemy.orm import Session

from dabao.models import AdvisoryStatus
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow


def list_advisories(session: Session, status: str | None = None) -> list[AffectedRow]:
    stmt = select(AffectedRow).order_by(AffectedRow.created_at.desc(), AffectedRow.id)
    if status:
        stmt = stmt.where(AffectedRow.status == status)
    return list(session.scalars(stmt))


def get_advisory(session: Session, advisory_id: str) -> AdvisoryRow | None:
    return session.get(AdvisoryRow, advisory_id)


def image_summaries(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(select(AffectedRow)).all()
    by_image: dict[str, list[AffectedRow]] = {}
    for r in rows:
        by_image.setdefault(r.image, []).append(r)
    out: list[dict[str, object]] = []
    for image, items in sorted(by_image.items()):
        times = [
            i.patched_at - i.created_at
            for i in items
            if i.status == AdvisoryStatus.PATCHED.value and i.patched_at is not None
        ]
        out.append(
            {
                "name": image,
                "total": len(items),
                "patched": sum(i.status == AdvisoryStatus.PATCHED.value for i in items),
                "unpatched": sum(
                    i.status in (AdvisoryStatus.UNPATCHED.value, AdvisoryStatus.NEEDS_HUMAN.value)
                    for i in items
                ),
                "pending": sum(i.status == AdvisoryStatus.PENDING.value for i in items),
                "median_time_to_patch_s": statistics.median(times) if times else None,
            }
        )
    return out


def affected_for_image(session: Session, image: str) -> list[AffectedRow]:
    stmt = select(AffectedRow).where(AffectedRow.image == image).order_by(AffectedRow.created_at)
    return list(session.scalars(stmt))


def list_artifacts(session: Session, image: str | None = None) -> list[ArtifactRow]:
    stmt = select(ArtifactRow).order_by(ArtifactRow.published_at.desc())
    if image:
        stmt = stmt.where(ArtifactRow.image == image)
    return list(session.scalars(stmt))


def revoke_artifact(session: Session, digest: str, reason: str, now: float) -> ArtifactRow | None:
    art = session.get(ArtifactRow, digest)
    if art is None:
        return None
    if art.status != "REVOKED":  # idempotent: keep the first revocation time and reason
        art.status = "REVOKED"
        art.revoked_at = now
        art.revoked_reason = reason
        session.commit()
    return art
