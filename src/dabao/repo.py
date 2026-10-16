"""Queries and the few writes the API needs. Everything else is written by the orchestrator."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, FlagRow


def list_advisories(session: Session, status: str | None = None) -> list[AffectedRow]:
    stmt = select(AffectedRow).order_by(AffectedRow.created_at.desc(), AffectedRow.id)
    if status:
        stmt = stmt.where(AffectedRow.status == status)
    return list(session.scalars(stmt))


def get_advisory(session: Session, advisory_id: str) -> AdvisoryRow | None:
    return session.get(AdvisoryRow, advisory_id)


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


def get_flag(session: Session, name: str) -> bool:
    row = session.get(FlagRow, name)
    return row is not None and row.value == "1"


def set_flag(session: Session, name: str, on: bool, note: str, now: float) -> None:
    row = session.get(FlagRow, name)
    if row is None:
        session.add(FlagRow(name=name, value="1" if on else "0", note=note, updated_at=now))
    else:
        row.value, row.note, row.updated_at = "1" if on else "0", note, now
    session.commit()
