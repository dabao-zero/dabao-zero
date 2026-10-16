"""Operator actions (ADR-0002): the human incident-response surface. Never part of the patch path.

Freeze is a kill switch: no new attempts and no signing. Revoke marks a published artifact.
Rerun puts a stuck advisory back in the queue.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from dabao import repo
from dabao.db import SessionFactory
from dabao.models import AdvisoryStatus
from dabao.orm import AffectedRow, ArtifactRow

FROZEN = "frozen"
RERUNNABLE = (AdvisoryStatus.UNPATCHED.value, AdvisoryStatus.NEEDS_HUMAN.value)


def freeze(session: Session, note: str, now: float) -> None:
    repo.set_flag(session, FROZEN, True, note, now)


def unfreeze(session: Session, note: str, now: float) -> None:
    repo.set_flag(session, FROZEN, False, note, now)


def rerun(session: Session, advisory_id: str) -> int:
    """Re-queue UNPATCHED / NEEDS_HUMAN rows of an advisory. Returns how many were queued.

    Rows that are PATCHED, PENDING or currently leased are left alone.
    """
    result = session.execute(
        update(AffectedRow)
        .where(
            AffectedRow.advisory_id == advisory_id,
            AffectedRow.status.in_(RERUNNABLE),
            AffectedRow.lease_owner.is_(None),
        )
        .values(status=AdvisoryStatus.PENDING.value)
    )
    session.commit()
    return int(result.rowcount)  # type: ignore[attr-defined]


def status(session: Session) -> dict[str, object]:
    counts = dict(
        session.execute(select(AffectedRow.status, func.count()).group_by(AffectedRow.status)).all()
    )
    revoked = session.scalar(
        select(func.count()).select_from(ArtifactRow).where(ArtifactRow.status == "REVOKED")
    )
    return {"frozen": repo.get_flag(session, FROZEN), "affected": counts, "revoked": revoked or 0}


def frozen_check(factory: SessionFactory) -> Callable[[], bool]:
    """Callable for `Pipeline.frozen` / `GuardedSigner(is_frozen=...)`, read fresh every call."""

    def check() -> bool:
        with factory() as s:
            return repo.get_flag(s, FROZEN)

    return check


def revoked_check(factory: SessionFactory) -> Callable[[str], bool]:
    """Callable for `GuardedSigner(is_revoked=...)`."""

    def check(digest: str) -> bool:
        with factory() as s:
            art = s.get(ArtifactRow, digest)
            return art is not None and art.status == "REVOKED"

    return check
