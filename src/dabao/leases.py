"""DB leases: one live attempt per (advisory, package) (PLAN S2, Q7).

The orchestrator is the sole writer. A losing writer is rejected, never merged.
Acquisition is a single conditional UPDATE, so it is atomic on SQLite and Postgres.
"""

from __future__ import annotations

from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from dabao.orm import AffectedRow
from dabao.seams import Clock


class LeaseHeld(Exception):
    """Another owner holds an unexpired lease."""


def acquire_lease(session: Session, affected_id: int, owner: str, ttl: float, clock: Clock) -> None:
    now = clock.now()
    result = session.execute(
        update(AffectedRow)
        .where(
            AffectedRow.id == affected_id,
            or_(
                AffectedRow.lease_owner.is_(None),
                AffectedRow.lease_expires <= now,
                AffectedRow.lease_owner == owner,
            ),
        )
        .values(lease_owner=owner, lease_expires=now + ttl)
    )
    session.commit()
    if result.rowcount != 1:  # type: ignore[attr-defined]
        raise LeaseHeld(f"affected {affected_id} is leased to another owner")


def release_lease(session: Session, affected_id: int, owner: str) -> bool:
    result = session.execute(
        update(AffectedRow)
        .where(AffectedRow.id == affected_id, AffectedRow.lease_owner == owner)
        .values(lease_owner=None, lease_expires=None)
    )
    session.commit()
    return bool(result.rowcount == 1)  # type: ignore[attr-defined]
