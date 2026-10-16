from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from dabao.fakes import FakeClock
from dabao.leases import LeaseHeld, acquire_lease, release_lease


def test_second_owner_is_rejected_while_lease_is_live(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    with seeded() as s:
        acquire_lease(s, 1, "worker-a", 60, clock)
        with pytest.raises(LeaseHeld):
            acquire_lease(s, 1, "worker-b", 60, clock)


def test_expired_lease_can_be_taken_over(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    with seeded() as s:
        acquire_lease(s, 1, "worker-a", 60, clock)
        clock.advance(60)
        acquire_lease(s, 1, "worker-b", 60, clock)
        with pytest.raises(LeaseHeld):
            acquire_lease(s, 1, "worker-a", 60, clock)


def test_owner_can_renew_and_release(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    with seeded() as s:
        acquire_lease(s, 1, "worker-a", 60, clock)
        acquire_lease(s, 1, "worker-a", 60, clock)  # renew
        assert not release_lease(s, 1, "worker-b")  # not the owner
        assert release_lease(s, 1, "worker-a")
        acquire_lease(s, 1, "worker-b", 60, clock)


def test_leases_are_per_row(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    with seeded() as s:
        acquire_lease(s, 1, "worker-a", 60, clock)
        acquire_lease(s, 2, "worker-b", 60, clock)


def test_unknown_row_is_rejected(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    with seeded() as s, pytest.raises(LeaseHeld):
        acquire_lease(s, 999, "worker-a", 60, clock)
