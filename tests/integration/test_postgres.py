"""Runs against a real Postgres (CI service container). Skipped when DATABASE_URL_TEST is unset."""

from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import sessionmaker

from dabao.fakes import FakeClock
from dabao.leases import LeaseHeld, acquire_lease
from dabao.orm import AdvisoryRow, AffectedRow

pytestmark = pytest.mark.integration

URL = os.environ.get("DATABASE_URL_TEST")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def engine() -> Iterator[Engine]:
    if not URL:
        pytest.skip("DATABASE_URL_TEST not set")
    eng = create_engine(URL)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", URL)
    command.upgrade(cfg, "head")
    yield eng
    eng.dispose()


def test_concurrent_lease_has_exactly_one_winner(engine: Engine) -> None:
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as s:
        s.add(AdvisoryRow(id="CVE-2024-0001"))
        s.add(
            AffectedRow(
                id=1,
                advisory_id="CVE-2024-0001",
                stream="debian",
                image="nginx",
                package="nginx",
                version="1",
                created_at=0.0,
            )
        )
        s.commit()
    clock = FakeClock(100.0)

    def attempt(owner: str) -> bool:
        with factory() as s:
            try:
                acquire_lease(s, 1, owner, 60, clock)
            except LeaseHeld:
                return False
            return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, [f"w{i}" for i in range(8)]))
    assert results.count(True) == 1
