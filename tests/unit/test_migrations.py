from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from dabao.orm import Base

ROOT = Path(__file__).resolve().parents[2]


def test_migrations_produce_the_orm_schema(tmp_path: Path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'm.db'}"
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    with create_engine(url).connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []  # a model change without a migration fails here


def test_0003_keeps_existing_attempts_and_adds_nullable_verdict(tmp_path: Path) -> None:
    from sqlalchemy import text

    url = f"sqlite+pysqlite:///{tmp_path / 'm3.db'}"
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "0002")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO advisories (id, aliases) VALUES ('CVE-1', '')"))
        conn.execute(
            text(
                "INSERT INTO affected (id, advisory_id, stream, image, package, version, status,"
                " created_at) VALUES (1, 'CVE-1', 'debian', 'nginx', 'nginx', '1', 'PENDING', 1.0)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO attempts (id, affected_id, outcome, started_at, tokens_in, tokens_out,"
                " cost_usd, log) VALUES (1, 1, 'FAILED', 2.0, 10, 5, 0.1, 'old')"
            )
        )
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        row = conn.execute(text("SELECT log, verdict FROM attempts WHERE id = 1")).one()
        assert tuple(row) == ("old", None)
        assert conn.execute(text("SELECT COUNT(*) FROM images")).scalar() == 0
    command.downgrade(cfg, "0002")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT log FROM attempts WHERE id = 1")).scalar() == "old"
