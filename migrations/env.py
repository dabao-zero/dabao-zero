import os

from alembic import context
from sqlalchemy import create_engine

from dabao.orm import Base

target_metadata = Base.metadata


def _url() -> str:
    return context.config.get_main_option("sqlalchemy.url") or os.environ.get(
        "DATABASE_URL", "sqlite+pysqlite:///./dabao.db"
    )


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
