from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite+pysqlite:///./dabao.db"
    operator_token: str | None = None  # unset disables operator actions (fail closed)
    cors_origins: tuple[str, ...] = ()
    manual_attempts_enabled: bool = False  # ADR-0009; off unless explicitly set to 1

    @classmethod
    def from_env(cls) -> Settings:
        origins = os.environ.get("DABAO_CORS_ORIGINS", "")
        return cls(
            database_url=os.environ.get("DATABASE_URL", cls.database_url),
            operator_token=os.environ.get("DABAO_OPERATOR_TOKEN") or None,
            cors_origins=tuple(o for o in origins.split(",") if o),
            manual_attempts_enabled=os.environ.get("MANUAL_ATTEMPTS_ENABLED") == "1",
        )
