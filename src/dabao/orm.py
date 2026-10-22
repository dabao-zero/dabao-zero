"""Relational schema (ADR-0006). Portable across SQLite (unit tests) and Postgres (production).

Times are epoch seconds (float), supplied by the injected Clock, never by the database.
"""

from __future__ import annotations

from sqlalchemy import Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from dabao.models import AdvisoryStatus


class Base(DeclarativeBase):
    pass


class AdvisoryRow(Base):
    __tablename__ = "advisories"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    aliases: Mapped[str] = mapped_column(Text, default="")  # newline-separated
    affected: Mapped[list[AffectedRow]] = relationship(back_populates="advisory")


class AffectedRow(Base):
    """An advisory against one package@version in one image and distro stream."""

    __tablename__ = "affected"
    __table_args__ = (UniqueConstraint("advisory_id", "stream", "image", "package", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    stream: Mapped[str] = mapped_column(String)
    image: Mapped[str] = mapped_column(String, index=True)
    package: Mapped[str] = mapped_column(String)
    version: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default=AdvisoryStatus.PENDING.value, index=True)
    created_at: Mapped[float] = mapped_column(Float)
    patched_at: Mapped[float | None] = mapped_column(Float, default=None)
    lease_owner: Mapped[str | None] = mapped_column(String, default=None)
    lease_expires: Mapped[float | None] = mapped_column(Float, default=None)

    advisory: Mapped[AdvisoryRow] = relationship(back_populates="affected")
    attempts: Mapped[list[AttemptRow]] = relationship(
        back_populates="affected", order_by="AttemptRow.id"
    )


class AttemptRow(Base):
    __tablename__ = "attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    affected_id: Mapped[int] = mapped_column(ForeignKey("affected.id"), index=True)
    outcome: Mapped[str] = mapped_column(String)  # RUNNING | SUCCEEDED | FAILED | ABORTED
    started_at: Mapped[float] = mapped_column(Float)
    finished_at: Mapped[float | None] = mapped_column(Float, default=None)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    log: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str | None] = mapped_column(Text, default=None)  # JSON gate results
    # Who ran the agent: "agent" (unattended) or "manual_codex" (ADR-0009). Shown on the ledger.
    runner: Mapped[str] = mapped_column(String, default="agent", server_default="agent")

    affected: Mapped[AffectedRow] = relationship(back_populates="attempts")
    patch: Mapped[PatchRow | None] = relationship(back_populates="attempt", uselist=False)


class PatchRow(Base):
    __tablename__ = "patches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempt_id: Mapped[int] = mapped_column(ForeignKey("attempts.id"), unique=True)
    source: Mapped[str] = mapped_column(String)  # PatchSource value
    upstream_ref: Mapped[str] = mapped_column(String)
    diff: Mapped[str] = mapped_column(Text)

    attempt: Mapped[AttemptRow] = relationship(back_populates="patch")


class ArtifactRow(Base):
    __tablename__ = "artifacts"

    digest: Mapped[str] = mapped_column(String, primary_key=True)
    image: Mapped[str] = mapped_column(String, index=True)
    tag: Mapped[str] = mapped_column(String)
    stream: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="PUBLISHED")  # PUBLISHED | REVOKED
    published_at: Mapped[float] = mapped_column(Float)
    revoked_at: Mapped[float | None] = mapped_column(Float, default=None)
    revoked_reason: Mapped[str | None] = mapped_column(Text, default=None)


class FlagRow(Base):
    """Operator switches (e.g. `frozen`). Absent means off, so a missing row can never freeze."""

    __tablename__ = "flags"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String)  # "1" on; anything else off
    note: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[float] = mapped_column(Float)


class ImageRow(Base):
    """Catalog metadata for an image: what a visitor sees before any advisory."""

    __tablename__ = "images"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    upstream: Mapped[str] = mapped_column(String, default="")  # official image it replaces
    created_at: Mapped[float] = mapped_column(Float)
