"""HTTP API: public read-only ledger under /v1, plus token-guarded operator actions."""

from __future__ import annotations

import hmac
import time
from collections.abc import Iterator
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from dabao import catalog, repo
from dabao.db import SessionFactory, make_engine, make_session_factory
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, AttemptRow
from dabao.seams import Clock
from dabao.settings import Settings


class SystemClock:
    def now(self) -> float:
        return time.time()


class GateOut(BaseModel):
    name: str
    passed: bool
    reason: str


class AttemptOut(BaseModel):
    id: int
    outcome: str
    started_at: float
    finished_at: float | None
    tokens_in: int
    tokens_out: int
    cost_usd: float
    patch_source: str | None
    patch_upstream_ref: str | None
    patch_diff: str | None
    gates: list[GateOut] | None


class AffectedOut(BaseModel):
    id: int
    advisory_id: str
    stream: str
    image: str
    package: str
    version: str
    status: str
    created_at: float
    patched_at: float | None


class AffectedDetailOut(AffectedOut):
    attempts: list[AttemptOut]


class AdvisoryOut(BaseModel):
    id: str
    aliases: list[str]
    affected: list[AffectedDetailOut]


class ImageSummaryOut(BaseModel):
    name: str
    description: str
    upstream: str
    bases: list[str]
    latest_tag: str | None
    updated_at: float | None
    total: int
    open: int
    fixed: int
    patched: int
    unpatched: int
    pending: int
    needs_human: int
    median_time_to_patch_s: float | None


class TagOut(BaseModel):
    digest: str
    tag: str
    stream: str
    status: str
    published_at: float
    revoked_at: float | None
    revoked_reason: str | None
    open_cves: int
    fixed_cves: int


class ImageDetailOut(ImageSummaryOut):
    tags: list[TagOut]
    advisories: list[AffectedOut]


class StatsOut(BaseModel):
    attempts: int
    fixes: int
    median_time_to_fix_s: float | None
    median_cost_per_fix_usd: float | None
    failed_spend_usd: float
    total_spend_usd: float


class RunOut(BaseModel):
    attempt_id: int
    advisory_id: str
    image: str
    package: str
    outcome: str
    status: str
    started_at: float
    duration_s: float | None
    tokens_in: int
    tokens_out: int
    cost_usd: float


class ArtifactOut(BaseModel):
    digest: str
    image: str
    tag: str
    stream: str
    status: str
    published_at: float
    revoked_at: float | None
    revoked_reason: str | None


class RevokeIn(BaseModel):
    reason: str


def _gates(raw: str | None) -> list[GateOut] | None:
    gates: list[GateOut] = []
    for item in catalog.parse_verdict(raw) or []:
        try:
            gates.append(GateOut.model_validate(item))
        except ValueError:
            continue  # a malformed stored entry must not take the page down
    return gates or None


def _attempt(a: AttemptRow) -> AttemptOut:
    p = a.patch
    return AttemptOut(
        id=a.id,
        outcome=a.outcome,
        started_at=a.started_at,
        finished_at=a.finished_at,
        tokens_in=a.tokens_in,
        tokens_out=a.tokens_out,
        cost_usd=a.cost_usd,
        patch_source=p.source if p else None,
        patch_upstream_ref=p.upstream_ref if p else None,
        patch_diff=p.diff if p else None,
        gates=_gates(a.verdict),
    )


def _affected(r: AffectedRow) -> AffectedOut:
    return AffectedOut.model_validate(r, from_attributes=True)


def _affected_detail(r: AffectedRow) -> AffectedDetailOut:
    return AffectedDetailOut(
        **_affected(r).model_dump(), attempts=[_attempt(a) for a in r.attempts]
    )


def _advisory(a: AdvisoryRow) -> AdvisoryOut:
    return AdvisoryOut(
        id=a.id,
        aliases=[x for x in a.aliases.split("\n") if x],
        affected=[_affected_detail(r) for r in a.affected],
    )


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def create_app(
    session_factory: SessionFactory | None = None,
    settings: Settings | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    clock = clock or SystemClock()
    if session_factory is None:
        session_factory = make_session_factory(make_engine(settings.database_url))

    app = FastAPI(title="dabao", version="0.0.0")
    app.state.session_factory = session_factory
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET"]
        )

    def require_operator(authorization: Annotated[str | None, Header()] = None) -> None:
        if not settings.operator_token:
            raise HTTPException(503, "operator actions are disabled")
        expected = f"Bearer {settings.operator_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(401, "invalid operator token")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    v1 = APIRouter(prefix="/v1")

    @v1.get("/status")
    def ledger_status(session: SessionDep) -> dict[str, bool]:
        return {"frozen": repo.get_flag(session, "frozen")}

    @v1.get("/images", response_model=list[ImageSummaryOut])
    def images(session: SessionDep) -> list[catalog.ImageSummary]:
        return catalog.image_summaries(session)

    @v1.get("/images/{name}", response_model=ImageDetailOut)
    def image(name: str, session: SessionDep) -> ImageDetailOut:
        found = catalog.get_image(session, name)
        if found is None:
            raise HTTPException(404, "unknown image")
        summary, tags, rows = found
        return ImageDetailOut(
            **asdict(summary),
            tags=[TagOut(**asdict(t)) for t in tags],
            advisories=[_affected(r) for r in rows],
        )

    @v1.get("/stats", response_model=StatsOut)
    def stats(session: SessionDep) -> catalog.Stats:
        return catalog.stats(session)

    @v1.get("/runs", response_model=list[RunOut])
    def runs(
        session: SessionDep, limit: Annotated[int, Query(ge=1, le=100)] = 20
    ) -> list[catalog.Run]:
        return catalog.recent_runs(session, limit)

    @v1.get("/advisories", response_model=list[AffectedOut])
    def advisories(session: SessionDep, status: str | None = None) -> list[AffectedOut]:
        return [_affected(r) for r in repo.list_advisories(session, status)]

    @v1.get("/advisories/{advisory_id}", response_model=AdvisoryOut)
    def advisory(advisory_id: str, session: SessionDep) -> AdvisoryOut:
        row = repo.get_advisory(session, advisory_id)
        if row is None:
            raise HTTPException(404, "unknown advisory")
        return _advisory(row)

    @v1.get("/artifacts", response_model=list[ArtifactOut])
    def artifacts(session: SessionDep, image: str | None = None) -> list[ArtifactRow]:
        return repo.list_artifacts(session, image)

    @v1.post(
        "/artifacts/{digest}/revoke",
        response_model=ArtifactOut,
        dependencies=[Depends(require_operator)],
    )
    def revoke(digest: str, body: RevokeIn, session: SessionDep) -> ArtifactRow:
        row = repo.revoke_artifact(session, digest, body.reason, clock.now())
        if row is None:
            raise HTTPException(404, "unknown artifact")
        return row

    app.include_router(v1)
    return app
