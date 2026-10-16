"""Read models for the public catalog: what a visitor sees about an image (PLAN S7).

Everything here is derived from ledger rows, never stored twice. An advisory is *open* until a
patched image has shipped for it.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from dabao.models import AdvisoryStatus
from dabao.orm import AffectedRow, ArtifactRow, AttemptRow, ImageRow

PATCHED = AdvisoryStatus.PATCHED.value
OPEN_STATUSES = (
    AdvisoryStatus.PENDING.value,
    AdvisoryStatus.UNPATCHED.value,
    AdvisoryStatus.NEEDS_HUMAN.value,
)


@dataclass(frozen=True)
class ImageSummary:
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


@dataclass(frozen=True)
class TagInfo:
    digest: str
    tag: str
    stream: str
    status: str
    published_at: float
    revoked_at: float | None
    revoked_reason: str | None
    open_cves: int
    fixed_cves: int


@dataclass(frozen=True)
class Stats:
    attempts: int
    fixes: int
    median_time_to_fix_s: float | None
    median_cost_per_fix_usd: float | None
    failed_spend_usd: float
    total_spend_usd: float


@dataclass(frozen=True)
class Run:
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


@dataclass
class _Acc:
    rows: list[AffectedRow] = field(default_factory=list)
    artifacts: list[ArtifactRow] = field(default_factory=list)


def _group(session: Session) -> tuple[dict[str, _Acc], dict[str, ImageRow]]:
    meta = {r.name: r for r in session.scalars(select(ImageRow))}
    acc: dict[str, _Acc] = {name: _Acc() for name in meta}
    for row in session.scalars(select(AffectedRow)):
        acc.setdefault(row.image, _Acc()).rows.append(row)
    for art in session.scalars(select(ArtifactRow)):
        acc.setdefault(art.image, _Acc()).artifacts.append(art)
    return acc, meta


def _summary(name: str, a: _Acc, meta: dict[str, ImageRow]) -> ImageSummary:
    live = [x for x in a.artifacts if x.status == "PUBLISHED"]
    latest = max(live, key=lambda x: x.published_at, default=None)
    times = [r.patched_at - r.created_at for r in a.rows if r.status == PATCHED and r.patched_at]

    def count(*statuses: str) -> int:
        return sum(r.status in statuses for r in a.rows)

    m = meta.get(name)
    return ImageSummary(
        name=name,
        description=m.description if m else "",
        upstream=m.upstream if m else "",
        bases=sorted({r.stream for r in a.rows} | {x.stream for x in a.artifacts}),
        latest_tag=latest.tag if latest else None,
        updated_at=latest.published_at if latest else None,
        total=len(a.rows),
        open=count(*OPEN_STATUSES),
        fixed=count(PATCHED),
        patched=count(PATCHED),
        unpatched=count(AdvisoryStatus.UNPATCHED.value),
        pending=count(AdvisoryStatus.PENDING.value),
        needs_human=count(AdvisoryStatus.NEEDS_HUMAN.value),
        median_time_to_patch_s=statistics.median(times) if times else None,
    )


def image_summaries(session: Session) -> list[ImageSummary]:
    acc, meta = _group(session)
    return [_summary(n, acc[n], meta) for n in sorted(acc)]


def get_image(
    session: Session, name: str
) -> tuple[ImageSummary, list[TagInfo], list[AffectedRow]] | None:
    acc, meta = _group(session)
    if name not in acc:
        return None
    a = acc[name]
    tags = [_tag(x, a.rows) for x in sorted(a.artifacts, key=lambda x: -x.published_at)]
    rows = sorted(a.rows, key=lambda r: (r.created_at, r.id))
    return _summary(name, a, meta), tags, rows


def _tag(art: ArtifactRow, rows: list[AffectedRow]) -> TagInfo:
    """CVE counts for a tag: open = known at publish time and still open; fixed = fixed by then."""
    same = [r for r in rows if r.stream == art.stream]
    return TagInfo(
        digest=art.digest,
        tag=art.tag,
        stream=art.stream,
        status=art.status,
        published_at=art.published_at,
        revoked_at=art.revoked_at,
        revoked_reason=art.revoked_reason,
        open_cves=sum(r.status in OPEN_STATUSES and r.created_at <= art.published_at for r in same),
        fixed_cves=sum(
            r.status == PATCHED and (r.patched_at or 0) <= art.published_at for r in same
        ),
    )


def stats(session: Session) -> Stats:
    attempts = [a for a in session.scalars(select(AttemptRow)) if a.outcome != "RUNNING"]
    ok = [a for a in attempts if a.outcome == "SUCCEEDED"]
    times = [
        a.affected.patched_at - a.affected.created_at
        for a in ok
        if a.affected.patched_at is not None
    ]
    return Stats(
        attempts=len(attempts),
        fixes=len(ok),
        median_time_to_fix_s=statistics.median(times) if times else None,
        median_cost_per_fix_usd=statistics.median([a.cost_usd for a in ok]) if ok else None,
        failed_spend_usd=round(sum(a.cost_usd for a in attempts if a.outcome != "SUCCEEDED"), 6),
        total_spend_usd=round(sum(a.cost_usd for a in attempts), 6),
    )


def recent_runs(session: Session, limit: int = 20) -> list[Run]:
    stmt = (
        select(AttemptRow).order_by(AttemptRow.started_at.desc(), AttemptRow.id.desc()).limit(limit)
    )
    return [
        Run(
            attempt_id=a.id,
            advisory_id=a.affected.advisory_id,
            image=a.affected.image,
            package=a.affected.package,
            outcome=a.outcome,
            status=a.affected.status,
            started_at=a.started_at,
            duration_s=(a.finished_at - a.started_at) if a.finished_at is not None else None,
            tokens_in=a.tokens_in,
            tokens_out=a.tokens_out,
            cost_usd=a.cost_usd,
        )
        for a in session.scalars(stmt)
    ]


def parse_verdict(raw: str | None) -> list[dict[str, object]] | None:
    """Gate results stored on an attempt; tolerant of rows written before verdicts existed."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, list) else None
