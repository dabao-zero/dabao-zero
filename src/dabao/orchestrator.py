"""Orchestrator: the sole writer of ledger state (PLAN S2, ADR-0002, ADR-0006).

For each pending (advisory, package) it takes a lease, asks the agent for a patch, builds,
runs the deterministic gates, and only then publishes. Agents propose; gates decide.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from dabao.db import SessionFactory
from dabao.gates import GateConfig, GateInput, Verdict, run_gates
from dabao.leases import LeaseHeld, acquire_lease, release_lease
from dabao.models import Advisory, AdvisoryStatus, Component, Finding
from dabao.models import Patch as PatchModel
from dabao.orm import (
    AdvisoryRow,
    AffectedRow,
    ArtifactRow,
    AttemptRow,
    PatchRow,
    ScanFindingRow,
)
from dabao.seams import (
    AgentRunner,
    BuildDiffer,
    Clock,
    DistroAdapter,
    Registry,
    Scanner,
    Signer,
    SuiteRunner,
)
from dabao.signing import SigningRefused

log = logging.getLogger(__name__)

MONTH_SECONDS = 30 * 86400


class Outcome(StrEnum):
    PUBLISHED = "published"
    UNPATCHED = "unpatched"
    NEEDS_HUMAN = "needs_human"
    ABORTED = "aborted"
    SKIPPED = "skipped"  # lease held elsewhere
    PAUSED = "paused"  # budget cap reached


@dataclass(frozen=True)
class Limits:
    lease_ttl_s: float = 3600.0
    max_cost_per_attempt_usd: float = 5.0
    monthly_budget_usd: float = 500.0
    max_aborted_attempts: int = 3


@dataclass
class Pipeline:
    agent: AgentRunner
    adapter: DistroAdapter
    scanners: Sequence[Scanner]
    suite_runner: SuiteRunner
    differ: BuildDiffer
    registry: Registry
    signer: Signer
    clock: Clock
    frozen: Callable[[], bool] = lambda: False  # operator kill switch: no new attempts
    gates: GateConfig = field(default_factory=GateConfig)
    limits: Limits = field(default_factory=Limits)
    owner: str = "orchestrator-1"
    # recorded on every attempt; "manual_codex" or "manual_claude_code" for imported bundles
    runner: str = "agent"
    # ADR-0010: which binary packages the build rebuilt, and where the gate may write a VEX.
    rebuilt: Callable[[str], Sequence[tuple[str, str]]] | None = None
    vex_dir: Path | None = None


class RecordingScanner:
    """Wraps a scanner and remembers what it returned per digest, so the gate scans once and the
    ledger can keep the result without a second scan."""

    def __init__(self, inner: Scanner) -> None:
        self._inner = inner
        self.name = inner.name
        self.results: dict[str, list[Finding]] = {}

    def scan(self, image_digest: str) -> list[Finding]:
        found = self._inner.scan(image_digest)
        self.results[image_digest] = found
        return found

    def with_vex(self, path: Path) -> Scanner:
        """The inner scanner told to apply a VEX. Not recorded: the ledger keeps the plain scan."""
        return self._inner.with_vex(path)  # type: ignore[attr-defined, no-any-return]


def _component(row: AffectedRow) -> Component:
    return Component(stream=row.stream, package=row.package, version=row.version)


def _advisory(row: AdvisoryRow) -> Advisory:
    return Advisory(
        id=row.id,
        aliases=tuple(a for a in row.aliases.split("\n") if a),
        fix_refs=tuple(r for r in row.fix_refs.split("\n") if r),
    )


def spent_last_month(session: Session, now: float) -> float:
    total = session.scalar(
        select(func.coalesce(func.sum(AttemptRow.cost_usd), 0.0)).where(
            AttemptRow.started_at >= now - MONTH_SECONDS
        )
    )
    return float(total or 0.0)


def _fail(
    session: Session,
    attempt: AttemptRow,
    affected: AffectedRow,
    status: AdvisoryStatus,
    outcome: str,
    log_text: str,
    now: float,
) -> None:
    attempt.outcome = outcome
    attempt.finished_at = now
    attempt.log = (attempt.log + "\n" + log_text).strip()
    affected.status = status.value
    session.commit()


def _describe(verdict: Verdict) -> str:
    return "; ".join(f"{r.name}: {r.reason}" for r in verdict.results if not r.passed)


def process(session_factory: SessionFactory, p: Pipeline, affected_id: int) -> Outcome:
    """Run one attempt for one affected row. Never publishes unless every gate passes."""
    if p.frozen():
        return Outcome.PAUSED
    with session_factory() as session:
        if spent_last_month(session, p.clock.now()) >= p.limits.monthly_budget_usd:
            return Outcome.PAUSED
        try:
            acquire_lease(session, affected_id, p.owner, p.limits.lease_ttl_s, p.clock)
        except LeaseHeld:
            return Outcome.SKIPPED
        try:
            return _attempt(session, p, affected_id)
        finally:
            release_lease(session, affected_id, p.owner)


def _attempt(session: Session, p: Pipeline, affected_id: int) -> Outcome:
    affected = session.get(AffectedRow, affected_id)
    if affected is None or affected.status in (
        AdvisoryStatus.PATCHED.value,
        AdvisoryStatus.NOT_AFFECTED.value,
    ):
        return Outcome.SKIPPED
    attempt = AttemptRow(
        affected_id=affected_id, outcome="RUNNING", started_at=p.clock.now(), runner=p.runner
    )
    session.add(attempt)
    session.commit()
    advisory, component = _advisory(affected.advisory), _component(affected)
    try:
        agent_started = p.clock.now()
        result = p.agent.propose_patch(advisory, component)
        measured = p.clock.now() - agent_started
        attempt.agent_seconds = (
            result.agent_seconds if result.agent_seconds is not None else measured
        )
        attempt.tokens_in, attempt.tokens_out = result.tokens_in, result.tokens_out
        attempt.cost_usd, attempt.log = result.cost_usd, result.log
        session.commit()
        if result.cost_usd > p.limits.max_cost_per_attempt_usd:
            _fail(
                session,
                attempt,
                affected,
                AdvisoryStatus.NEEDS_HUMAN,
                "FAILED",
                f"cost ${result.cost_usd:.2f} exceeds per-attempt cap",
                p.clock.now(),
            )
            return Outcome.NEEDS_HUMAN
        if result.patch is None:
            _fail(
                session,
                attempt,
                affected,
                AdvisoryStatus.UNPATCHED,
                "FAILED",
                "agent found no fix",
                p.clock.now(),
            )
            return Outcome.UNPATCHED
        patch = result.patch
        before = p.adapter.build_image(component, None)
        after = p.adapter.build_image(component, patch)
        recorders = [RecordingScanner(s) for s in p.scanners]
        verdict = run_gates(
            GateInput(
                advisory,
                patch,
                before,
                after,
                recorders,
                p.suite_runner,
                p.differ,
                rebuilt_packages=tuple(p.rebuilt(after)) if p.rebuilt else (),
                stream=component.stream,
                vex_dir=p.vex_dir,
                now=p.clock.now(),
            ),
            p.gates,
        )
        attempt.verdict = json.dumps(
            [{"name": r.name, "passed": r.passed, "reason": r.reason} for r in verdict.results]
        )
        session.commit()
        if not verdict.passed:
            _fail(
                session,
                attempt,
                affected,
                AdvisoryStatus.UNPATCHED,
                "FAILED",
                "gates failed: " + _describe(verdict),
                p.clock.now(),
            )
            return Outcome.UNPATCHED
        return _publish(session, p, attempt, affected, patch, after, verdict, recorders)
    except Exception as exc:  # noqa: BLE001 - an attempt must never take the loop down
        log.exception("attempt %s aborted", attempt.id)
        session.rollback()
        aborted = (
            session.scalar(
                select(func.count())
                .select_from(AttemptRow)
                .where(AttemptRow.affected_id == affected_id, AttemptRow.outcome == "ABORTED")
            )
            or 0
        )
        status = (
            AdvisoryStatus.NEEDS_HUMAN
            if aborted + 1 >= p.limits.max_aborted_attempts
            else AdvisoryStatus(affected.status)
        )
        _fail(session, attempt, affected, status, "ABORTED", f"aborted: {exc!r}", p.clock.now())
        return Outcome.ABORTED


def _record_findings(
    session: Session, digest: str, recorders: Sequence[RecordingScanner], now: float
) -> None:
    """Keep what each scanner still reported on the published image: one row per scanner,
    advisory and package. The unfixed ones are the known-unfixed list (ADR-0011)."""
    session.flush()  # the artifact row must exist before rows that point at it
    session.execute(delete(ScanFindingRow).where(ScanFindingRow.artifact_digest == digest))
    seen: set[tuple[str, str, str]] = set()
    for rec in recorders:
        for f in rec.results.get(digest, []):
            key = (rec.name, f.advisory_id, f.package)
            if key in seen:
                continue
            seen.add(key)
            session.add(
                ScanFindingRow(
                    artifact_digest=digest,
                    scanner=rec.name,
                    advisory_id=f.advisory_id,
                    package=f.package,
                    severity=f.severity,
                    fix_state=f.fix_state,
                    created_at=now,
                )
            )


def _publish(
    session: Session,
    p: Pipeline,
    attempt: AttemptRow,
    affected: AffectedRow,
    patch: PatchModel,
    digest: str,
    verdict: Verdict,
    recorders: Sequence[RecordingScanner] = (),
) -> Outcome:
    now = p.clock.now()
    tag = f"{affected.version}-dabao1"
    try:
        # Sign first: a refusal must leave nothing published. (A real registry pushes by digest,
        # signs, then tags; the tag is what makes it public.)
        p.signer.sign(digest, verdict)
    except SigningRefused as exc:
        _fail(
            session,
            attempt,
            affected,
            AdvisoryStatus.NEEDS_HUMAN,
            "FAILED",
            f"signer refused: {exc}",
            now,
        )
        return Outcome.NEEDS_HUMAN
    p.registry.push(digest, f"{affected.image}:{tag}")
    session.add(
        PatchRow(
            attempt_id=attempt.id,
            source=patch.source.value,
            upstream_ref=patch.upstream_ref,
            diff=patch.diff,
        )
    )
    if session.get(ArtifactRow, digest) is None:
        session.add(
            ArtifactRow(
                digest=digest,
                image=affected.image,
                tag=tag,
                stream=affected.stream,
                published_at=now,
            )
        )
    _record_findings(session, digest, recorders, now)
    attempt.outcome, attempt.finished_at = "SUCCEEDED", now
    affected.status, affected.patched_at = AdvisoryStatus.PATCHED.value, now
    session.commit()
    return Outcome.PUBLISHED


def run_once(session_factory: SessionFactory, p: Pipeline) -> dict[str, int]:
    """Process every pending row once, oldest first. Returns outcome counts."""
    with session_factory() as session:
        ids = list(
            session.scalars(
                select(AffectedRow.id)
                .where(AffectedRow.status == AdvisoryStatus.PENDING.value)
                .order_by(AffectedRow.created_at, AffectedRow.id)
            )
        )
    counts: dict[str, int] = {}
    for affected_id in ids:
        outcome = process(session_factory, p, affected_id)
        counts[outcome.value] = counts.get(outcome.value, 0) + 1
        if outcome is Outcome.PAUSED:
            break
    return counts
