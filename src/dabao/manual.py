"""Import a manual agent run as a gated attempt (ADR-0009).

A human started the run; they do not approve the result. The bundle's patch goes through the
same orchestrator, gates, signer and ledger as any agent's patch, and nothing here relaxes them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from sqlalchemy import select

from dabao.bundle import CandidateBundle
from dabao.db import SessionFactory
from dabao.models import Advisory, Component
from dabao.orchestrator import Outcome, Pipeline, process
from dabao.orm import AffectedRow
from dabao.seams import AgentResult


class ManualImportRefused(Exception):
    """The import was refused before any attempt was recorded."""


@dataclass(frozen=True)
class BundleAgent:
    """An AgentRunner that replays the bundle's patch. It costs nothing and asks no model."""

    bundle: CandidateBundle

    def propose_patch(self, advisory: Advisory, component: Component) -> AgentResult:
        b = self.bundle
        log = f"runner={b.runner.value} model={b.model} tools={b.tool_versions}\n{b.run_log}"
        return AgentResult(patch=b.patch, log=log)


def import_bundle(
    factory: SessionFactory, p: Pipeline, bundle: CandidateBundle, *, enabled: bool
) -> list[Outcome]:
    """Run the bundle's patch through the pipeline for every matching affected row."""
    if not enabled:
        raise ManualImportRefused("manual attempts are off; set MANUAL_ATTEMPTS_ENABLED=1")
    patch = bundle.patch
    with factory() as session:
        ids = list(
            session.scalars(
                select(AffectedRow.id)
                .where(
                    AffectedRow.advisory_id == patch.advisory_id,
                    AffectedRow.stream == patch.component.stream,
                    AffectedRow.package == patch.component.package,
                    AffectedRow.version == patch.component.version,
                )
                .order_by(AffectedRow.id)
            )
        )
    if not ids:
        raise ManualImportRefused(
            f"no affected row for {patch.advisory_id} {patch.component.stream}/"
            f"{patch.component.package}@{patch.component.version}"
        )
    manual = replace(p, agent=BundleAgent(bundle), runner=bundle.runner.value)
    return [process(factory, manual, i) for i in ids]
