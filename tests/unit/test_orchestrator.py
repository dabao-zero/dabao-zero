from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from dabao import fakes
from dabao.gates import GateConfig
from dabao.leases import acquire_lease
from dabao.models import Component, Finding, Patch, PatchSource
from dabao.orchestrator import Limits, Outcome, Pipeline, process, run_once
from dabao.orm import (
    AdvisoryRow,
    AffectedRow,
    ArtifactRow,
    AttemptRow,
    PatchRow,
    ScanFindingRow,
)
from dabao.seams import AgentResult, SuiteResult
from dabao.signing import GuardedSigner

SRC = "https://github.com/nginx/nginx/commit/"
CFG = GateConfig(provenance_allowlist=(SRC,))
COMP = Component(stream="debian", package="nginx", version="1.22.0-1")
DIFF = "--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1 @@\n-a\n+b\n"
PATCH = Patch(
    advisory_id="CVE-2024-0001",
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref=SRC + "abc",
    diff=DIFF,
)
ADAPTER = fakes.FakeDistroAdapter()
BEFORE, AFTER = ADAPTER.build_image(COMP, None), ADAPTER.build_image(COMP, PATCH)
FINDING = Finding(advisory_id="CVE-2024-0001", package="nginx")


def pipeline(
    *,
    patch: Patch | None = PATCH,
    still_vulnerable: bool = False,
    suite_ok: bool = True,
    cost: float = 0.1,
    raises: Exception | None = None,
    limits: Limits | None = None,
    clock: fakes.FakeClock | None = None,
) -> Pipeline:
    after_findings = [FINDING] if still_vulnerable else []
    return Pipeline(
        agent=fakes.FakeAgentRunner(
            {("CVE-2024-0001", "nginx"): patch} if patch else {}, cost_usd=cost, raises=raises
        ),
        adapter=ADAPTER,
        scanners=(
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: after_findings}, name="grype"),
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: after_findings}, name="trivy"),
        ),
        suite_runner=fakes.FakeSuiteRunner({AFTER: SuiteResult(suite_ok, "x")}),
        differ=fakes.FakeBuildDiffer({(BEFORE, AFTER): ["src/x.c"]}),
        registry=fakes.FakeRegistry(),
        signer=fakes.FakeSigner(),
        clock=clock or fakes.FakeClock(1000.0),
        gates=CFG,
        limits=limits or Limits(),
    )


@pytest.fixture
def pending(factory: sessionmaker[Session]) -> sessionmaker[Session]:
    with factory() as s:
        s.add(AdvisoryRow(id="CVE-2024-0001"))
        s.add(
            AffectedRow(
                id=1,
                advisory_id="CVE-2024-0001",
                stream="debian",
                image="nginx",
                package="nginx",
                version="1.22.0-1",
                created_at=10.0,
            )
        )
        s.commit()
    return factory


def row(f: sessionmaker[Session]) -> AffectedRow:
    with f() as s:
        r = s.get(AffectedRow, 1)
        assert r is not None
        return r


def test_happy_path_publishes_records_and_releases_lease(pending: sessionmaker[Session]) -> None:
    p = pipeline()
    assert process(pending, p, 1) is Outcome.PUBLISHED
    r = row(pending)
    assert (r.status, r.patched_at, r.lease_owner) == ("PATCHED", 1000.0, None)
    assert p.registry.pushed == {"nginx:1.22.0-1-dabao1": AFTER}  # type: ignore[attr-defined]
    with pending() as s:
        assert s.get(ArtifactRow, AFTER) is not None
        patch = s.scalars(select(PatchRow)).one()
        assert (patch.source, patch.upstream_ref) == ("upstream_derived", SRC + "abc")
        att = s.scalars(select(AttemptRow)).one()
        assert (att.outcome, att.tokens_in, att.cost_usd) == ("SUCCEEDED", 100, 0.1)


def test_gate_failure_publishes_nothing(pending: sessionmaker[Session]) -> None:
    p = pipeline(still_vulnerable=True)
    assert process(pending, p, 1) is Outcome.UNPATCHED
    assert row(pending).status == "UNPATCHED"
    assert p.registry.pushed == {}  # type: ignore[attr-defined]
    with pending() as s:
        att = s.scalars(select(AttemptRow)).one()
        assert att.outcome == "FAILED" and "scanners_clear" in att.log
        assert s.scalars(select(ArtifactRow)).all() == []


def test_failing_official_suite_publishes_nothing(pending: sessionmaker[Session]) -> None:
    p = pipeline(suite_ok=False)
    assert process(pending, p, 1) is Outcome.UNPATCHED
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_original_patch_is_never_published(pending: sessionmaker[Session]) -> None:
    p = pipeline(patch=PATCH.model_copy(update={"source": PatchSource.ORIGINAL}))
    assert process(pending, p, 1) is Outcome.UNPATCHED
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_agent_finding_no_fix_is_unpatched_not_partial(pending: sessionmaker[Session]) -> None:
    p = pipeline(patch=None)
    assert process(pending, p, 1) is Outcome.UNPATCHED
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_lease_held_elsewhere_skips(pending: sessionmaker[Session]) -> None:
    p = pipeline()
    with pending() as s:
        acquire_lease(s, 1, "someone-else", 3600, p.clock)
    assert process(pending, p, 1) is Outcome.SKIPPED
    assert row(pending).status == "PENDING"
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_per_attempt_cost_cap_needs_human_and_does_not_publish(
    pending: sessionmaker[Session],
) -> None:
    p = pipeline(cost=9.0, limits=Limits(max_cost_per_attempt_usd=5.0))
    assert process(pending, p, 1) is Outcome.NEEDS_HUMAN
    assert row(pending).status == "NEEDS_HUMAN"
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_monthly_budget_pauses_the_pipeline(pending: sessionmaker[Session]) -> None:
    with pending() as s:
        s.add(AttemptRow(affected_id=1, outcome="FAILED", started_at=900.0, cost_usd=500.0))
        s.commit()
    p = pipeline(limits=Limits(monthly_budget_usd=500.0))
    assert process(pending, p, 1) is Outcome.PAUSED
    assert row(pending).status == "PENDING"


def test_old_spend_does_not_count_against_this_month(pending: sessionmaker[Session]) -> None:
    clock = fakes.FakeClock(40 * 86400.0)
    with pending() as s:
        s.add(AttemptRow(affected_id=1, outcome="FAILED", started_at=100.0, cost_usd=999.0))
        s.commit()
    assert process(pending, pipeline(clock=clock), 1) is Outcome.PUBLISHED


def test_crash_aborts_attempt_and_three_crashes_need_a_human(
    pending: sessionmaker[Session],
) -> None:
    p = pipeline(raises=RuntimeError("boom"))
    assert process(pending, p, 1) is Outcome.ABORTED
    assert row(pending).status == "PENDING"
    assert process(pending, p, 1) is Outcome.ABORTED
    assert process(pending, p, 1) is Outcome.ABORTED
    assert row(pending).status == "NEEDS_HUMAN"
    assert row(pending).lease_owner is None
    assert p.registry.pushed == {}  # type: ignore[attr-defined]


def test_run_once_handles_only_pending_rows_and_is_idempotent(
    pending: sessionmaker[Session],
) -> None:
    p = pipeline()
    assert run_once(pending, p) == {"published": 1}
    assert run_once(pending, p) == {}


def test_run_once_stops_when_paused(pending: sessionmaker[Session]) -> None:
    with pending() as s:
        s.add(
            AffectedRow(
                id=2,
                advisory_id="CVE-2024-0001",
                stream="debian",
                image="nginx",
                package="libc6",
                version="2",
                created_at=20.0,
            )
        )
        s.add(AttemptRow(affected_id=1, outcome="FAILED", started_at=900.0, cost_usd=10.0))
        s.commit()
    p = pipeline(limits=replace(Limits(), monthly_budget_usd=5.0))
    assert run_once(pending, p) == {"paused": 1}


def test_signer_refusal_publishes_nothing_and_needs_a_human(
    pending: sessionmaker[Session],
) -> None:
    p = pipeline()
    p.signer = GuardedSigner(fakes.FakeSigner(), is_revoked=lambda _d: True)
    assert process(pending, p, 1) is Outcome.NEEDS_HUMAN
    assert row(pending).status == "NEEDS_HUMAN"
    assert p.registry.pushed == {}  # type: ignore[attr-defined]
    with pending() as s:
        assert s.scalars(select(ArtifactRow)).all() == []
        assert "signer refused" in s.scalars(select(AttemptRow)).one().log


def test_guarded_signer_accepts_a_real_passing_verdict_end_to_end(
    pending: sessionmaker[Session],
) -> None:
    p = pipeline()
    backend = fakes.FakeSigner()
    p.signer = GuardedSigner(backend)
    assert process(pending, p, 1) is Outcome.PUBLISHED
    assert backend.signed == [AFTER]


def test_frozen_switch_stops_new_attempts(pending: sessionmaker[Session]) -> None:
    p = pipeline()
    p.frozen = lambda: True
    assert process(pending, p, 1) is Outcome.PAUSED
    assert row(pending).status == "PENDING"
    with pending() as s:
        assert s.scalars(select(AttemptRow)).all() == []


def test_attempt_stores_the_gate_verdict_for_the_fix_page(
    pending: sessionmaker[Session],
) -> None:
    import json

    assert process(pending, pipeline(), 1) is Outcome.PUBLISHED
    with pending() as s:
        gates = json.loads(s.scalars(select(AttemptRow)).one().verdict or "[]")
    assert [g["name"] for g in gates] == [
        "advisory_present_before",
        "scanners_clear",
        "tests_pass",
        "build_diff",
        "provenance",
    ]
    assert all(g["passed"] for g in gates)


def test_failed_attempt_stores_which_gate_failed(pending: sessionmaker[Session]) -> None:
    import json

    assert process(pending, pipeline(still_vulnerable=True), 1) is Outcome.UNPATCHED
    with pending() as s:
        gates = json.loads(s.scalars(select(AttemptRow)).one().verdict or "[]")
    assert {g["name"] for g in gates if not g["passed"]} == {"scanners_clear"}


def test_ordinary_attempts_are_recorded_as_agent_runs(pending: sessionmaker[Session]) -> None:
    process(pending, pipeline(), 1)
    with pending() as s:
        assert s.scalars(select(AttemptRow)).one().runner == "agent"


class SlowAgent:
    """An agent that takes `seconds` of (fake) wall time and reports its own figure if given."""

    def __init__(
        self, clock: fakes.FakeClock, seconds: float, reported: float | None = None
    ) -> None:
        self.clock, self.seconds, self.reported = clock, seconds, reported

    def propose_patch(self, advisory: object, component: object) -> AgentResult:
        self.clock.advance(self.seconds)
        return AgentResult(PATCH, 10, 5, 0.25, "log", agent_seconds=self.reported)


def test_agent_wall_time_is_measured_around_the_agent_call(pending: sessionmaker[Session]) -> None:
    clock = fakes.FakeClock(1000.0)
    p = replace(pipeline(clock=clock), agent=SlowAgent(clock, 42.0))
    process(pending, p, 1)
    with pending() as s:
        a = s.scalars(select(AttemptRow)).one()
        assert a.agent_seconds == 42.0
        assert (a.tokens_in, a.tokens_out, a.cost_usd) == (10, 5, 0.25)


def test_a_run_that_happened_elsewhere_reports_its_own_wall_time(
    pending: sessionmaker[Session],
) -> None:
    clock = fakes.FakeClock(1000.0)
    p = replace(pipeline(clock=clock), agent=SlowAgent(clock, 1.0, reported=378.0))
    process(pending, p, 1)
    with pending() as s:
        assert s.scalars(select(AttemptRow)).one().agent_seconds == 378.0


def pipeline_with_after_findings(findings: list[Finding]) -> Pipeline:
    """Both scanners see the target CVE before, and `findings` (not the target) after."""
    return replace(
        pipeline(),
        scanners=(
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: findings}, name="grype"),
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: findings}, name="trivy"),
        ),
    )


def test_a_published_artifact_keeps_what_each_scanner_still_reported(
    pending: sessionmaker[Session],
) -> None:
    left = [
        Finding(
            advisory_id="CVE-2025-1", package="busybox", severity="MEDIUM", fix_state="unfixed"
        ),
        Finding(advisory_id="CVE-2025-2", package="zlib", severity="LOW", fix_state="fixed"),
    ]
    assert process(pending, pipeline_with_after_findings(left), 1) is Outcome.PUBLISHED
    with pending() as s:
        rows = s.scalars(select(ScanFindingRow).order_by(ScanFindingRow.id)).all()
        got = {(r.scanner, r.advisory_id, r.package, r.severity, r.fix_state) for r in rows}
        assert got == {
            (sc, "CVE-2025-1", "busybox", "MEDIUM", "unfixed") for sc in ("grype", "trivy")
        } | {(sc, "CVE-2025-2", "zlib", "LOW", "fixed") for sc in ("grype", "trivy")}
        assert {r.artifact_digest for r in rows} == {AFTER}


def test_duplicate_findings_from_one_scanner_are_stored_once(
    pending: sessionmaker[Session],
) -> None:
    dup = Finding(advisory_id="CVE-2025-1", package="busybox", fix_state="unfixed")
    process(pending, pipeline_with_after_findings([dup, dup]), 1)
    with pending() as s:
        assert len(s.scalars(select(ScanFindingRow)).all()) == 2  # one per scanner


def test_a_failed_attempt_stores_no_findings(pending: sessionmaker[Session]) -> None:
    process(pending, pipeline(still_vulnerable=True), 1)
    with pending() as s:
        assert s.scalars(select(ScanFindingRow)).all() == []


def test_a_clean_artifact_stores_nothing(pending: sessionmaker[Session]) -> None:
    process(pending, pipeline(), 1)
    with pending() as s:
        assert s.scalars(select(ScanFindingRow)).all() == []


def vex_pipeline(tmp_path: Path, *, enabled: bool) -> Pipeline:
    """Both scanners still report the target after the patch; the fakes honour a VEX."""
    still = [FINDING]
    return replace(
        pipeline(),
        scanners=(
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: still}, name="grype"),
            fakes.FakeScanner({BEFORE: [FINDING], AFTER: still}, name="trivy"),
        ),
        gates=replace(CFG, vex_enabled=enabled),
        rebuilt=lambda digest: [("nginx", "1.22.0-1-dabao1")],
        vex_dir=tmp_path,
    )


def test_with_the_flag_on_a_cve_the_scanners_still_report_is_cleared_by_a_vex(
    pending: sessionmaker[Session], tmp_path: Path
) -> None:
    assert process(pending, vex_pipeline(tmp_path, enabled=True), 1) is Outcome.PUBLISHED
    assert len(list(tmp_path.glob("*.vex.json"))) == 2
    with pending() as s:
        att = s.scalars(select(AttemptRow)).one()
        assert att.outcome == "SUCCEEDED" and "via VEX" in (att.verdict or "")
        # the ledger keeps what a stock scan says, not what the VEX changed it to
        assert {r.advisory_id for r in s.scalars(select(ScanFindingRow))} == {"CVE-2024-0001"}


def test_with_the_flag_off_the_same_scan_is_unpatched_and_nothing_is_written(
    pending: sessionmaker[Session], tmp_path: Path
) -> None:
    assert process(pending, vex_pipeline(tmp_path, enabled=False), 1) is Outcome.UNPATCHED
    assert list(tmp_path.iterdir()) == []
