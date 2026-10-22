from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from dabao import cli
from dabao.bundle import BUNDLE_VERSION, CandidateBundle, Runner
from dabao.fakes import FakeAgentRunner
from dabao.leases import acquire_lease
from dabao.manual import ManualImportRefused, import_bundle
from dabao.models import AdvisoryStatus
from dabao.orchestrator import Outcome
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, AttemptRow
from tests.unit.test_orchestrator import COMP, PATCH, pipeline


def bundle(**over: object) -> CandidateBundle:
    base: dict[str, object] = {
        "schema_version": BUNDLE_VERSION,
        "runner": Runner.MANUAL_CODEX,
        "patch": PATCH,
        "upstream_links": (PATCH.upstream_ref,),
        "run_log": "codex transcript",
        "tool_versions": {"codex": "0.1.0"},
        "model": "gpt-5",
        "created_at": 1.0,
    }
    return CandidateBundle.model_validate({**base, **over})


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
                package=COMP.package,
                version=COMP.version,
                created_at=10.0,
            )
        )
        s.commit()
    return factory


def test_flag_off_refuses_and_touches_nothing(pending: sessionmaker[Session]) -> None:
    with pytest.raises(ManualImportRefused, match="MANUAL_ATTEMPTS_ENABLED"):
        import_bundle(pending, pipeline(), bundle(), enabled=False)
    with pending() as s:
        assert s.scalar(select(AttemptRow)) is None
        assert s.get(AffectedRow, 1).status == AdvisoryStatus.PENDING.value  # type: ignore[union-attr]


def test_good_bundle_goes_through_the_gates_and_is_marked_manual(
    pending: sessionmaker[Session],
) -> None:
    p = replace(pipeline(), agent=FakeAgentRunner())  # the agent must not be consulted
    assert import_bundle(pending, p, bundle(), enabled=True) == [Outcome.PUBLISHED]
    with pending() as s:
        attempt = s.scalars(select(AttemptRow)).one()
        assert attempt.outcome == "SUCCEEDED"
        assert attempt.log.startswith("runner=manual_codex")
        assert "codex transcript" in attempt.log
        assert s.scalars(select(ArtifactRow)).one().image == "nginx"


def test_bad_bundle_is_rejected_by_the_gates(pending: sessionmaker[Session]) -> None:
    p = pipeline(still_vulnerable=True)
    assert import_bundle(pending, p, bundle(), enabled=True) == [Outcome.UNPATCHED]
    with pending() as s:
        assert s.scalars(select(ArtifactRow)).first() is None
        assert s.scalars(select(AttemptRow)).one().outcome == "FAILED"


def test_duplicate_import_loses_to_the_lease(pending: sessionmaker[Session]) -> None:
    p = pipeline()
    with pending() as s:
        acquire_lease(s, 1, "someone-else", 3600.0, p.clock)
    assert import_bundle(pending, p, bundle(), enabled=True) == [Outcome.SKIPPED]


def test_no_matching_row_is_refused(pending: sessionmaker[Session]) -> None:
    other = PATCH.model_copy(update={"component": COMP.model_copy(update={"version": "9.9"})})
    with pytest.raises(ManualImportRefused, match="no affected row"):
        import_bundle(pending, pipeline(), bundle(patch=other), enabled=True)


def write(tmp_path: Path) -> str:
    f = tmp_path / "b.json"
    f.write_text(bundle().model_dump_json())
    return str(f)


def test_cli_refuses_with_flag_off(
    pending: sessionmaker[Session],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MANUAL_ATTEMPTS_ENABLED", raising=False)
    assert cli.main(["attempt-import", write(tmp_path)], factory=pending, pipeline=pipeline()) == 5
    assert "MANUAL_ATTEMPTS_ENABLED" in json.loads(capsys.readouterr().out)["error"]


def test_cli_rejects_an_invalid_bundle(
    pending: sessionmaker[Session],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MANUAL_ATTEMPTS_ENABLED", "1")
    f = tmp_path / "bad.json"
    f.write_text("{nope")
    assert cli.main(["attempt-import", str(f)], factory=pending, pipeline=pipeline()) == 6
    assert "JSON" in json.loads(capsys.readouterr().out)["error"]


def test_cli_without_a_live_pipeline_says_so(
    pending: sessionmaker[Session],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MANUAL_ATTEMPTS_ENABLED", "1")
    assert cli.main(["attempt-import", write(tmp_path)], factory=pending) == 4
    assert "pipeline" in json.loads(capsys.readouterr().out)["error"]


def test_cli_imports_with_flag_on(
    pending: sessionmaker[Session],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MANUAL_ATTEMPTS_ENABLED", "1")
    code = cli.main(["attempt-import", write(tmp_path)], factory=pending, pipeline=pipeline())
    assert code == 0
    assert json.loads(capsys.readouterr().out) == {"outcomes": ["published"]}
