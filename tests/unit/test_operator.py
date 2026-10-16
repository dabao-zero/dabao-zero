from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from dabao import cli, operator
from dabao.fakes import FakeClock
from dabao.orm import AffectedRow


def run(
    f: sessionmaker[Session], capsys: pytest.CaptureFixture[str], *argv: str
) -> tuple[int, Any]:
    code = cli.main(list(argv), factory=f, now=FakeClock(500.0).now)
    out = capsys.readouterr().out.strip()
    return code, json.loads(out) if out else None


def test_freeze_unfreeze_status_and_checks(
    seeded: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    check = operator.frozen_check(seeded)
    assert check() is False
    assert run(seeded, capsys, "freeze", "--note", "incident") == (0, {"frozen": True})
    assert check() is True  # read fresh from the database on every call
    code, st = run(seeded, capsys, "status")
    assert code == 0 and st["frozen"] is True and st["affected"] == {"PATCHED": 1, "UNPATCHED": 1}
    assert run(seeded, capsys, "unfreeze", "--note", "resolved") == (0, {"frozen": False})
    assert check() is False


def test_revoke_via_cli_marks_artifact_and_feeds_the_signer_check(
    seeded: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    revoked = operator.revoked_check(seeded)
    assert revoked("sha256:aaa") is False and revoked("sha256:nope") is False
    code, out = run(seeded, capsys, "revoke", "sha256:aaa", "--reason", "bad build")
    assert (code, out["status"], out["reason"]) == (0, "REVOKED", "bad build")
    assert revoked("sha256:aaa") is True
    code, out = run(seeded, capsys, "revoke", "sha256:nope", "--reason", "x")
    assert (code, out) == (1, {"error": "unknown artifact"})


def test_rerun_requeues_only_failed_and_unleased_rows(
    seeded: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(seeded, capsys, "rerun", "CVE-2024-0002") == (0, {"queued": 1})
    with seeded() as s:
        row = s.get(AffectedRow, 2)
        assert row is not None and row.status == "PENDING"
    # nothing left to queue for it, and a PATCHED row is never re-queued
    assert run(seeded, capsys, "rerun", "CVE-2024-0002")[0] == 1
    assert run(seeded, capsys, "rerun", "CVE-2024-0001") == (1, {"queued": 0})


def test_rerun_skips_leased_rows(
    seeded: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    with seeded() as s:
        row = s.get(AffectedRow, 2)
        assert row is not None
        row.lease_owner = "worker-a"
        s.commit()
    assert run(seeded, capsys, "rerun", "CVE-2024-0002") == (1, {"queued": 0})


def test_bad_usage_is_exit_code_2(
    seeded: sessionmaker[Session], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["freeze"], factory=seeded) == 2  # --note is required
    assert cli.main([], factory=seeded) == 2
    capsys.readouterr()


def test_unmigrated_database_is_a_clean_error_not_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dabao.db import make_engine, make_session_factory

    empty = make_session_factory(make_engine("sqlite+pysqlite:///:memory:"))
    code = cli.main(["status"], factory=empty)
    out = json.loads(capsys.readouterr().out)
    assert code == 3 and "alembic upgrade head" in out["error"]
