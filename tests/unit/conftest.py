from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy.orm import Session, sessionmaker

from dabao.db import make_engine, make_session_factory
from dabao.fakes import FakeClock
from dabao.models import AdvisoryStatus
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, AttemptRow, Base, PatchRow


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(1_000.0)


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    engine = make_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield make_session_factory(engine)
    engine.dispose()


@pytest.fixture
def seeded(factory: sessionmaker[Session]) -> sessionmaker[Session]:
    with factory() as s:
        s.add(AdvisoryRow(id="CVE-2024-0001", aliases="GHSA-aaaa-bbbb-cccc"))
        s.add(AdvisoryRow(id="CVE-2024-0002", aliases=""))
        s.add_all(
            [
                AffectedRow(
                    id=1,
                    advisory_id="CVE-2024-0001",
                    stream="debian",
                    image="nginx",
                    package="nginx",
                    version="1.22.0-1",
                    status=AdvisoryStatus.PATCHED.value,
                    created_at=100.0,
                    patched_at=400.0,
                ),
                AffectedRow(
                    id=2,
                    advisory_id="CVE-2024-0002",
                    stream="debian",
                    image="nginx",
                    package="libssl3",
                    version="3.0.1",
                    status=AdvisoryStatus.UNPATCHED.value,
                    created_at=200.0,
                ),
            ]
        )
        s.add(
            AttemptRow(
                id=1,
                affected_id=1,
                outcome="SUCCEEDED",
                started_at=110.0,
                finished_at=390.0,
                tokens_in=1000,
                tokens_out=200,
                cost_usd=0.5,
            )
        )
        s.add(
            PatchRow(
                attempt_id=1,
                source="upstream_derived",
                upstream_ref="https://github.com/nginx/nginx/commit/abc",
                diff="--- a/x\n+++ b/x\n",
            )
        )
        s.add(
            ArtifactRow(
                digest="sha256:aaa",
                image="nginx",
                tag="1.22.0-dabao1",
                stream="debian",
                published_at=400.0,
            )
        )
        s.commit()
    return factory
