from __future__ import annotations

import json

from sqlalchemy.orm import Session, sessionmaker

from dabao import catalog
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, AttemptRow, ImageRow


def seed(f: sessionmaker[Session]) -> None:
    with f() as s:
        s.add_all([AdvisoryRow(id=f"CVE-{i}", aliases="") for i in range(1, 6)])
        s.add(
            ImageRow(
                name="nginx",
                description="HTTP server",
                upstream="docker.io/library/nginx",
                created_at=0.0,
            )
        )
        s.add(ImageRow(name="empty", description="Nothing yet", created_at=0.0))

        def row(
            i: int, adv: int, image: str, stream: str, status: str, seen: float, fixed: float | None
        ) -> AffectedRow:
            return AffectedRow(
                id=i,
                advisory_id=f"CVE-{adv}",
                stream=stream,
                image=image,
                package="p",
                version="1",
                status=status,
                created_at=seen,
                patched_at=fixed,
            )

        s.add_all(
            [
                row(1, 1, "nginx", "debian", "PATCHED", 100.0, 200.0),
                row(2, 2, "nginx", "debian", "PATCHED", 100.0, 500.0),
                row(3, 3, "nginx", "debian", "UNPATCHED", 150.0, None),
                row(4, 4, "nginx", "alpine", "NEEDS_HUMAN", 150.0, None),
                row(5, 5, "redis", "debian", "PENDING", 900.0, None),
            ]
        )
        # an older tag (published at 300) and a newer one (600), plus a revoked one
        s.add_all(
            [
                ArtifactRow(
                    digest="sha256:old",
                    image="nginx",
                    tag="1-dabao1",
                    stream="debian",
                    published_at=300.0,
                ),
                ArtifactRow(
                    digest="sha256:new",
                    image="nginx",
                    tag="1-dabao2",
                    stream="debian",
                    published_at=600.0,
                ),
                ArtifactRow(
                    digest="sha256:bad",
                    image="nginx",
                    tag="1-dabao0",
                    stream="debian",
                    published_at=700.0,
                    status="REVOKED",
                    revoked_at=710.0,
                    revoked_reason="broken",
                ),
            ]
        )
        s.commit()


def test_summaries_union_catalog_rows_and_ledger_images(factory: sessionmaker[Session]) -> None:
    seed(factory)
    with factory() as s:
        by = {i.name: i for i in catalog.image_summaries(s)}
    assert set(by) == {"nginx", "empty", "redis"}
    n = by["nginx"]
    assert (n.description, n.upstream) == ("HTTP server", "docker.io/library/nginx")
    assert n.bases == ["alpine", "debian"]
    assert (n.total, n.open, n.fixed) == (4, 2, 2)
    assert (n.unpatched, n.needs_human, n.pending) == (1, 1, 0)
    assert n.median_time_to_patch_s == 250.0  # (100 and 400) -> 250
    assert (n.latest_tag, n.updated_at) == ("1-dabao2", 600.0)  # the revoked tag is never latest
    e = by["empty"]
    assert (e.total, e.open, e.latest_tag, e.bases) == (0, 0, None, [])
    assert by["redis"].open == 1 and by["redis"].description == ""


def test_tag_counts_reflect_what_was_known_and_fixed_at_publish_time(
    factory: sessionmaker[Session],
) -> None:
    seed(factory)
    with factory() as s:
        found = catalog.get_image(s, "nginx")
    assert found is not None
    _, tags, rows = found
    by = {t.tag: t for t in tags}
    assert [t.tag for t in tags] == ["1-dabao0", "1-dabao2", "1-dabao1"]  # newest first
    # old tag (300): CVE-1 was fixed by then (200). CVE-2 was fixed later (500) so it is not open
    # now; it is neither "open" nor "fixed" for this tag. CVE-3 (150) is known and still open.
    assert (by["1-dabao1"].open_cves, by["1-dabao1"].fixed_cves) == (1, 1)
    # new tag (600): CVE-1 and CVE-2 fixed; CVE-3 (150) is still open
    assert (by["1-dabao2"].open_cves, by["1-dabao2"].fixed_cves) == (1, 2)
    assert by["1-dabao0"].status == "REVOKED" and by["1-dabao0"].revoked_reason == "broken"
    # alpine rows never count against a debian tag
    assert all(r.stream in ("debian", "alpine") for r in rows)


def test_unknown_image_is_none(factory: sessionmaker[Session]) -> None:
    seed(factory)
    with factory() as s:
        assert catalog.get_image(s, "nope") is None


def test_stats_and_runs(factory: sessionmaker[Session]) -> None:
    seed(factory)
    with factory() as s:
        s.add_all(
            [
                AttemptRow(
                    id=1,
                    affected_id=1,
                    outcome="SUCCEEDED",
                    started_at=110.0,
                    finished_at=200.0,
                    cost_usd=0.4,
                ),
                AttemptRow(
                    id=2,
                    affected_id=2,
                    outcome="SUCCEEDED",
                    started_at=120.0,
                    finished_at=500.0,
                    cost_usd=0.8,
                ),
                AttemptRow(
                    id=3,
                    affected_id=3,
                    outcome="FAILED",
                    started_at=160.0,
                    finished_at=170.0,
                    cost_usd=1.5,
                ),
                AttemptRow(id=4, affected_id=4, outcome="RUNNING", started_at=170.0, cost_usd=9.0),
            ]
        )
        s.commit()
        st = catalog.stats(s)
        runs = catalog.recent_runs(s, limit=2)
    assert (st.attempts, st.fixes) == (3, 2)  # the running attempt is not counted yet
    assert st.median_time_to_fix_s == 250.0
    assert abs(st.median_cost_per_fix_usd - 0.6) < 1e-9  # type: ignore[operator]
    assert st.failed_spend_usd == 1.5 and abs(st.total_spend_usd - 2.7) < 1e-9
    assert [r.attempt_id for r in runs] == [4, 3]  # newest first, limited
    assert runs[0].duration_s is None and runs[1].duration_s == 10.0


def test_stats_on_an_empty_ledger(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        st = catalog.stats(s)
    assert (st.attempts, st.fixes, st.median_time_to_fix_s, st.median_cost_per_fix_usd) == (
        0,
        0,
        None,
        None,
    )


def test_parse_verdict_is_tolerant() -> None:
    assert catalog.parse_verdict(None) is None
    assert catalog.parse_verdict("") is None
    assert catalog.parse_verdict("{not json") is None
    assert catalog.parse_verdict(json.dumps({"a": 1})) is None  # wrong shape
    assert catalog.parse_verdict(json.dumps([{"name": "x", "passed": True, "reason": "ok"}])) == [
        {"name": "x", "passed": True, "reason": "ok"}
    ]
