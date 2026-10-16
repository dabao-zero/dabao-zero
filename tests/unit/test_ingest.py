from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from dabao.ingest import (
    FeedRecord,
    canonical_id,
    ingest,
    is_vulnerable,
    parse_debian_tracker,
    parse_osv,
)
from dabao.orm import AdvisoryRow, AffectedRow

FIX = Path(__file__).resolve().parents[1] / "fixtures"
IMAGES = {
    "nginx": {"nginx": "1.22.0-1", "libssl3": "3.0.11-1~deb12u2", "libxml2": "2.9.14+dfsg-1.3"},
    "redis": {"libssl3": "3.0.11-1~deb12u3"},  # already at the fixed version
}


def osv() -> list[FeedRecord]:
    return parse_osv(json.loads((FIX / "osv_debian.json").read_text()))


def test_canonical_id_prefers_the_lowest_cve() -> None:
    assert canonical_id(["GHSA-x", "CVE-2099-0002", "CVE-2099-0001"]) == "CVE-2099-0001"
    assert canonical_id(["DSA-1-1", "GHSA-x"]) == "DSA-1-1"


def test_parse_osv_keeps_only_the_ecosystem_and_skips_malformed_records() -> None:
    recs = osv()
    assert [(r.id, r.package, r.fixed_version) for r in recs] == [
        ("CVE-2099-0001", "nginx", "1.22.1-9"),
        ("CVE-2099-0001", "libssl3", "3.0.11-1~deb12u3"),
        ("CVE-2099-0003", "libxml2", None),
    ]
    assert recs[0].aliases == ("DSA-9999-1",)
    assert recs[1].aliases == ("CVE-2099-0002", "GHSA-demo-aaaa-bbbb")


def test_parse_debian_tracker_handles_resolved_open_and_not_affected() -> None:
    data = json.loads((FIX / "debian_tracker.json").read_text())
    bookworm = {(r.id, r.fixed_version) for r in parse_debian_tracker(data, "bookworm")}
    assert bookworm == {("CVE-2099-0004", "1.22.1-9+deb12u1"), ("CVE-2099-0005", None)}
    bullseye = parse_debian_tracker(data, "bullseye")
    assert [(r.id, r.fixed_version) for r in bullseye] == [("CVE-2099-0004", "1.18.0-6.1+deb11u9")]


def test_is_vulnerable_uses_dpkg_ordering() -> None:
    assert is_vulnerable("1.22.0-1", "1.22.1-9")
    assert not is_vulnerable("1.22.1-9", "1.22.1-9")
    assert not is_vulnerable("1.22.1-9+b1", "1.22.1-9")
    assert is_vulnerable("1.0~rc1", "1.0")
    assert is_vulnerable("anything", None)


def test_ingest_creates_pending_rows_only_for_vulnerable_installed_packages(
    factory: sessionmaker[Session],
) -> None:
    with factory() as s:
        counts = ingest(s, osv(), IMAGES, now=100.0)
        assert counts == {
            "advisories": 2,
            "affected": 3,
            "skipped_not_installed": 2,
            "skipped_fixed": 1,
        }
        rows = s.scalars(select(AffectedRow).order_by(AffectedRow.id)).all()
        assert {(r.advisory_id, r.image, r.package, r.status) for r in rows} == {
            ("CVE-2099-0001", "nginx", "nginx", "PENDING"),
            ("CVE-2099-0001", "nginx", "libssl3", "PENDING"),
            ("CVE-2099-0003", "nginx", "libxml2", "PENDING"),
        }
        # redis' libssl3 is already fixed, so it has no row
        assert all(r.image == "nginx" for r in rows)


def test_ingest_is_idempotent_and_never_resets_progress(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        ingest(s, osv(), IMAGES, now=100.0)
        row = s.scalars(select(AffectedRow).where(AffectedRow.package == "nginx")).one()
        row.status, row.patched_at = "PATCHED", 150.0
        s.commit()
        again = ingest(s, osv(), IMAGES, now=999.0)
        assert again["advisories"] == 0 and again["affected"] == 0
        assert len(s.scalars(select(AffectedRow)).all()) == 3
        assert len(s.scalars(select(AdvisoryRow)).all()) == 2
        row = s.scalars(select(AffectedRow).where(AffectedRow.package == "nginx")).one()
        assert (row.status, row.patched_at, row.created_at) == ("PATCHED", 150.0, 100.0)


def test_alias_resolution_attaches_new_ids_to_the_existing_advisory(
    factory: sessionmaker[Session],
) -> None:
    with factory() as s:
        ingest(s, [FeedRecord("CVE-2099-0001", (), "nginx", "1.22.1-9")], IMAGES, now=1.0)
        # a later feed names the same issue by a distro id and a GHSA, not the CVE id first
        ingest(
            s,
            [
                FeedRecord(
                    "DSA-9999-1", ("CVE-2099-0001", "GHSA-zzzz"), "libssl3", "3.0.11-1~deb12u3"
                )
            ],
            IMAGES,
            now=2.0,
        )
        advisories = s.scalars(select(AdvisoryRow)).all()
        assert [a.id for a in advisories] == ["CVE-2099-0001"]
        assert set(advisories[0].aliases.split("\n")) == {"DSA-9999-1", "GHSA-zzzz"}
        assert {r.package for r in s.scalars(select(AffectedRow))} == {"nginx", "libssl3"}
