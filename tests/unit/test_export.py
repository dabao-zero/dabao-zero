"""ADR-0012: the static snapshot is the API's own responses, and only those."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from dabao.api import create_app
from dabao.export import ExportError, export_site
from dabao.fakes import FakeClock
from dabao.orm import AdvisoryRow, AffectedRow
from dabao.settings import Settings


def load(out: Path, rel: str) -> object:
    return json.loads((out / rel).read_text())


def test_every_file_equals_the_api_response(seeded: sessionmaker[Session], tmp_path: Path) -> None:
    files = export_site(seeded, tmp_path, now=1234.0)
    api = TestClient(create_app(seeded, Settings(operator_token=None), FakeClock(1234.0)))
    assert load(tmp_path, "v1/images.json") == api.get("/v1/images").json()
    assert load(tmp_path, "v1/images/nginx.json") == api.get("/v1/images/nginx").json()
    assert load(tmp_path, "v1/stats.json") == api.get("/v1/stats").json()
    assert load(tmp_path, "v1/runs.json") == api.get("/v1/runs?limit=20").json()
    assert (
        load(tmp_path, "v1/advisories/CVE-2024-0001.json")
        == api.get("/v1/advisories/CVE-2024-0001").json()
    )
    assert load(tmp_path, "v1/meta.json") == {"generated_at": 1234.0}
    assert "v1/advisories/CVE-2024-0002.json" in files


def test_nothing_but_the_public_read_endpoints_is_exported(
    seeded: sessionmaker[Session], tmp_path: Path
) -> None:
    files = export_site(seeded, tmp_path, now=1.0)
    assert all(f.startswith("v1/") and f.endswith(".json") for f in files)
    assert not any("artifacts" in f or "status" in f or "revoke" in f for f in files)


def test_a_rerun_replaces_the_snapshot(seeded: sessionmaker[Session], tmp_path: Path) -> None:
    stale = tmp_path / "v1/images/gone.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("[]")
    export_site(seeded, tmp_path, now=1.0)
    assert not stale.exists()


def test_an_empty_ledger_exports_an_empty_catalog(
    factory: sessionmaker[Session], tmp_path: Path
) -> None:
    export_site(factory, tmp_path, now=1.0)
    assert load(tmp_path, "v1/images.json") == []


def test_an_unsafe_image_name_stops_the_export_and_writes_nothing(
    factory: sessionmaker[Session], tmp_path: Path
) -> None:
    with factory() as s:
        s.add(AdvisoryRow(id="CVE-2024-0009"))
        s.add(
            AffectedRow(
                advisory_id="CVE-2024-0009",
                stream="debian",
                image="../evil",
                package="p",
                version="1",
                created_at=1.0,
            )
        )
        s.commit()
    out = tmp_path / "site"
    with pytest.raises(ExportError, match="not safe"):
        export_site(factory, out, now=1.0)
    assert not out.exists()
