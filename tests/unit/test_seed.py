"""The README quick start depends on the demo seed, so it is tested like code."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dabao.api import create_app

SEED = Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"


def run_seed(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("DATABASE_URL", url)
    spec = importlib.util.spec_from_file_location("seed_demo", SEED)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()


def test_seed_produces_a_realistic_catalog_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'demo.db'}"
    run_seed(monkeypatch, url)
    run_seed(monkeypatch, url)
    assert "already present" in capsys.readouterr().out
    client = TestClient(create_app())
    images = {i["name"]: i for i in client.get("/v1/images").json()}
    assert set(images) == {"nginx", "postgres", "redis", "python", "node", "httpd"}
    assert all(i["description"] for i in images.values())
    assert images["nginx"]["bases"] == ["alpine", "debian"] and images["nginx"]["open"] == 1
    assert images["python"]["open"] == 0 and images["python"]["fixed"] == 4
    nginx = client.get("/v1/images/nginx").json()
    assert {t["status"] for t in nginx["tags"]} == {"PUBLISHED", "REVOKED"}
    assert [t["tag"] for t in nginx["tags"]][0] == "1.22.0-1-dabao1"  # newest first
    fixed = client.get("/v1/advisories/DEMO-0001").json()["affected"][0]["attempts"][0]
    assert [g["passed"] for g in fixed["gates"]] == [True] * 5
    stalled = client.get("/v1/advisories/DEMO-0003").json()["affected"][0]["attempts"][0]
    assert [g["name"] for g in stalled["gates"] if not g["passed"]] == ["scanners_clear"]
    assert client.get("/v1/stats").json()["fixes"] == 13
