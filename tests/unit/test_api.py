from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from dabao.api import create_app
from dabao.fakes import FakeClock
from dabao.settings import Settings


def client(
    seeded: sessionmaker[Session], clock: FakeClock, token: str | None = "s3cret"
) -> TestClient:
    return TestClient(create_app(seeded, Settings(operator_token=token), clock))


def test_healthz(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    assert client(seeded, clock).get("/healthz").json() == {"status": "ok"}


def test_images_summary_includes_median_time_to_patch(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    (img,) = client(seeded, clock).get("/v1/images").json()
    assert img == {
        "name": "nginx",
        "total": 2,
        "patched": 1,
        "unpatched": 1,
        "pending": 0,
        "median_time_to_patch_s": 300.0,
    }


def test_image_detail_and_unknown_image(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    c = client(seeded, clock)
    assert [r["advisory_id"] for r in c.get("/v1/images/nginx").json()] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]
    assert c.get("/v1/images/nope").status_code == 404


def test_advisory_list_filters_by_status(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    rows = client(seeded, clock).get("/v1/advisories", params={"status": "UNPATCHED"}).json()
    assert [r["advisory_id"] for r in rows] == ["CVE-2024-0002"]


def test_advisory_detail_has_attempts_and_patch_diff(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    body = client(seeded, clock).get("/v1/advisories/CVE-2024-0001").json()
    assert body["aliases"] == ["GHSA-aaaa-bbbb-cccc"]
    (attempt,) = body["affected"][0]["attempts"]
    assert attempt["patch_source"] == "upstream_derived"
    assert attempt["patch_diff"].startswith("--- a/x")
    assert client(seeded, clock).get("/v1/advisories/CVE-0000-0000").status_code == 404


def test_revoke_requires_operator_token(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    c = client(seeded, clock)
    url = "/v1/artifacts/sha256:aaa/revoke"
    assert c.post(url, json={"reason": "bad"}).status_code == 401
    assert (
        c.post(url, json={"reason": "bad"}, headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
    assert c.get("/v1/artifacts").json()[0]["status"] == "PUBLISHED"


def test_revoke_fails_closed_when_no_token_configured(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    c = client(seeded, clock, token=None)
    r = c.post(
        "/v1/artifacts/sha256:aaa/revoke",
        json={"reason": "x"},
        headers={"Authorization": "Bearer "},
    )
    assert r.status_code == 503


def test_revoke_marks_artifact_and_is_idempotent(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    c = client(seeded, clock)
    h = {"Authorization": "Bearer s3cret"}
    url = "/v1/artifacts/sha256:aaa/revoke"
    first = c.post(url, json={"reason": "first"}, headers=h).json()
    clock.advance(50)
    again = c.post(url, json={"reason": "second"}, headers=h).json()
    assert first["status"] == "REVOKED" and again["revoked_reason"] == "first"
    assert again["revoked_at"] == first["revoked_at"] == 1000.0
    assert (
        c.post("/v1/artifacts/sha256:nope/revoke", json={"reason": "x"}, headers=h).status_code
        == 404
    )
