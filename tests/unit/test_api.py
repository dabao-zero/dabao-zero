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


def test_images_summary_has_catalog_fields(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    (img,) = client(seeded, clock).get("/v1/images").json()
    assert img["name"] == "nginx"
    assert (img["open"], img["fixed"], img["total"]) == (1, 1, 2)
    assert (img["patched"], img["unpatched"], img["pending"], img["needs_human"]) == (1, 1, 0, 0)
    assert img["bases"] == ["debian"]
    assert img["latest_tag"] == "1.22.0-dabao1" and img["updated_at"] == 400.0
    assert img["median_time_to_patch_s"] == 300.0
    assert img["description"] == ""  # no catalog row yet: empty, not an error


def test_image_detail_has_tags_and_advisories_and_unknown_is_404(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    c = client(seeded, clock)
    body = c.get("/v1/images/nginx").json()
    assert [a["advisory_id"] for a in body["advisories"]] == ["CVE-2024-0001", "CVE-2024-0002"]
    (tag,) = body["tags"]
    assert (tag["tag"], tag["status"], tag["open_cves"], tag["fixed_cves"]) == (
        "1.22.0-dabao1",
        "PUBLISHED",
        1,
        1,
    )
    assert c.get("/v1/images/nope").status_code == 404


def test_stats_and_runs(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    c = client(seeded, clock)
    assert c.get("/v1/stats").json() == {
        "attempts": 1,
        "fixes": 1,
        "median_time_to_fix_s": 300.0,
        "median_cost_per_fix_usd": 0.5,
        "failed_spend_usd": 0.0,
        "total_spend_usd": 0.5,
    }
    (run,) = c.get("/v1/runs").json()
    assert (run["advisory_id"], run["image"], run["outcome"], run["duration_s"]) == (
        "CVE-2024-0001",
        "nginx",
        "SUCCEEDED",
        280.0,
    )
    assert c.get("/v1/runs", params={"limit": 0}).status_code == 422
    assert c.get("/v1/runs", params={"limit": 101}).status_code == 422


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


def test_status_reports_freeze_state(seeded: sessionmaker[Session], clock: FakeClock) -> None:
    from dabao import operator

    c = client(seeded, clock)
    assert c.get("/v1/status").json() == {"frozen": False}
    with seeded() as s:
        operator.freeze(s, "incident", 1.0)
    assert c.get("/v1/status").json() == {"frozen": True}


def test_advisory_detail_includes_gates_and_ignores_malformed_entries(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    import json

    from dabao.orm import AttemptRow

    with seeded() as s:
        att = s.get(AttemptRow, 1)
        assert att is not None
        att.verdict = json.dumps(
            [{"name": "tests_pass", "passed": True, "reason": "ok"}, {"name": "broken"}]
        )
        s.commit()
    body = client(seeded, clock).get("/v1/advisories/CVE-2024-0001").json()
    gates = body["affected"][0]["attempts"][0]["gates"]
    assert gates == [{"name": "tests_pass", "passed": True, "reason": "ok"}]


def test_attempts_and_runs_say_who_ran_them(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    from dabao.orm import AttemptRow

    c = client(seeded, clock)
    assert c.get("/v1/runs").json()[0]["runner"] == "agent"
    assert c.get("/v1/advisories/CVE-2024-0001").json()["affected"][0]["attempts"][0]["runner"] == (
        "agent"
    )
    with seeded() as s:
        s.get(AttemptRow, 1).runner = "manual_codex"  # type: ignore[union-attr]
        s.commit()
    assert c.get("/v1/runs").json()[0]["runner"] == "manual_codex"
    body = c.get("/v1/advisories/CVE-2024-0001").json()
    assert body["affected"][0]["attempts"][0]["runner"] == "manual_codex"


def test_attempts_and_runs_report_agent_time(
    seeded: sessionmaker[Session], clock: FakeClock
) -> None:
    from dabao.orm import AttemptRow

    c = client(seeded, clock)
    assert c.get("/v1/runs").json()[0]["agent_seconds"] is None  # old rows have no figure
    with seeded() as s:
        s.get(AttemptRow, 1).agent_seconds = 378.0  # type: ignore[union-attr]
        s.commit()
    assert c.get("/v1/runs").json()[0]["agent_seconds"] == 378.0
    body = c.get("/v1/advisories/CVE-2024-0001").json()
    assert body["affected"][0]["attempts"][0]["agent_seconds"] == 378.0
