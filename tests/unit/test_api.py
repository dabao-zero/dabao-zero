from fastapi.testclient import TestClient

from dabao.api import app


def test_healthz() -> None:
    assert TestClient(app).get("/healthz").json() == {"status": "ok"}
