"""HTTP API. Only the health endpoint exists yet (observability floor)."""

from fastapi import FastAPI

app = FastAPI(title="dabao", version="0.0.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
