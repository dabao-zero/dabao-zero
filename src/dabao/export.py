"""Export the public ledger as static JSON for GitHub Pages (ADR-0012).

The files are the responses of the read-only `/v1` endpoints the frontend uses, written under
`<out>/v1/` with a `.json` suffix, plus `meta.json` with the export time. The export goes through
the real API app, so it can never show a field the API would not. Nothing else is read: no operator
endpoint, no database table the API does not serve.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from dabao.api import create_app
from dabao.fakes import FakeClock
from dabao.settings import Settings

RUNS_LIMIT = 20
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class ExportError(Exception):
    """The ledger could not be exported; nothing is left half written."""


def _write(root: Path, rel: str, data: object) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def export_site(factory: sessionmaker[Session], out: Path, now: float) -> list[str]:
    """Write the snapshot into `out`, replacing its `v1` directory. Returns the files written."""
    client = TestClient(create_app(factory, Settings(operator_token=None), FakeClock(now)))

    def get(path: str) -> object:
        res = client.get(path)
        if res.status_code != 200:
            raise ExportError(f"{path} answered {res.status_code}")
        return res.json()

    images = get("/v1/images")
    assert isinstance(images, list)
    files: dict[str, object] = {
        "v1/images.json": images,
        "v1/stats.json": get("/v1/stats"),
        "v1/runs.json": get(f"/v1/runs?limit={RUNS_LIMIT}"),
        "v1/meta.json": {"generated_at": now},
    }
    advisory_ids: set[str] = set()
    for img in images:
        name = img["name"]
        if not _SAFE.match(name):
            raise ExportError(f"image name is not safe as a file name: {name!r}")
        detail = get(f"/v1/images/{name}")
        assert isinstance(detail, dict)
        files[f"v1/images/{name}.json"] = detail
        advisory_ids.update(a["advisory_id"] for a in detail["advisories"])
    for adv in advisory_ids:
        if not _SAFE.match(adv):
            raise ExportError(f"advisory id is not safe as a file name: {adv!r}")
        files[f"v1/advisories/{adv}.json"] = get(f"/v1/advisories/{adv}")

    v1 = out / "v1"
    if v1.exists():
        for old in sorted(v1.rglob("*"), reverse=True):
            old.unlink() if old.is_file() else old.rmdir()
        v1.rmdir()
    for rel, data in files.items():
        _write(out, rel, data)
    return sorted(files)
