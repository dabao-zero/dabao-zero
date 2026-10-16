"""Create ./dabao.db (or $DATABASE_URL) and fill it with clearly fake demo data.

Advisory ids are `DEMO-*`: nothing here is a real vulnerability or a real patch.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config

from dabao.db import make_engine, make_session_factory
from dabao.orm import AdvisoryRow, AffectedRow, ArtifactRow, AttemptRow, PatchRow

ROOT = Path(__file__).resolve().parents[1]
H, D = 3600.0, 86400.0
NOW = 1_800_000_000.0  # fixed so the demo looks the same every time

DIFF = """\
--- a/src/http/ngx_http_request.c
+++ b/src/http/ngx_http_request.c
@@ -1021,7 +1021,9 @@ ngx_http_process_request_headers(ngx_event_t *rev)
-        if (r->header_in->pos == r->header_in->end) {
+        if (r->header_in->pos == r->header_in->end
+            || r->header_in->last < r->header_in->pos)
+        {
"""

# (advisory, image, package, version, status, first seen, patched after, cost)
ROWS = [
    ("DEMO-0001", "nginx", "nginx", "1.22.0-1", "PATCHED", 9 * D, 5 * H, 0.42),
    ("DEMO-0002", "nginx", "libssl3", "3.0.11-1", "PATCHED", 7 * D, 9 * H, 0.77),
    ("DEMO-0003", "nginx", "libxml2", "2.9.14", "UNPATCHED", 6 * D, None, 1.35),
    ("DEMO-0004", "postgres", "libpq5", "15.4-1", "PATCHED", 5 * D, 3 * H, 0.31),
    ("DEMO-0005", "postgres", "postgresql-15", "15.4-1", "PENDING", 4 * H, None, 0.0),
    ("DEMO-0006", "redis", "redis-server", "7.0.12", "PATCHED", 3 * D, 22 * H, 0.95),
    ("DEMO-0007", "redis", "libc6", "2.36-9", "NEEDS_HUMAN", 2 * D, None, 5.40),
]


def main() -> None:
    url = os.environ.get("DATABASE_URL", "sqlite+pysqlite:///./dabao.db")
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")

    factory = make_session_factory(make_engine(url))
    with factory() as s:
        if s.get(AdvisoryRow, "DEMO-0001") is not None:
            print("demo data already present")
            return
        for i, (adv, image, pkg, ver, status, ago, took, cost) in enumerate(ROWS, start=1):
            first_seen = NOW - ago
            patched_at = first_seen + took if took is not None else None
            s.add(AdvisoryRow(id=adv, aliases=f"GHSA-demo-{i:04d}"))
            s.add(
                AffectedRow(
                    id=i,
                    advisory_id=adv,
                    stream="debian",
                    image=image,
                    package=pkg,
                    version=ver,
                    status=status,
                    created_at=first_seen,
                    patched_at=patched_at,
                )
            )
            if status == "PENDING":
                continue
            outcome = "SUCCEEDED" if status == "PATCHED" else "FAILED"
            s.add(
                AttemptRow(
                    id=i,
                    affected_id=i,
                    outcome=outcome,
                    started_at=first_seen + 60,
                    finished_at=patched_at or first_seen + H,
                    tokens_in=41_000,
                    tokens_out=3_200,
                    cost_usd=cost,
                    log=""
                    if status == "PATCHED"
                    else "gates failed: scanners_clear"
                    if status == "UNPATCHED"
                    else "cost cap exceeded",
                )
            )
            if status == "PATCHED":
                s.add(
                    PatchRow(
                        attempt_id=i,
                        source="upstream_derived",
                        diff=DIFF,
                        upstream_ref=f"https://example.invalid/{image}/commit/demo{i}",
                    )
                )
                s.add(
                    ArtifactRow(
                        digest=f"sha256:demo{i:060d}",
                        image=image,
                        tag=f"{ver}-dabao1",
                        stream="debian",
                        published_at=patched_at or NOW,
                    )
                )
        s.commit()
    print(f"seeded demo data into {url}")


if __name__ == "__main__":
    main()
