"""Create ./dabao.db (or $DATABASE_URL) and fill it with clearly fake demo data.

Advisory ids are `DEMO-*` and source URLs are `example.invalid`: nothing here is a real
vulnerability, patch or published image.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from alembic import command
from alembic.config import Config

from dabao.db import make_engine, make_session_factory
from dabao.orm import (
    AdvisoryRow,
    AffectedRow,
    ArtifactRow,
    AttemptRow,
    ImageRow,
    PatchRow,
    ScanFindingRow,
)

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

IMAGES = [
    ("nginx", "HTTP server and reverse proxy."),
    ("postgres", "Relational database."),
    ("redis", "In-memory data store, cache and message broker."),
    ("python", "Python runtime for applications and tooling."),
    ("node", "JavaScript runtime for servers and build tools."),
    ("httpd", "Apache HTTP server."),
]

# (advisory, image, stream, package, version, status, first seen ago, fixed after, cost)
ROWS = [
    ("DEMO-0001", "nginx", "debian", "nginx", "1.22.0-1", "PATCHED", 9 * D, 5 * H, 0.42),
    ("DEMO-0002", "nginx", "debian", "libssl3", "3.0.11-1", "PATCHED", 7.5 * D, 9 * H, 0.77),
    ("DEMO-0003", "nginx", "debian", "libxml2", "2.9.14", "UNPATCHED", 8 * D, None, 1.35),
    ("DEMO-0004", "postgres", "debian", "libpq5", "15.4-1", "PATCHED", 5 * D, 3 * H, 0.31),
    ("DEMO-0005", "postgres", "debian", "postgresql-15", "15.4-1", "PENDING", 4 * H, None, 0.0),
    ("DEMO-0006", "redis", "debian", "redis-server", "7.0.12", "PATCHED", 3 * D, 22 * H, 0.95),
    ("DEMO-0007", "redis", "debian", "libc6", "2.36-9", "NEEDS_HUMAN", 2 * D, None, 5.40),
    ("DEMO-0008", "python", "debian", "python3.12", "3.12.4-1", "PATCHED", 6 * D, 4 * H, 0.38),
    ("DEMO-0009", "python", "alpine", "python3", "3.12.4-r0", "PATCHED", 6 * D, 6 * H, 0.44),
    ("DEMO-0010", "python", "debian", "libexpat1", "2.5.0-1", "PATCHED", 4 * D, 2 * H, 0.21),
    ("DEMO-0011", "python", "debian", "zlib1g", "1.2.13", "PATCHED", 2 * D, 3 * H, 0.27),
    ("DEMO-0012", "node", "debian", "nodejs", "22.9.0-1", "PATCHED", 5 * D, 7 * H, 0.52),
    ("DEMO-0013", "node", "debian", "libssl3", "3.0.11-1", "PATCHED", 4 * D, 8 * H, 0.61),
    ("DEMO-0014", "node", "debian", "libnghttp2", "1.52.0", "PATCHED", 3 * D, 5 * H, 0.35),
    ("DEMO-0015", "httpd", "alpine", "apache2", "2.4.62-r0", "PATCHED", 6 * D, 6 * H, 0.47),
    ("DEMO-0016", "httpd", "alpine", "apr", "1.7.4-r0", "PATCHED", 6 * D, 4 * H, 0.29),
]

# (image, tag, stream, published ago, status, revoked reason)
ARTIFACTS = [
    ("nginx", "1.22.0-1-dabao1", "debian", 7 * D, "PUBLISHED", None),
    ("nginx", "1.22.0-r0-dabao1", "alpine", 8 * D, "PUBLISHED", None),
    ("nginx", "1.20.2-1-dabao4", "debian", 30 * D, "PUBLISHED", None),
    ("nginx", "1.22.0-1-dabao0", "debian", 12 * D, "REVOKED", "Build changed an unrelated file"),
    ("postgres", "15.4-1-dabao1", "debian", 5 * D - 3 * H, "PUBLISHED", None),
    ("redis", "7.0.12-dabao1", "debian", 3 * D - 22 * H, "PUBLISHED", None),
    ("python", "3.12.4-dabao2", "debian", 2 * D - 3 * H, "PUBLISHED", None),
    ("python", "3.12.4-r0-dabao1", "alpine", 6 * D - 6 * H, "PUBLISHED", None),
    ("node", "22.9.0-dabao1", "debian", 3 * D - 5 * H, "PUBLISHED", None),
    ("httpd", "2.4.62-dabao1", "alpine", 6 * D - 4 * H, "PUBLISHED", None),
]


def verdict(status: str, ref: str) -> str | None:
    gates = [
        ("advisory_present_before", True, "reported by ['grype', 'trivy']"),
        ("scanners_clear", status == "PATCHED", "all scanners clear"),
        ("tests_pass", True, "test suite passed"),
        ("build_diff", True, "1 changed file(s), all expected"),
        ("provenance", True, f"derived from {ref}"),
    ]
    if status == "NEEDS_HUMAN":
        return None  # stopped by the cost cap before any gate ran
    if status == "UNPATCHED":
        gates[1] = ("scanners_clear", False, "still reported by ['grype']")
    return json.dumps([{"name": n, "passed": p, "reason": r} for n, p, r in gates])


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
        for name, desc in IMAGES:
            s.add(
                ImageRow(
                    name=name,
                    description=desc,
                    upstream=f"docker.io/library/{name}",
                    created_at=NOW - 40 * D,
                )
            )
        for i, (adv, image, stream, pkg, ver, status, ago, took, cost) in enumerate(ROWS, start=1):
            first_seen = NOW - ago
            patched_at = first_seen + took if took is not None else None
            ref = f"https://example.invalid/{image}/commit/demo{i}"
            s.add(AdvisoryRow(id=adv, aliases=f"GHSA-demo-{i:04d}"))
            s.add(
                AffectedRow(
                    id=i,
                    advisory_id=adv,
                    stream=stream,
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
            log = {"PATCHED": "", "UNPATCHED": "gates failed: scanners_clear"}.get(
                status, "cost cap exceeded"
            )
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
                    log=log,
                    verdict=verdict(status, ref),
                )
            )
            if status == "PATCHED":
                s.add(
                    PatchRow(attempt_id=i, source="upstream_derived", upstream_ref=ref, diff=DIFF)
                )
        for n, (image, tag, stream, ago, status, reason) in enumerate(ARTIFACTS, start=1):
            published = NOW - ago
            s.add(
                ArtifactRow(
                    digest=f"sha256:demo{n:060d}",
                    image=image,
                    tag=tag,
                    stream=stream,
                    status=status,
                    published_at=published,
                    revoked_at=published + D if status == "REVOKED" else None,
                    revoked_reason=reason,
                )
            )
        # python is fully fixed, but scanners still report two CVEs nobody has fixed (fake ids)
        live = [
            (NOW - ago, n)
            for n, (image, _tag, _stream, ago, status, _reason) in enumerate(ARTIFACTS, start=1)
            if image == "python" and status == "PUBLISHED"
        ]
        digest = f"sha256:demo{max(live)[1]:060d}"
        s.flush()
        for scanner in ("grype", "trivy"):
            for adv, pkg, sev in (
                ("DEMO-9001", "libdemo1", "MEDIUM"),
                ("DEMO-9002", "demo-tools", "LOW"),
            ):
                s.add(
                    ScanFindingRow(
                        artifact_digest=digest,
                        scanner=scanner,
                        advisory_id=adv,
                        package=pkg,
                        severity=sev,
                        fix_state="unfixed",
                        created_at=NOW,
                    )  # fmt: skip
                )
        s.commit()
    print(f"seeded demo data into {url}")


if __name__ == "__main__":
    main()
