"""Scan stock official images with Trivy and Grype, no VEX, for the baseline (DAB-74, ADR-0011).

Needs `trivy` and `grype` on PATH and network access. Images are read through
`mirror.gcr.io/library` (no Docker daemon, no Docker Hub rate limit). Each image is tried as
`:latest` and `:alpine`; the base actually found is taken from the scanner, not from the tag.

    uv run python scripts/baseline_scan.py --out docs/baseline-scan
"""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from dabao.baseline import Counts, summarise_grype, summarise_trivy

IMAGES = [
    "nginx", "postgres", "redis", "python", "node", "httpd", "memcached", "haproxy",
    "rabbitmq", "golang", "php", "ruby", "mariadb", "mysql", "eclipse-temurin",
]  # fmt: skip
TAGS = ["latest", "alpine"]
MIRROR = "mirror.gcr.io/library"
TRIVY_LOCK = threading.Lock()  # trivy's cache allows one process at a time; grype runs in parallel


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=1500, check=False)


def scan(image: str, tag: str) -> dict[str, object]:
    ref = f"{MIRROR}/{image}:{tag}"
    with TRIVY_LOCK:
        t = run(["trivy", "image", "--quiet", "--image-src", "remote", "--format", "json",
                 "--scanners", "vuln", ref])  # fmt: skip
    if t.returncode != 0:
        err = t.stderr
        msg = "no such tag" if "MANIFEST_UNKNOWN" in err else err.strip().splitlines()[-1][:160]
        return {"image": image, "tag": tag, "error": msg}
    trivy, base, digest = summarise_trivy(t.stdout)
    g = run(["grype", f"registry:{ref}", "-o", "json", "-q"])
    if g.returncode != 0:
        return {"image": image, "tag": tag, "error": "grype: " + g.stderr.strip()[-200:]}
    return {
        "image": image, "tag": tag, "base": base, "digest": digest,
        "trivy": asdict(trivy), "grype": asdict(summarise_grype(g.stdout)),
    }  # fmt: skip


def table(rows: list[dict[str, object]]) -> str:
    out = [
        "| image:tag | base | Trivy total / fixable | Grype total / fixable "
        "| fixable HIGH+ (Trivy) |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        name = f"{r['image']}:{r['tag']}"
        if "error" in r:
            out.append(f"| {name} | n/a | {r['error']} | | |")
            continue
        t, g = Counts(**r["trivy"]), Counts(**r["grype"])  # type: ignore[arg-type]
        out.append(
            f"| {name} | {r['base']} | {t.total} / {t.fixable} | {g.total} / {g.fixable} "
            f"| {t.fixable_high} |"
        )
    return "\n".join(out)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True, help="path prefix; writes .json")
    args = p.parse_args()
    jobs = [(i, t) for i in IMAGES for t in TAGS]
    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = list(pool.map(lambda j: scan(*j), jobs))
    versions = {
        "trivy": run(["trivy", "--version"]).stdout.splitlines()[0],
        "grype": run(["grype", "version"]).stdout.splitlines()[1].split()[-1],
    }
    doc = {
        "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "versions": versions,
        "rows": rows,
    }
    args.out.with_suffix(".json").write_text(json.dumps(doc, indent=2) + "\n")
    print(table(rows))


if __name__ == "__main__":
    main()
