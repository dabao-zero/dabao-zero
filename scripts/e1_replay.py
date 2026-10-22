"""Replay one E1 bundle through the live Debian pipeline and print what the gates said.

Needs Docker with a docker-container buildx builder, network, and `trivy` and `grype` on PATH.
Builds the patched image, scans before and after, runs the smoke commands and records the attempt
in a SQLite ledger. Nothing is published: the registry and signer are fakes.

    uv run python scripts/e1_replay.py BUNDLE.json --work DIR --db ledger.db --builder NAME
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import replace
from pathlib import Path

from sqlalchemy import select

from dabao import fakes
from dabao.bundle import load_bundle
from dabao.db import make_engine, make_session_factory
from dabao.debian import DebianAdapter, DebianBase
from dabao.gates import GateConfig
from dabao.live import GrypeScanner, ImageSource, OciDiffer, SmokeSuiteRunner, TrivyScanner
from dabao.manual import import_bundle
from dabao.orchestrator import Limits, Pipeline
from dabao.orm import AdvisoryRow, AffectedRow, AttemptRow, Base

BASE = DebianBase(
    image="debian:bookworm-20240110-slim",
    digest="sha256:f4a83aa865a2b4a064ff142aa91c713180df9fcb86ce676b5de2981029379c37",
    snapshot="20240110T000000Z",
    source_date_epoch=1704844800,
)
SMOKE = [
    "dpkg-query -W -f='${Version}' tar | grep -q 'dabao1'",
    "cd /tmp && echo hello > a && tar -cf t.tar a && rm a && tar -xf t.tar && grep -q hello a",
    "cd /tmp && tar --format=pax -cf p.tar /etc/hostname && tar -tf p.tar | grep -q hostname",
]


class Clock:
    def now(self) -> float:
        return time.time()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("bundle", type=Path)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--builder", default="dabao-builder")
    args = p.parse_args()

    bundle = load_bundle(args.bundle.read_text())
    comp = bundle.patch.component
    engine = make_engine(f"sqlite+pysqlite:///{args.db}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as s:
        if s.get(AdvisoryRow, bundle.patch.advisory_id) is None:
            s.add(AdvisoryRow(id=bundle.patch.advisory_id))
        s.add(
            AffectedRow(
                advisory_id=bundle.patch.advisory_id,
                stream=comp.stream,
                image="debian",
                package=comp.package,
                version=comp.version,
                created_at=time.time(),
            )  # fmt: skip
        )
        s.commit()

    adapter = DebianAdapter(BASE, args.work, builder=args.builder)
    source = ImageSource(BASE.digest, BASE.image, adapter.archives)
    scanners = (TrivyScanner(source), GrypeScanner(source))
    pipeline = Pipeline(
        agent=fakes.FakeAgentRunner(),  # replaced by the bundle in import_bundle
        adapter=adapter,
        scanners=scanners,
        suite_runner=SmokeSuiteRunner(source, SMOKE, builder=args.builder),
        differ=OciDiffer(source),
        registry=fakes.FakeRegistry(),
        signer=fakes.FakeSigner(),
        clock=Clock(),
        gates=GateConfig(
            provenance_allowlist=("https://git.savannah.gnu.org/cgit/tar.git/commit/",)
        ),
        limits=Limits(),
    )
    started = time.time()
    outcomes = import_bundle(factory, replace(pipeline), bundle, enabled=True)
    with factory() as s:
        attempt = s.scalars(select(AttemptRow).order_by(AttemptRow.id.desc())).first()
        verdict = json.loads(attempt.verdict) if attempt and attempt.verdict else None
        print(
            json.dumps(
                {
                    "outcomes": [o.value for o in outcomes],
                    "attempt_outcome": attempt.outcome if attempt else None,
                    "runner": attempt.runner if attempt else None,
                    "seconds": round(time.time() - started),
                    "gates": verdict,
                    "log_tail": attempt.log[-300:] if attempt else None,
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
