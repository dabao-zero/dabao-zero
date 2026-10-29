"""Replay one E1 patch through the live Debian pipeline and print what the gates said.

Needs Docker with a docker-container buildx builder, network, and `trivy` and `grype` on PATH.
Builds the patched image, scans before and after, runs the smoke commands and records the attempt
in a SQLite ledger. Nothing is published: the registry and signer are fakes.

The patch comes from a manual Codex bundle (ADR-0009):

    uv run python scripts/e1_replay.py BUNDLE.json --work DIR --db ledger.db --builder NAME

or from the unattended LLM agent (DAB-10; needs LLM_API_KEY, LLM_MODEL and optionally
LLM_BASE_URL, see ADR-0008), which looks things up through the allow-listed toolbox:

    uv run python scripts/e1_replay.py --agent --advisory CVE-2022-48303 --package tar \
        --version 1.34+dfsg-1.2 --source-dir ./tar-src --work DIR --db ledger.db --builder NAME
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import replace
from pathlib import Path
from urllib.request import urlopen

from sqlalchemy import select

from dabao import fakes
from dabao.agent import LLMAgentRunner
from dabao.bundle import load_bundle
from dabao.db import make_engine, make_session_factory
from dabao.debian import DebianAdapter, DebianBase
from dabao.gates import GateConfig
from dabao.live import (
    GrypeScanner,
    HttpUpstreamFetcher,
    ImageSource,
    OciDiffer,
    SmokeSuiteRunner,
    TrivyScanner,
    fetch_debian_fix_refs,
)
from dabao.llm import ChatClient, ConfigError, LLMConfig
from dabao.manual import import_bundle
from dabao.models import Component
from dabao.orchestrator import Limits, Pipeline, process
from dabao.orm import AdvisoryRow, AffectedRow, AttemptRow, Base
from dabao.seams import UpstreamFetcher
from dabao.toolbox import SandboxToolBox

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


ALLOWLIST = ("https://git.savannah.gnu.org/cgit/tar.git/commit/",)


def feed_fix_refs(advisory_id: str) -> list[str]:
    """OSV FIX references and the Debian tracker's fix commits for the advisory, read live."""
    refs: set[str] = set(fetch_debian_fix_refs({advisory_id}).get(advisory_id, ()))
    try:
        with urlopen(f"https://api.osv.dev/v1/vulns/{advisory_id}", timeout=30) as resp:  # noqa: S310
            record = json.load(resp)
        refs.update(r["url"] for r in record.get("references", []) if r.get("type") == "FIX")
    except (OSError, ValueError):
        pass
    return sorted(refs)


class Clock:
    def now(self) -> float:
        return time.time()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("bundle", type=Path, nargs="?", help="a candidate bundle (omit with --agent)")
    p.add_argument("--agent", action="store_true", help="use the unattended LLM agent instead")
    p.add_argument("--advisory")
    p.add_argument("--package")
    p.add_argument("--version")
    p.add_argument("--source-dir", type=Path, help="unpacked source the agent may read")
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--builder", default="dabao-builder")
    p.add_argument(
        "--vex", action="store_true", help="let the gate clear the CVE with a VEX (ADR-0010)"
    )
    p.add_argument(
        "--fix-ref",
        action="append",
        default=[],
        help="fix reference for the advisory; default: OSV FIX refs and Debian tracker notes",
    )
    p.add_argument(
        "--upstream-patch",
        type=Path,
        help="read the upstream commit from this file instead of the network (offline runs)",
    )
    args = p.parse_args()

    if args.agent:
        if not (args.advisory and args.package and args.version and args.source_dir):
            p.error("--agent needs --advisory, --package, --version and --source-dir")
        advisory_id = args.advisory
        comp = Component(stream="debian", package=args.package, version=args.version)
        bundle = None
    else:
        if args.bundle is None:
            p.error("give a bundle, or use --agent")
        bundle = load_bundle(args.bundle.read_text())
        advisory_id, comp = bundle.patch.advisory_id, bundle.patch.component
    engine = make_engine(f"sqlite+pysqlite:///{args.db}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    with factory() as s:
        if s.get(AdvisoryRow, advisory_id) is None:
            refs = args.fix_ref or feed_fix_refs(advisory_id)
            print(f"fix references on the advisory: {refs}")
            s.add(AdvisoryRow(id=advisory_id, fix_refs="\n".join(refs)))
        s.add(
            AffectedRow(
                advisory_id=advisory_id,
                stream=comp.stream,
                image="debian",
                package=comp.package,
                version=comp.version,
                created_at=time.time(),
            )  # fmt: skip
        )
        s.commit()

    upstream: UpstreamFetcher = HttpUpstreamFetcher(ALLOWLIST)
    if args.upstream_patch is not None and bundle is not None:
        print(f"upstream commit read from {args.upstream_patch}, not the network")
        upstream = fakes.FakeUpstream({bundle.patch.upstream_ref: args.upstream_patch.read_text()})
    vex_dir = args.work / "vex"
    vex_dir.mkdir(parents=True, exist_ok=True)
    adapter = DebianAdapter(BASE, args.work, builder=args.builder)
    source = ImageSource(BASE.digest, BASE.image, adapter.archives)
    scanners = (TrivyScanner(source), GrypeScanner(source))
    differ = OciDiffer(source)
    pipeline = Pipeline(
        agent=fakes.FakeAgentRunner(),  # replaced by the bundle in import_bundle
        adapter=adapter,
        scanners=scanners,
        suite_runner=SmokeSuiteRunner(source, SMOKE, builder=args.builder),
        differ=differ,
        rebuilt=lambda digest: differ.rebuilt_packages(digest) or [],
        registry=fakes.FakeRegistry(),
        signer=fakes.FakeSigner(),
        clock=Clock(),
        gates=GateConfig(provenance_allowlist=ALLOWLIST, vex_enabled=args.vex),
        limits=Limits(),
        upstream=upstream,
        vex_dir=vex_dir,
    )
    started = time.time()
    if bundle is not None:
        outcomes = import_bundle(factory, replace(pipeline), bundle, enabled=True)
    else:
        try:
            config = LLMConfig.from_env()
        except ConfigError as exc:
            print(f"cannot start the agent: {exc} (see ADR-0008)")
            return 2
        agent = LLMAgentRunner(ChatClient(config), SandboxToolBox(args.source_dir))
        with factory() as s:
            row = s.scalars(select(AffectedRow).order_by(AffectedRow.id.desc())).first()
            assert row is not None
            affected_id = row.id
        outcomes = [process(factory, replace(pipeline, agent=agent), affected_id)]
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
