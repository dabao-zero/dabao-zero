"""`dabao` operator CLI. Talks straight to the ledger database ($DATABASE_URL).

Output is JSON on stdout. Exit codes: 0 ok, 1 not found / nothing to do, 2 bad usage,
3 database error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Sequence

from sqlalchemy.exc import SQLAlchemyError

from dabao import operator, repo
from dabao.db import SessionFactory, make_engine, make_session_factory
from dabao.settings import Settings


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dabao", description="dabao operator commands")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="freeze state and ledger counts")
    for name in ("freeze", "unfreeze"):
        s = sub.add_parser(name, help=f"{name} signing and new attempts")
        s.add_argument("--note", required=True, help="why (kept in the ledger)")
    r = sub.add_parser("revoke", help="revoke a published artifact")
    r.add_argument("digest")
    r.add_argument("--reason", required=True)
    rr = sub.add_parser("rerun", help="re-queue UNPATCHED/NEEDS_HUMAN rows of an advisory")
    rr.add_argument("advisory_id")
    return p


def main(
    argv: Sequence[str] | None = None,
    factory: SessionFactory | None = None,
    now: Callable[[], float] = time.time,
) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    if factory is None:
        url = os.environ.get("DATABASE_URL", Settings.database_url)
        factory = make_session_factory(make_engine(url))

    def out(obj: object) -> None:
        print(json.dumps(obj, sort_keys=True))

    try:
        return _run(args, factory, now, out)
    except SQLAlchemyError as exc:
        out(
            {
                "error": "database error (is it migrated? run `alembic upgrade head`)",
                "detail": type(exc).__name__,
            }
        )
        return 3


def _run(
    args: argparse.Namespace,
    factory: SessionFactory,
    now: Callable[[], float],
    out: Callable[[object], None],
) -> int:
    with factory() as s:
        if args.cmd == "status":
            out(operator.status(s))
        elif args.cmd == "freeze":
            operator.freeze(s, args.note, now())
            out({"frozen": True})
        elif args.cmd == "unfreeze":
            operator.unfreeze(s, args.note, now())
            out({"frozen": False})
        elif args.cmd == "revoke":
            art = repo.revoke_artifact(s, args.digest, args.reason, now())
            if art is None:
                out({"error": "unknown artifact"})
                return 1
            out({"digest": art.digest, "status": art.status, "reason": art.revoked_reason})
        elif args.cmd == "rerun":
            n = operator.rerun(s, args.advisory_id)
            out({"queued": n})
            return 0 if n else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
