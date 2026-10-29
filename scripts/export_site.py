"""Write the public ledger as static JSON for the Pages site (ADR-0012).

    DATABASE_URL=... uv run python scripts/export_site.py site-data

The output is committed through a PR, so a human sees exactly what goes public before it does.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from dabao.db import make_engine, make_session_factory
from dabao.export import export_site
from dabao.settings import Settings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    factory = make_session_factory(make_engine(Settings.from_env().database_url))
    files = export_site(factory, Path(argv[1]), time.time())
    print(f"wrote {len(files)} files under {argv[1]}/v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
