"""ADR-0010 check 2: the changes of the upstream commit are contained in the patch.

The gate fetches the upstream commit itself and compares changed lines, so an agent cannot claim a
fix it did not derive. Context may shift between versions; changed lines may not. Everything here is
pure; fetching lives in `live.py` behind the `UpstreamFetcher` seam.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
_SUPPORT_DIRS = {"tests", "test", "testsuite", "doc", "docs", "po", "m4"}
_SUPPORT_FILES = {"changelog", "news", "authors", "thanks", "readme", "todo", "copying"}
_SUPPORT_SUFFIXES = (".texi", ".md", ".rst", ".txt", ".1", ".at")


@dataclass
class Changes:
    added: Counter[str] = field(default_factory=Counter)
    removed: Counter[str] = field(default_factory=Counter)


def _norm(line: str) -> str:
    return " ".join(line.split())


def _path(raw: str) -> str:
    raw = raw.split("\t")[0].strip()
    return raw.removeprefix("a/").removeprefix("b/")


def parse_changes(diff: str) -> dict[str, Changes]:
    """Changed lines per file of a unified diff or git mailbox patch, whitespace-normalised.

    Hunks are read by their line counts, so a removed line that starts with `-- ` is never taken
    for a header and the mail trailer after the last hunk is ignored.
    """
    out: dict[str, Changes] = {}
    lines = diff.splitlines()
    i, current = 0, ""
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            old, new = _path(line[4:]), _path(lines[i + 1][4:])
            current = old if new == "/dev/null" else new
            out.setdefault(current, Changes())
            i += 2
            continue
        m = _HUNK.match(line)
        if m and current:
            old_left = int(m.group(1)) if m.group(1) is not None else 1
            new_left = int(m.group(2)) if m.group(2) is not None else 1
            i += 1
            while i < len(lines) and (old_left > 0 or new_left > 0):
                body = lines[i]
                if body.startswith("+"):
                    new_left -= 1
                    if n := _norm(body[1:]):
                        out[current].added[n] += 1
                elif body.startswith("-"):
                    old_left -= 1
                    if n := _norm(body[1:]):
                        out[current].removed[n] += 1
                elif body.startswith("\\"):
                    pass  # "\ No newline at end of file"
                else:
                    old_left -= 1
                    new_left -= 1
                i += 1
            continue
        i += 1
    return out


def is_support_file(path: str) -> bool:
    """Tests, docs and changelogs: part of an upstream commit, not of a security backport."""
    parts = path.lower().split("/")
    name = parts[-1]
    return (
        any(p in _SUPPORT_DIRS for p in parts[:-1])
        or name in _SUPPORT_FILES
        or name.endswith(_SUPPORT_SUFFIXES)
    )


def _same_file(a: str, b: str) -> bool:
    """Equal paths, or one is the other under a leading directory (`tar-1.34/src/list.c`)."""
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


# Hosts the Debian tracker's notes name fix commits on, among the CVEs open on bookworm (2026-10-30:
# 5,593 commit URLs, 93% on github.com). A host list, not a repository list: check 1 already
# narrows a patch to the exact commit an independent source names; a repo list would not scale.
UPSTREAM_HOSTS = (
    "github.com",
    "gitlab.com",
    "git.kernel.org",
    "git.savannah.gnu.org",
    "cgit.git.savannah.gnu.org",
    "git.savannah.nongnu.org",
    "cgit.git.savannah.nongnu.org",
    "cgit.ghostscript.com",
    "git.musl-libc.org",
)


def host_allowlist(hosts: tuple[str, ...] = UPSTREAM_HOSTS) -> tuple[str, ...]:
    """Provenance allow-list entries (URL prefixes) for whole hosts."""
    return tuple(f"https://{h}/" for h in hosts)


def containment_problem(
    upstream_diff: str, patch_diff: str, *, allow_support_only: bool = False
) -> str:
    """ "" when every changed line of the upstream commit's source files is in the patch.

    A commit that changes only tests and docs has nothing to compare: a problem for the commit a
    patch cites, fine (`allow_support_only`) for another commit the advisory lists.
    """
    upstream = parse_changes(upstream_diff)
    if not upstream:
        return "the upstream commit has no readable changes"
    source = {f: c for f, c in upstream.items() if not is_support_file(f)}
    if not source:
        if allow_support_only:
            return ""
        return "the upstream commit changes only tests and docs, so there is nothing to compare"
    ours = parse_changes(patch_diff)
    for path, want in sorted(source.items()):
        have = Changes()
        for p, c in ours.items():
            if _same_file(p, path):
                have.added.update(c.added)
                have.removed.update(c.removed)
        if not any(_same_file(p, path) for p in ours):
            return f"the patch does not touch {path}, which the upstream commit changes"
        for kind in ("added", "removed"):
            missing = getattr(want, kind) - getattr(have, kind)
            if missing:
                sign = "+" if kind == "added" else "-"
                first = sorted(missing)[0]
                return f"the patch lacks upstream's changed line in {path}: {sign}{first[:80]}"
    return ""


def patch_url(ref: str) -> str | None:
    """Where to read the raw patch of a commit reference, or None for a host we cannot read."""
    parts = urlsplit(ref.strip())
    host, path, query = parts.netloc.lower(), parts.path.rstrip("/"), dict(parse_qsl(parts.query))
    if host in {"github.com", "gitlab.com"} and "/commit/" in path:
        return urlunsplit(("https", host, path.removesuffix(".patch") + ".patch", "", ""))
    if "id" in query and path.endswith("/commit"):
        q = urlencode({"id": query["id"]})
        return urlunsplit(("https", host, path.removesuffix("/commit") + "/patch/", q, ""))
    return None
