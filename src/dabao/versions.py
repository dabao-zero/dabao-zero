"""Debian package version ordering (Debian Policy 5.6.12), needed to decide whether an
installed package predates an advisory's fixed version."""

from __future__ import annotations


def _split(version: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in version:
        e, version = version.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    revision = ""
    if "-" in version:
        version, revision = version.rsplit("-", 1)
    return epoch, version, revision


def _order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit prefix
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            oa = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            ob = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if oa != ob:
                return -1 if oa < ob else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # digit run
        si = i
        while i < len(a) and a[i].isdigit():
            i += 1
        sj = j
        while j < len(b) and b[j].isdigit():
            j += 1
        na, nb = int(a[si:i] or 0), int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
    return 0


def compare_dpkg(a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)
