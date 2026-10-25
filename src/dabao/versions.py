"""Package version ordering for the Debian and Alpine streams, needed to decide whether an
installed package predates an advisory's fixed version.

Debian: Debian Policy 5.6.12. Alpine: apk-tools' version syntax; the tests pin it to what
`apk version -t` answers."""

from __future__ import annotations

import re


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


_APK_SUFFIX_RANK = {
    "alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9,
}  # fmt: skip
_APK_VERSION = re.compile(r"^(\d+(?:\.\d+)*)([a-z])?((?:_[a-z]+\d*)*)(?:~[0-9a-f]+)?$")


def _apk_parts(version: str) -> tuple[list[int], str, list[tuple[int, int]], int]:
    rel = 0
    if "-r" in version:
        version, _, r = version.rpartition("-r")
        rel = int(r) if r.isdigit() else 0
    m = _APK_VERSION.match(version)
    if m is None:
        raise ValueError(f"not an apk version: {version!r}")
    numbers = [int(n) for n in m.group(1).split(".")]
    suffixes = []
    for s in filter(None, m.group(3).split("_")):
        name = s.rstrip("0123456789")
        suffixes.append((_APK_SUFFIX_RANK.get(name, 4), int(s[len(name) :] or 0)))
    return numbers, m.group(2) or "", suffixes, rel


def compare_apk(a: str, b: str) -> int:
    """-1 if a < b, 0 if equal, 1 if a > b, in apk's ordering (`1.2.1-r0`, `1.0_rc1-r0`)."""
    na, la, sa, ra = _apk_parts(a)
    nb, lb, sb, rb = _apk_parts(b)
    for left, right in ((na, nb), (la, lb)):
        if left != right:
            return -1 if left < right else 1  # type: ignore[operator]
    none = (_APK_SUFFIX_RANK[""], 0)  # a missing suffix sorts between rc and cvs
    for i in range(max(len(sa), len(sb))):
        x, y = (sa[i] if i < len(sa) else none), (sb[i] if i < len(sb) else none)
        if x != y:
            return -1 if x < y else 1
    return (ra > rb) - (ra < rb)
