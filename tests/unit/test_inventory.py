from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dabao.inventory import (
    APK_INSTALLED,
    DPKG_STATUS,
    Regctl,
    RegctlError,
    diff_inventories,
    inventory,
    parse_apk_installed,
    parse_dpkg_status,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def done(rc: int = 0, out: bytes = b"", err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], rc, out, err)


def test_dpkg_parser_keeps_only_installed_and_ignores_continuation_lines() -> None:
    pkgs = parse_dpkg_status((FIX / "dpkg_status.txt").read_text())
    assert pkgs == {"adduser": "3.134", "libssl3": "3.0.11-1~deb12u2"}


def test_apk_parser() -> None:
    assert parse_apk_installed((FIX / "apk_installed.txt").read_text()) == {
        "alpine-baselayout": "3.6.5-r0",
        "musl": "1.2.5-r0",
    }


def test_regctl_get_file_found_missing_and_error() -> None:
    calls: list[list[str]] = []

    def runner(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        if args[-1] == "present":
            return done(out=b"data")
        if args[-1] == "absent":
            return done(1, err=b"not found")
        return done(1, err=b"auth failure")

    r = Regctl("regctl", runner)
    assert r.get_file("img", "present") == b"data"
    assert r.get_file("img", "absent") is None
    with pytest.raises(RegctlError, match="auth failure"):
        r.get_file("img", "other")
    assert calls[0] == ["regctl", "image", "get-file", "img", "present"]


def test_digest_error() -> None:
    with pytest.raises(RegctlError, match="denied"):
        Regctl("regctl", lambda _a: done(1, err=b"denied")).digest("img")
    assert Regctl("regctl", lambda _a: done(out=b"sha256:abc\n")).digest("img") == "sha256:abc"


def test_inventory_detects_debian_alpine_and_unknown() -> None:
    files = {
        ("deb", DPKG_STATUS): (FIX / "dpkg_status.txt").read_bytes(),
        ("apk", APK_INSTALLED): (FIX / "apk_installed.txt").read_bytes(),
    }

    def runner(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        data = files.get((args[3], args[4]))
        return done(out=data) if data is not None else done(1, err=b"not found")

    r = Regctl("regctl", runner)
    assert inventory(r, "deb")[0] == "debian"
    assert inventory(r, "apk") == ("alpine", {"alpine-baselayout": "3.6.5-r0", "musl": "1.2.5-r0"})
    with pytest.raises(RegctlError, match="no dpkg or apk"):
        inventory(r, "scratch")


def test_diff_inventories() -> None:
    d = diff_inventories({"a": "1", "b": "1", "c": "1"}, {"a": "1", "b": "2", "d": "1"})
    assert d.added == {"d": "1"} and d.removed == {"c": "1"} and d.changed == {"b": ("1", "2")}
    assert diff_inventories({"a": "1"}, {"a": "1"}).empty
