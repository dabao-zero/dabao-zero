from __future__ import annotations

import pytest

from dabao.versions import compare_apk, compare_dpkg

LESS = [
    ("1.0~rc1", "1.0"),
    ("1.0", "1.0+b1"),
    ("1.9", "1.10"),
    ("2.0", "1:0.9"),  # epoch wins
    ("1.2.3-1", "1.2.3-1+deb12u1"),
    ("3.0.11-1~deb12u2", "3.0.11-1~deb12u3"),
    ("1.0~~", "1.0~"),
    ("1.0~", "1.0"),
    ("1.0a", "1.0b"),
    ("1.22.0-1", "1.22.1-9"),
    ("0.9", "0.10"),
    ("1.0-1", "1.0-2"),
]


@pytest.mark.parametrize(("lo", "hi"), LESS)
def test_ordering_both_directions(lo: str, hi: str) -> None:
    assert compare_dpkg(lo, hi) == -1
    assert compare_dpkg(hi, lo) == 1


@pytest.mark.parametrize(
    ("a", "b"), [("1.0", "1.0"), ("1.0-0", "1.0"), ("0:1.0", "1.0"), ("1.00", "1.0")]
)
def test_equal_versions(a: str, b: str) -> None:
    assert compare_dpkg(a, b) == 0


# Expected results were produced by `apk version -t A B` in alpine:3.24, not by this code.
APK = [
    ("1.2.0-r1", "1.2.1-r0", "<"),
    ("1.2.1-r0", "1.2.1-r1", "<"),
    ("1.2.1-r1", "1.2.1-r1", "="),
    ("1.0_rc1-r0", "1.0-r0", "<"),
    ("1.0-r0", "1.0_p1-r0", "<"),
    ("1.0a-r0", "1.0-r0", ">"),
    ("1.10-r0", "1.9-r0", ">"),
    ("2.0_alpha1-r0", "2.0_beta1-r0", "<"),
    ("1.0_git20240101-r0", "1.0-r0", ">"),
    ("1.0-r0", "1.0_git20240101-r0", "<"),
    ("1.0_pre1-r0", "1.0_rc1-r0", "<"),
    ("1.0-r10", "1.0-r9", ">"),
    ("1.2.3-r0", "1.2.3.1-r0", "<"),
    ("1.0_alpha-r0", "1.0_alpha2-r0", "<"),
    ("3.0.11-r0", "3.0.9-r1", ">"),
    ("1.0b-r0", "1.0a-r5", ">"),
]


@pytest.mark.parametrize(("a", "b", "op"), APK)
def test_apk_ordering_matches_apk_itself(a: str, b: str, op: str) -> None:
    assert {-1: "<", 0: "=", 1: ">"}[compare_apk(a, b)] == op
