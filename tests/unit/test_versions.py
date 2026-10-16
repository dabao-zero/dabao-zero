from __future__ import annotations

import pytest

from dabao.versions import compare_dpkg

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
