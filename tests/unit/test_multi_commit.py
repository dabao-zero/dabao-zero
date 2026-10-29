"""Every fix commit the advisory lists must be contained in the patch (ADR-0010 check 2, DAB-81)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from dabao import fakes
from dabao.gates import GateInput, commit_refs, upstream_problem
from dabao.live import HttpUpstreamFetcher
from dabao.models import Advisory, Component, Patch, PatchSource
from dabao.upstream import UPSTREAM_HOSTS, host_allowlist

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SMALL = (FIX / "libtasn1-4082ca22-upstream.patch").read_text()  # lib/decoding.c
BIG = (FIX / "libtasn1-869a97aa-upstream.patch").read_text()  # five files
A = "https://gitlab.com/gnutls/libtasn1/-/commit/4082ca2220b5ba910b546afddf7780fc4a51f75a"
B = "https://gitlab.com/gnutls/libtasn1/-/commit/869a97aa259dffa2620dabcad84e1c22545ffc3d"
TESTS_ONLY = "--- a/tests/t.c\n+++ b/tests/t.c\n@@ -1 +1 @@\n-a\n+b\n"
COMP = Component(stream="debian", package="libtasn1-6", version="4.19.0-2")


def gate_input(
    patch_diff: str, upstream: fakes.FakeUpstream, refs: tuple[str, ...] = (A, B)
) -> GateInput:
    return GateInput(
        advisory=Advisory(id="CVE-2024-12133", fix_refs=refs),
        patch=Patch(
            advisory_id="CVE-2024-12133",
            component=COMP,
            source=PatchSource.UPSTREAM_DERIVED,
            upstream_ref=A,
            diff=patch_diff,
        ),
        before_digest="sha256:b",
        after_digest="sha256:a",
        upstream=upstream,
    )


def test_a_patch_with_both_commits_passes() -> None:
    inp = gate_input(SMALL + BIG, fakes.FakeUpstream({A: SMALL, B: BIG}))
    assert upstream_problem(inp) == ""


def test_half_of_a_multi_commit_fix_is_refused_and_names_the_missing_commit() -> None:
    inp = gate_input(SMALL, fakes.FakeUpstream({A: SMALL, B: BIG}))
    problem = upstream_problem(inp)
    assert (
        problem.startswith(f"listed fix commit {B}:") and "does not touch lib/element.c" in problem
    )


def test_the_commit_the_patch_cites_is_still_checked_first_and_without_a_prefix() -> None:
    inp = gate_input(BIG, fakes.FakeUpstream({A: SMALL, B: BIG}))
    assert upstream_problem(inp).startswith("the patch does not touch lib/decoding.c")


def test_an_unreadable_listed_commit_fails_closed() -> None:
    inp = gate_input(SMALL + BIG, fakes.FakeUpstream({A: SMALL}))
    assert upstream_problem(inp) == f"could not read the upstream commit {B}"


def test_a_listed_commit_that_only_changes_tests_needs_nothing_from_the_patch() -> None:
    inp = gate_input(SMALL, fakes.FakeUpstream({A: SMALL, B: TESTS_ONLY}))
    assert upstream_problem(inp) == ""


def test_the_cited_commit_may_not_be_tests_only() -> None:
    inp = gate_input(SMALL, fakes.FakeUpstream({A: TESTS_ONLY, B: TESTS_ONLY}))
    assert "only tests and docs" in upstream_problem(inp)


def test_the_same_commit_listed_twice_is_read_once() -> None:
    short = A.replace("4082ca2220b5ba910b546afddf7780fc4a51f75a", "4082ca22")
    up = fakes.FakeUpstream({A: SMALL, short: SMALL})
    assert upstream_problem(gate_input(SMALL, up, refs=(A, short, A + ".patch"))) == ""
    assert up.asked == [A]


def test_links_that_are_not_commits_are_not_fetched() -> None:
    adv = Advisory(id="X", fix_refs=("https://savannah.gnu.org/patch/?10307", B))
    assert commit_refs(adv, A) == [A, B]


def test_without_a_reader_nothing_passes() -> None:
    inp = replace(gate_input(SMALL, fakes.FakeUpstream()), upstream=None)
    assert upstream_problem(inp) == "no way to read the upstream commit"


@pytest.mark.parametrize(
    ("ref", "readable"),
    [
        ("https://github.com/nginx/nginx/commit/abc1234", True),
        (A, True),
        (
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abc1234",
            True,
        ),
        ("https://cgit.git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400", True),
        ("https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400", True),
        ("https://github.com.evil.example/o/r/commit/abc1234", False),
        ("https://github.com@evil.example/o/r/commit/abc1234", False),
        ("http://github.com/o/r/commit/abc1234", False),
        ("https://evil.example/o/r/commit/abc1234", False),
    ],
)
def test_the_host_allow_list_admits_whole_hosts_and_nothing_that_merely_starts_like_one(
    ref: str, readable: bool
) -> None:
    seen: list[str] = []

    def opener(url: str, timeout: float) -> tuple[str, bytes]:
        seen.append(url)
        return url, b"--- a/x\n+++ b/x\n"

    got = HttpUpstreamFetcher(host_allowlist(), opener=opener).commit_diff(ref)
    assert (got is not None) is readable
    assert bool(seen) is readable


def test_the_host_list_matches_what_the_tracker_names() -> None:
    assert {"github.com", "gitlab.com", "git.kernel.org", "git.savannah.gnu.org"} <= set(
        UPSTREAM_HOSTS
    )
    assert all(p.startswith("https://") and p.endswith("/") for p in host_allowlist())
