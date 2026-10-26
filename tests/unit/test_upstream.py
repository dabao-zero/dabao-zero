"""ADR-0010 check 2: upstream's changed lines must be contained in the patch."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from dabao import fakes
from dabao.gates import GateConfig, gate_provenance
from dabao.live import HttpUpstreamFetcher
from dabao.upstream import containment_problem, is_support_file, parse_changes, patch_url
from tests.corpus.cases import ADV, ALLOWED_SOURCE, CFG, DIFF, PATCH, good_input

HERE = Path(__file__).resolve().parents[1]
UPSTREAM = (HERE / "fixtures/tar-3da78400-upstream.patch").read_text()  # the savannah commit
DEBIAN = (HERE / "integration/fixtures/tar-CVE-2022-48303.diff").read_text()  # Debian's own copy


def test_the_upstream_tar_fix_and_debians_copy_of_it_agree() -> None:
    assert containment_problem(UPSTREAM, DEBIAN) == ""


def test_parse_changes_reads_each_file_by_hunk_counts() -> None:
    got = parse_changes(UPSTREAM)
    assert list(got) == ["src/list.c"]
    assert sum(got["src/list.c"].added.values()) == 3
    assert sum(got["src/list.c"].removed.values()) == 2


def test_a_removed_line_that_looks_like_a_header_is_still_a_line() -> None:
    diff = "--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,1 @@\n--- not a header\n keep\n"
    assert dict(parse_changes(diff)["f.c"].removed) == {"-- not a header": 1}


def test_a_diff_that_changes_other_lines_fails() -> None:
    other = DEBIAN.replace("where <= lim - 2", "where <= lim - 3")
    assert "lacks upstream's changed line in src/list.c" in containment_problem(UPSTREAM, other)


def test_a_diff_that_leaves_out_a_removed_line_fails() -> None:
    other = DEBIAN.replace("-  else if (*where == '\\200' /* positive base-256 */", " context")
    assert "-else if" in containment_problem(UPSTREAM, other)


def test_a_patch_to_another_file_fails() -> None:
    other = DEBIAN.replace("src/list.c", "src/other.c")
    assert "does not touch src/list.c" in containment_problem(UPSTREAM, other)


def test_whitespace_and_a_leading_directory_are_tolerated() -> None:
    reindented = DEBIAN.replace("\t", "        ").replace("src/list.c", "tar-1.34/src/list.c")
    assert containment_problem(UPSTREAM, reindented) == ""


def test_extra_changes_do_not_fail_containment() -> None:
    """Containment is one direction: upstream's lines must be in the patch, not the reverse."""
    extra = DEBIAN + "--- a/src/more.c\n+++ b/src/more.c\n@@ -1 +1 @@\n-old\n+new\n"
    assert containment_problem(UPSTREAM, extra) == ""


def test_a_change_repeated_upstream_must_be_repeated_in_the_patch() -> None:
    twice = "--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,2 @@\n-x\n-x\n+y\n+y\n"
    once = "--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-x\n+y\n"
    assert containment_problem(twice, twice) == ""
    assert containment_problem(twice, once) != ""


def test_tests_and_docs_upstream_are_not_required_but_source_is() -> None:
    source = "--- a/src/f.c\n+++ b/src/f.c\n@@ -1 +1 @@\n-a\n+b\n"
    support = (
        "--- a/tests/t.at\n+++ b/tests/t.at\n@@ -1 +1 @@\n-c\n+d\n"
        "--- a/NEWS\n+++ b/NEWS\n@@ -1 +1 @@\n-e\n+f\n"
    )
    assert containment_problem(source + support, source) == ""
    assert "only tests and docs" in containment_problem(support, source)


def test_unreadable_upstream_text_is_a_problem() -> None:
    assert "no readable changes" in containment_problem("<html>502</html>", DEBIAN)


@pytest.mark.parametrize(
    ("path", "support"),
    [
        ("tests/testsuite.at", True),
        ("doc/tar.texi", True),
        ("ChangeLog", True),
        ("src/list.c", False),
        ("src/tests.c", False),
    ],
)
def test_support_files(path: str, support: bool) -> None:
    assert is_support_file(path) is support


@pytest.mark.parametrize(
    ("ref", "url"),
    [
        (
            "https://github.com/nginx/nginx/commit/abc1234",
            "https://github.com/nginx/nginx/commit/abc1234.patch",
        ),
        (
            "https://github.com/nginx/nginx/commit/abc1234.patch",
            "https://github.com/nginx/nginx/commit/abc1234.patch",
        ),
        (
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
            "https://git.savannah.gnu.org/cgit/tar.git/patch/?id=3da78400",
        ),
        ("https://example.org/blog/post", None),
        ("https://github.com/nginx/nginx", None),
    ],
)
def test_patch_url(ref: str, url: str | None) -> None:
    assert patch_url(ref) == url


SAVANNAH = ("https://git.savannah.gnu.org/cgit/tar.git/commit/",)
SAV_REF = "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400"


def test_the_fetcher_follows_a_redirect_inside_the_same_site() -> None:
    seen: list[str] = []

    def opener(url: str, timeout: float) -> tuple[str, bytes]:
        seen.append(url)
        return (
            "https://cgit.git.savannah.gnu.org/cgit/tar.git/patch/?id=3da78400",
            UPSTREAM.encode(),
        )

    got = HttpUpstreamFetcher(SAVANNAH, opener=opener).commit_diff(SAV_REF)
    assert got == UPSTREAM and seen == [
        "https://git.savannah.gnu.org/cgit/tar.git/patch/?id=3da78400"
    ]


@pytest.mark.parametrize(
    "case", ["off-allow-list", "other-site", "too-big", "error", "not-utf8", "unreadable-host"]
)
def test_the_fetcher_returns_none_for_anything_it_should_not_trust(case: str) -> None:
    def opener(url: str, timeout: float) -> tuple[str, bytes]:
        if case == "other-site":
            return "https://evil.example/patch", b"x"
        if case == "too-big":
            return url, b"x" * 2_000_001
        if case == "error":
            raise OSError("down")
        if case == "not-utf8":
            return url, b"\xff\xfe"
        return url, b"x"

    ref = {
        "off-allow-list": "https://evil.example/cgit/tar.git/commit/?id=3da78400",
        "unreadable-host": "https://git.savannah.gnu.org/blog",
    }.get(case, SAV_REF)
    assert HttpUpstreamFetcher(SAVANNAH, opener=opener).commit_diff(ref) is None


def test_provenance_ignores_containment_until_the_flag_is_on() -> None:
    inp = good_input()  # no upstream reader at all
    assert gate_provenance(inp, CFG).passed
    r = gate_provenance(inp, replace(CFG, require_containment=True))
    assert not r.passed and "no way to read" in r.reason


def test_provenance_with_the_flag_passes_when_contained_and_fails_when_not() -> None:
    on = replace(CFG, require_containment=True)
    ref = ALLOWED_SOURCE + "abc123"
    ok = replace(good_input(), upstream=fakes.FakeUpstream({ref: DIFF}))
    assert gate_provenance(ok, on).passed
    bad = replace(good_input(), upstream=fakes.FakeUpstream({ref: DIFF.replace("+y", "+z")}))
    r = gate_provenance(bad, on)
    assert not r.passed and "lacks upstream's changed line" in r.reason
    gone = replace(good_input(), upstream=fakes.FakeUpstream({}))
    assert "could not read" in gate_provenance(gone, on).reason


def test_default_config_does_not_require_it() -> None:
    assert GateConfig().require_containment is False
    assert ADV.fix_refs and PATCH.upstream_ref in ADV.fix_refs
