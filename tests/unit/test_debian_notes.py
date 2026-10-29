"""ADR-0010 check 1: the Debian tracker's NOTE lines are a fix-reference source."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from dabao.gates import fix_reference_problem
from dabao.ingest import FeedRecord, parse_debian_notes, with_fix_refs
from dabao.models import Advisory

EXCERPT = Path(__file__).resolve().parents[1] / "fixtures/debian_cve_list_excerpt.txt"  # real lines
TAR = (
    "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400eafcccb97e2f2fd4b227ea40d794ede8"
)
TASN1_A = "https://gitlab.com/gnutls/libtasn1/-/commit/4082ca2220b5ba910b546afddf7780fc4a51f75a"
TASN1_B = "https://gitlab.com/gnutls/libtasn1/-/commit/869a97aa259dffa2620dabcad84e1c22545ffc3d"


def notes() -> dict[str, tuple[str, ...]]:
    return parse_debian_notes(EXCERPT.read_text().splitlines(keepends=True))


def test_a_fixed_by_note_gives_the_commit_without_its_version_tag() -> None:
    assert notes()["CVE-2022-48303"] == (TAR,)


def test_bare_commit_urls_count_and_a_cve_can_have_several() -> None:
    assert notes()["CVE-2024-12133"] == tuple(sorted([TASN1_A, TASN1_B]))


def test_bug_issue_list_and_advisory_links_are_not_fix_references() -> None:
    urls = {u for refs in notes().values() for u in refs}
    assert not any(
        x in u for u in urls for x in ("issues", "bugs", "openwall", "lists.gnu.org", "blob")
    )


def test_a_block_does_not_leak_into_the_next_cve() -> None:
    assert "a339f05c" not in " ".join(notes()["CVE-2022-48303"])
    assert "a339f05c" in " ".join(notes()["CVE-2023-39804"])


def test_a_cve_with_no_commit_notes_has_no_entry() -> None:
    text = "CVE-2099-1 (x)\n\tNOTE: https://example.org/blog\n\t- pkg 1\n"
    assert parse_debian_notes(text.splitlines(keepends=True)) == {}


def test_trailing_punctuation_is_not_part_of_the_url() -> None:
    text = "CVE-2099-1 (x)\n\tNOTE: fixed in (https://github.com/o/r/commit/abc1234).\n"
    assert parse_debian_notes(text.splitlines(keepends=True)) == {
        "CVE-2099-1": ("https://github.com/o/r/commit/abc1234",)
    }


def test_reading_stops_once_every_wanted_cve_has_been_seen() -> None:
    consumed = 0

    def stream() -> Iterator[str]:
        nonlocal consumed
        for line in EXCERPT.read_text().splitlines(keepends=True):
            consumed += 1
            yield line
        raise AssertionError("read past the end: it should have stopped earlier")

    got = parse_debian_notes(stream(), wanted={"CVE-2022-48303"})
    assert set(got) == {"CVE-2022-48303"}
    assert consumed < len(EXCERPT.read_text().splitlines())


def test_wanted_filters_out_other_cves() -> None:
    got = parse_debian_notes(
        EXCERPT.read_text().splitlines(keepends=True), wanted={"CVE-2024-12133"}
    )
    assert set(got) == {"CVE-2024-12133"}


def test_with_fix_refs_merges_by_id_or_alias_and_keeps_the_feed_refs() -> None:
    rec = FeedRecord("DSA-1-1", ("CVE-2022-48303",), "tar", None, ("https://example.org/fix",))
    other = FeedRecord("CVE-2099-9", (), "tar", None)
    a, b = with_fix_refs([rec, other], notes())
    assert a.fix_refs == tuple(sorted([TAR, "https://example.org/fix"]))
    assert b.fix_refs == ()


def test_the_tar_commit_now_passes_check_1_which_it_failed_on_osv_alone() -> None:
    osv_only = Advisory(id="CVE-2022-48303", fix_refs=("https://savannah.gnu.org/patch/?10307",))
    assert "not one of the advisory's fix references" in fix_reference_problem(osv_only, TAR)
    with_tracker = Advisory(
        id="CVE-2022-48303", fix_refs=(*osv_only.fix_refs, *notes()["CVE-2022-48303"])
    )
    assert fix_reference_problem(with_tracker, TAR) == ""


def test_the_tracker_fetch_retries_and_a_final_failure_is_logged_not_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from dabao.live import fetch_debian_fix_refs

    calls = 0
    waited: list[float] = []

    def flaky(url: str, timeout: float) -> Iterator[bytes]:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise OSError("429")
        yield from EXCERPT.read_bytes().splitlines(keepends=True)

    got = fetch_debian_fix_refs({"CVE-2022-48303"}, opener=flaky, sleep=waited.append)
    assert got == {"CVE-2022-48303": (TAR,)} and waited == [5.0, 10.0]

    def down(url: str, timeout: float) -> Iterator[bytes]:
        raise OSError("down")

    waited.clear()
    with caplog.at_level("WARNING"):
        assert fetch_debian_fix_refs({"X"}, opener=down, sleep=waited.append) == {}
    assert "could not read the Debian tracker" in caplog.text and waited == [5.0, 10.0]
