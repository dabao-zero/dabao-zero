"""ADR-0010 check 1: the patch's upstream_ref must be one of the advisory's own fix references."""

from __future__ import annotations

from dataclasses import replace

import pytest
from sqlalchemy.orm import Session, sessionmaker

from dabao.gates import GateConfig, fix_reference_problem, gate_provenance
from dabao.ingest import FeedRecord, ingest, parse_osv
from dabao.models import Advisory
from dabao.orm import AdvisoryRow
from tests.corpus.cases import ADV, ALLOWED_SOURCE, CFG, good_input

COMMIT = "https://github.com/nginx/nginx/commit/0123456789abcdef0123456789abcdef01234567"


def osv(refs: object) -> dict[str, object]:
    return {
        "id": "DSA-1-1",
        "aliases": ["CVE-2099-1"],
        "references": refs,
        "affected": [
            {"package": {"ecosystem": "Debian:12", "name": "nginx"}, "ranges": []},
        ],
    }


def test_parse_osv_keeps_only_fix_references_once_each() -> None:
    rec = osv(
        [
            {"type": "FIX", "url": COMMIT},
            {"type": "FIX", "url": COMMIT},
            {"type": "WEB", "url": "https://example.org/blog"},
            {"type": "ADVISORY", "url": "https://example.org/dsa"},
            {"type": "FIX"},
            {"type": "FIX", "url": 5},
            "junk",
        ]
    )
    (out,) = parse_osv([rec])
    assert out.fix_refs == (COMMIT,)


@pytest.mark.parametrize("refs", [None, "x", {}, []])
def test_parse_osv_without_usable_references_has_none(refs: object) -> None:
    (out,) = parse_osv([osv(refs)])
    assert out.fix_refs == ()


def test_ingest_stores_fix_references_and_merges_new_ones(factory: sessionmaker[Session]) -> None:
    first = FeedRecord("CVE-2099-1", (), "nginx", "9", (COMMIT,))
    second = FeedRecord("CVE-2099-1", (), "nginx", "9", ("https://example.org/fix/2",))
    with factory() as s:
        ingest(s, [first], {"img": {"nginx": "1"}}, 1.0)
        ingest(s, [second], {"img": {"nginx": "1"}}, 2.0)
        row = s.get(AdvisoryRow, "CVE-2099-1")
        assert row is not None
        assert row.fix_refs.split("\n") == sorted([COMMIT, "https://example.org/fix/2"])


@pytest.mark.parametrize(
    ("ref", "known", "ok"),
    [
        (COMMIT, COMMIT, True),
        (COMMIT + ".patch", COMMIT, True),
        (COMMIT + "/", COMMIT, True),
        ("http://GitHub.com/nginx/nginx/commit/0123456789abcdef", COMMIT, True),  # short sha
        (COMMIT, "https://github.com/nginx/nginx/commit/0123456", True),
        (
            "https://github.com/nginx/nginx/commit/0123456789abcdef",
            "https://github.com/nginx/other/commit/0123456789abcdef",
            False,
        ),
        (
            "https://github.com/nginx/nginx/commit/0123",
            "https://github.com/nginx/nginx/commit/0123456789",
            False,
        ),  # too short
        ("https://github.com/nginx/nginx/commit/fedcba9876543210", COMMIT, False),
        ("https://github.com/nginx/nginx", COMMIT, False),
        ("https://evil.example/nginx/nginx/commit/0123456789abcdef", COMMIT, False),
        (
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da784000000",
            True,
        ),
        (
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=4eb89511",
            False,
        ),
        (
            "https://git.savannah.gnu.org/cgit/tar.git/commit/",
            "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400",
            False,
        ),
    ],
)
def test_reference_matching(ref: str, known: str, ok: bool) -> None:
    adv = Advisory(id="CVE-2099-1", fix_refs=(known,))
    assert (fix_reference_problem(adv, ref) == "") is ok


def test_no_fix_reference_in_the_feed_is_its_own_message() -> None:
    assert "names no fix reference" in fix_reference_problem(Advisory(id="CVE-2099-1"), COMMIT)


def test_provenance_ignores_fix_references_until_the_flag_is_on() -> None:
    inp = replace(good_input(), advisory=Advisory(id=ADV.id))
    assert gate_provenance(inp, CFG).passed
    assert not gate_provenance(inp, replace(CFG, require_fix_reference=True)).passed


def test_provenance_with_the_flag_passes_a_listed_fix_reference() -> None:
    assert ALLOWED_SOURCE + "abc123" in ADV.fix_refs
    r = gate_provenance(good_input(), replace(CFG, require_fix_reference=True))
    assert r.passed, r.reason


def test_default_config_does_not_require_it() -> None:
    assert GateConfig().require_fix_reference is False
