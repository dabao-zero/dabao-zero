"""ADR-0010 checks 4 and 7 in the scanner gate: a VEX clears the target CVE and nothing else."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from dabao import fakes
from dabao.gates import GateConfig, GateInput, gate_scanners_clear
from dabao.models import Advisory, Component, Finding, Patch, PatchSource

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
DEBIAN_COPY = (
    Path(__file__).resolve().parents[1] / "integration/fixtures/tar-CVE-2022-48303.diff"
).read_text()
UPSTREAM = (FIXTURES / "tar-3da78400-upstream.patch").read_text()
REF = "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=3da78400"
ADV = Advisory(id="CVE-2022-48303", fix_refs=(REF,))
COMP = Component(stream="debian", package="tar", version="1.34+dfsg-1.2")
PATCH = Patch(
    advisory_id=ADV.id,
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref=REF,
    diff=DEBIAN_COPY,
)
BEFORE, AFTER = "sha256:before", "sha256:after"
TARGET = Finding(advisory_id=ADV.id, package="tar", fix_state="fixed")
SIBLING = Finding(advisory_id="CVE-2023-39804", package="tar", fix_state="fixed")
NOISE = Finding(advisory_id="CVE-2005-2541", package="tar", fix_state="unfixed")
ON = GateConfig(vex_enabled=True)


def scanner(name: str, after: list[Finding], **kw: bool) -> fakes.FakeScanner:
    return fakes.FakeScanner({BEFORE: [TARGET], AFTER: after}, name=name, **kw)


def gate_input(tmp_path: Path, *scanners: fakes.FakeScanner, **over: object) -> GateInput:
    base = GateInput(
        advisory=ADV,
        patch=PATCH,
        before_digest=BEFORE,
        after_digest=AFTER,
        scanners=scanners,
        rebuilt_packages=(("tar", "1.34+dfsg-1.2+dabao1"),),
        stream="debian",
        vex_dir=tmp_path,
        upstream=fakes.FakeUpstream({REF: UPSTREAM}),
        now=1_792_800_000.0,
    )
    return replace(base, **over)  # type: ignore[arg-type]


def test_a_scanner_that_is_already_clear_needs_no_vex(tmp_path: Path) -> None:
    inp = gate_input(tmp_path, scanner("grype", []), scanner("trivy", []))
    r = gate_scanners_clear(inp, ON)
    assert r.passed and r.reason == "all scanners clear"
    assert list(tmp_path.iterdir()) == []  # nothing was issued


def test_with_the_flag_off_a_reported_cve_still_fails_as_before(tmp_path: Path) -> None:
    inp = gate_input(tmp_path, scanner("grype", [TARGET]), scanner("trivy", [TARGET]))
    r = gate_scanners_clear(inp, GateConfig())
    assert not r.passed and r.reason == "still reported by ['grype', 'trivy']"
    assert list(tmp_path.iterdir()) == []


def test_a_vex_that_clears_only_the_target_passes_and_is_written_down(tmp_path: Path) -> None:
    after = [TARGET, SIBLING, NOISE]
    inp = gate_input(tmp_path, scanner("grype", after), scanner("trivy", after))
    r = gate_scanners_clear(inp, ON)
    assert r.passed, r.reason
    assert "via VEX" in r.reason
    written = sorted(p.name for p in tmp_path.iterdir())
    assert len(written) == 2 and all(n.endswith(".json") for n in written)


def test_one_scanner_clear_by_itself_and_one_by_vex_still_passes(tmp_path: Path) -> None:
    inp = gate_input(tmp_path, scanner("grype", [SIBLING]), scanner("trivy", [TARGET, SIBLING]))
    r = gate_scanners_clear(inp, ON)
    assert r.passed and "grype natively" in r.reason and "trivy via VEX" in r.reason


def test_a_vex_that_would_also_clear_another_cve_is_refused(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    inp = gate_input(tmp_path, scanner("grype", after, overclear=True), scanner("trivy", after))
    r = gate_scanners_clear(inp, ON)
    assert not r.passed
    assert "grype" in r.reason and "CVE-2023-39804" in r.reason


def test_a_scanner_that_ignores_the_vex_leaves_the_cve_and_fails(tmp_path: Path) -> None:
    inp = gate_input(
        tmp_path, scanner("grype", [TARGET], honours_vex=False), scanner("trivy", [TARGET])
    )
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "grype" in r.reason and "ignored" in r.reason


def test_without_rebuilt_packages_no_statement_can_be_written(tmp_path: Path) -> None:
    inp = gate_input(
        tmp_path, scanner("grype", [TARGET]), scanner("trivy", [TARGET]), rebuilt_packages=()
    )
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "rebuilt packages" in r.reason


def test_without_a_place_to_write_it_fails_closed(tmp_path: Path) -> None:
    inp = gate_input(tmp_path, scanner("grype", [TARGET]), scanner("trivy", [TARGET]), vex_dir=None)
    assert not gate_scanners_clear(inp, ON).passed


def test_a_scanner_without_vex_support_cannot_be_cleared_that_way(tmp_path: Path) -> None:
    class Plain:
        name = "plain"

        def scan(self, digest: str) -> list[Finding]:
            return [TARGET] if digest == AFTER else []

    inp = gate_input(tmp_path, scanner("grype", []), Plain())  # type: ignore[arg-type]
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "plain" in r.reason and "VEX" in r.reason


def test_an_alias_reported_instead_of_the_canonical_id_is_cleared_by_name(tmp_path: Path) -> None:
    adv = Advisory(id=ADV.id, aliases=("GHSA-aaaa-bbbb-cccc",), fix_refs=(REF,))
    alias = Finding(advisory_id="GHSA-aaaa-bbbb-cccc", package="tar", fix_state="fixed")
    s1 = fakes.FakeScanner({BEFORE: [alias], AFTER: [alias, SIBLING]}, name="grype")
    s2 = fakes.FakeScanner({BEFORE: [alias], AFTER: [alias, SIBLING]}, name="trivy")
    r = gate_scanners_clear(gate_input(tmp_path, s1, s2, advisory=adv), ON)
    assert r.passed, r.reason


def test_a_vex_needs_the_patch_ref_to_be_a_fix_reference_of_the_advisory(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    other = PATCH.model_copy(
        update={"upstream_ref": "https://git.savannah.gnu.org/cgit/tar.git/commit/?id=ffff0000"}
    )
    inp = gate_input(tmp_path, scanner("grype", after), scanner("trivy", after), patch=other)
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "not one of the advisory's fix references" in r.reason
    assert list(tmp_path.iterdir()) == []  # no statement was written


def test_a_vex_is_refused_when_the_feed_names_no_fix_reference(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    inp = gate_input(
        tmp_path, scanner("grype", after), scanner("trivy", after), advisory=Advisory(id=ADV.id)
    )
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "names no fix reference" in r.reason


def test_a_vex_needs_the_upstream_commit_to_be_contained_in_the_patch(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    other = PATCH.model_copy(
        update={"diff": "--- a/src/list.c\n+++ b/src/list.c\n@@ -1 +1 @@\n-a\n+b\n"}
    )
    inp = gate_input(tmp_path, scanner("grype", after), scanner("trivy", after), patch=other)
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "lacks upstream's changed line" in r.reason
    assert list(tmp_path.iterdir()) == []


def test_an_unreadable_upstream_commit_fails_closed(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    inp = gate_input(
        tmp_path,
        scanner("grype", after),
        scanner("trivy", after),
        upstream=fakes.FakeUpstream({}),
    )
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "could not read the upstream commit" in r.reason


def test_without_any_way_to_read_upstream_a_vex_is_refused(tmp_path: Path) -> None:
    after = [TARGET, SIBLING]
    inp = gate_input(tmp_path, scanner("grype", after), scanner("trivy", after), upstream=None)
    r = gate_scanners_clear(inp, ON)
    assert not r.passed and "no way to read the upstream commit" in r.reason
