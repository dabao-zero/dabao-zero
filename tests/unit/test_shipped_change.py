"""DAB-83: a patch must change what the package ships, shown against a rebuild without it."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from dabao import fakes
from dabao.gates import GateConfig, run_gates
from tests.corpus.cases import AFTER, BEFORE, CFG, COMP, PATCH, good_input

CONTROL = "sha256:control"
ON = replace(CFG, require_shipped_change=True)


@dataclass
class FakeShipped:
    changes: dict[tuple[str, str], list[str] | None] = field(default_factory=dict)
    asked: list[tuple[str, str]] = field(default_factory=list)

    def shipped_changes(self, control_digest: str, after_digest: str) -> list[str] | None:
        self.asked.append((control_digest, after_digest))
        return self.changes.get((control_digest, after_digest))


def with_shipped(changes: list[str] | None):  # type: ignore[no-untyped-def]
    return replace(
        good_input(),
        control_digest=CONTROL,
        shipped=FakeShipped({(CONTROL, AFTER): changes}),
    )


def build_diff(inp, cfg: GateConfig):  # type: ignore[no-untyped-def]
    return next(r for r in run_gates(inp, cfg).results if r.name == "build_diff")


def test_off_by_default_so_a_patch_with_no_control_still_passes() -> None:
    assert build_diff(good_input(), CFG).passed


def test_a_patch_that_changes_shipped_files_passes() -> None:
    result = build_diff(with_shipped(["usr/bin/tar"]), ON)
    assert result.passed, result.reason


def test_a_patch_whose_build_is_the_control_fails_the_build_diff_gate() -> None:
    result = build_diff(with_shipped([]), ON)
    assert not result.passed
    assert "changes nothing the package ships" in result.reason


def test_no_control_build_fails_closed() -> None:
    inp = replace(good_input(), control_digest="", shipped=FakeShipped())
    result = build_diff(inp, ON)
    assert not result.passed and "control" in result.reason


def test_no_comparer_fails_closed() -> None:
    result = build_diff(replace(good_input(), control_digest=CONTROL), ON)
    assert not result.passed


def test_a_comparison_that_cannot_run_fails_closed() -> None:
    result = build_diff(with_shipped(None), ON)
    assert not result.passed and "could not run" in result.reason


def test_the_gate_compares_the_control_with_the_patched_build() -> None:
    inp = with_shipped(["x"])
    build_diff(inp, ON)
    assert inp.shipped.asked == [(CONTROL, AFTER)]
    assert BEFORE not in inp.shipped.asked[0]


def test_the_fake_adapter_builds_a_control_that_differs_from_the_patched_build() -> None:
    adapter = fakes.FakeDistroAdapter()
    assert adapter.build_control(COMP, PATCH) not in (
        adapter.build_image(COMP, None),
        adapter.build_image(COMP, PATCH),
    )
