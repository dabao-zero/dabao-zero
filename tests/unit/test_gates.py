import pytest

from dabao.gates import GATE_NAMES, patch_paths, run_gates
from tests.corpus.cases import BAD_CASES, CFG, good_input


def test_known_good_passes_every_gate() -> None:
    verdict = run_gates(good_input(), CFG)
    assert verdict.passed, verdict.failed_gates()
    assert [r.name for r in verdict.results] == list(GATE_NAMES)


@pytest.mark.parametrize("case", BAD_CASES, ids=lambda c: c.label)
def test_known_bad_is_rejected_by_the_expected_gate(case) -> None:  # type: ignore[no-untyped-def]
    verdict = run_gates(case.input, case.config)
    assert not verdict.passed
    assert case.expected_gate in verdict.failed_gates()


def test_every_gate_is_proven_by_watching_it_fail() -> None:
    covered = {c.expected_gate for c in BAD_CASES}
    assert covered == set(GATE_NAMES)


def test_all_failures_are_reported_not_just_the_first() -> None:
    bad = BAD_CASES[0]
    broken = type(bad.input)(**{**bad.input.__dict__, "suite_runner": None})
    verdict = run_gates(broken, CFG)
    assert {"scanners_clear", "tests_pass"} <= set(verdict.failed_gates())


def test_patch_paths_parses_git_and_plain_diffs() -> None:
    diff = "--- a/x.c\t2024\n+++ b/x.c\n--- /dev/null\n+++ b/new.c\n"
    assert patch_paths(diff) == {"x.c", "new.c"}
