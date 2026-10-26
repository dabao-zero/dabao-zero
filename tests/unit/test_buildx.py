from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dabao.buildx import BuildError, build_oci

STDERR = (
    "#12 [build 9/9] RUN set -eu; cd aports; ...\n"
    "#12 0.210 no aports commit has brotli 9.9.9-r0\n"
    '#12 ERROR: process "/bin/sh -c ..." did not complete successfully: exit code: 1\n'
    "------\n > [build 9/9] RUN ...:\n"
    + "0.210 no aports commit has brotli 9.9.9-r0\n"
    + "------\n"
    + "".join(f"  {n} | >>> RUN something long {n}\n" for n in range(60))
    + "ERROR: failed to build: failed to solve: process did not complete successfully\n"
)


def test_a_failed_build_reports_what_the_failing_step_printed_not_just_the_tail(
    tmp_path: Path,
) -> None:
    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 1, b"", STDERR.encode())

    with pytest.raises(BuildError) as exc:
        build_oci(run, "b", tmp_path, tmp_path / "out", 1)
    assert "no aports commit has brotli 9.9.9-r0" in str(exc.value)  # buried far above the tail
    assert len(str(exc.value)) < 2500


def test_an_unrecognised_failure_still_reports_the_tail(tmp_path: Path) -> None:
    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 1, b"", b"x" * 4000 + b"daemon not running")

    with pytest.raises(BuildError, match="daemon not running"):
        build_oci(run, "b", tmp_path, tmp_path / "out", 1)


def test_the_failing_step_is_picked_out_even_when_other_steps_log_after_it(tmp_path: Path) -> None:
    # BuildKit builds stages in parallel and interleaves their logs, so "the last lines" can belong
    # to a step that succeeded. The failing step is the one named in the `#N ERROR:` line.
    stderr = (
        "#7 0.5 (48/59) Installing xz-libs\n"
        "#9 0.2 no aports commit has brotli 9.9.9-r0\n"
        '#9 ERROR: process "/bin/sh -c ..." did not complete successfully: exit code: 1\n'
        "#7 9.9 (59/59) Installing sudo\n"
        "#7 10.0 OK: 327 MiB in 75 packages\n"
    )

    def run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args, 1, b"", stderr.encode())

    with pytest.raises(BuildError) as exc:
        build_oci(run, "b", tmp_path, tmp_path / "out", 1)
    assert "no aports commit has brotli 9.9.9-r0" in str(exc.value)
    assert "Installing sudo" not in str(exc.value)
