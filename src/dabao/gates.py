"""Deterministic publish gates (ADR-0002).

Agents propose; these decide. Every gate fails closed: missing data is a failure, never a pass.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from dabao.models import Advisory, Patch, PatchSource
from dabao.seams import BuildDiffer, Scanner, SuiteRunner

GATE_NAMES = ("advisory_present_before", "scanners_clear", "tests_pass", "build_diff", "provenance")


@dataclass(frozen=True)
class GateResult:
    name: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class Verdict:
    results: tuple[GateResult, ...]
    digest: str = ""  # the image digest this verdict is about; the signer checks it

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def failed_gates(self) -> list[str]:
        return [r.name for r in self.results if not r.passed]


@dataclass(frozen=True)
class GateConfig:
    required_scanners: int = 2
    allow_original: bool = False  # ADR-0003: the original-fix stream is off
    provenance_allowlist: tuple[str, ...] = ()
    allowed_extra_paths: tuple[str, ...] = ()  # e.g. package metadata that legitimately changes


@dataclass(frozen=True)
class GateInput:
    advisory: Advisory
    patch: Patch
    before_digest: str
    after_digest: str
    scanners: Sequence[Scanner] = field(default_factory=tuple)
    suite_runner: SuiteRunner | None = None
    differ: BuildDiffer | None = None


def _advisory_ids(advisory: Advisory) -> set[str]:
    return {advisory.id, *advisory.aliases}


def _scan_ids(scanner: Scanner, digest: str) -> set[str]:
    return {f.advisory_id for f in scanner.scan(digest)}


def _distinct_scanners(scanners: Sequence[Scanner]) -> dict[str, Scanner]:
    return {s.name: s for s in scanners}


def gate_advisory_present_before(inp: GateInput, cfg: GateConfig) -> GateResult:
    """A fix for a CVE the scanners never saw proves nothing."""
    name = "advisory_present_before"
    scanners = _distinct_scanners(inp.scanners)
    if len(scanners) < cfg.required_scanners:
        return GateResult(
            name, False, f"need {cfg.required_scanners} scanners, have {len(scanners)}"
        )
    ids = _advisory_ids(inp.advisory)
    seen = [n for n, s in scanners.items() if ids & _scan_ids(s, inp.before_digest)]
    if not seen:
        return GateResult(name, False, "no scanner reported the advisory on the unpatched image")
    return GateResult(name, True, f"reported by {sorted(seen)}")


def gate_scanners_clear(inp: GateInput, cfg: GateConfig) -> GateResult:
    name = "scanners_clear"
    scanners = _distinct_scanners(inp.scanners)
    if len(scanners) < cfg.required_scanners:
        return GateResult(
            name, False, f"need {cfg.required_scanners} scanners, have {len(scanners)}"
        )
    ids = _advisory_ids(inp.advisory)
    still = [n for n, s in scanners.items() if ids & _scan_ids(s, inp.after_digest)]
    if still:
        return GateResult(name, False, f"still reported by {sorted(still)}")
    return GateResult(name, True, "all scanners clear")


def gate_tests_pass(inp: GateInput, cfg: GateConfig) -> GateResult:
    name = "tests_pass"
    if inp.suite_runner is None:
        return GateResult(name, False, "no test runner configured")
    result = inp.suite_runner.run(inp.after_digest)
    if result is None:
        return GateResult(name, False, "test suite could not run")
    if not result.passed:
        return GateResult(name, False, f"test suite failed: {result.details}")
    return GateResult(name, True, "test suite passed")


def patch_paths(diff: str) -> set[str]:
    """Paths named in a unified diff's ---/+++ headers (git a/ b/ prefixes stripped)."""
    paths: set[str] = set()
    for line in diff.splitlines():
        if line.startswith(("--- ", "+++ ")):
            raw = line[4:].split("\t")[0].strip()
            if raw == "/dev/null":
                continue
            paths.add(raw.removeprefix("a/").removeprefix("b/"))
    return paths


def gate_build_diff(inp: GateInput, cfg: GateConfig) -> GateResult:
    name = "build_diff"
    if inp.differ is None:
        return GateResult(name, False, "no build differ configured")
    changed = inp.differ.changed_files(inp.before_digest, inp.after_digest)
    if changed is None:
        return GateResult(name, False, "build comparison could not run")
    allowed = patch_paths(inp.patch.diff)
    unexpected = sorted(
        f
        for f in changed
        if f not in allowed and not any(f.startswith(p) for p in cfg.allowed_extra_paths)
    )
    if unexpected:
        return GateResult(name, False, f"unexpected changes: {unexpected}")
    return GateResult(name, True, f"{len(changed)} changed file(s), all expected")


def gate_provenance(inp: GateInput, cfg: GateConfig) -> GateResult:
    name = "provenance"
    if inp.patch.source is PatchSource.ORIGINAL and not cfg.allow_original:
        return GateResult(name, False, "original-fix stream is disabled (ADR-0003)")
    if inp.patch.source is PatchSource.ORIGINAL:
        return GateResult(name, False, "original-fix gating is not implemented yet")
    ref = inp.patch.upstream_ref
    if not ref:
        return GateResult(name, False, "patch has no upstream reference")
    if not any(ref.startswith(p) for p in cfg.provenance_allowlist):
        return GateResult(name, False, f"source not on the allow-list: {ref}")
    return GateResult(name, True, f"derived from {ref}")


_GATES = (
    gate_advisory_present_before,
    gate_scanners_clear,
    gate_tests_pass,
    gate_build_diff,
    gate_provenance,
)


def run_gates(inp: GateInput, cfg: GateConfig) -> Verdict:
    """Run every gate (no short-circuit, so the ledger shows all failures)."""
    return Verdict(tuple(g(inp, cfg) for g in _GATES), digest=inp.after_digest)
