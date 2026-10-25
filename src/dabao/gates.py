"""Deterministic publish gates (ADR-0002).

Agents propose; these decide. Every gate fails closed: missing data is a failure, never a pass.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from dabao.models import Advisory, Patch, PatchSource
from dabao.seams import BuildDiffer, Scanner, SuiteRunner
from dabao.vex import VexStatement, write_openvex

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
    # ADR-0010: let the gate clear a CVE a scanner still reports with a VEX it issues. Off until the
    # evidence checks (fix reference of the advisory, upstream change contained in the patch) exist.
    vex_enabled: bool = False


@dataclass(frozen=True)
class GateInput:
    advisory: Advisory
    patch: Patch
    before_digest: str
    after_digest: str
    scanners: Sequence[Scanner] = field(default_factory=tuple)
    suite_runner: SuiteRunner | None = None
    differ: BuildDiffer | None = None
    # What a VEX statement needs (ADR-0010): which binary packages were rebuilt, in which stream, a
    # directory to write the document in, and the time to put in it.
    rebuilt_packages: tuple[tuple[str, str], ...] = ()
    stream: str = ""
    vex_dir: Path | None = None
    now: float = 0.0


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
    plain = {n: _scan_ids(s, inp.after_digest) for n, s in scanners.items()}
    still = [n for n, found in plain.items() if ids & found]
    if not still:
        return GateResult(name, True, "all scanners clear")
    if not cfg.vex_enabled:
        return GateResult(name, False, f"still reported by {sorted(still)}")
    how = {n: "natively" for n in plain if n not in still}
    for n in sorted(still):
        problem = _clear_with_vex(inp, n, scanners[n], plain[n], ids)
        if problem:
            return GateResult(name, False, f"{n}: {problem}")
        how[n] = "via VEX"
    return GateResult(name, True, "clear: " + ", ".join(f"{n} {h}" for n, h in sorted(how.items())))


def _clear_with_vex(
    inp: GateInput, scanner_name: str, scanner: Scanner, plain_ids: set[str], ids: set[str]
) -> str:
    """Issue a statement for the target CVE and check the scanner then reports one finding fewer.

    Returns "" when the scanner is clear with the VEX and the VEX changed nothing but the target
    CVE (ADR-0010 check 4); otherwise the reason it is not.
    """
    if not inp.rebuilt_packages:
        return "cannot issue a VEX: no rebuilt packages are known"
    if inp.vex_dir is None:
        return "cannot issue a VEX: nowhere to write it"
    with_vex = getattr(scanner, "with_vex", None)
    if with_vex is None:
        return "this scanner cannot apply a VEX"
    target = sorted(ids & plain_ids)
    statements = [
        VexStatement(
            advisory_id=i,
            stream=inp.stream,
            packages=inp.rebuilt_packages,
            upstream_ref=inp.patch.upstream_ref,
            patch_sha256=hashlib.sha256(inp.patch.diff.encode()).hexdigest(),
        )
        for i in target
    ]
    path = inp.vex_dir / f"{scanner_name}-{inp.after_digest.removeprefix('sha256:')[:12]}.vex.json"
    write_openvex(path, statements, inp.now)
    try:
        after_vex = _scan_ids(with_vex(path), inp.after_digest)
    except AttributeError:
        return "this scanner cannot apply a VEX"
    if ids & after_vex:
        return f"still reports {sorted(ids & after_vex)} with the VEX (the VEX was ignored)"
    extra = (plain_ids - after_vex) - ids
    if extra:
        return f"the VEX would also clear {sorted(extra)}, which the patch is not shown to fix"
    added = after_vex - plain_ids
    if added:
        return f"the VEX changed the scan unexpectedly: new findings {sorted(added)}"
    return ""


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
