"""Deterministic publish gates (ADR-0002).

Agents propose; these decide. Every gate fails closed: missing data is a failure, never a pass.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from dabao.models import Advisory, Patch, PatchSource
from dabao.seams import BuildDiffer, Scanner, ShippedDiffer, SuiteRunner, UpstreamFetcher
from dabao.upstream import containment_problem, patch_url
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
    # ADR-0010 check 1 for every patch, not only VEX ones: upstream_ref must be one of the
    # advisory's own fix references from the feed, not just any URL on the allow-list.
    require_fix_reference: bool = False
    # ADR-0010 check 2 for every patch: the upstream commit, fetched by the gate, must be contained
    # in the patch diff. Always required for a VEX.
    require_containment: bool = False
    # DAB-83: the patched build must differ in shipped files from a rebuild without the patch (the
    # "control"). Stops a "fixed" claim for code the package does not build or ship.
    require_shipped_change: bool = False


@dataclass(frozen=True)
class GateInput:
    advisory: Advisory
    patch: Patch
    before_digest: str
    after_digest: str
    scanners: Sequence[Scanner] = field(default_factory=tuple)
    suite_runner: SuiteRunner | None = None
    differ: BuildDiffer | None = None
    upstream: UpstreamFetcher | None = None  # reads the commit the patch says it derives from
    control_digest: str = ""  # the same build without the patch (DAB-83)
    shipped: ShippedDiffer | None = None
    # What a VEX statement needs (ADR-0010): which binary packages were rebuilt, in which stream, a
    # directory to write the document in, and the time to put in it.
    rebuilt_packages: tuple[tuple[str, str], ...] = ()
    stream: str = ""
    vex_dir: Path | None = None
    now: float = 0.0


def _parse_ref(url: str) -> tuple[str, str, str, str]:
    """(host, path, other query, commit) of a reference; scheme, fragment, slash and .patch ignored.

    The commit is the last path segment under /commit/ or the `id` query parameter (cgit).
    """
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/").removesuffix(".patch").removesuffix(".diff")
    query = dict(parse_qsl(parts.query))
    commit = ""
    if "id" in query:
        commit = query.pop("id")
    elif path.rpartition("/")[0].endswith(("/commit", "/commits")):
        path, _, commit = path.rpartition("/")
    return parts.netloc.lower(), path, urlencode(sorted(query.items())), commit.lower()


def _same_ref(a: str, b: str) -> bool:
    """Same reference, or same repository with one commit id a prefix (7+ hex) of the other."""
    *where_a, commit_a = _parse_ref(a)
    *where_b, commit_b = _parse_ref(b)
    if where_a != where_b:
        return False
    if commit_a == commit_b:
        return True
    short, long = sorted((commit_a, commit_b), key=len)
    return (
        len(short) >= 7 and all(c in "0123456789abcdef" for c in short) and long.startswith(short)
    )


def fix_reference_problem(advisory: Advisory, ref: str) -> str:
    """ADR-0010 check 1. "" when `ref` is one of the advisory's fix references from the feed."""
    if not advisory.fix_refs:
        return "the feed names no fix reference for this advisory"
    if not any(_same_ref(ref, known) for known in advisory.fix_refs):
        return f"{ref} is not one of the advisory's fix references"
    return ""


def commit_refs(advisory: Advisory, upstream_ref: str) -> list[str]:
    """The commit the patch cites, then every other commit the advisory lists as a fix."""
    refs = [upstream_ref]
    for ref in advisory.fix_refs:
        if patch_url(ref) is not None and not any(_same_ref(ref, known) for known in refs):
            refs.append(ref)
    return refs


def upstream_problem(inp: GateInput) -> str:
    """ADR-0010 check 2. "" when every upstream fix commit is contained in the patch.

    The cited commit and every other commit the advisory lists are read by the gate and checked on
    their own, so half of a multi-commit fix (libtasn1 lists two) cannot pass. A commit that cannot
    be read, for any reason, fails closed.
    """
    if inp.upstream is None:
        return "no way to read the upstream commit"
    cited = inp.patch.upstream_ref
    for ref in commit_refs(inp.advisory, cited):
        text = inp.upstream.commit_diff(ref)
        if text is None:
            return f"could not read the upstream commit {ref}"
        problem = containment_problem(text, inp.patch.diff, allow_support_only=ref != cited)
        if problem:
            return problem if ref == cited else f"listed fix commit {ref}: {problem}"
    return ""


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
    problem = fix_reference_problem(inp.advisory, inp.patch.upstream_ref)
    if problem:
        return f"cannot issue a VEX: {problem}"
    problem = upstream_problem(inp)
    if problem:
        return f"cannot issue a VEX: {problem}"
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


def _shipped_problem(inp: GateInput) -> str:
    """DAB-83. "" when the patched build ships files the control build (no patch) does not."""
    if not inp.control_digest or inp.shipped is None:
        return "no control build to compare with: cannot show the patch changes what ships"
    changes = inp.shipped.shipped_changes(inp.control_digest, inp.after_digest)
    if changes is None:
        return "comparison with the control build could not run"
    if not changes:
        return (
            "the patch changes nothing the package ships: the build is identical to a rebuild "
            "without it (the fixed code may not be built)"
        )
    return ""


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
    if cfg.require_shipped_change:
        problem = _shipped_problem(inp)
        if problem:
            return GateResult(name, False, problem)
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
    if cfg.require_fix_reference:
        problem = fix_reference_problem(inp.advisory, ref)
        if problem:
            return GateResult(name, False, problem)
    if cfg.require_containment:
        problem = upstream_problem(inp)
        if problem:
            return GateResult(name, False, problem)
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
