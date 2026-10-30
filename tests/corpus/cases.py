"""Known-good and known-bad corpus for the publish gates (docs/testing-and-ci.md).

Every gate must be turned red by at least one bad case; test_corpus.py enforces that.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from dabao import fakes
from dabao.gates import GateConfig, GateInput
from dabao.models import Advisory, Component, Finding, Patch, PatchSource
from dabao.seams import SuiteResult

ALLOWED_SOURCE = "https://github.com/nginx/nginx/commit/"
CFG = GateConfig(provenance_allowlist=(ALLOWED_SOURCE,), allowed_extra_paths=("var/lib/dpkg/",))

ADV = Advisory(
    id="CVE-2024-0001",
    aliases=("GHSA-aaaa-bbbb-cccc",),
    fix_refs=(ALLOWED_SOURCE + "abc123",),
)
COMP = Component(stream="debian", package="nginx", version="1.22.0-1")
DIFF = "--- a/src/http/ngx_http_parse.c\n+++ b/src/http/ngx_http_parse.c\n@@ -1 +1 @@\n-x\n+y\n"
PATCH = Patch(
    advisory_id=ADV.id,
    component=COMP,
    source=PatchSource.UPSTREAM_DERIVED,
    upstream_ref=ALLOWED_SOURCE + "abc123",
    diff=DIFF,
)
BEFORE, AFTER = "sha256:before", "sha256:after"
FINDING = Finding(advisory_id=ADV.id, package="nginx")
SIBLING = Finding(advisory_id="CVE-2024-0002", package="nginx")  # same upload, not fixed here
_VEX_DIR = tempfile.TemporaryDirectory(prefix="dabao-corpus-")  # removed at exit
GOOD_CHANGED = ["src/http/ngx_http_parse.c", "var/lib/dpkg/status"]


def good_input() -> GateInput:
    return GateInput(
        advisory=ADV,
        patch=PATCH,
        before_digest=BEFORE,
        after_digest=AFTER,
        scanners=(
            fakes.FakeScanner({BEFORE: [FINDING]}, name="grype"),
            fakes.FakeScanner({BEFORE: [FINDING]}, name="trivy"),
        ),
        suite_runner=fakes.FakeSuiteRunner({AFTER: SuiteResult(True)}),
        differ=fakes.FakeBuildDiffer({(BEFORE, AFTER): GOOD_CHANGED}),
    )


@dataclass(frozen=True)
class _Shipped:
    changes: dict[tuple[str, str], list[str]]

    def shipped_changes(self, control_digest: str, after_digest: str) -> list[str] | None:
        return self.changes.get((control_digest, after_digest))


@dataclass(frozen=True)
class BadCase:
    label: str
    expected_gate: str
    input: GateInput
    config: GateConfig = CFG


def _bad_cases() -> list[BadCase]:
    g = good_input()
    still_vulnerable = (
        fakes.FakeScanner({BEFORE: [FINDING], AFTER: [FINDING]}, name="grype"),
        fakes.FakeScanner({BEFORE: [FINDING]}, name="trivy"),
    )
    never_seen = (
        fakes.FakeScanner({}, name="grype"),
        fakes.FakeScanner({}, name="trivy"),
    )
    alias_still_reported = (
        fakes.FakeScanner({BEFORE: [FINDING]}, name="grype"),
        fakes.FakeScanner(
            {
                BEFORE: [FINDING],
                AFTER: [Finding(advisory_id="GHSA-aaaa-bbbb-cccc", package="nginx")],
            },
            name="trivy",
        ),
    )
    return [
        BadCase(
            "fix does not fix the CVE", "scanners_clear", replace(g, scanners=still_vulnerable)
        ),
        BadCase(
            "CVE still reported under an alias",
            "scanners_clear",
            replace(g, scanners=alias_still_reported),
        ),
        BadCase(
            "a VEX for this CVE would also clear a sibling CVE (ADR-0010 check 4)",
            "scanners_clear",
            replace(
                g,
                scanners=(
                    fakes.FakeScanner(
                        {BEFORE: [FINDING], AFTER: [FINDING, SIBLING]}, name="grype", overclear=True
                    ),
                    fakes.FakeScanner({BEFORE: [FINDING], AFTER: [FINDING, SIBLING]}, name="trivy"),
                ),
                rebuilt_packages=(("nginx", "1.22.0-1-dabao1"),),
                stream="debian",
                vex_dir=Path(_VEX_DIR.name),
            ),
            replace(CFG, vex_enabled=True),
        ),
        BadCase(
            "only one scanner configured", "scanners_clear", replace(g, scanners=g.scanners[:1])
        ),
        BadCase(
            "CVE never present before (vacuous fix)",
            "advisory_present_before",
            replace(g, scanners=never_seen),
        ),
        BadCase(
            "official suite fails",
            "tests_pass",
            replace(g, suite_runner=fakes.FakeSuiteRunner({AFTER: SuiteResult(False, "boom")})),
        ),
        BadCase(
            "official suite could not run",
            "tests_pass",
            replace(g, suite_runner=fakes.FakeSuiteRunner({AFTER: None})),
        ),
        BadCase("no test runner at all", "tests_pass", replace(g, suite_runner=None)),
        BadCase(
            "patch deletes/changes an unrelated file",
            "build_diff",
            replace(
                g,
                differ=fakes.FakeBuildDiffer(
                    {(BEFORE, AFTER): [*GOOD_CHANGED, "usr/sbin/nginx-extra-binary"]}
                ),
            ),
        ),
        BadCase(
            "patch builds identically to a rebuild without it (DAB-83)",
            "build_diff",
            replace(
                g,
                control_digest="sha256:control",
                shipped=_Shipped({("sha256:control", AFTER): []}),
            ),
            replace(CFG, require_shipped_change=True),
        ),
        BadCase(
            "build comparison unavailable",
            "build_diff",
            replace(g, differ=fakes.FakeBuildDiffer({(BEFORE, AFTER): None})),
        ),
        BadCase(
            "patch cites a source outside the allow-list",
            "provenance",
            replace(
                g, patch=PATCH.model_copy(update={"upstream_ref": "https://evil.example/commit/1"})
            ),
        ),
        BadCase(
            "allow-listed URL that is not a fix reference of this advisory (ADR-0010 check 1)",
            "provenance",
            replace(
                g, patch=PATCH.model_copy(update={"upstream_ref": ALLOWED_SOURCE + "other999"})
            ),
            replace(CFG, require_fix_reference=True),
        ),
        BadCase(
            "advisory with no fix reference in the feed (ADR-0010 check 1)",
            "provenance",
            replace(g, advisory=Advisory(id=ADV.id, aliases=ADV.aliases)),
            replace(CFG, require_fix_reference=True),
        ),
        BadCase(
            "patch changes other lines than the upstream commit it cites (ADR-0010 check 2)",
            "provenance",
            replace(g, upstream=fakes.FakeUpstream({PATCH.upstream_ref: DIFF.replace("+y", "+z")})),
            replace(CFG, require_containment=True),
        ),
        BadCase(
            "upstream commit cannot be read (ADR-0010 check 2)",
            "provenance",
            replace(g, upstream=fakes.FakeUpstream({})),
            replace(CFG, require_containment=True),
        ),
        BadCase(
            "patch has no upstream reference",
            "provenance",
            replace(g, patch=PATCH.model_copy(update={"upstream_ref": ""})),
        ),
        BadCase(
            "original-fix patch while the stream is off",
            "provenance",
            replace(g, patch=PATCH.model_copy(update={"source": PatchSource.ORIGINAL})),
        ),
        BadCase(
            "original-fix patch even with the flag on (not implemented)",
            "provenance",
            replace(g, patch=PATCH.model_copy(update={"source": PatchSource.ORIGINAL})),
            replace(CFG, allow_original=True),
        ),
    ]


BAD_CASES = _bad_cases()
