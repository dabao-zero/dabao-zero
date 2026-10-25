from __future__ import annotations

import json

from dabao.baseline import Counts, summarise_grype, summarise_trivy

TRIVY = json.dumps(
    {
        "Metadata": {
            "OS": {"Family": "debian", "Name": "12.7"},
            "RepoDigests": ["nginx@sha256:" + "a" * 64],
        },
        "Results": [
            {
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "tar",
                        "FixedVersion": "1.2",
                        "Severity": "HIGH",
                        "Status": "fixed",
                    },
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "tar-scripts",
                        "FixedVersion": "1.2",
                        "Severity": "HIGH",
                        "Status": "fixed",
                    },
                    {
                        "VulnerabilityID": "CVE-2",
                        "PkgName": "libc6",
                        "Severity": "LOW",
                        "Status": "will_not_fix",
                    },
                    {
                        "VulnerabilityID": "CVE-3",
                        "PkgName": "zlib1g",
                        "Severity": "CRITICAL",
                        "Status": "affected",
                    },
                ],
            },
            {
                "Class": "lang-pkgs",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-9", "PkgName": "x"}],
            },
            {"Class": "os-pkgs", "Vulnerabilities": None},
        ],
    }
)
GRYPE = json.dumps(
    {
        "matches": [
            {
                "vulnerability": {"id": "CVE-1", "severity": "High", "fix": {"state": "fixed"}},
                "artifact": {"name": "tar", "type": "deb"},
            },
            {
                "vulnerability": {"id": "CVE-2", "severity": "Low", "fix": {"state": "wont-fix"}},
                "artifact": {"name": "libc6", "type": "deb"},
            },
            {
                "vulnerability": {
                    "id": "CVE-3",
                    "severity": "Critical",
                    "fix": {"state": "not-fixed"},
                },
                "artifact": {"name": "zlib1g", "type": "deb"},
            },
            {
                "vulnerability": {"id": "GHSA-x", "severity": "High", "fix": {"state": "fixed"}},
                "artifact": {"name": "left-pad", "type": "npm"},
            },
        ]
    }
)


def test_trivy_counts_os_packages_only_and_splits_fixable_from_not() -> None:
    c, base, digest = summarise_trivy(TRIVY)
    assert c == Counts(total=4, fixable=2, unfixable=2, fixable_high=2, critical_or_high=3)
    assert base == "debian 12.7" and digest == "sha256:" + "a" * 64


def test_grype_ignores_language_packages_and_counts_fix_states() -> None:
    c = summarise_grype(GRYPE)
    assert c == Counts(total=3, fixable=1, unfixable=2, fixable_high=1, critical_or_high=2)


def test_empty_results_are_zero() -> None:
    assert summarise_trivy("{}")[0] == Counts(0, 0, 0, 0, 0)
    assert summarise_grype('{"matches": []}') == Counts(0, 0, 0, 0, 0)
