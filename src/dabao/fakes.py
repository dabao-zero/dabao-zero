"""In-memory fakes: deterministic, no network, no Docker."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from dabao.gates import Verdict
from dabao.models import Advisory, Component, Finding, Patch
from dabao.seams import AgentResult, SuiteResult


@dataclass
class FakeAgentRunner:
    """Replays recorded patches keyed by (advisory id, package)."""

    recorded: dict[tuple[str, str], Patch] = field(default_factory=dict)
    cost_usd: float = 0.0
    raises: Exception | None = None

    def propose_patch(self, advisory: Advisory, component: Component) -> AgentResult:
        if self.raises is not None:
            raise self.raises
        patch = self.recorded.get((advisory.id, component.package))
        return AgentResult(patch=patch, tokens_in=100, tokens_out=50, cost_usd=self.cost_usd)


@dataclass
class FakeDistroAdapter:
    """Digest is a function of component and patch, so builds are reproducible."""

    def build_image(self, component: Component, patch: Patch | None) -> str:
        suffix = patch.upstream_ref if patch else "unpatched"
        key = f"{component.stream}-{component.package}-{component.version}-{suffix}"
        return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


@dataclass
class FakeScanner:
    findings_by_digest: dict[str, list[Finding]] = field(default_factory=dict)
    name: str = "fake"
    honours_vex: bool = True  # False: the scanner ignores any VEX it is given
    overclear: bool = False  # True: given any VEX it clears everything, as a buggy scanner might
    vex_applied: bool = False

    def with_vex(self, path: Path) -> FakeScanner:
        """Apply an OpenVEX file the way the real scanners do: drop a finding when a `fixed`
        statement names its CVE and a product whose package URL names its package."""
        if not self.honours_vex:
            return replace(self, vex_applied=True)
        doc = json.loads(path.read_text())
        fixed = [
            (s["vulnerability"]["name"], [p["@id"] for p in s["products"]])
            for s in doc["statements"]
            if s["status"] == "fixed"
        ]

        def cleared(f: Finding) -> bool:
            return self.overclear or any(
                f.advisory_id == adv and any(f"/{f.package}@" in purl for purl in purls)
                for adv, purls in fixed
            )

        return replace(
            self,
            vex_applied=True,
            findings_by_digest={
                d: [f for f in fs if not cleared(f)] for d, fs in self.findings_by_digest.items()
            },
        )

    def scan(self, image_digest: str) -> list[Finding]:
        return list(self.findings_by_digest.get(image_digest, []))


@dataclass
class FakeRegistry:
    pushed: dict[str, str] = field(default_factory=dict)

    def push(self, image_digest: str, tag: str) -> None:
        self.pushed[tag] = image_digest


@dataclass
class FakeSigner:
    signed: list[str] = field(default_factory=list)

    def sign(self, image_digest: str, verdict: Verdict) -> str:
        self.signed.append(image_digest)
        return f"sig:{image_digest}"


@dataclass
class FakeAdvisorySource:
    advisories: list[Advisory] = field(default_factory=list)

    def fetch(self) -> list[Advisory]:
        return list(self.advisories)


@dataclass
class FakeClock:
    t: float = 0.0

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@dataclass
class FakeSuiteRunner:
    results: dict[str, SuiteResult | None] = field(default_factory=dict)

    def run(self, image_digest: str) -> SuiteResult | None:
        return self.results.get(image_digest)


@dataclass
class FakeBuildDiffer:
    diffs: dict[tuple[str, str], list[str] | None] = field(default_factory=dict)

    def changed_files(self, before_digest: str, after_digest: str) -> list[str] | None:
        return self.diffs.get((before_digest, after_digest))


@dataclass
class FakeUpstream:
    """Upstream commits by reference; an unknown reference is unreadable (None)."""

    diffs: dict[str, str] = field(default_factory=dict)
    asked: list[str] = field(default_factory=list)

    def commit_diff(self, ref: str) -> str | None:
        self.asked.append(ref)
        return self.diffs.get(ref)
