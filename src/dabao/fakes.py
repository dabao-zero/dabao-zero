"""In-memory fakes: deterministic, no network, no Docker."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

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
