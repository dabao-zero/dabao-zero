"""In-memory fakes: deterministic, no network, no Docker."""

from __future__ import annotations

from dataclasses import dataclass, field

from dabao.models import Advisory, Component, Finding, Patch


@dataclass
class FakeAgentRunner:
    """Replays recorded patches keyed by (advisory id, package)."""

    recorded: dict[tuple[str, str], Patch] = field(default_factory=dict)

    def propose_patch(self, advisory: Advisory, component: Component) -> Patch | None:
        return self.recorded.get((advisory.id, component.package))


@dataclass
class FakeDistroAdapter:
    """Digest is a function of component and patch, so builds are reproducible."""

    def build_image(self, component: Component, patch: Patch | None) -> str:
        suffix = patch.upstream_ref if patch else "unpatched"
        return f"sha256:{component.stream}-{component.package}-{component.version}-{suffix}"


@dataclass
class FakeScanner:
    findings_by_digest: dict[str, list[Finding]] = field(default_factory=dict)

    def scan(self, image_digest: str) -> list[Finding]:
        return list(self.findings_by_digest.get(image_digest, []))


@dataclass
class FakeRegistry:
    pushed: dict[str, str] = field(default_factory=dict)

    def push(self, image_digest: str, tag: str) -> None:
        self.pushed[tag] = image_digest


@dataclass
class FakeSigner:
    def sign(self, image_digest: str) -> str:
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
