"""Injection seams (docs/testing-and-ci.md). Fakes live in dabao.fakes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from dabao.models import Advisory, Component, Finding, Patch

if TYPE_CHECKING:
    from dabao.gates import Verdict


@dataclass(frozen=True)
class AgentResult:
    """What an agent run produced and what it cost. `patch` is None when it found no fix."""

    patch: Patch | None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    log: str = ""
    agent_seconds: float | None = None  # set when the run happened elsewhere; else measured


class AgentRunner(Protocol):
    def propose_patch(self, advisory: Advisory, component: Component) -> AgentResult: ...


class DistroAdapter(Protocol):
    def build_image(self, component: Component, patch: Patch | None) -> str:
        """Return the digest of the built image."""
        ...


class Scanner(Protocol):
    name: str

    def scan(self, image_digest: str) -> list[Finding]: ...


class UpstreamFetcher(Protocol):
    def commit_diff(self, ref: str) -> str | None:
        """The patch text of the upstream commit `ref`, or None when it cannot be read."""
        ...


class Registry(Protocol):
    def push(self, image_digest: str, tag: str) -> None: ...


class Signer(Protocol):
    def sign(self, image_digest: str, verdict: Verdict) -> str:
        """Return a signature reference. May raise SigningRefused."""
        ...


class AdvisorySource(Protocol):
    def fetch(self) -> list[Advisory]: ...


class Clock(Protocol):
    def now(self) -> float: ...


@dataclass(frozen=True)
class SuiteResult:
    passed: bool
    details: str = ""


class SuiteRunner(Protocol):
    def run(self, image_digest: str) -> SuiteResult | None:
        """Run the official-image test suite and smoke tests. None means it could not run."""
        ...


class BuildDiffer(Protocol):
    def changed_files(self, before_digest: str, after_digest: str) -> list[str] | None:
        """Files that differ between two builds. None means the comparison could not run."""
        ...


class ShippedDiffer(Protocol):
    def shipped_changes(self, control_digest: str, after_digest: str) -> list[str] | None:
        """Files whose bytes differ between a build without the patch and the patched build, or
        exist in only one. None means the comparison could not run."""
        ...
