"""Injection seams (docs/testing-and-ci.md). Fakes live in dabao.fakes."""

from __future__ import annotations

from typing import Protocol

from dabao.models import Advisory, Component, Finding, Patch


class AgentRunner(Protocol):
    def propose_patch(self, advisory: Advisory, component: Component) -> Patch | None: ...


class DistroAdapter(Protocol):
    def build_image(self, component: Component, patch: Patch | None) -> str:
        """Return the digest of the built image."""
        ...


class Scanner(Protocol):
    def scan(self, image_digest: str) -> list[Finding]: ...


class Registry(Protocol):
    def push(self, image_digest: str, tag: str) -> None: ...


class Signer(Protocol):
    def sign(self, image_digest: str) -> str:
        """Return a signature reference."""
        ...


class AdvisorySource(Protocol):
    def fetch(self) -> list[Advisory]: ...


class Clock(Protocol):
    def now(self) -> float: ...
