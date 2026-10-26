"""Core entities (PLAN §Implementation decisions)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class PatchSource(StrEnum):
    """Where a patch came from (ADR-0003). Only UPSTREAM_DERIVED can be published today."""

    UPSTREAM_DERIVED = "upstream_derived"
    ORIGINAL = "original"


class AdvisoryStatus(StrEnum):
    PENDING = "PENDING"
    PATCHED = "PATCHED"
    UNPATCHED = "UNPATCHED"
    NOT_AFFECTED = "NOT_AFFECTED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class Advisory(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str  # canonical ID, e.g. CVE-2024-1234
    aliases: tuple[str, ...] = ()
    # URLs the feed names as the fix (OSV references of type FIX); ADR-0010 check 1.
    fix_refs: tuple[str, ...] = ()


class Component(BaseModel):
    """A package at a version inside one distro stream."""

    model_config = ConfigDict(frozen=True)

    stream: str  # "debian" | "alpine" | "wolfi"
    package: str
    version: str


class Patch(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory_id: str
    component: Component
    source: PatchSource
    upstream_ref: str  # commit or advisory the fix derives from
    diff: str


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory_id: str
    package: str
    severity: str = ""
    fix_state: str = "unknown"  # "fixed" (scanner names a fix), "unfixed", or "unknown"
