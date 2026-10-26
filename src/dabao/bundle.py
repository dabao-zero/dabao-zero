"""Candidate-patch bundle: the hand-off from a manual agent run to the orchestrator (ADR-0009).

A bundle is data, never instructions. Importing one is a separate step; this module only
validates its shape and refuses anything the gates would refuse anyway (ADR-0003).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from dabao.models import Patch, PatchSource

BUNDLE_VERSION: Literal[1] = 1


class Runner(StrEnum):
    MANUAL_CODEX = "manual_codex"
    MANUAL_CLAUDE_CODE = "manual_claude_code"


class BundleError(ValueError):
    """The bundle is not valid; the message names the offending fields."""


class Usage(BaseModel):
    """What the run cost. A subscription run has no per-token price, so cost_usd is 0.0."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    cost_usd: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)


class CandidateBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1]
    runner: Runner
    patch: Patch
    upstream_links: tuple[str, ...] = Field(min_length=1)
    run_log: str
    tool_versions: dict[str, str]
    model: str
    created_at: float
    usage: Usage | None = None  # optional so older bundles still load

    @model_validator(mode="after")
    def _check_patch(self) -> CandidateBundle:
        if self.patch.source is not PatchSource.UPSTREAM_DERIVED:
            raise ValueError("patch.source must be upstream_derived")
        if not self.patch.diff.strip():
            raise ValueError("patch.diff is empty")
        if self.patch.upstream_ref not in self.upstream_links:
            raise ValueError("patch.upstream_ref must be one of upstream_links")
        return self


def load_bundle(text: str) -> CandidateBundle:
    try:
        return CandidateBundle.model_validate_json(text)
    except ValidationError as e:
        if any(err["type"] == "json_invalid" for err in e.errors()):
            raise BundleError("bundle is not valid JSON") from e
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()
        )
        raise BundleError(problems) from e
