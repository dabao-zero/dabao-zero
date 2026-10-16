"""Signing policy and the cosign backend (ADR-0002, ADR-0005).

`GuardedSigner` is the only way an artifact gets signed. It re-checks the gate verdict itself,
so an orchestrator bug (or a compromised caller) cannot get an ungated image signed. The real
backend is keyless cosign using the CI identity; agent sandboxes never hold a signing identity.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable

from dabao.gates import GATE_NAMES, Verdict
from dabao.seams import Signer

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SigningRefused(Exception):
    """The request does not justify a signature. Nothing was signed."""


class SigningError(Exception):
    """The backend failed to sign."""


class GuardedSigner:
    def __init__(
        self,
        backend: Signer,
        is_revoked: Callable[[str], bool] = lambda _d: False,
        is_frozen: Callable[[], bool] = lambda: False,
    ) -> None:
        self._backend, self._is_revoked, self._is_frozen = backend, is_revoked, is_frozen

    def sign(self, image_digest: str, verdict: Verdict) -> str:
        self._check(image_digest, verdict)
        return self._backend.sign(image_digest, verdict)

    def _check(self, digest: str, verdict: Verdict) -> None:
        if self._is_frozen():
            raise SigningRefused("signing is frozen by an operator")
        if not DIGEST_RE.match(digest):
            raise SigningRefused(f"not a valid sha256 digest: {digest!r}")
        if verdict.digest != digest:
            raise SigningRefused("verdict is for a different image digest")
        names = [r.name for r in verdict.results]
        if sorted(names) != sorted(GATE_NAMES):
            raise SigningRefused(f"verdict does not cover exactly the required gates: {names}")
        failed = verdict.failed_gates()
        if failed:
            raise SigningRefused(f"gates failed: {failed}")
        if self._is_revoked(digest):
            raise SigningRefused("digest has been revoked")


Runner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


def _run(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=300, check=False)


class CosignSigner:
    """Keyless cosign (Sigstore) signing of `<repository>@<digest>`.

    Identity comes from the CI environment's OIDC token; no key material exists here.
    Wrap in GuardedSigner: this class performs no policy checks of its own.
    """

    def __init__(self, repository: str, binary: str = "cosign", runner: Runner = _run) -> None:
        self._repo, self._binary, self._runner = repository, binary, runner

    def sign(self, image_digest: str, verdict: Verdict) -> str:
        ref = f"{self._repo}@{image_digest}"
        res = self._runner([self._binary, "sign", "--yes", ref])
        if res.returncode != 0:
            raise SigningError(res.stderr.decode(errors="replace").strip()[:500])
        return ref
