from __future__ import annotations

import subprocess
from dataclasses import replace

import pytest

from dabao import fakes
from dabao.gates import GATE_NAMES, GateResult, Verdict
from dabao.signing import CosignSigner, GuardedSigner, SigningError, SigningRefused

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32


def good_verdict(digest: str = DIGEST) -> Verdict:
    return Verdict(tuple(GateResult(n, True, "ok") for n in GATE_NAMES), digest=digest)


def failing(name: str) -> Verdict:
    results = tuple(GateResult(n, n != name, "x") for n in GATE_NAMES)
    return Verdict(results, digest=DIGEST)


def guarded(**kw: object) -> tuple[GuardedSigner, fakes.FakeSigner]:
    backend = fakes.FakeSigner()
    return GuardedSigner(backend, **kw), backend  # type: ignore[arg-type]


def test_signs_a_fully_passing_verdict_for_the_same_digest() -> None:
    signer, backend = guarded()
    assert signer.sign(DIGEST, good_verdict()) == f"sig:{DIGEST}"
    assert backend.signed == [DIGEST]


@pytest.mark.parametrize("gate", GATE_NAMES)
def test_refuses_when_any_single_gate_failed(gate: str) -> None:
    signer, backend = guarded()
    with pytest.raises(SigningRefused, match=gate):
        signer.sign(DIGEST, failing(gate))
    assert backend.signed == []


@pytest.mark.parametrize("missing", GATE_NAMES)
def test_refuses_when_a_required_gate_is_missing_from_the_verdict(missing: str) -> None:
    results = tuple(GateResult(n, True, "ok") for n in GATE_NAMES if n != missing)
    signer, backend = guarded()
    with pytest.raises(SigningRefused, match="exactly the required gates"):
        signer.sign(DIGEST, Verdict(results, digest=DIGEST))
    assert backend.signed == []


def test_refuses_a_verdict_for_a_different_digest() -> None:
    signer, backend = guarded()
    with pytest.raises(SigningRefused, match="different image digest"):
        signer.sign(OTHER, good_verdict(DIGEST))
    assert backend.signed == []


def test_refuses_an_empty_verdict_and_unbound_verdict() -> None:
    signer, backend = guarded()
    with pytest.raises(SigningRefused):
        signer.sign(DIGEST, Verdict(()))
    with pytest.raises(SigningRefused):
        signer.sign(DIGEST, replace(good_verdict(), digest=""))
    assert backend.signed == []


@pytest.mark.parametrize(
    "bad", ["latest", "sha256:abc", "sha256:" + "AB" * 32, "sha1:" + "a" * 40, ""]
)
def test_refuses_malformed_digests(bad: str) -> None:
    signer, backend = guarded()
    with pytest.raises(SigningRefused, match="not a valid sha256 digest"):
        signer.sign(bad, good_verdict(bad))
    assert backend.signed == []


def test_refuses_revoked_digests() -> None:
    signer, backend = guarded(is_revoked=lambda d: d == DIGEST)
    with pytest.raises(SigningRefused, match="revoked"):
        signer.sign(DIGEST, good_verdict())
    assert backend.signed == []


def test_refuses_everything_while_frozen() -> None:
    signer, backend = guarded(is_frozen=lambda: True)
    with pytest.raises(SigningRefused, match="frozen"):
        signer.sign(DIGEST, good_verdict())
    assert backend.signed == []


def done(rc: int = 0, err: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess([], rc, b"", err)


def test_cosign_signs_repository_at_digest_with_keyless_flags() -> None:
    calls: list[list[str]] = []

    def runner(args: list[str]) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        return done()

    signer = CosignSigner("ghcr.io/dabao-zero/nginx", runner=runner)
    assert signer.sign(DIGEST, good_verdict()) == f"ghcr.io/dabao-zero/nginx@{DIGEST}"
    assert calls == [["cosign", "sign", "--yes", f"ghcr.io/dabao-zero/nginx@{DIGEST}"]]
    assert not any("key" in part for part in calls[0])  # keyless: no key material


def test_cosign_failure_is_an_error_not_a_signature() -> None:
    signer = CosignSigner("r", runner=lambda _a: done(1, b"oidc token missing"))
    with pytest.raises(SigningError, match="oidc token missing"):
        signer.sign(DIGEST, good_verdict())
