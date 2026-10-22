# E1 Codex baseline: tar CVE-2022-48303 on the laptop

First real run of ADR-0009 (DAB-52), 2026-10-22. Codex CLI 0.155.1 on the maintainer's own login, started by
hand with `python -m dabao.laptop --network`, model left at Codex's default. Target and CVE: `docs/e1-targets.md`.
The bundle is `docs/e1-codex-bundle-cve-2022-48303.json` (run log trimmed).

## What Codex did

| | |
|-|-|
| Wall time | 378 s, one attempt |
| Tokens | 1,076,405 in (1,040,128 cached), 3,811 out, 209 reasoning |
| Commands | 29 shell commands in the sandbox, including a configure, build and part of tar's own test suite |
| Upstream fix found | savannah `tar` commit `3da78400eafcccb97e2f2fd4b227ea40d794ede8`, fetched by `curl` from a savannah mirror after the main host answered 502 |
| Source of the patch | `upstream_derived`, `upstream_ref` is that commit |

The `src/list.c` hunk is the upstream fix, line for line. It also added a quilt patch,
`debian/patches/CVE-2022-48303.patch`, and a `series` entry, so the same change is in the diff twice. That is
harmless to the binary (see below) but noisy; a prompt change should ask for source edits only (DAB-68).

## Reproducibility check

The image built from Codex's diff has digest `sha256:65973efa…f71d844`, byte-for-byte the digest of the image built
from Debian's own patch for the same CVE (`tests/integration/fixtures/tar-CVE-2022-48303.diff`). Same inputs, same
build, same bits: Codex's change is functionally the reference change.

## Gate verdicts (live pipeline, `scripts/e1_replay.py`)

Shown in the ledger as `docs/img/e1-codex-attempt.png` (attempt recorded as run by the maintainer).

| Gate | Result | Note |
|------|--------|------|
| advisory present before | pass | Trivy and Grype both report it on the pinned base |
| scanners clear | **fail** | both still report CVE-2022-48303 after the patch, see below |
| tests pass | pass | smoke commands only, not an official suite |
| build diff | pass | every changed file belongs to a rebuilt package or to dpkg's own state |
| provenance | pass | on the savannah allow-list |

## The finding: scanners judge by version, not by content

Trivy and Grype match a package version against the distro's fixed version. The patched `tar` is
`1.34+dfsg-1.2+dabao1`, which sorts below Debian's fixed `1.34+dfsg-1.2+deb12u1`, so both keep reporting the CVE
although the fix is in the binary.

Throwaway experiment: rebuild with version `1.34+dfsg-1.2+deb12u1+dabao1`. All five gates pass and the pipeline
"publishes" (to a fake registry). But **CVE-2023-39804, which this patch does not touch, is also reported as cleared**,
because Debian fixed both CVEs in the same upload. Bumping the version above the fixed one is therefore a false-clear
risk, not a fix. The scanner gate needs a different way to say "this CVE is fixed in this build": evidence per CVE,
such as a VEX statement the scanners honour, backed by something an agent cannot self-attest (ADR-0002). Filed as
DAB-66; it needs a decision, probably an ADR, before the first publish.

## Also found

- Codex's Linux sandbox helper cannot be created under `/tmp`, so every command failed and the run hung. Scratch
  space now lives under `~/.cache/dabao-attempts` and codex has a timeout (fixed, tested).
- A failed attempt keeps no patch, so the ledger page says "no patch to show yet". PLAN promises public diffs for
  every attempt (DAB-67).
- libtasn1 CVE-2024-12133 and the second tar CVE were not run.

## For the later kopicode comparison

Baseline to beat or match: 378 s, about 1.08 M input tokens (97% cached), a correct upstream backport on the first try.
Codex ran on a ChatGPT subscription, so there is no dollar cost to compare; token counts are the common measure.
