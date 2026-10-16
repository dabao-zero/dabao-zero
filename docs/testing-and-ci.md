# Testing and CI

Applies the dev-playbook to dabao-zero. Principle: layer checks by cost, gate by layer,
and never let a slow check gate a local push.

**Stack (ADR-0007):** Python 3.13, FastAPI, uv, pytest, ruff, mypy; frontend (from V4) is Svelte 5 + Vite 8 + TypeScript with Vitest; GitHub Actions.

## What is different here: the LLM is the nondeterministic part

The pipeline's safety comes from deterministic gates (ADR-0002), so the rule is:
**everything that gates a merge or a publish is deterministic; everything that measures
the LLM is non-gating and scheduled.**

- The agent sits behind an `AgentRunner` seam. In gating tests it is a fake that replays a
  recorded transcript and patch. Real model calls never run in PR CI.
- Agent quality is measured by a separate live-model eval on the held-out backlog
  (nightly/manual, with a cost cap). It reports success rate and cost per patch against the
  PLAN targets; it never blocks a PR.

## Seams (build for testability)

| Seam | Real impl | Fake impl |
|------|-----------|-----------|
| `AgentRunner` | OpenAI-compatible API (OpenRouter) in a sandbox | Replays a recorded patch and transcript |
| `DistroAdapter` | Debian / Alpine / Wolfi builders | In-memory adapter returning canned packages |
| `Scanner` | Grype, Trivy | Returns canned findings per image digest |
| `Registry` | GHCR | Local OCI registry or in-memory |
| `Signer` | Keyless cosign via CI identity | Test-key signer |
| `AdvisorySource` | NVD, OSV, distro trackers | Fixture feeds |
| `Clock`, `Sandbox`, DB session | Real | Fake clock, in-process sandbox stub, rolled-back transaction |

Smell check: if a unit test must monkeypatch internals, the seam is missing.

## Layers

| Layer | Needs | Contains | Runs |
|-------|-------|----------|------|
| **Unit (fast)** | nothing | Gate verdict logic (pass, fail, missing data), advisory alias resolution, advisory-to-package mapping, attempt state machine, lease logic, budget caps, original-stream flag, provenance allow-list | pre-push, every CI job |
| **Integration** | Docker (testcontainers) | Postgres leases and concurrent attempts, a real Debian build of a `.deb` from source + patch, Grype/Trivy on fixture images, local OCI registry plus cosign with test keys, sandbox egress test (only mirror and proxy reachable), signer refuses ungated submissions | CI, local with Docker |
| **End-to-end (replay)** | Docker, network off | One historical CVE through the whole pipeline with a recorded agent: scanners flag, patch applies, gates pass, image published to a local registry, signature verifies. Thin: one per distro stream | CI (required once V2 exists) |
| **Live eval (non-gating)** | Real LLM key, budget | Held-out advisory backlog with the real model; metrics: % auto-patched, median time, cost per patch | Nightly/manual, reported |

## Prove each guard by watching it fail

This is the heart of the project, since the gates are the whole safety margin.

- Keep a **known-bad corpus**: patches that must be rejected (deletes a needed file,
  doesn't fix the CVE, fixes it but breaks the official test suite, adds an unexpected binary,
  cites a source outside the allow-list, `source=original` with the flag off, prompt-injection
  text in an advisory). Each gate has at least one corpus entry that turns it red.
- A **known-good corpus** (the historical CVE fixes) must stay green.
- Do mutation checks non-destructively: commit or stash first, or apply the break as a patch and
  reverse it with `git apply -R`. Never `git checkout --` on uncommitted work.
- Every bug and every flake becomes a corpus entry or a test before the fix.

## Determinism rules

No sleeps; drive time with the fake clock; reproducible builds compared by digest; prefixed,
self-cleaning test data (`test-*`); pin every fixture (upstream source tarballs, advisory feeds,
scanner DB snapshot) so a scanner database update doesn't turn CI red. Refresh the scanner DB
snapshot as a deliberate, reviewed change.

## Pre-push hook

`scripts/git-hooks/pre-push`: `ruff check`, `ruff format --check`, `mypy`, `pytest tests/unit`.
No Docker, under ~30s. Install: `ln -sf ../../scripts/git-hooks/pre-push .git/hooks/pre-push`.
`--no-verify` for scoped exceptions; CI is the real gate.

## CI workflows (GitHub Actions)

`ci.yml`, parallel jobs, frozen installs (`uv sync --frozen`), dependency cache, cancel-in-progress:

| Job | Required | Notes |
|-----|----------|-------|
| `lint` (ruff, format check) | yes | |
| `typecheck` (mypy) | yes | |
| `unit` | yes | |
| `integration` | yes | Testcontainers; pinned fixtures |
| `e2e-replay` | yes from V2 | Network off; recorded agent |
| `secret-scan` (gitleaks) | yes | Credentials must never enter git |
| `dep-scan` (Grype on lockfile/our images) | yes | We run our own scanners on ourselves |
| `docs` (build docs) | yes from V4 | |
| `frontend` (svelte-check, tsc, vitest, `vite build`; Node 22, `npm ci`) | yes from V4 | Path-filtered; reports green when frontend is untouched |

Path filters may skip docs-only changes, but required checks must still report (gate-safe skip).
Pin actions to resolving tags and sweep all workflows when the runner deprecates a runtime.

`eval-live.yml`: scheduled/manual, key from environment secret, hard cost cap, uploads a
report. Not required for merge.

`publish.yml` (this is the deploy): triggered by a successful CI run on the exact SHA; keyless
OIDC signing; armable by a repository variable (`PUBLISH_ENABLED`), off by default until V2; skipped
for docs-only changes. After publishing, verify the digest in GHCR matches and `cosign verify` passes.

Infra flake vs real failure: a round-duration failure or "no runner" is infra, so re-run. A failing
assertion is real, so fix. A flaky test on an unrelated PR is a determinism bug; file it and fix the race.

## Branch and review

Branch per slice off fresh `main`, PR-only, protected `main`, required checks above. Anything that
changes gate behaviour or the publish path gets a security-focused review. Behaviour-changing
config (e.g. enabling the original-fix stream) ships off by default.

## Agent brief

`CLAUDE.md` at the repo root (task T0.2): honest build status, exact commands, the layering
above, and "trust the code over the docs".

## Mapping to slices

| Slice | Test emphasis |
|-------|---------------|
| V1 | Unit gates, integration Debian build, known-good and known-bad corpus, sandbox egress |
| V2 | Concurrency, signer refusal, e2e-replay, `publish.yml` armed |
| V3 | Injection corpus, budget caps, original-stream lock |
| V4 | Ingest idempotence, live-eval harness on held-out backlog |
| V5, V6 | Shared adapter contract tests across Debian, Alpine, Wolfi |
