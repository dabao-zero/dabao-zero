# ADR-0007: Python (FastAPI, uv, pytest) backend; Svelte + Vite + TypeScript frontend

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

The orchestrator, agent runner and gates are glue between LLM APIs, build tools and
scanners, which Python handles well. A small HTTP API (ledger, operator actions) and a
read-only ledger site are needed. Versions below were checked against the PyPI and npm
registries on 2026-10-16.

## Decision

**Backend**
- Python 3.13, managed with **uv** (lockfile committed, `uv sync --frozen` in CI).
- **FastAPI** (0.143.x) with Pydantic 2.x, served by uvicorn.
- **pytest** 9.x, **ruff** (lint and format), **mypy**.
- Dependencies are pinned by `uv.lock`; the versions above are a starting point and
  Renovate/Dependabot keeps them current.

**Frontend (only when the ledger UI is built, slice V4)**
- **Svelte 5** (5.57.x), **Vite 8** (8.3.x, needs Node 20.19+ or 22.12+; use Node 22 LTS),
  **TypeScript**, **@sveltejs/vite-plugin-svelte 7**, **Vitest** for tests.
- **TypeScript 6.0.x, not 7:** `svelte-check` 4.7 declares a peer range of TypeScript `^5 || ^6`, so 7.x cannot be installed without `--force`. Revisit when svelte-check supports 7.
- Plain Svelte + Vite single-page app reading the `/v1` API or generated static JSON,
  not SvelteKit, because the ledger is read-only and has no server-side needs. SvelteKit
  (now 3.x) is the upgrade path if prerendered per-advisory pages or SEO prove necessary.
- Before scaffolding, re-check `npm view svelte version`, `npm view vite version` and the
  peer ranges of the vite plugin, and pin exact versions in the lockfile.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Go orchestrator | Faster binaries, but slower iteration on agent and prompt code and a smaller LLM-tooling ecosystem |
| SvelteKit for the ledger | More framework than a read-only ledger needs; can be adopted later |
| poetry / pip-tools | uv is faster and is the owner's choice |

## Consequences

- Gets: one language across orchestrator, agent runner, gates and API; fast CI installs.
- Costs: Python's weaker static typing (mitigated by mypy and Pydantic); two toolchains once
  the frontend exists, so CI path filters and per-package jobs are needed.
- Needs: Node 22 in CI for the frontend, and a frontend job that does not block backend-only PRs.
