# Contributing

Thanks for helping. Read [`PLAN.md`](PLAN.md) for what this is and [`TASKS.md`](TASKS.md)
for what needs doing. Decisions live in [`docs/adr/`](docs/adr/); please don't re-litigate an
accepted ADR in a PR, open an issue proposing a superseding one instead.

## Set up

Needs [uv](https://docs.astral.sh/uv/) (it fetches Python 3.13 itself) and, for the frontend,
Node 22 (`frontend/.node-version`). Docker is optional and only used for Postgres integration tests.

```bash
make sync        # install backend dependencies from the lockfile
make hooks       # install the pre-push hook (lint + types + unit tests)
make             # list every target
```

## Checks

| Command | What it runs | Needs |
|---------|--------------|-------|
| `make check` | ruff, mypy (strict), unit tests: the pre-push gate | nothing |
| `make frontend-check` | svelte-check, vitest, production build | Node 22 |
| `make db-up` then `make test-integration` | Postgres lease/concurrency tests | Docker |

CI runs the same jobs plus a secret scan and a dependency scan, in parallel. Layering and
determinism rules are in [`docs/testing-and-ci.md`](docs/testing-and-ci.md).

## Workflow

- One branch per change off fresh `main`; open a PR; never push to `main`. Merge commits, not squash.
- Keep changes small and reversible. A change that alters behaviour ships behind a flag that
  defaults to the old behaviour. A schema change needs an Alembic migration and lands alone.
- Fix a bug by writing the failing test first. Prove any gate or safety check by watching it
  fail: break it on purpose, see the right test go red, then restore the code.
- Everything that gates a merge or a publish must be deterministic. Agents are faked in tests;
  real model calls only happen in the (non-gating) live evaluation.
- Never commit secrets. LLM access is an OpenAI-compatible endpoint configured by environment
  ([ADR-0008](docs/adr/0008-openai-compatible-llm-via-openrouter.md)).

## Reporting security problems

See [`SECURITY.md`](SECURITY.md).
