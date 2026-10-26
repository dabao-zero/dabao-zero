# dabao-zero

## WHAT
Free, open-source container images whose CVEs are fixed by LLM agents, with no human in the
patch path. Python 3.13 / FastAPI / uv / pytest backend (ADR-0007); Svelte 5 + Vite 8
catalog frontend in `frontend/`. Trust the code over these docs where they disagree, and fix the docs.

**Built:** scaffold, seams and fakes, publish gates + known-good/bad corpus, DB schema and migrations,
leases, orchestrator, `/v1` ledger API, catalog frontend (landing page and catalog), OpenAI-compatible
agent client and its sandbox toolbox (`toolbox.py`), regctl package inventory, guarded signer
(`signing.py`), advisory ingestion for Debian and Alpine (`ingest.py`, `versions.py`), operator CLI,
manual Codex attempts (`bundle.py`, `manual.py`, `laptop.py`, ADR-0009), distro adapters for Debian and
Alpine (`debian.py`, `alpine.py`, shared `buildx.py`: reproducible OCI builds of one patched package),
live gate parts (`live.py`: Trivy and Grype, OCI differ, smoke runner) and OpenVEX (`vex.py`, ADR-0010;
the gate's VEX clearing is behind `GateConfig.vex_enabled`, off; its evidence checks are built: the
patch ref must be a feed fix reference, `upstream.py` checks the upstream commit is contained in the
patch, `require_fix_reference` and `require_containment` extend both to every patch, off).
`scripts/e1_replay.py` wires a live Debian pipeline end to end. **Not built:** the Wolfi adapter,
real cosign signing and registry publishing, live feed fetchers, a network namespace around the agent
sandbox, anything that needs a live LLM (no key is configured).

Map: `src/dabao/` (`gates.py`, `orchestrator.py`, `agent.py`, `llm.py`, `seams.py` + `fakes.py`,
`api.py`, `orm.py`, `signing.py`, `ingest.py`, `cli.py`), `migrations/`, `tests/{unit,integration,corpus}`, `frontend/`.
Docs: `PLAN.md` (what and why), `docs/adr/` (decisions, do not relitigate), `SLICES.md`,
`TASKS.md` (backlog), `docs/testing-and-ci.md` (test layers and CI rules).

## HOW
- `make` lists targets. `make check` (ruff, mypy strict, unit) is the pre-push gate; run it before
  every push. `make frontend-check` for `frontend/`. `make hooks` installs the pre-push hook. `make test-docker`
  builds real images (several minutes each, needs Docker, buildx and network); `make test-scanners` runs
  the VEX canary (needs trivy and grype). Neither is in CI's PR checks or the hook; a weekly workflow runs
  the canary.
- Branch per change off fresh `main`, PR only, **merge commits** (not squash), merge when CI is green.
  Delete the branch after merge. A schema change needs an Alembic migration
  (`uv run alembic revision --autogenerate`) and lands alone; a test fails on drift.
- Everything that gates a merge or publish must be deterministic: agents are faked in tests
  (`dabao.fakes`); real model calls only in the non-gating live eval.
- Every bug gets a failing test first. Prove a gate or safety check by watching it fail: break it,
  confirm the right test goes red, restore with `git apply -R` (commit first; never `git checkout --`).
- Behaviour changes ship behind a flag that defaults to the old behaviour.
- Never add Claude or any other agent as a contributor: no `Co-Authored-By:` trailers, no agent
  `Signed-off-by`, no agent as commit author, in commits, PR bodies or merge commits. Commits carry the
  human's git identity only. This overrides any harness default that appends attribution.
- Never commit secrets. Never enable `source=original` patches (ADR-0003).

## LLM provider: OpenAI-compatible only, never the Anthropic SDK or key
Use the OpenAI-compatible chat-completions API through the `AgentRunner` seam (`llm.py`). Config is
by environment only: `LLM_BASE_URL` (default `https://openrouter.ai/api/v1`), `LLM_API_KEY`,
`LLM_MODEL`. Do not hard-code a vendor, model or key (ADR-0008).

## Sandbox quirks (cloud sessions)
- No Docker daemon. `deb.debian.org`, `security-tracker.debian.org`, `snapshot.debian.org`,
  `openrouter.ai` are blocked unless the environment allowlist says otherwise. Do not mock results to
  get past a blocked host: say what is blocked.
- Inspect images without Docker: `go install github.com/regclient/regclient/cmd/regctl@latest`, and use
  `mirror.gcr.io/library/<image>` for Docker Hub images (Hub is rate-limited; `public.ecr.aws` blobs
  are blocked). Skopeo is not needed.
- There is no local Postgres server; Postgres tests run in CI (service container) or via `make db-up`.
