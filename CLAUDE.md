# dabao-zero

## WHAT
Agent-run CVE patching for container images. Plan: `PLAN.md`; decisions: `docs/adr/`;
slices: `SLICES.md`; backlog: `TASKS.md`; test/CI rules: `docs/testing-and-ci.md`.
Python 3.13, FastAPI, uv, pytest (ADR-0007). Frontend (Svelte + Vite) comes in V4.
Status: E0 scaffold only; the pipeline is not built yet. Trust the code over these docs.

## HOW
- `make` lists targets. `make sync` installs; `make check` = lint + mypy + unit tests (the pre-push hook).
- `make hooks` installs the pre-push hook. `make test-integration` needs Docker.
- Branch per slice off fresh `main`, PR only, never push to `main`. CI must be green to merge.
- Anything gating a merge or publish must be deterministic: agents are faked in tests
  (`dabao.fakes`); real model calls only in the non-gating eval.
- Every bug or flake gets a test first. Prove a gate by watching it fail (known-bad corpus).
- Never commit secrets. Do not enable `source=original` patches (ADR-0003).
