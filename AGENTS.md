# dabao-zero

## WHAT
Agent-run CVE patching for container images; free and open source. Python 3.13, FastAPI,
uv, pytest (ADR-0007); Svelte + Vite frontend from slice V4. Start at `PLAN.md`; decisions in
`docs/adr/`; slices in `SLICES.md`; backlog in `TASKS.md`; test and CI rules in
`docs/testing-and-ci.md`. Status: scaffold, seams and publish gates only; the pipeline is not
built yet. Trust the code over these docs where they disagree, and fix the docs.

## HOW
- `make` lists targets. `make sync` installs; `make check` (lint, mypy, unit) is the pre-push hook.
  `make hooks` installs it. `make test-integration` needs Docker.
- Branch per slice off fresh `main`, PR only, never push to `main`; merge when CI is green.
- Gates and publish must be deterministic: agents are faked in tests (`dabao.fakes`); real model
  calls only in the non-gating eval. Prove a gate by watching it fail (`tests/corpus`).
- Never commit secrets. Never enable `source=original` patches (ADR-0003).

## LLM provider: OpenAI-compatible only (OpenRouter), never the Anthropic SDK or API key
Use the OpenAI-compatible chat-completions API through one thin client behind the `AgentRunner`
seam. Config is by environment only: `LLM_BASE_URL` (default `https://openrouter.ai/api/v1`),
`LLM_API_KEY` (an OpenRouter key), `LLM_MODEL`. Do not hard-code a vendor, model or key. See ADR-0008.

## Sandbox quirks (cloud sessions)
- No Docker daemon, and the Debian mirrors and `openrouter.ai` are blocked unless the environment
  allowlist says otherwise. Do not mock results to get past a blocked host: say what is blocked.
- Inspect images without Docker using `regctl` (`go install github.com/regclient/regclient/cmd/regctl@latest`).
  Use `mirror.gcr.io/library/<image>` for Docker Hub images (Docker Hub itself is rate-limited, and
  `public.ecr.aws` blob downloads are blocked). Skopeo is not needed.
