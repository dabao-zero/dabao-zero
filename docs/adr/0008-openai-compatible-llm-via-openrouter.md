# ADR-0008: Use an OpenAI-compatible LLM API (OpenRouter), not a vendor SDK

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

PLAN assumed the Anthropic API (Q13). The owner prefers OpenAI-compatible access through
OpenRouter, which gives one key and many models. The pipeline's safety comes from the
deterministic gates (ADR-0002), not from the model, so the model can be swapped freely.

## Decision

The `AgentRunner` implementation talks to any OpenAI-compatible chat-completions endpoint via
the `openai` Python SDK (or plain `httpx`), configured only by `LLM_BASE_URL` (default
`https://openrouter.ai/api/v1`), `LLM_API_KEY` and `LLM_MODEL`. No vendor-specific features are
required. Per-task-class model choice (cheap model for triage, stronger for backporting) is a
config map. Tool use uses the OpenAI `tools` format; if a chosen model lacks it, the runner falls
back to a structured-JSON protocol. The key lives only in the orchestrator's environment and never in sandboxes (ADR-0005).

## Alternatives considered

| Option | Why not |
|--------|---------|
| Anthropic API/SDK | Owner's preference is OpenRouter; vendor lock-in for no safety benefit |
| One hard-coded OpenRouter model | Models change monthly; cost/quality tuning needs to be config |

## Consequences

- Gets: swap models without code changes; one key; cost visible per model.
- Costs: tool-calling behaviour varies by model, so the agent loop must tolerate it and the live eval must be run per model; OpenRouter adds a third party that sees advisory and source text (all public data).
- Needs: `openrouter.ai` on the sandbox allowlist for any live run; token and cost accounting from the provider's usage fields.
