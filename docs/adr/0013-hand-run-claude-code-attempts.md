# ADR-0013: Allow human-launched Claude Code attempts from a laptop

- Status: Accepted 2026-10-27
- Date: 2026-10-27
- Deciders: Jian Rong Lee
- Amends: ADR-0009 (adds a second harness), clarifies ADR-0008

## Context

ADR-0009 lets the owner start Codex by hand on a laptop, on their own login, and import the result as a
candidate. The owner also has a Claude Code subscription and wants Claude Code to do the initial patching
too. ADR-0008 forbids the Anthropic SDK and an Anthropic API key in this project's code and config. It governs
what the product's own code calls. It does not say which tool a human may start by hand on their own machine.

## Decision

1. **Claude Code is allowed as a hand-started harness, on the same terms as Codex in ADR-0009**: the
   owner's own login, one advisory at a time, started by the human, never a scheduler, CI job, server or shared
   machine. No credential file leaves the laptop. Decisions 2 to 6 of ADR-0009 apply unchanged: candidate not
   artifact, unchanged gates, labelled on the ledger, flag off by default, throwaway container or worktree with
   no secrets.
2. **ADR-0008 stands.** No Anthropic SDK, no Anthropic API key, nothing in `llm.py`, settings, CI or the
   orchestrator. Claude Code is an external program the human runs; this repo only reads the bundle it leaves.
   The unattended path (E7) stays OpenAI-compatible only.
3. **New runner value `manual_claude_code`**, recorded and shown beside `manual_codex`. The ledger and
   catalog say "agent-patched, run started by the maintainer" for both. `MANUAL_ATTEMPTS_ENABLED` covers both.
4. **Terms not read.** As with Codex, the vendor's terms for hand-run use have not been read by the agent
   that wrote this. The owner judges a hand-started run on their own subscription to be ordinary use. If the terms
   forbid it, revisit; do not work around.
5. **The Claude Code session that develops this repo is a different thing from the patching run.** It
   never signs, never imports its own bundle and is never a contributor (AGENTS.md).

## Consequences

- Needs: a Claude Code driver in `laptop.py` (non-interactive run in the throwaway sandbox, same bundle
  output), the `manual_claude_code` runner value (enum, migration only if the column is constrained), frontend labels
  for both runners, and runbook text. Tracked as a board card.
- Costs: two harnesses to keep compatible with one bundle schema; baseline numbers must record which
  harness produced them.
