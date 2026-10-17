# ADR-0009: Bootstrap with human-launched Codex attempts from a laptop

- Status: Proposed
- Date: 2026-10-17
- Deciders: Jian Rong Lee

## Context

The unattended path needs a hosted worker, a sandbox with restricted egress and an LLM key that
stays outside it (spike: `docs/spikes/vps-agent-host.md`, epic E7). That is weeks of work before one
real CVE is patched. Meanwhile the owner has a Codex subscription on a personal machine.

OpenAI recommends API keys for automation and documents a ChatGPT login on CI only for "trusted private
automation", not for public or open-source repositories. Nothing read says a person may not run Codex
by hand on their own login, and that is the product's ordinary use. Running a subscription unattended
on a server is not authorised in writing, so this ADR does not do that.

## Decision

1. **A human launches Codex on their own machine for one advisory at a time.** Their own login,
   interactive or a single `codex exec` they start, never a scheduler, CI job, server or shared
   machine. No `auth.json` leaves the laptop.
2. **Codex produces a candidate, not an artifact.** A candidate bundle holds: the diff, `source`
   (`upstream_derived` only, ADR-0003), links to the upstream fix, the run log, tool and model versions,
   and the advisory and component it targets. The human does not edit the diff. An edited diff is a
   different run and is recorded as such.
3. **The gates are unchanged and still decide.** The bundle is imported as a `PatchAttempt` with
   `runner = manual_codex` and goes through the same gate runner, signer and ledger as any attempt.
   A human launching the run is not a human approving the patch: no approval step is added (ADR-0002).
4. **The ledger says so.** Every artifact built from a manual attempt shows "agent-patched, run started
   by the maintainer" on the ledger and the catalog, so the "no human in the patch path" claim stays
   true: the human starts the run and does not choose or alter what ships.
5. **Behind a flag, default off.** `MANUAL_ATTEMPTS_ENABLED` defaults to false. With it off, import is
   refused. Behaviour changes ship behind a flag that defaults to the old behaviour.
6. **Untrusted input.** The agent reads advisory and upstream text on a machine that also holds the
   owner's credentials. Runs happen in a throwaway container or worktree with no secrets, no GHCR or
   cosign credentials, and Codex's `workspace-write` sandbox, never `danger-full-access` on the host.
7. **Sunset.** When the E7 runner and an API key exist, unattended attempts become the default path and
   this one stays for debugging and one-off rescues. If OpenAI's terms are later read and forbid it,
   decision 1 is revisited, not worked around.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Codex subscription on a Droplet, unattended | Not authorised in writing, and OpenAI warns against it for public and open-source work |
| Wait for the VPS and an API key | Nothing real is patched for weeks; gates and corpus go untested on live output |
| Human reviews and edits each patch | Defeats ADR-0002 and misrepresents what shipped |

## Consequences

- Gets: real patches through real gates now, a cost and success baseline for Codex, and no new
  infrastructure.
- Costs: throughput is one person's laptop and subscription limits; a new import path to build, test
  and label honestly.
- Needs: the candidate-bundle schema, an import command, a sandboxed run script and a runbook (epic E8).
- Open: nobody has read OpenAI's Terms of Use text (the pages returned 403). Read it before this goes
  from Proposed to Accepted.
