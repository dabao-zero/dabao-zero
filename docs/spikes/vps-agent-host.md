# Spike: run the patch agents on a VPS, with a human overseer over Slack

Status: desk research only, nothing run yet · Date: 2026-10-17 · Owner: Jian

Question: can container patching and CVE mitigation run on a DigitalOcean-class VPS, which coding
harness drives it (kopicode, Codex CLI or Claude Code), and how does a human talk to the agents
from outside? This note records what is known, what is assumed, and the experiments that settle
the rest (epic E7 on the board).

## Decision (2026-10-17)

Phase 1: Codex on Jian's laptop with his own subscription, started by hand, results imported
through the unchanged gates (ADR-0009, epic E8). Phase 2: unattended on a Droplet with kopicode and an
API key through OpenRouter (epic E7). Codex is still measured in E7 using an API key.

## Verdict so far

- **VPS: yes, with one exception.** Debian package rebuilds, `docker build`, Grype/Trivy and the
  official-image test suites need a normal Linux box with Docker, not nested virtualisation.
  The exception is microVM sandboxes (Firecracker): DigitalOcean's own answers disagree on nested
  KVM, and community reports say it is slow. Plan on container isolation, not microVMs.
- **Harness: build the seam, spike Codex first, keep kopicode as the second arm.** Claude Code is
  out under ADR-0008 (OpenAI-compatible API only, never the Anthropic SDK or key) unless that ADR
  changes. Codex with an API key is the documented unattended route. A ChatGPT-subscription login is not.
- **Overseer channel: a small Slack bot in Socket Mode that talks to the orchestrator, not to the
  agent.** Socket Mode is an outbound websocket, so the Droplet opens no inbound port.

## 1. Can a VPS do the work?

What an attempt needs (PLAN.md S2 to S5): fetch source and upstream fix, edit, build a `.deb`,
assemble an image, run scanners and the image's test suite, return a patch.

| Need | On a Droplet | Confidence |
|------|--------------|------------|
| Docker and rootless BuildKit | Normal Linux VM, works | High |
| CPU and RAM for builds (Debian `openssl`, `glibc` rebuilds are heavy) | CPU-Optimized 8 vCPU / 16 GB is about $168/mo per a reseller listing; a general-purpose 8 vCPU / 16 GB is about $96/mo. Verify on DigitalOcean's pricing page before budgeting | Medium |
| Nested KVM for Firecracker or Kata | Unreliable: one staff answer says supported but not recommended, another says unsupported; Intel only per a 2022 request | Low, avoid |
| Egress restricted to a source mirror and package proxy (ADR-0005) | Cloud Firewalls filter by IP and port, not hostname (to verify). Needs an allowlisting forward proxy on an internal Docker network | Medium |
| Reach `deb.debian.org`, `security-tracker.debian.org`, `snapshot.debian.org`, the LLM endpoint | Open internet, no sandbox allowlist like the cloud sessions have | High |
| Ephemeral per-attempt sandbox | One container per attempt, no credentials mounted, destroyed after; gVisor (`runsc`) is an option that needs no KVM (to verify) | Medium |

Scale is the real limit. One Droplet is a worker, not the orchestrator: keep Postgres, the
orchestrator and the signer off it (managed Postgres, CI for signing, ADR-0005). The Droplet runs
attempts only and can be rebuilt from a script.

### Trust boundary

The Droplet holds the LLM key and nothing else. No GHCR token, no cosign identity, no Slack
tokens, no database credentials. Results leave as a candidate patch plus a log, over a narrow
channel to the orchestrator. If the Droplet is owned, the worst outcome is a bad candidate the
gates must catch (ADR-0005), and a spent LLM budget, which the key's hard cap bounds.

## 2. Which harness

All three are coding agents that can run a prompt to completion unattended. They differ on what
this project's rules allow and on who provides the sandbox.

| | kopicode | Codex CLI | Claude Code |
|---|---|---|---|
| Fits ADR-0008 (OpenAI-compatible, env config) | Yes, OpenRouter or custom URL (kopicode ADR-0027) | Yes with an OpenAI key. Custom OpenAI-compatible providers via `config.toml` (to verify, OpenRouter in particular) | No: Anthropic API |
| Unattended entry | `run --print`, `serve` (JSON-RPC over stdio or unix socket), `mcp` | `codex exec`, `--json` event stream, `--output-schema`, `resume` | `claude -p` |
| Auth for a server | `OPENROUTER_API_KEY` env only | `CODEX_API_KEY` for `codex exec`; OpenAI recommends API keys for automation | Out of scope |
| Own sandbox | None; shell runs with the user's privileges (kopicode ADR-0008). The container is the sandbox | Landlock/seccomp style sandbox, default read-only; `danger-full-access` only inside a container. Whether it works inside Docker on a Droplet is untested | n/a |
| Remote human approval | Built in: `consent.request` and `ask.request` over `serve` (kopicode ADR-0016, ADR-0020), `session.events` replay after reconnect | Approval policy exists; piping it to Slack is not documented, would be wrapped | n/a |
| Maturity for this | v0.4, owned by Jian, two models measured; we control fixes | Mature, closed | n/a |

Constraints worth stating plainly:

- **Subscription login for the fleet: not forbidden in anything I could read, not authorised either.**
  Checked 2026-10-17. OpenAI's auth pages say API keys are the recommended default for automation.
  They document ChatGPT-managed `auth.json` on CI as "an advanced workflow for enterprise and other
  trusted private automation": trusted private runners only, one `auth.json` per runner, and "do not
  use this workflow for public or open-source repositories". No page I could fetch says a personal
  Plus or Pro login may not run unattended jobs. The Terms of Use returned 403 and are unread (kopicode's
  `docs/research/2026-10-codex-oauth-spike.md` found the same gap). The "multi-user and commercial"
  restriction in kopicode ADR-0035 comes from a third-party plugin's notice, not from OpenAI. dabao-zero
  is a public OSS project reading untrusted advisory text, so a subscription on a Droplet sits in the
  grey zone and would also hit plan rate limits. A subscription driven by Jian by hand on his own
  machine is the plain, intended use.
- **Key exposure.** OpenAI advises not setting `CODEX_API_KEY` at job level where repo-controlled code
  runs, since build scripts can read it. Our agents run builds on hostile source, so the key must
  live outside the build sandbox: a local LLM proxy that holds the key and hands the sandbox a
  scoped, revocable token is the likely shape. This applies to every harness.
- **Output is a patch, not a push.** OpenAI's own safe pattern is a read-only step that emits a diff
  and a separate privileged step that applies it. That is already ADR-0005's design.

Recommendation: define one `AgentRunner` adapter contract (it exists in `llm.py` and `agent.py` for
chat-completions; the harness adapter is a coarser, "run task in sandbox, return patch" layer above it).
Spike Codex (`codex exec --json`) and kopicode (`serve --listen`) against the same historical CVE and
compare success, cost, wall time and how cleanly each routes approvals. Decide after the numbers, not
before. Jian prefers Codex; the spike should give it the first slot and a fair comparison.

## 3. Overseer channel

Requirements: a human outside the VPS can see what each agent is doing, ask for status, approve or
deny a request, pause, freeze or kill, and raise a budget, without SSH and without the agent being
able to impersonate the human.

Proposal: a **bridge service** (small Slack Bolt app in Socket Mode) running next to the
orchestrator, not on the agent Droplet.

```
Jian in Slack  <->  Slack  <-ws->  bridge  <->  orchestrator /v1 + operator CLI  <->  runner on Droplet  <->  harness
```

- The bridge speaks the orchestrator's operator API (freeze, revoke, rerun already exist in
  `operator.py`), plus new verbs: `status`, `pause`, `resume`, `budget`, `approve`, `deny`, `say`.
- One Slack thread per `PatchAttempt`; the runner streams a few lines of progress (turn, tool, cost).
- Approval requests arrive as Block Kit buttons. For kopicode this maps onto `consent.request`.
  For Codex it maps onto a wrapper around its approval policy (to be built, risk below).
- Authorisation is by Slack user ID allowlist and the bridge only accepts interactions signed by Slack.
  Advisory and agent text is rendered to Slack as data and never parsed as commands.
- `say <text>` injects a human message into the running session. Treat it as the only path from Slack
  to the agent prompt.

Alternatives, if Slack is a poor fit: Telegram or Discord bot (same bridge, different adapter), ntfy
for one-way alerts, or no chat at all and use the operator CLI over Tailscale SSH. Slack wins on
threads and buttons; keep the bridge adapter-shaped so the choice is cheap to change.

## 4. Experiments (each is a card in E7)

1. Provision one Droplet from a script; run `docker build`, Grype and one Debian source rebuild;
   record wall time and cost. Check `/dev/kvm` and nested flag and close the Firecracker question.
2. Prove egress: from the sandbox, only the mirror, package proxy and LLM proxy resolve and connect.
3. `codex exec --json` with `CODEX_API_KEY` in the sandbox, on one historical CVE: does the Linux sandbox
   work inside Docker, does a custom OpenAI-compatible provider work, what does an event stream give us.
4. kopicode `serve --listen` on the same CVE through OpenRouter; compare with experiment 3.
5. Slack bridge walking skeleton: status command and one approve/deny round trip against a fake runner.
6. Key custody: LLM proxy with a per-attempt token and a hard spend cap; confirm the sandbox cannot read the real key.

## Open questions

- Is the chosen harness's sandbox compatible with running inside our own container sandbox (nested
  seccomp/landlock restrictions often are not)?
- Does OpenRouter work as a Codex provider with tool calling, or only the OpenAI API directly? ADR-0008
  names OpenRouter as the default, so a "no" means an ADR amendment.
- Is one worker Droplet enough for ~15 images, or does E4 need a pool and a queue?
- Does Slack's free tier suffice (history limits, app count)?

## Sources

- DigitalOcean community, nested virtualisation: https://digitalocean.com/community/questions/does-digitalocean-support-kvm-or-nested-virtulzation and https://ideas.digitalocean.com/core-compute-platform/p/enable-nested-kvm-in-amd-servers
- Codex auth and automation: https://learn.chatgpt.com/docs/auth (formerly developers.openai.com/codex/auth)
- Codex non-interactive mode: https://learn.chatgpt.com/docs/non-interactive-mode.md
- Droplet prices (third party, unverified): https://www.whtop.com/amp/plans/digitalocean.com/137795 and https://pcr.cloud-mercato.com/providers/digitalocean/flavors/s-8vcpu-16gb
- kopicode: `docs/kopicode-serve-protocol.md`, `docs/kopicode-mcp.md`, ADR-0008, 0016, 0027, 0035 in `~/projects/abang-ai/kopicode`
- Slack Socket Mode with Bolt: general guidance only, confirm against Slack's official Bolt docs
