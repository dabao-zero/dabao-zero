# dabao-zero: Board tasks (staging file for Pandan)

Pandan was not reachable from this session (no `pandan` CLI, no token, no MCP tools), so the
backlog lives here first. Format follows the pandan skill's epics-and-stories guide. Refs are
temporary (`E1`, `T1.2`); dependencies are listed as `Blocked by` so they can be filed as
`pandan dep add` edges. Points are 1-5. Once access exists: create the board, file epics first,
then stories with `--epic`, then dependencies. See "Filing" at the bottom.

---

## E0: Foundations (repo, tests, CI)
**Goal** a contributor or agent can clone, run the fast checks in one command, and see CI gate a PR.
**Done when** a PR with a failing unit test is blocked by CI; the pre-push hook runs in under 30s.
**Not in scope** publish workflow (E2).

- **T0.1 Confirm ADR-0007 and pin versions** (1 pt)
  **Why** ADR-0007 fixes the stack (Python/FastAPI/uv/pytest; Svelte/Vite for the V4 frontend); exact versions must be locked.
  **Done when** - [ ] `uv.lock` committed - [ ] Python 3.13 pinned in `.python-version` - [ ] re-check of package versions recorded
- **T0.2 Add CLAUDE.md agent brief** (1 pt) Blocked by T0.1
  **Why** agents should follow the layering and PR rules by default.
  **Do** honest status, exact commands, conventions, "trust the code over the docs".
  **Done when** - [ ] commands in it all run
- **T0.3 Scaffold project with seams and fakes** (3 pts) Blocked by T0.1
  **Why** the fast test layer needs injectable boundaries from the start.
  **Do** interfaces plus in-memory fakes for AgentRunner, DistroAdapter, Scanner, Registry, Signer, AdvisorySource, Clock.
  **Done when** - [ ] `make test-unit` passes with no Docker - [ ] bare `make` prints help
- **T0.4 Pre-push hook** (1 pt) Blocked by T0.3
  **Do** ruff, format check, mypy, unit tests; documented one-line install.
  **Done when** - [ ] hook runs in under 30s - [ ] `--no-verify` documented
- **T0.5 CI workflow with required checks** (3 pts) Blocked by T0.3
  **Do** parallel lint, typecheck, unit, integration, secret-scan, dep-scan; frozen installs, caching, cancel-in-progress; branch protection on `main`.
  **Done when** - [ ] a red unit test blocks merge - [ ] a planted fake secret fails secret-scan
- **T0.6 Pin fixtures and scanner DB snapshot** (2 pts) Blocked by T0.3
  **Why** a scanner database update must not turn CI red.
  **Done when** - [ ] CI runs offline against pinned fixtures - [ ] refresh procedure documented

## E1: V1 One historical CVE, Debian, end to end
**Goal** prove an agent can backport an upstream fix and the gates can be trusted.
**Done when** 3 historical CVEs on one image go vulnerable-to-clean and pass the official tests; a deliberately broken patch is rejected.
**Not in scope** signing, publishing, orchestration, other distros.

- **T1.1 Licence and redistribution audit** (2 pts) Blocked by T0.1
  **Why** a dependency's licence or trademark can invalidate a slice (Wolfi, Alpine, official-image test suites, scanners).
  **Done when** - [ ] docs/licence-audit.md lists licence, offline story, platform support per dependency
- **T1.2 Choose the target image and 3 historical CVEs** (1 pt)
  **Done when** - [ ] each CVE has known vulnerable version, upstream fix commit and fixed version recorded
- **T1.3 Debian DistroAdapter** (5 pts) Blocked by T0.3, T1.2
  **Do** fetch source at vulnerable version, apply patch, build `.deb`, assemble image.
  **Done when** - [ ] same inputs give the same digest - [ ] integration test builds it in a container
- **T1.4 Sandboxed patch agent** (5 pts) Blocked by T1.3
  **Do** agent retrieves the upstream fix, backports it, emits a `Patch` with source and diff. Network limited to source mirror and package proxy.
  **Done when** - [ ] patch matches the upstream fix in substance for all 3 CVEs - [ ] egress test proves nothing else is reachable
- **T1.5 Gate runner** (5 pts) Blocked by T1.3
  **Do** Grype and Trivy clear the advisory; official-image suite passes; build diff limited to expected files; provenance upstream-derived.
  **Done when** - [ ] each gate has a unit test for pass, fail, missing data
- **T1.6 Known-good and known-bad corpus** (3 pts) Blocked by T1.5
  **Why** prove each guard by watching it fail.
  **Done when** - [ ] every gate is turned red by at least one bad-corpus entry - [ ] good corpus is green
- **T1.7 Record cost and time per attempt** (1 pt) Blocked by T1.4
  **Done when** - [ ] each attempt logs tokens, dollars, wall time
- **T1.8 Demo command `dabao attempt`** (2 pts) Blocked by T1.4, T1.5
  **Done when** - [ ] scanners flag before, clear after; official tests pass; diff printed

## E2: V2 Orchestrator, ledger and signed publish
**Goal** attempts run through one writer and passing ones are published signed.
**Done when** `docker pull` plus `cosign verify` succeeds on a published image; a failed attempt publishes nothing.
**Not in scope** continuous ingest, public site.

- **T2.1 Postgres schema and migrations** (3 pts) Blocked by T1.8
  **Done when** - [ ] entities per PLAN §Implementation - [ ] migration tool in CI
- **T2.2 Orchestrator with DB leases** (5 pts) Blocked by T2.1
  **Done when** - [ ] two concurrent attempts on one (component, advisory): one wins, one is rejected
- **T2.3 Separate signer service** (5 pts) Blocked by T2.2
  **Do** push to GHCR with keyless cosign, SLSA provenance, SBOM, VEX; refuse anything that has not passed all gates.
  **Done when** - [ ] signer rejects an ungated submission - [ ] `cosign verify` passes
- **T2.4 Honest failure states** (2 pts) Blocked by T2.2
  **Done when** - [ ] no passing patch gives `UNPATCHED` with attempt log and VEX `under_investigation`; nothing partial is published
- **T2.5 Operator CLI: freeze, revoke, rerun** (3 pts) Blocked by T2.3
  **Done when** - [ ] revoke marks the artifact in the ledger and VEX
- **T2.6 Replay e2e test and `publish.yml`** (3 pts) Blocked by T2.3
  **Do** recorded-agent e2e against a local registry; publish workflow triggered on green CI for the tested SHA, armable via `PUBLISH_ENABLED`, off by default.
  **Done when** - [ ] e2e is a required check - [ ] publish skips docs-only changes

## E3: V3 Hardening
**Goal** a hostile advisory or compromised agent cannot cause a signed bad artifact.
**Done when** the injection suite and budget tests pass and `original` patches are rejected.

- **T3.1 Prompt-injection corpus and tests** (3 pts) Blocked by T2.3
  **Done when** - [ ] poisoned advisory and commit text produce no publish and no credential access
- **T3.2 Token and monthly budget caps** (2 pts) Blocked by T2.2
  **Done when** - [ ] budget breach gives `NEEDS_HUMAN`, pauses the pipeline, publishes nothing partial
- **T3.3 Provenance allow-list of fix sources** (3 pts) Blocked by T1.5
  **Done when** - [ ] a patch citing a source outside the list is rejected
- **T3.4 Original-fix stream lock** (2 pts) Blocked by T1.5
  **Done when** - [ ] `source=original` rejected with flag off; with flag on routes to a separate tag namespace

## E4: V4 Continuous feed and public ledger
**Goal** the system patches new advisories unattended and shows its work.
**Done when** 80% of in-scope held-out advisories are auto-patched, median time under 24h, zero published artifacts fail smoke tests.

- **T4.1 Advisory ingest (NVD, OSV, Debian tracker)** (5 pts) Blocked by T2.2
  **Done when** - [ ] re-polling creates no duplicates - [ ] alias resolution handles CVE/GHSA/distro IDs
- **T4.2 Expand to ~15 images on Debian** (5 pts) Blocked by T4.1
- **T4.3 Ledger site (Svelte 5 + Vite 8 + TypeScript)** (3 pts) Blocked by T2.1
  **Why** ADR-0007; re-check Svelte/Vite versions before scaffolding.
  **Done when** - [ ] `frontend` CI job passes (svelte-check, vitest, build) - - [ ] image and advisory pages show status, attempts, diff, time-to-patch
- **T4.4 Live-model eval harness (non-gating)** (3 pts) Blocked by T2.2
  **Done when** - [ ] scheduled run reports success rate, time, cost per patch with a hard cost cap
- **T4.5 Observability floor** (2 pts) Blocked by T2.2
  **Done when** - [ ] health endpoint, structured logs, alert on stalled queue

## E5: V5 Alpine stream
**Goal** the same pipeline patches an Alpine image with changes only inside the adapter.

- **T5.1 Alpine DistroAdapter and secdb feed** (5 pts) Blocked by T2.6
- **T5.2 Shared adapter contract tests** (3 pts) Blocked by T5.1
  **Done when** - [ ] Debian and Alpine pass one contract suite

## E6: V6 Wolfi stream
**Goal** a Wolfi stream, subject to the licence check in T1.1.

- **T6.1 Wolfi DistroAdapter (melange/apko) and feed** (5 pts) Blocked by T5.2, T1.1
  **Done when** - [ ] passes the shared contract suite; adapter interface frozen
  **Not in scope** drop this card if T1.1 finds Wolfi's licence unsuitable

---

## Filing

When `pandan` is available (`pandan login`, then `pandan board create` / `board use`): file the 7 epics,
then stories with `--epic`, then `pandan dep add <story> --blocked-by <story>` for each "Blocked by". Re-read
one card with `pandan get` before bulk-filing via `pandan batch-create`. Done-when checklists above are
compressed onto one line; expand them to one bullet per line in the card description.
