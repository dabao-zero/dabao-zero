# dabao-zero: Plan

Status: draft · Milestone: MVP

## Problem

Container images with known CVEs are everywhere, and patching them is slow human work.
The two usual escapes both hurt: Chainguard is paid and expensive, and Docker's free
Hardened Images are hardened by stripping functionality, so they are not drop-in. People
end up either running vulnerable images or spending engineering time making hardened ones work.

## Solution

Free, open-source container images that behave like the official ones but have their CVEs
fixed by a team of LLM agents, with no human maintainer in the patch path. You change
`FROM nginx:1.27` to `FROM ghcr.io/dabao-zero/nginx:1.27` and your scanner gets quieter and
your app still works. Each image is signed, comes with an SBOM and VEX, and every patch's
diff and agent run are public. Debian, Alpine and Wolfi variants are offered (ADR-0004).
No SLA and no warranty; use at your own risk (ADR-0001).

## Users and actors

- **Primary:** engineers and platform teams who want patched images that just work.
- **Agents:** read advisories, write and test patches. They propose; they never publish or sign.
- **Gates (deterministic code):** decide. If agent and gate disagree, the gate wins.
- **Operator (human):** incident response only: freeze, revoke or roll back an artifact.
  The operator's action always wins, and is never part of the normal patch path (ADR-0002).

## Scope

**In this milestone**
- ~15 popular images (e.g. nginx, postgres, redis, python, node), Debian stream first, then Alpine, then Wolfi.
- Patches derived only from upstream or vendor fixes (ADR-0003).
- Automated advisory ingestion, patch attempts, gating, signed publish, public ledger.
- Drop-in compatibility checked against each image's official-image test suite.

**Out**
- Original, agent-invented fixes: designed for, disabled (ADR-0003).
- Language-ecosystem libraries (pip, npm, Maven): after this milestone.
- SLAs, billing, accounts, FIPS/FedRAMP: until someone wants to pay.
- Stripped or distroless variants: the wedge is that images work, not that they are small.

## Requirements

| ID | Requirement | Status |
|----|-------------|--------|
| R0 | Published images are CVE-patched without a human in the patch path | Core goal |
| R1 | Images are drop-in compatible with the official image they derive from | Must-have |
| R2 | A patch is only published if machine-checkable gates pass | Must-have |
| R3 | Every artifact is signed and has verifiable provenance, SBOM and VEX | Must-have |
| R4 | A failed or unfinished advisory is shown honestly, never papered over | Must-have |
| R5 | Agents are isolated and cannot reach signing keys or customers' pulls | Must-have |
| R6 | Debian, Alpine and Wolfi streams share one pipeline | Must-have |
| R7 | Public ledger of advisories, attempts, patches and time-to-patch | Must-have |
| R8 | Original-fix stream can be turned on later without redesign | Nice-to-have |

## Shape

| Part | Mechanism | ADR |
|------|-----------|-----|
| S1 | Advisory ingest: poll NVD, OSV, Debian/Alpine/Wolfi trackers, normalise to `Advisory`, map to affected package@version in each image | |
| S2 | Orchestrator: for each (package, advisory) takes a DB lease, opens a `PatchAttempt`, launches an agent sandbox | ADR-0006 |
| S3 | Patch agent: fetches the upstream fix, backports it to the shipped version, builds the distro package, reports `PatchSource` | ADR-0003 |
| S4 | Distro adapter (`debian`, `alpine`, `wolfi`): fetch source package, apply patch, build package, assemble image | ADR-0004 |
| S5 | Gate runner: Grype and Trivy clean for the advisory, official-image test suite passes, build diff has no unintended changes, patch provenance is upstream-derived | ADR-0002 |
| S6 | Signer, a separate service: only after gates pass, push to GHCR with cosign keyless signature, SLSA provenance, SBOM, VEX | ADR-0005 |
| S7 | Ledger: Postgres state plus a git repo of patches; generates the public ledger site | ADR-0006 |
| S8 | Operator CLI: freeze, revoke, rollback, re-run | ADR-0002 |

## Affordances

**UI** (static ledger site)

| Affordance | Place | Wires to |
|------------|-------|----------|
| Image page: versions, open advisories, time-to-patch | `/images/<name>` | S7 |
| Advisory page: attempts, status (`PATCHED`, `UNPATCHED`, `NOT_AFFECTED`, `NEEDS_HUMAN`), patch diff | `/advisories/<id>` | S7 |

**Non-UI**

| Affordance | Kind | Wires to |
|------------|------|----------|
| `docker pull ghcr.io/dabao-zero/<image>:<tag>` | OCI registry | S6 |
| `cosign verify` and `cosign verify-attestation` | CLI on the user's side | S6 |
| `dabao freeze\|revoke\|rerun <artifact>` | operator CLI | S8 |
| Ingest, orchestrator, build worker | services and jobs | S1, S2, S4 |

## Implementation decisions

- **Entities:** `Advisory` -> `AffectedComponent` (package@version per stream) -> `PatchAttempt` -> `Patch` -> `Artifact`. Artifacts are identified by OCI digest; `<upstream>-<patchlevel>` tags are mutable pointers only until published, then immutable (Q4, Q5, Q32).
- **One write path:** only the orchestrator writes state. One live attempt per (component, advisory) via DB lease; a losing writer is rejected (Q7).
- **Agent tools:** fetch advisory, fetch upstream source, apply patch, build, run tests, submit. Structured JSON; a gate failure is a nonzero exit (Q9).
- **Patch record:** every `Patch` carries `source` (`upstream_derived` | `original`), links to the upstream commit or advisory it came from, and the diff. Only `upstream_derived` can pass the gate today (ADR-0003).
- **Failure:** no passing patch means `UNPATCHED` in the ledger with the attempt log and VEX `under_investigation`; never a partial publish (Q11). Token budget per advisory; breach gives `NEEDS_HUMAN` (Q12).
- **Model:** any OpenAI-compatible endpoint (OpenRouter by default) through a thin `AgentRunner` client, configured by environment (ADR-0008, Q13).
- **Hosting:** orchestrator as a service, builds as ephemeral Kubernetes jobs, managed Postgres, GHCR for images (Q26, Q36).
- **Secrets:** signing identity and API keys exist only in the orchestrator and signer, never in sandboxes or logs (Q20).
- **Versioning:** ledger API under `/v1`; schema migrations by a standard tool (Q32).

## Testing approach

Test at the highest seams: replay a *historical* CVE (known fix, known fixed version) through the whole pipeline and check the observable results (R0, R1, R2), rather than unit-testing agent prompts. Gates are deterministic code and get ordinary tests. Agent behaviour is measured on a held-out backlog, not asserted. Per-slice plans are in SLICES.md.

Success targets (Q27): median advisory-to-published time under 24h for upstream-fixed CVEs; at least 80% of in-scope advisories on the held-out backlog auto-patched; zero published artifacts that fail smoke tests; zero unsigned artifacts.

## Assumed defaults

| ID | Assumed | Cost if wrong |
|----|---------|---------------|
| Q1 | Free self-serve users, no sales-led customer | Low: pricing is deferred anyway |
| Q13 | OpenAI-compatible API via OpenRouter (decided, ADR-0008) | Low: behind an interface |
| Q15 | "Patched" = Grype and Trivy clean, or evidence-backed VEX `not_affected` | Medium: scanners disagree and false-clears are possible |
| Q16 | Upstream/official-image test suite plus smoke tests prove drop-in behaviour | High for V1/V3: weak tests let a broken patch through |
| Q26 | Kubernetes jobs for builds | Medium: rework of S4 |
| Q36 | GHCR hosts public images | Low |
| Q37 | The maintainer pays inference cost, with a hard cap | Medium: a cap pauses patching |

## Open risks

- **Test coverage is the safety net (R1, R2).** If upstream suites are thin, a wrong backport ships. Earliest signal: V1, V3.
- **Cost.** Free product, maintainer-paid inference. Cost per patch is measured from V1 (Q28).
- **Prompt injection through advisory or source text.** Mitigated by ADR-0005; tested in V3.
- **Three distro streams multiply build work.** V1 stays on Debian; V5 and V6 reveal the real adapter cost.
- **Legal.** Trademarks and redistribution of each image's contents; licences audited in V1 (Q21, Q31).
- **A fully unattended supply chain is a target.** An attacker who controls a trusted upstream fix source can feed it to us. Mitigation (provenance allow-list) is in ADR-0002; reviewed again in V3.
