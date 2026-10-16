# Questions

Statuses: `DECIDED` (user answered) · `ASSUMED` (default taken, correct it if
wrong) · `FORK` (waiting on the user) · `DEFERRED` (not needed this milestone).

Project: an agent-run alternative to Chainguard. LLM agents, with no human
maintainers in the patch path, remediate CVEs in hardened software artifacts
and publish them to customers.

Market facts checked 2026-10-16 (vendor-sourced, treat as indicative):
Docker made its Hardened Images catalog free under Apache 2.0 in Dec 2025;
Chainguard has shrunk its free tier and uses AI agents itself (rebuild
reconcilers, the "Guardener" Dockerfile migrator). "Minimal image, few CVEs" is
therefore commoditised. Wolfi's licence is unverified (slice V0 checks it).

## Open forks

| ID | Question | Recommendation | What changes |
|----|----------|----------------|--------------|
| F1 | Wedge: what do we sell that free DHI and Chainguard do not? | Backported fixes for versions customers are pinned to (EOL and old releases), delivered as images | Whole product shape; competing head-on on "latest minimal image" loses to free |
| F2 | What gates a patch from agent to customer? | Fully automated publish, gated only by machine-verifiable checks; humans on incident response, never in the patch path | The core claim and the liability posture |
| F3 | May agents write original fixes when upstream has none? | No. Upstream-derived only (cherry-pick/backport/vendor advisory patch) | Supply-chain risk, testability, how much of the CVE backlog is coverable |
| F4 | Build base: Wolfi/apko/melange, Alpine, or Debian? | Debian/Ubuntu-derived for MVP (customers' pinned versions live there) | Package-build tooling, glibc compatibility, which dependency we are locked to |
| F5 | First customer | Platform/security teams, 50-500 engineers, running old pinned images, no FedRAMP/FIPS need yet | Pricing, compliance scope, onboarding |
| F6 | Contractual CVE-fix SLA in MVP? | No contract; publish measured time-to-patch and a public ledger | Legal exposure, and whether anyone pays |

## Register

| ID | Question | Status | Answer or default | Landed |
|----|----------|--------|-------------------|--------|
| Q1 | Primary user | FORK | F5 | PLAN §Users |
| Q2 | Human vs agent actors; who wins on conflict | ASSUMED | Agents act, deterministic gates decide; a human operator can freeze or revoke any artifact, and that always wins | ADR (gates) |
| Q3 | Milestone boundary | FORK | F1; MVP = one ecosystem, ~15 images | PLAN §Scope |
| Q4 | Entity model and identity | ASSUMED | `Advisory` (CVE/GHSA/distro ID) -> `Affected component@version` -> `PatchAttempt` -> `Patch` -> `Artifact` (OCI digest). Content-addressed by digest; advisories keyed by canonical ID plus aliases | PLAN §Implementation |
| Q5 | Identity across rebuilds | ASSUMED | Artifact = digest; human-readable tag `<upstream>-<patchlevel>` is a pointer, never identity | PLAN §Implementation |
| Q6 | Where state lives | ASSUMED | Postgres for state; git repo of patches (reviewable, diffable) as the source of truth for patch content; OCI registry for artifacts | ADR (storage) |
| Q7 | Concurrent writers | ASSUMED | One PatchAttempt per (component, advisory) at a time via DB lease; losing writes rejected, not merged | PLAN §Shape |
| Q8 | Interfaces | ASSUMED | OCI registry (pull), REST API + CLI for catalogue/advisories/ledger, a dashboard later; one write path, all via the orchestrator | PLAN §Affordances |
| Q9 | Agent-facing contract | ASSUMED | Agents use a narrow tool set (fetch advisory, fetch upstream source, apply patch, build, run tests, submit); structured JSON outputs, nonzero exit on gate failure | PLAN §Implementation |
| Q10 | Delivery model (registry vs PR bot) | ASSUMED | Private OCI registry, cosign-signed, SBOM + VEX attached | PLAN §Shape |
| Q11 | Failure: agent cannot produce a passing patch | ASSUMED | Mark advisory `UNPATCHED` in the ledger with attempt log; never publish a partial fix; surface to customers via VEX `under_investigation` | PLAN §Shape |
| Q12 | Failure: LLM API down / budget exhausted | ASSUMED | Queue; per-advisory token budget with hard cap; breach sets `NEEDS_HUMAN` and pages the operator | PLAN §Implementation |
| Q13 | Model/provider | ASSUMED | Anthropic API via Agent SDK behind a thin interface; swappable; model chosen per task class | PLAN §Implementation |
| Q14 | Advisory sources | ASSUMED | NVD, OSV, distro security trackers (Debian/Ubuntu), upstream git. All free and API-accessible | PLAN §Shape |
| Q15 | Definition of "patched" | ASSUMED | Grype and Trivy both report clean for that advisory, or an evidence-backed VEX `not_affected`; the original exploit/regression test (where public) fails before and passes after | ADR (gates) |
| Q16 | Behaviour-preservation check | ASSUMED | Upstream test suite on the patched build, plus per-image smoke tests; reproducible build compared against the unpatched build for unintended file changes | PLAN §Testing |
| Q17 | Sandboxing the agents | ASSUMED | Each attempt in an ephemeral, network-restricted microVM/container; no production credentials; only source mirror and package proxy reachable | ADR (isolation) |
| Q18 | Prompt injection via advisory/upstream text | ASSUMED | Advisory and source text is untrusted data; agents have no signing key; signing happens in a separate service only after gates pass | ADR (isolation) |
| Q19 | Signing and provenance | ASSUMED | Sigstore/cosign keyless from CI identity, SLSA provenance attestation, a published patch diff per artifact | PLAN §Shape |
| Q20 | Secrets | ASSUMED | Signing identity and LLM keys exist only in the orchestrator and signer; never in agent sandboxes or logs | PLAN §Implementation |
| Q21 | Dependencies and licences | ASSUMED | Debian source packages (distro licences), cosign/Sigstore (Apache-2.0), Grype (Apache-2.0), Trivy (Apache-2.0), Postgres, an OCI registry (Distribution, Apache-2.0). Verify each in V0 | ADR (deps) |
| Q22 | Base distro and tooling | FORK | F4 | ADR (base) |
| Q23 | Patch sourcing | FORK | F3 | ADR (sourcing) |
| Q24 | Trust gates | FORK | F2 | ADR (gates) |
| Q25 | SLA and public claims | FORK | F6 | PLAN §Scope |
| Q26 | Hosting and runtime | ASSUMED | One cloud region; orchestrator as a service, build workers as ephemeral jobs on Kubernetes; Postgres managed | PLAN §Implementation |
| Q27 | Success metrics | ASSUMED | Median advisory-to-published-artifact time < 24h for upstream-fixed CVEs; >= 80% of in-scope advisories auto-patched on a held-out backlog; 0 patches that fail the smoke tests published; 0 unsigned artifacts | PLAN §Testing |
| Q28 | Cost per patch | ASSUMED | Track LLM cost per attempt; target < $5 median at MVP. Measured from V1 | PLAN §Open risks |
| Q29 | Tenancy and auth | ASSUMED | Org accounts with registry pull tokens; single-tenant data per org not required in MVP because artifacts are shared | PLAN §Affordances |
| Q30 | Billing | DEFERRED | Manual invoicing until first design partner | n/a |
| Q31 | Legal: redistribution, trademarks, liability | ASSUMED | Rebuild only permissively redistributable sources; rename ("dabao/<name>") not use upstream trademarks; ToS disclaims fitness. Needs a lawyer before first paying customer | PLAN §Open risks |
| Q32 | Versioning and migration | ASSUMED | Ledger and API versioned (`/v1`); schema migrations via a standard tool; artifact tags immutable once published | PLAN §Implementation |
| Q33 | Transparency about AI authorship | ASSUMED | Every artifact carries machine-readable provenance naming the agent run; patch diff is public | PLAN §Shape |
| Q34 | FIPS / FedRAMP / compliance certifications | DEFERRED | Post-MVP | n/a |
| Q35 | Language-ecosystem libraries (pip, npm, Maven) | DEFERRED | After the OS-package milestone | n/a |

## Coverage

| Category | Covered by |
|----------|-----------|
| Primary user and actors | Q1, Q2 |
| Scope boundary | Q3, Q34, Q35 |
| Data model and identity | Q4, Q5 |
| State and storage | Q6 |
| Concurrency and conflict | Q7 |
| Interfaces and contracts | Q8, Q9, Q10 |
| Failure behaviour | Q11, Q12 |
| External dependencies | Q13, Q14, Q21, Q22 |
| Runtime and deployment | Q26 |
| Measurable success | Q15, Q16, Q27, Q28 |
| Security and secrets | Q17, Q18, Q19, Q20 |
| Versioning and migration | Q32 |
| Legal and trust (added) | Q24, Q25, Q31, Q33 |
