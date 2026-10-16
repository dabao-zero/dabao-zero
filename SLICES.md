# dabao-zero: Slices

Vertical increments. Each ends in something you can demonstrate. V1 confronts the
riskiest unknown: can an agent backport an upstream fix and have deterministic gates
trustworthy enough to ship it?

## V1: One historical CVE, Debian, end to end (local)

**Delivers:** R0, R1, R2 (partial), R4 (partial)

**Build plan**

1. Licence and redistribution audit for each dependency used (Grype, Trivy, cosign, Debian source packages, official-image test suites); record in `docs/licence-audit.md`. Check Wolfi and Alpine licences too, for later.
2. Pick one official image (e.g. nginx) and 3 historical CVEs whose upstream fix and fixed version are known.
3. `DistroAdapter` for Debian: fetch the source package at the vulnerable version, apply a patch, build `.deb`, assemble the image.
4. Agent in a sandbox: given advisory + source, retrieve the upstream fix and backport it; emit a `Patch` with `source=upstream_derived` and the diff.
5. Gate runner: Grype and Trivy clear the advisory; official-image test suite passes; build diff is limited to expected files.
6. Record per-attempt LLM cost and wall time.

**Demo:** run `dabao attempt --image nginx:<vuln-version> --advisory CVE-X`; the scanners flag the CVE before and report it fixed after; the official test suite passes; the patch diff is printed and matches the upstream fix in substance.

**Rests on assumptions:** Q15 (two scanners as truth) and Q16 (official suites are strong enough); if wrong, the gate cannot be trusted and V2+ must wait.

### Test plan

#### End-to-end

- For each of the 3 historical CVEs: the vulnerable image is flagged by both scanners and the patched one is not.
- The patched image passes the official-image test suite.
- A deliberately broken patch (e.g. deleting a needed file) is rejected by the gates.

#### Integration

- Debian adapter builds a `.deb` from source plus patch deterministically (same inputs, same digest).
- Sandbox cannot reach any host other than the source mirror and package proxy.

#### Unit

- Advisory-to-package mapping for Debian tracker entries.
- Gate verdict logic for each gate with pass, fail and missing-data inputs.

## V2: Orchestrator, ledger and signed publish

**Delivers:** R2, R3, R4, R5 (partial)

**Build plan**

1. Postgres schema (Advisory, AffectedComponent, PatchAttempt, Patch, Artifact) and the orchestrator as sole writer with DB leases.
2. Separate signer service: pushes to GHCR with keyless cosign signature, SLSA provenance, SBOM and VEX.
3. Operator CLI: freeze, revoke, rerun.

**Demo:** run an attempt through the orchestrator; `docker pull` the image from GHCR, `cosign verify` succeeds, SBOM and VEX are attached; `dabao revoke` marks it revoked in the ledger.

### Test plan

#### End-to-end

- A passing attempt appears in GHCR with a valid signature and attestations.
- A failing attempt publishes nothing and the advisory shows `UNPATCHED` with the attempt log.
- A revoked artifact is marked in the ledger and VEX.

#### Integration

- Two concurrent attempts for the same (component, advisory): one gets the lease, the other is rejected.
- The signer refuses a submission that did not pass all gates.

#### Unit

- State transitions of `PatchAttempt`; lease expiry.

## V3: Hardening: injection, budgets, original-stream lock

**Delivers:** R2, R5, R8

**Build plan**

1. Prompt-injection suite: advisories and commit messages containing hostile instructions.
2. Per-advisory token budget and monthly cap; `NEEDS_HUMAN` and pause behaviours.
3. Provenance allow-list of trusted fix sources.
4. `source=original` tier exists in model and gate and is rejected while the flag is off.

**Demo:** feed a poisoned advisory; show the agent output is inert and nothing is signed. Submit an `original` patch; show rejection with the flag off.

### Test plan

#### End-to-end

- Poisoned advisory leads to no publish and no credential access.
- Budget exhaustion produces `NEEDS_HUMAN`, no partial publish.

#### Integration

- A patch citing a source outside the allow-list is rejected.

#### Unit

- Config flag off rejects `original`; on routes to the separate tag namespace.

## V4: Continuous feed over ~15 images, public ledger

**Delivers:** R0, R1, R7

**Build plan**

1. Advisory ingestion from NVD, OSV and Debian tracker on a schedule.
2. Expand to ~15 official images on Debian.
3. Static ledger site generated from Postgres.
4. Held-out backlog evaluation harness for the success targets.

**Demo:** the system patches new advisories unattended for a week; the ledger shows each, with time-to-patch; the backlog run reports the percentage auto-patched.

### Test plan

#### End-to-end

- On the held-out backlog, at least 80% of in-scope advisories are auto-patched and zero published artifacts fail the smoke tests.
- Median advisory-to-published time under 24h on upstream-fixed CVEs.

#### Integration

- Ingest is idempotent: re-polling creates no duplicate advisories.

#### Unit

- Alias resolution (CVE/GHSA/distro IDs).

## V5: Alpine stream

**Delivers:** R6

**Build plan:** Alpine `DistroAdapter` (apk source packages), advisory feed (Alpine secdb), reuse the gates, same demo CVEs where applicable.

**Demo:** the same pipeline patches an Alpine-based image with no pipeline code changes outside the adapter.

### Test plan

#### End-to-end

- Alpine image for a historical CVE passes the same gates as V1.

#### Integration

- Adapter contract tests shared with Debian.

#### Unit

- Alpine advisory mapping.

## V6: Wolfi stream

**Delivers:** R6

**Build plan:** Wolfi adapter (melange/apko), advisory feed, licence confirmed in V1, then the same gates. Freeze the adapter interface after this.

**Demo:** same as V5, on Wolfi.

**Rests on assumptions:** Wolfi's licence permits redistribution as needed (to be confirmed in V1); if not, drop this slice.

### Test plan

#### End-to-end

- Wolfi image for a historical CVE passes the same gates.

#### Integration

- Adapter contract tests shared with Debian and Alpine.

#### Unit

- Wolfi advisory mapping.
