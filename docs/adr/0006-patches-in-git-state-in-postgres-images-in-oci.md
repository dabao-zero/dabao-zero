# ADR-0006: Patches in git, state in Postgres, artifacts in an OCI registry

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

Users and reviewers must be able to see and diff what changed; the orchestrator needs transactional leases and queries; images need a standard distribution channel.

## Decision

Patch content lives in a public git repo (reviewable, diffable). Advisory, attempt and artifact state lives in Postgres, and only the orchestrator writes it. Images, signatures, SBOMs and VEX live in GHCR as OCI artifacts. The ledger site is generated from Postgres.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Everything in git | No transactions or leases; awkward queries |
| Everything in Postgres | Patches are not diffable by outsiders |

## Consequences

- Gets: transparency and transactional correctness.
- Costs: three stores to keep consistent; the orchestrator is the single reconciler.
