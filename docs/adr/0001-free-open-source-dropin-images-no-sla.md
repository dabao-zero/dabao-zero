# ADR-0001: Ship free, open-source, drop-in-compatible images with no SLA

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

Chainguard is paid and expensive. Docker's free Hardened Images are hardened by stripping functionality, so they are not plug-and-play. The owner wants to start as a free open-source project and only take on contractual obligations once someone wants to pay.

## Decision

Images behave like the official images they derive from (same entrypoints, shells, package managers and paths unless a patch requires otherwise) and are published free under an open-source licence (Apache-2.0 for our code; upstream licences ship with each image). No SLA, warranty or support; "use at your own risk". Time-to-patch is measured and published instead of promised.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Minimal/distroless images | Free DHI already does this, and the owner's point is that they do not work out of the box |
| Paid with SLA from day one | Legal exposure and a sales motion before the pipeline is proven |

## Consequences

- Gets: a clear wedge (works like upstream, fewer CVEs), zero contractual risk, public trust built by the ledger.
- Costs: larger attack surface than minimal images; the maintainer pays inference cost.
- Forecloses nothing: SLAs can be added later for paying customers.
