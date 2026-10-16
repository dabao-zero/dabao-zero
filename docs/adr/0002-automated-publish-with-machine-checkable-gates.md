# ADR-0002: Publish automatically when machine-checkable gates pass; humans only handle incidents

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

The product claim is that LLM agents, not human maintainers, patch CVEs. A human approval step would be unscalable and would undermine the claim, but unreviewed agent output reaching users is dangerous.

## Decision

Agents propose patches. Deterministic gates decide whether to publish. Gates: (1) Grype and Trivy both clear the advisory, or a VEX `not_affected` is backed by evidence; (2) the official-image test suite and smoke tests pass; (3) a reproducible build diff against the unpatched build shows only expected changes; (4) the patch's provenance is upstream-derived (ADR-0003). Humans are not in the patch path. An operator may freeze, revoke or roll back any artifact, and that action always wins.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Human approves every patch | Defeats the product and does not scale |
| Human reviews sampled patches | Possible later as a quality audit, but it is not a gate |
| Agent self-attests success | A model grading itself is not evidence |

## Consequences

- Gets: unattended operation with an auditable reason for every publish.
- Costs: the gates are the entire safety margin, so weak tests mean bad patches ship. Gate quality is the main engineering risk.
- Needs: a provenance allow-list of trusted fix sources, a kill switch, and a public ledger so mistakes are visible and reversible.
