# ADR-0003: Two patch streams: upstream-derived now, original fixes designed in but disabled

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

Agents could write fixes for CVEs that upstream has not fixed. That is much riskier: no reference fix to compare against and no one else has reviewed it. The owner wants to start safe but keep the option open.

## Decision

Every `Patch` has `source` = `upstream_derived` or `original`. Only `upstream_derived` (cherry-pick, backport, or a vendor/distro advisory patch) can pass the publish gate today. The `original` stream exists in the data model and the gate as a distinct tier, disabled by a config flag, and when enabled in future must publish under a separate, clearly labelled tag namespace and never mixed into the default tags. A test asserts that an `original` patch is rejected while the flag is off.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Upstream-derived only, no provision for more | Would force a data-model change to add the stream later |
| Original fixes from day one | Unreviewed fixes in an unattended supply chain, and weaker gates |

## Consequences

- Gets: safe default, low rework later.
- Costs: advisories with no upstream fix stay `UNPATCHED` for now. Coverage is bounded by upstream.
- Needs: stronger gates (e.g. exploit reproduction) before the original stream is ever enabled.
