# ADR-0004: Support Debian, Alpine and Wolfi streams behind a distro adapter

- Status: Accepted
- Date: 2026-10-16
- Deciders: Jian Rong Lee

## Context

Official images are mostly Debian- or Alpine-based, so drop-in compatibility (ADR-0001) points to those. Wolfi is the base Chainguard uses. The owner wants to explore all three. Wolfi's licence has not been verified, and each stream costs build effort.

## Decision

The pipeline is distro-agnostic; each stream implements a `DistroAdapter` (fetch source package, apply patch, build package, assemble image, map advisory to package). Order of delivery: Debian (V1), Alpine (V5), Wolfi (V6). The adapter interface is fixed after Debian and Alpine both exist. Each dependency's licence, offline story and platform support is checked in V1 before relying on it.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Debian only | Excludes Alpine users, who are a large share of image consumers |
| Wolfi only | Not drop-in for most official images, and a dependency on another vendor's ecosystem |

## Consequences

- Gets: broad coverage, and a forced clean separation between pipeline and distro.
- Costs: three build toolchains and three advisory feeds; a bad adapter abstraction would be painful. Designing against two real distros before freezing the interface reduces that risk.
