# Baseline: what stock scanners say about stock official images

DAB-74, scanned 2026-10-25T09:33:06+00:00. Trivy 0.70.0 and Grype 0.121.0 with
their then-current databases, no VEX, operating-system packages only (`deb` and `apk`), read through
`mirror.gcr.io/library` with no Docker daemon. Raw numbers, with image digests: `docs/baseline-scan.json`.
Repeat with `uv run python scripts/baseline_scan.py --out docs/baseline-scan` (needs `trivy` and `grype`).

"Fixable" means the scanner's own data names a fixed version. Everything else is a CVE nobody has fixed, which
no rebuild or version number can clear on a stock scan (ADR-0011).

| image:tag | base | Trivy total / fixable | Grype total / fixable | fixable HIGH+ (Trivy) |
|---|---|---|---|---|
| nginx:latest | debian 13.7 | 391 / 55 | 329 / 1 | 1 |
| nginx:alpine | alpine 3.24.3 | 1 / 1 | 5 / 1 | 1 |
| postgres:latest | debian 13.7 | 313 / 0 | 308 / 0 | 0 |
| postgres:alpine | alpine 3.24.3 | 1 / 1 | 4 / 1 | 1 |
| redis:latest | debian 13.7 | 162 / 0 | 157 / 0 | 0 |
| redis:alpine | alpine 3.23.7 | 0 / 0 | 3 / 0 | 0 |
| python:latest | debian 13.7 | 3547 / 61 | 2631 / 7 | 2 |
| python:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| node:latest | debian 13.7 | 3500 / 61 | 2584 / 7 | 2 |
| node:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| httpd:latest | debian 13.7 | 263 / 1 | 258 / 1 | 1 |
| httpd:alpine | alpine 3.24.3 | 1 / 1 | 7 / 1 | 1 |
| memcached:latest | debian 13.7 | 165 / 0 | 160 / 0 | 0 |
| memcached:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| haproxy:latest | debian 13.7 | 162 / 0 | 157 / 0 | 0 |
| haproxy:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| rabbitmq:latest | ubuntu 26.04 | 43 / 1 | 101 / 3 | 0 |
| rabbitmq:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| golang:latest | debian 13.7 | 1972 / 1 | 1118 / 1 | 1 |
| golang:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| php:latest | debian 13.7 | 1797 / 1 | 943 / 1 | 1 |
| php:alpine | alpine 3.24.3 | 1 / 1 | 8 / 1 | 1 |
| ruby:latest | debian 13.7 | 3500 / 61 | 2584 / 7 | 2 |
| ruby:alpine | alpine 3.24.3 | 0 / 0 | 3 / 0 | 0 |
| mariadb:latest | ubuntu 26.04 | 53 / 1 | 663 / 3 | 0 |
| mariadb:alpine | n/a | no such tag | | |
| mysql:latest | oracle 9.8 | 0 / 0 | 0 / 0 | 0 |
| mysql:alpine | n/a | no such tag | | |
| eclipse-temurin:latest | ubuntu 26.04 | 57 / 1 | 350 / 3 | 0 |
| eclipse-temurin:alpine | n/a | no such tag | | |

## What it shows

**Debian images: hundreds to thousands of findings, almost none fixable.** The eleven Debian-based images
(`debian 13.7`) show 162 to 3,547 findings under Trivy. For seven of them, 1 to 61 are fixable; for four
(`postgres`, `redis`, `memcached`, `haproxy`) none are. Every other finding has no fix in Debian's data, so a
Debian stream can never reach zero on a stock scan, exactly as ADR-0011 says. The 55 to 61 fixable findings on
`nginx`, `python`, `node` and `ruby` are packages Debian has already fixed and the image has not picked up yet:
for those, rebuilding with Debian's own fixed packages is the whole remedy.

**Alpine images: 0 or 1 finding under Trivy, and the one is fixable.** Twelve Alpine images were found. Eight show 0.
`nginx`, `postgres`, `httpd` and `php` show 1 each, and each is fixable. Those four are the first real Alpine targets:
a rebuilt package at the fixed version should take them to zero with no VEX (DAB-75).

**Grype shows a few more, none from Alpine's own feed.** Every Alpine image shows 3 to 8 findings in Grype, and
almost all are `not fixed` matches from the NVD by CPE (for example `busybox` `CVE-2025-60876` on `redis:alpine`)
that Alpine's advisory data does not list. A zero-tolerance user running Grype with its defaults will therefore see
them. Whether to say so, ignore them with Grype's CPE settings, or ask Alpine about them is open; the ledger list from
DAB-77 should carry them either way.

**Not every `:latest` is Debian, and not every image has an Alpine variant.** `rabbitmq`, `mariadb` and
`eclipse-temurin` are Ubuntu 26.04, and `mysql` is Oracle Linux (0 findings in both scanners, and outside our streams).
`mariadb`, `mysql` and `eclipse-temurin` have no `:alpine` tag (`eclipse-temurin` uses suffixed tags, not scanned).

## Limits of this baseline

- Default tags are the full images. `python`, `node` and `ruby` carry a large build toolchain, hence 3,500 findings;
  their `-slim` tags would be far smaller and are the better targets. Not scanned yet.
- One point in time. Debian's and Alpine's data change daily; the JSON records the date.
- OS packages only: language-ecosystem findings are out of scope for this milestone (PLAN).
- Both scanners ran with defaults. Grype's CPE matching is a default, not a requirement of the tool.
