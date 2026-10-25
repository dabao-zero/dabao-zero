# ADR-0011: A zero-finding tier for users whose scanners ignore VEX

- Status: Proposed
- Date: 2026-10-23
- Deciders: Jian Rong Lee

Builds on [ADR-0010](0010-clear-cves-with-gate-issued-vex.md), which covers users whose scanners read our VEX.
Touches the stream order of [ADR-0004](0004-multi-distro-adapters-debian-alpine-wolfi.md).

## Context

The owner wants to serve users with zero tolerance: no findings from a stock scanner, even if a VEX says the CVE
does not apply. VEX cannot serve them by definition, and neither can an honest version number when the distro has
not shipped a fix. Measured on 2026-10-23 with Trivy 0.70.0 and its current database:

| Image | Findings | With a fixed version | Statuses |
|-------|----------|----------------------|----------|
| `alpine:3.19.0` | 48 | 48 | all `fixed` |
| `debian:bookworm-slim` (current) | 228 | 0 | `affected`, `fix_deferred`, `will_not_fix` |
| `cgr.dev/chainguard/wolfi-base:latest` | 0 | n/a | scanner recognises the `wolfi` OS family and its own feed |

- Alpine's advisory data lists only vulnerabilities that have a fix. A rebuilt package at the fixed version, or
  later, makes the finding go away by a plain version comparison. No VEX is needed, and none can be ignored.
- Debian's tracker also lists unfixed, deferred and will-not-fix CVEs, and scanners report them for every version of
  the package. Even the newest `debian:bookworm-slim`, with every available fix installed, shows 228. A patched
  `tar` at a version above Debian's last fix still shows `CVE-2026-18477` (`fix_deferred`) and `CVE-2005-2541`
  (`affected`), found on the 2026-10-22 replay image. Stock scanners cannot be satisfied on a Debian base, however good
  our patches are.

Wolfi behaves like Alpine here: scanners read a feed that lists only fixed vulnerabilities (both feeds answer
at `secdb.alpinelinux.org` and `packages.wolfi.dev/os/security.json`).

**A caveat that shapes the wording.** "Zero findings" on Alpine or Wolfi is a property of the feed's policy, not proof
that no CVE is known: a CVE the distro has not fixed is simply not listed, so the stock scan stays silent about it.
The ledger therefore keeps its own list of known-unfixed CVEs per image from other sources (OSV, NVD, upstream) and
shows it beside the scan result. Claiming "no CVEs" without that list would be the same kind of false clean as hiding
the OS.

## Decision (proposed)

1. **Two tiers, named plainly.**
   - *VEX tier* (Debian stream): stock scanners may still list CVEs we patched; our signed VEX (ADR-0010) says which
     are fixed. We never claim "zero findings" for it.
   - *Zero-finding tier* (Alpine first, then Wolfi once its licence is checked, DAB-7; both are wanted): a stock scan with no VEX and no configuration reports nothing that
     has a fix. Any finding that remains is a CVE nobody has fixed yet, shown openly in the ledger.
2. **Zero-finding means zero fixable findings,** never "zero CVEs in the universe". The site states the measured
   number per image and tag, from a scan we run without VEX.
3. **Alpine moves ahead of further Debian work** for the product's headline claim. Debian stays as the stream that
   proves the pipeline and serves VEX-reading users.
4. **Scanner-overlay data is a later option, not a promise.** Publishing our own advisory feed in the scanners'
   database format (as Alpine and Wolfi do) would let a Debian image show clean for users who add our feed. It is a
   feasibility spike first, because it asks users to change their scanner configuration, which is a weaker offer
   than the zero-configuration Alpine tier.
5. **Never hide a finding by changing what the scanner sees.** Editing `/etc/os-release` so scanners no longer
   recognise the OS, renaming packages, or stripping package databases would produce a clean scan and a false claim.
   Rejected for all tiers.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Promise zero findings on Debian | Not achievable with stock scanner data, shown above |
| Rely on VEX for everyone | The stated users reject suppression by definition |
| Hide the OS from scanners | A false clean result; deceives exactly the users who need the truth |
| Debian only, no tiers | Cannot serve the zero-tolerance users at all |

## Consequences

- Gets: an honest, measurable claim for the users who asked for it, and a reason to build Alpine early.
- Costs: Alpine's adapter and `secdb` feed (E6) are pulled forward; two kinds of image to explain on the site.
- Needs: a baseline measurement across the ~15 target images (how many fixable findings do the stock images have
  today?), and Alpine tests that prove a rebuilt package at the fixed version clears a finding with no VEX.
- Open: whether Wolfi (own advisory feed, licence unchecked, DAB-7) joins the zero-finding tier; whether to build the
  scanner-overlay feed for Debian.
