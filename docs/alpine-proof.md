# Alpine proof: a rebuilt package at the fixed version clears a finding with no VEX

DAB-75, 2026-10-25. Tests the central bet of ADR-0011: on Alpine, a stock scan goes quiet by version alone. Reproduce with
`docs/spikes/alpine-proof/Dockerfile` (needs Docker and a `docker-container` buildx builder).

## What was done

`nginx:alpine` (digest `sha256:a3554c0d…e17417`, Alpine 3.24.3) ships `brotli-libs 1.2.0-r1`, which Alpine's feed lists as
vulnerable to `CVE-2026-111497` (HIGH), fixed in `1.2.1-r0`. The spike rebuilt Alpine's own `brotli` recipe (`aports`
branch `3.24-stable`, `main/brotli`, `1.2.1-r0`) with `abuild` in an Alpine 3.24 container, using the full recipe (its
14 C tests and the python tests pass), signed it with a throwaway key, installed the `brotli-libs` package into that
image. The apk manager reported `Upgrading brotli-libs (1.2.0-r1 -> 1.2.1-r0)`.
The resulting image digest was `sha256:f8820f41…c0cc4cc4`.

## Result (Trivy 0.70.0 and Grype 0.121.0, no VEX, no configuration)

| | Trivy | Grype |
|-|-------|-------|
| `nginx:alpine` before | 1: `brotli-libs` `CVE-2026-111497` | 5: the same, from Alpine's feed (`alpine:distro:alpine:3.24`), plus 4 NVD CPE matches |
| after the rebuild | **0** | 4: the NVD CPE matches only |

The brotli finding is gone in both scanners with no VEX. Findings that have no fix were not touched: the four Grype
leftovers are `busybox` `CVE-2025-60876` (three packages) and `curl` `CVE-2026-92392`, matched by CPE against the NVD, not
from Alpine's own feed.

## What this proves, and what it does not

- It proves the mechanism ADR-0011 relies on. Alpine's feed lists only fixed vulnerabilities, so a package at or above the
  fixed version stops being reported, and nothing in the user's scanner has to be configured or has to read a VEX.
- It does **not** show an agent patching. The fix here is Alpine's own recipe at the version Alpine already shipped. For a
  CVE Alpine has already fixed, a patch applied to the old version (say `1.2.0-r2`) would still sort below the fixed
  `1.2.1-r0` and stay reported, the same ordering effect found on Debian; that case was reasoned about, not run.
  The case that matters is a CVE Alpine has not listed at all, where the scan is already silent (see the caveat in ADR-0011).
- **Grype still reports NVD CPE matches on Alpine images.** A zero-tolerance user running Grype with its defaults will see
  them. Whether to document the Grype setting that turns CPE matching off, or to ask upstream whether these should be
  listed, is open (DAB-77 keeps them visible in the ledger).
- The build was not checked for reproducibility. `abuild` output is not assumed byte-identical between runs.
- **Correction (2026-10-25).** An earlier version of this note said the throwaway signing key was removed after the
  install. It was not: the key was named `-6addd9e6.rsa.pub` (the build had no `$USER`), the cleanup looked for
  `builder-*`, and the image kept the key in `/etc/apk/keys`. The scan result is unaffected, but the spike image was
  not clean. The spike Dockerfile and the adapter (`dabao.alpine`) now remove every copied key by its own name, and a
  Docker test checks that no key is left in the layers the build adds.
