# E1 target image and historical CVEs

Chosen 2026-10-22 for DAB-8. These are the replay targets for the first end-to-end run (DAB-9 adapter,
DAB-52 laptop Codex run, E1 demo). All facts below were checked on that date against the Debian security
tracker, sources.debian.org, snapshot.debian.org and a Trivy scan of the pinned image.

## Image

`debian:bookworm-20240110-slim`, pinned by digest:

```
debian@sha256:f4a83aa865a2b4a064ff142aa91c713180df9fcb86ce676b5de2981029379c37   (linux/amd64, built 2024-01-11)
```

Why this image and not `nginx`: the official `nginx` image installs nginx from nginx.org's own packages,
not Debian's, so a Debian source-package adapter cannot rebuild it. `debian:bookworm-slim` is a real
official image, every package in it is a Debian package, and it is small (88 packages). The same trick (an
older dated tag, a CVE fixed later) gives replayable targets without waiting for new advisories.

## CVEs

All three are fixed in Debian bookworm by a `+deb12u1` upload. The pinned image predates both uploads
(`tar` +deb12u1 first appeared 2024-01-21, `libtasn1-6` +deb12u1 on 2025-02-10), so all three are open in it.
Trivy 0.70.0 reports each, with the fixed version shown.

| CVE | Package (source) | Vulnerable | Fixed in Debian | Upstream fix | Severity (Trivy) |
|-----|------------------|------------|-----------------|--------------|------------------|
| CVE-2022-48303 | `tar` | 1.34+dfsg-1.2 | 1.34+dfsg-1.2+deb12u1 | savannah `tar` commit `3da78400eafcccb97e2f2fd4b227ea40d794ede8` (src/list.c, base-256 boundary check; one file, 3 lines) | LOW |
| CVE-2023-39804 | `tar` | 1.34+dfsg-1.2 | 1.34+dfsg-1.2+deb12u1 | savannah `tar` commit `a339f05cd269013fa133d2f148d73f6f7d4247e4` (src/xheader.c, extended header prefixes) | LOW |
| CVE-2024-12133 | `libtasn1-6` (`libtasn1-6`) | 4.19.0-2 | 4.19.0-2+deb12u1 | libtasn1 commits `4082ca2220b5ba910b546afddf7780fc4a51f75a` and `869a97aa259dffa2620dabcad84e1c22545ffc3d` (two commits, lib/decoding.c and lib/parser_aux.c) | MEDIUM |

Debian's own patches for these live in `debian/patches/` of the `+deb12u1` source packages
(`Fix-boundary-checking-in-base-256-decoder.patch`, `Fix-handling-of-extended-header-prefixes.patch`,
`0001-…`/`0002-…` for libtasn1). They are the reference for what a correct backport looks like; an agent
must derive its patch from the upstream commits, not copy Debian's.

Variety on purpose: a one-hunk fix, a multi-line fix in another file, and a two-commit fix.

## Caveats

- `libcap2` (also in the image, CVE-2025-1390) was left out: its Debian source tree was not retrievable
  from sources.debian.org under the epoch version string. Revisit if a fourth target is wanted.
- `tar` findings are LOW. They are valid replay targets (a real advisory, a real upstream fix) but not
  dramatic; libtasn1 carries the MEDIUM one.
- Only Trivy was run. Grype is not installed on this machine; the gate needs both scanners to agree.
- Docker pulls and Trivy's DB download failed here until `DOCKER_CONFIG` pointed at a directory with an
  empty `config.json` (a broken credential helper). Keep that in mind for the integration test.
- "Fixed in Debian" is the tracker's `fixed_version` for bookworm. Upstream versions that carry the fix:
  tar 1.35, libtasn1 4.20.0.
