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

## Shortlist: CVEs Debian has not fixed (2026-10-30)

For the first replay of the case the product exists for: a CVE the Debian tracker lists as `open` on bookworm, in a
package this base image contains, with fix commit(s) named in the tracker's notes (ADR-0010 check 1). tar's and
libtasn1 CVE-2024-12133 above are already fixed in bookworm (`+deb12u1`, DSA-5863-1), so they prove the mechanics
but not this case.

How it was built: tracker JSON and `data/CVE/list` read 2026-10-30; 95 open bookworm CVEs in the base image's 23
source packages, 35 of them with a named commit (37%, in line with the 33% across all of bookworm); each commit read
through `HttpUpstreamFetcher` and measured (source files and changed lines, tests and docs excluded).
**Not checked:** whether each commit applies to the base's older version, and whether the vulnerable code exists
there. Debian's urgency is "not yet assigned" for most, so none is known to be high severity.

| # | Package (base version) | CVE | Commits | Source files / lines | Why |
|---|---|---|---|---|---|
| 1 | libtasn1-6 (4.19.0-2) | CVE-2025-13151 | 1 | 1 / 2 | Smallest fix, small package, fast build. 4.19.0 has the same declaration. Run 2026-10-30: all gates pass |
| 2 | util-linux (2.38.1-5) | CVE-2025-14104 | 2 | 1 / 12 | **Wrong target:** Debian's note says the affected code (chsh/chfn) is not built in any Debian binary of src:util-linux. See `docs/e1-unfixed-replays.md` |
| 3 | util-linux | CVE-2026-3184 | 1 | 1 / 4 | One commit, 4 lines, same package build as #2 |
| 4 | p11-kit (0.24.1-2) | CVE-2026-18938 | 1 | 1 / 6 | Small, different package |
| 5 | pam (1.5.2-6) | CVE-2024-10041 | 2 | 3 / 52 | Two commits across three files; run 2026-10-30: the agent carried one, the multi-commit rule refused it |
| 6 | gnupg2 (2.2.40-1.1) | CVE-2026-57062 | 1 | 1 / 9 | Small, security-relevant parser fix |

Also readable and small, in reserve: util-linux CVE-2026-78408 (1 file, 10 lines), systemd CVE-2026-15059 (2 commits,
8 lines; systemd is a long build), perl CVE-2026-9538 (1 file, 15 lines; perl is a long build).

Avoid for a first run:
- **zlib CVE-2023-45853**: the fix is in `contrib/minizip`, which Debian's `zlib1g` does not ship, so the patch would
  change nothing in the image. Worth a test of its own later (the gate must not call that a fix).
- **zlib CVE-2026-27171**: the commit is 11,182 lines. **gcc-12 CVE-2026-95619**: 4 commits, 192 lines, a toolchain.
- **Anything on savannah or sourceware** (coreutils, diffutils, gzip, acl, attr, bzip2, tar CVE-2026-5704, 14 CVEs):
  18 commits could not be read from this machine on 2026-10-30 (the cgit hosts are IPv6-only here), so they were not
  measured. `sourceware.org` (bzip2) is also not on the host allow-list.

Correction (2026-10-30): the shortlist was built from commit counts and sizes only. Before choosing a target, read the
tracker's non-URL `NOTE:` lines too: Debian records there when the code is not built in a binary package
(CVE-2025-14104 and CVE-2022-0563 for util-linux, CVE-2023-45853 for zlib). Results of the first replays are in
`docs/e1-unfixed-replays.md`.
