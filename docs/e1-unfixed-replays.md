# First replays of CVEs Debian has not fixed (DAB-82, 2026-10-30)

Claude Code (ADR-0013, on the maintainer's own login, no shell) patched each target on the laptop; the bundle then
went through the live pipeline with `scripts/e1_replay.py --vex`: real image builds from the pinned base
(`debian:bookworm-20240110-slim`), Trivy 0.70.0 and Grype 0.121.0, the upstream commits and the Debian tracker's fix
references read live. Nothing was published (fake registry and signer). Targets are from the shortlist in
`docs/e1-targets.md`.

## Results

| Target | Agent | Gates | Outcome |
|---|---|---|---|
| libtasn1-6 4.19.0-2, CVE-2025-13151 (1 commit, 1 line) | 31 s, 40k tokens in, the upstream fix | **all five pass**: both scanners clear via VEX | published (fake registry) |
| util-linux 2.38.1-5, CVE-2025-14104 (2 commits) | 35 s, 52k tokens in | not run: see below | the target was wrong |
| pam 1.5.2-6+deb12u1, CVE-2024-10041 (2 commits, 3 files) | 34 s, 37k tokens in; cited one of the two commits | scanners **fail** (multi-commit rule), build diff **fail**, tests and provenance pass | unpatched |

- **libtasn1** is the first CVE Debian has not fixed to clear every gate: advisory fix reference from the tracker's
  notes (check 1), the commit fetched live from gitlab (check 2), a VEX that changed only the target (check 4).
  Built to `libtasn1-6 4.19.0-2+dabao1`; the Grype statement names that package.
- **pam** is the first real run of "every listed fix commit must be contained". The patch carried
  `b3020da7` (passverify.c) and not `b7b96362` (pam_unix_acct.c and support.c); the gate refused with `listed fix
  commit …b7b96362…: the patch does not touch modules/pam_unix/pam_unix_acct.c`. The agent was not told the advisory
  lists two commits; it found one on its own.

## What the runs found (all fixed unless a card is named)

- **The shortlist had a wrong target.** Debian's own note on CVE-2025-14104 says the affected code (`setpwnam()`,
  used by chsh and chfn) is not built in any Debian binary package from src:util-linux. I had counted commits and not
  read the notes. The same notes mark CVE-2022-0563 (util-linux) and CVE-2023-45853 (zlib, minizip) as not built.
  Such a patch changes nothing in the image, and the gate would still have issued a "fixed" statement: **DAB-83**.
- **Tracker fetch.** The 65 MB list is dropped by the host mid-transfer, which looked like "no fix commit named" for
  older CVEs (found when an advisory came back with no references). Now: retries, a logged warning, a short stream
  treated as a failure, and the download resumes from the last whole line with an HTTP `Range` request.
- **Multi-arch libraries.** dpkg names their file list `libtasn1-6:amd64.list`; the differ only looked for
  `libtasn1-6.list` and called the library's own files unexpected changes. Fixed, with tests.
- **"Installed in the base" was wrong.** `dpkg-query -W` succeeds for a package with status `not-installed`
  (libpam0g-dev in this base), so the adapter tried to install a `-dev` package. It now reads the status.
- **Pre-Depends between rebuilt packages.** libpam-modules pre-depends on libpam-modules-bin of the same version; one
  `dpkg -i` over both failed. A second pass now covers it; a real error still fails both.
- **Version of a source package (open, DAB-85).** The base's binary `util-linux` is `1:2.38.1-5+b1`; the source
  package is `2.38.1-5` (no epoch, no binNMU suffix), and `apt-get source` needs the latter. Inventory records
  binary names and versions, so a component built from it cannot be fetched.
- **Maintainer scripts change files (open, DAB-84).** Reinstalling pam's `libpam-runtime` reran `pam-auth-update` and
  debconf, which rewrote `/etc/pam.d/common-*`, `/var/lib/pam/*` and the debconf caches; the build-diff gate counts
  those as unexpected. Probably content-identical, but the differ compares names only. Reinstalling only the packages
  the patch changed would avoid it.
- **The agent should be told the advisory's fix commits (open, DAB-86)**, so it can derive the patch from all of them.

## Not shown

- Only Claude Code produced these patches, on easy single-function fixes; the libtasn1 fix is one line.
- Whether the commits apply to the base's older version was checked only by the build and the gates, not by running
  the vulnerable code.
- A VEX clearing a scanner is not proof the bug is gone in the shipped binary (DAB-83).
- libtasn1's pass is one CVE; the product's coverage is bounded by the tracker naming a fix commit (33% of open
  bookworm CVEs, ADR-0010).
