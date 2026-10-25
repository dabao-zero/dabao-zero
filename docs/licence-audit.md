# Licence and redistribution audit

DAB-7, 2026-10-25. Not legal advice. "Verified" means read from the repository's own licence metadata or file on that
date; "secondary" means a third-party summary of a policy whose own text I could not retrieve; "unverified" means not
checked. Anything unverified or secondary must be read by a human before the dependent slice ships.

## What matters most

1. **Wolfi trademark (secondary, must be read before DAB-32).** Chainguard's open-source material, as summarised in
   search results, says that rebuilding Chainguard packages or containers from source means removing references to
   Chainguard and Wolfi, and making clear who authored changes. The recipes are Apache-2.0 (verified), but the name may
   not be usable on our images. The primary policy page is client-rendered and I could not fetch its text. Until a
   human reads it, plan the Wolfi stream without the words "Wolfi" or "Chainguard" in image names or marketing.
2. **Wolfi package retention (secondary).** The same source says old package builds are removed on a schedule. A replay
   that depends on `packages.wolfi.dev` keeping a version will break; Wolfi needs our own pinned mirror of what we use.
3. **GPL and LGPL in the images.** Debian and Alpine images carry GPL packages (tar, bash, glibc under LGPL, and so on).
   Redistributing them obliges us to provide the corresponding source. The plan: keep each package's copyright file in
   the image (we do not strip `/usr/share/doc`), publish every patch in git, and link the distro source for the rest from
   the README and image pages. A written source offer is the fallback. Needs a human check of the exact wording.
4. **Product trademarks in image names.** `ghcr.io/dabao-zero/nginx` uses a project's name to say what the image is
   compatible with. Use it descriptively, add "not affiliated with or endorsed by", never use project logos. Check each
   of the ~15 projects' policies before listing it.
5. **Licence changes in upstream software (from memory, verify).** Redis moved to source-available licences from 7.4
   and later added an AGPL option; other popular server software has done the same. Redistributing a patched build may
   be allowed or restricted per version. Check the licence of every image's software at the exact versions we publish.
6. **`snapshot.debian.org` is heavy automated use** (every Debian build downloads source and packages from it). I found
   no published usage policy. Be polite: cache, pin, rate-limit, and plan a local mirror before E4 runs unattended at scale.

## Tools we run

| Dependency | Role | Licence | Offline story | Platforms | Status |
|------------|------|---------|---------------|-----------|--------|
| Trivy (`aquasecurity/trivy`) | scanner (gate) | Apache-2.0 | needs its vulnerability DB; the DB can be fetched once and reused with `--skip-db-update`; DB download from `mirror.gcr.io` failed here until the Docker credential helper was bypassed | linux amd64, arm64 | licence verified; DB terms unverified |
| Grype (`anchore/grype`) | scanner (gate) | Apache-2.0 | same, with its own DB and `GRYPE_DB_AUTO_UPDATE=false` | linux amd64, arm64 | licence verified; DB terms unverified |
| Syft (`anchore/syft`) | SBOM | Apache-2.0 | fully offline | linux amd64, arm64 | licence verified |
| cosign (`sigstore/cosign`) | keyless signing, attestations | Apache-2.0 | keyless signing needs Fulcio and Rekor online; a key-based mode works offline | linux amd64, arm64 | licence verified |
| regctl (`regclient/regclient`) | read package DBs from images without Docker | Apache-2.0 | needs the registry | linux amd64, arm64 | licence verified |
| BuildKit, buildx (`moby/buildkit`, `docker/buildx`) | reproducible image builds | Apache-2.0 | needs base images and package sources | linux amd64, arm64 | licence verified |
| OpenVEX spec (`openvex/spec`) | VEX format (ADR-0010) | CC0-1.0 | offline | n/a | licence verified |
| docker-library/official-images | test suites for official images | Apache-2.0 | runs against local images with Docker | linux amd64 | licence verified; not yet run, see DAB-6 |
| melange, apko (`chainguard-dev/*`) | Wolfi package and image builders | Apache-2.0 | need Wolfi package repo | linux amd64, arm64 | licence verified; unused until DAB-32 |

## Distros and their data

| Dependency | What we take | Licence and terms | Offline story | Status |
|------------|--------------|-------------------|---------------|--------|
| Debian packages | source and binaries, rebuilt | DFSG-free; each package under its own licence (see item 3) | `snapshot.debian.org` pinned by timestamp, mirrorable | licences vary per package, check per image |
| Debian name | "Debian" in our text | derivatives must not be named Debian; "based on Debian" is accepted (secondary: derivatives guidelines, one project-leader reply) | n/a | primary trademark policy not retrieved |
| Debian security tracker | advisories, fixed versions | public data on `security-tracker.debian.org`, terms unverified | JSON dump, cacheable | unverified |
| Alpine packages (`aports`) | recipes and sources, rebuilt | the repository has no top-level licence file; each `APKBUILD` names its package's licence; `apk-tools` is GPL-2.0 (verified) | package mirrors | per-package, check per image |
| Alpine name and logo | "Alpine Linux" in our text | no published trademark policy found; mailing-list threads suggest factual use is tolerated and logos need permission (secondary) | n/a | unverified, ask alpine-devel if unsure |
| Alpine secdb | advisory feed for the zero-finding tier | unverified | JSON, cacheable | unverified |
| Wolfi recipes (`wolfi-dev/os`) | recipes, rebuilt with melange | Apache-2.0 for recipes (stated in its LICENSE); packages "under the license terms provided by each FOSS project"; packages must be open source | `packages.wolfi.dev/os`, signing key published | verified; trademark and retention are items 1 and 2 |
| Wolfi secdb | advisory feed | unverified | JSON at `packages.wolfi.dev/os/security.json` | unverified |
| Docker Hub official images | base images (`debian`, `alpine`) pulled by digest | images are open-source software; Docker Hub terms and rate limits apply to pulls | `mirror.gcr.io` mirrors reads | pull terms unverified |

## Consequences for the plan

- DAB-32 (Wolfi adapter) is blocked on a human reading Chainguard's trademark policy, and on deciding whether to ship
  Wolfi images without the name.
- Image pages and the README need a source-and-licence section: where the corresponding source is, which patch was applied,
  and the "not affiliated" line (follow-up card).
- The ~15 target images need a per-image licence and trademark check before they are listed (follow-up card).
- A local mirror of Debian snapshot data and of the Wolfi packages we use is a prerequisite for unattended runs.
