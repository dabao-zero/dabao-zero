# ADR-0010: Clear a CVE for a rebuilt package with a gate-issued VEX statement, not a version number

- Status: Accepted
- Date: 2026-10-23
- Deciders: Jian Rong Lee

Amends gate (1) of [ADR-0002](0002-automated-publish-with-machine-checkable-gates.md), which already allows
an evidence-backed VEX. Evidence for this decision: `docs/e1-codex-baseline.md` and the experiment recorded on
card DAB-66.

## Context

Trivy and Grype decide "is this package vulnerable" by comparing its version with the distro's fixed version.
A package we rebuild with an upstream fix (`1.34+dfsg-1.2+dabao1`) is still reported in two cases:

- **Debian has already fixed the CVE.** Our version sorts below Debian's fixed one (`+deb12u1`). Bumping it above
  clears the CVE, and also every other CVE fixed in that same upload that our patch did not touch. A live run
  showed CVE-2023-39804 cleared by a patch that never touched it.
- **Debian has not fixed it,** which is the case dabao-zero exists for. There is no fixed version to compare with,
  so no version we choose makes the scanner stop reporting it.

Some statement that scanners read is therefore needed. On 2026-10-23, with Trivy 0.70.0 and Grype 0.121.0, an
OpenVEX statement of status `fixed`, naming the rebuilt binary packages by plain package URL (no qualifiers), made
both scanners drop that CVE and keep the others. Naming the image as the product with the packages as
subcomponents did not work in either.

## Decision

1. **The version stays honest** (`<upstream version>+dabao1`). It is never raised to beat a scanner.
2. **The gate runner issues an OpenVEX statement per (CVE, rebuilt package), status `fixed`.** Never the agent, and
   never a human in the patch path. The statement carries the upstream ref and the patch digest.
3. **It is issued only if all four checks pass:**
   1. the patch's `upstream_ref` is one of the advisory's own fix references from the feeds (OSV `FIX`
      references and the fix commits named in the Debian security tracker's notes, amended 2026-10-30), not just
      any URL on the provenance allow-list;
   2. the changes of the upstream commit, fetched by the gate itself from the allow-list, are contained in the
      patch diff (context may shift, changed lines may not);
   3. the patch applies, the image builds and the tests pass;
   4. scanning with that VEX changes exactly one finding compared with the scan before it: the target CVE. A patch
      for CVE A can never clear CVE B.
4. **Both scanners must clear it** with the VEX applied (Grype and Trivy, as ADR-0002 requires). If either still
   reports the CVE, or a check cannot run, the advisory is `UNPATCHED` or `NEEDS_HUMAN`, never published.
5. **The evidence lives in the ledger, not in the VEX.** The diff, upstream ref, fetched upstream commit hash, scan
   results and gate verdicts are stored per attempt. The VEX is a rendering of that evidence and can be
   regenerated in another format (CycloneDX VEX, CSAF) if consumers move.
6. **The VEX is published signed,** as a cosign attestation on the image, in OpenVEX first.
7. **Scanner behaviour is pinned and watched.** Scanner versions are pinned in CI, and a canary test with a known
   package and CVE fails if a scanner stops honouring `fixed` statements. If scanners stop supporting this, we fall
   back to the ledger evidence alone, with the scanners kept only as a regression check, and say so publicly.
8. **Target CVEs Debian has not fixed.** Where Debian already ships a fixed package, `apt` is the remedy and
   dabao-zero adds nothing. Those CVEs stay valuable as replay fixtures for testing agents (`docs/e1-targets.md`),
   not as product.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Raise the version above the distro's fix | Clears CVEs the patch did not fix, and does nothing for CVEs with no distro fix |
| Patch every CVE of the distro's upload | Only helps already-fixed CVEs, which `apt upgrade` already handles |
| Drop scanners as a clearing check, rely on tests and source evidence | Gives up the ADR-0002 promise that two independent scanners agree |
| Let the agent write the VEX | A model grading itself is not evidence (ADR-0002) |

## Consequences

- Gets: per-CVE clearing that works for unfixed CVEs, and a built-in guard against one patch clearing another CVE.
- Costs: more gate code (a VEX builder, fix-reference lookup, upstream containment check); a dependency on how
  scanners read VEX, which varies by tool and version.
- **Users' scanners only go quiet if they read our VEX** (`trivy --vex`, `grype --vex`). Docker Scout's docs say
  only `not_affected` suppresses a CVE, so `fixed` may not quiet Scout. Product wording must say "your scanner
  gets quieter when it reads our signed VEX", not "your scanner just gets quieter".
- A check that cannot run fails closed. A large or reformatted upstream commit may fail check 3.ii and end in
  `NEEDS_HUMAN`; that is accepted.
- Open: whether a second VEX format should ship from day one; how to handle an advisory whose feed lists no fix
  reference (it stays `UNPATCHED` until one appears).

## Implementation notes (2026-10-27)

- Check 1 (`gates.fix_reference_problem`): OSV references of type `FIX` are stored on the advisory
  (`advisories.fix_refs`). The Debian tracker and Alpine secdb feeds carry no fix links, so an advisory known
  only from them has none and can never get a VEX. Matching ignores scheme, fragment, a trailing slash and
  `.patch`, and accepts a commit id that is a 7+ hex prefix of the other, in the same repository.
- Check 2 (`upstream.containment_problem`): the gate reads the upstream commit through `UpstreamFetcher`
  (`live.HttpUpstreamFetcher`: allow-listed hosts only, GitHub, GitLab and cgit patch URLs, redirects only
  within the same site, 2 MB cap). Every changed line of the commit's source files must appear in the patch
  for the same file, whitespace-normalised; upstream tests, docs and changelogs are not required. It is
  **one-directional**: a patch that also changes other lines still passes this check. Extra changes are
  limited by the build-diff gate (files) and, for agents, by the prompt (DAB-68), not by this check.
- An unreadable commit makes the gate fail, so the attempt is `UNPATCHED` with the reason in the verdict,
  not `NEEDS_HUMAN` as the card said; every gate failure is handled that way in the orchestrator.
- Both checks always apply to a VEX. `GateConfig.require_fix_reference` and `require_containment` (default
  off) apply them to every patch through the provenance gate.

## Amendment (2026-10-30): where fix references come from (DAB-81)

A live gate run on a correct patch (`docs/e1-claude-code-baseline.md`) showed check 1 refusing it: OSV's only
`FIX` reference for CVE-2022-48303 is a bug-tracker patch page, not the commit, and for CVE-2024-12133 neither OSV
nor NVD lists any. Check 1 is the only thing that ties the upstream commit to the CVE, so it stays; what changed is
where the link may come from. The Debian security tracker's `data/CVE/list` names the fix commit in `NOTE:` lines
for both CVEs (`NOTE: Fixed by: <url> (v1.35)`, or a bare commit URL).

- **Source added:** commit URLs in those notes (`ingest.parse_debian_notes`, streamed by
  `live.fetch_debian_fix_refs`, merged by `ingest.with_fix_refs`). Only URLs the gate can read as a commit count;
  bug, mailing-list and advisory links do not. The notes are written by the Debian security team, not by an agent,
  the same trust root as the advisory feed itself.
- **Failure mode:** if the file cannot be read or names no commit, the advisory has no fix reference and no VEX is
  issued (the attempt is `UNPATCHED` with that reason).
- **Not done, on purpose:** a reviewed `fix-links` file maintained by hand, and NVD or commit-message links. Add
  them only if tracker notes turn out not to cover enough CVEs; two have been checked.
- **Several fix commits (decided 2026-10-30):** 28% of the CVEs with named commits list more than one, and
  libtasn1's two are both needed for its fix. Check 1 still accepts a patch that cites any listed commit, but check
  2 now reads **every** commit the advisory lists as a fix (`gates.commit_refs`, the same commit under different
  URLs read once) and requires each to be contained in the patch, checked on its own. A listed commit that cannot
  be read fails closed; one that changes only tests and docs asks nothing of the patch. Cost: a patch derived from
  one adapted version of a fix is refused when the tracker also lists another adapted version. That is a visible
  `UNPATCHED`, not a false "fixed"; loosen it only when replays show how often it happens.
- **Allow-list (decided 2026-10-30):** a list of hosts, not repositories (`upstream.UPSTREAM_HOSTS`: github.com,
  gitlab.com, git.kernel.org, the savannah hosts, cgit.ghostscript.com, git.musl-libc.org). Among CVEs open on
  bookworm the tracker names 5,593 commit URLs on 22 hosts, 93% on github.com. Check 1 already narrows a patch to
  the exact commit an independent source names, so a repository list would add upkeep, not safety.
- **Coverage limit:** of 11,711 CVEs open on bookworm, 3,911 (33%) name a fix commit in the tracker. The Debian
  tier can clear at most that third, and only where an agent also backports the fix. Say so publicly.
- **Direction:** following Chainguard's approach long term (own advisory feed, possibly Wolfi or our own distro) is
  recorded in `PLAN.md`; it does not change this check.
