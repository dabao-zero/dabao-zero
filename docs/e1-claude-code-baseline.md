# E1 Claude Code run: tar CVE-2022-48303 on the laptop

First real run of ADR-0013 (DAB-80), 2026-10-29. Claude Code 2.1.312 on the maintainer's own login, started by
hand with `python -m dabao.laptop --harness claude-code --network --budget-usd 5`, model left at Claude Code's
default. Same target as the Codex run in `docs/e1-codex-baseline.md`. The bundle is
`docs/e1-claude-code-bundle-cve-2022-48303.json`. No Anthropic SDK or API key was involved (ADR-0008).

## Result

| | Claude Code | Codex (2026-10-22) |
|-|-|-|
| Wall time | 62 s | 378 s |
| Tokens | 115,002 in (cache reads and writes included), 3,327 out | 1,076,405 in, 3,811 out |
| Turns / commands | 14 turns, no shell (Read, Edit, Write, Glob, Grep, WebFetch only) | 29 shell commands incl. configure, build, part of tar's tests |
| Permission denials | 0 | n/a |
| Fix found | savannah commit `3da78400eafcccb97e2f2fd4b227ea40d794ede8` | the same commit |
| Diff | `src/list.c` only, 3 added and 2 removed lines | `src/list.c` plus a quilt patch and `series` entry (the same change twice) |
| List-price figure in the log | $0.18 (a subscription is not billed per token; the bundle records 0) | n/a |

The diff is the upstream hunk line for line. `upstream.containment_problem` (ADR-0010 check 2) run against the
savannah commit returns "" for it, so the gate's check 2 passes on a real agent patch.

## What this does not show

- **Not built or tested.** Claude Code had no shell, so it never compiled or ran tar's tests; the Codex run did.
  The gates do that afterwards, and they have not been run on this bundle yet: no image was built and no
  scanner was run. Whether it builds to the same digest as Debian's own patch is unchecked.
- **One run, one easy CVE** (3 lines, one file). It says the harness works end to end, not how it does on hard
  backports.
- **Different tool access, so the numbers are not a like-for-like comparison.** The speed gap is mostly that
  Claude Code did not build or test.
- The run read Debian's patch listing on sources.debian.org as well as the upstream commit. The bundle's
  `upstream_ref` is the upstream commit, as ADR-0003 requires.

## Gate run (2026-10-30, `scripts/e1_replay.py --vex`, live Debian pipeline)

Real image builds, Trivy 0.70.0 and Grype 0.121.0, the savannah commit fetched live, fix references read live from
OSV. 320 s. The attempt is recorded as `manual_claude_code`.

| Gate | Result |
|------|--------|
| advisory present before | pass |
| scanners clear | **fail**: `cannot issue a VEX: <the savannah commit> is not one of the advisory's fix references` |
| tests pass | pass (smoke commands) |
| build diff | pass (every change explained by a rebuilt package or dpkg state) |
| provenance | pass |

The patch is right and the gate refused it anyway, because of check 1 of ADR-0010. OSV's only `FIX` reference for
CVE-2022-48303 is `https://savannah.gnu.org/patch/?10307`, a bug-tracker patch page, not the commit. NVD lists the
same page (tag Patch). For CVE-2024-12133 (libtasn1) neither OSV nor NVD lists any fix reference or commit.
So with real feed data, check 1 as written would refuse almost every VEX. What check 1 is for, and the options,
are in the decision on DAB-81.
