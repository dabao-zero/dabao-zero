# Runbook: patch one CVE with Codex on your laptop

ADR-0009. You start one Codex run by hand, with your own subscription, for one advisory. The result
goes through the same gates as any agent's patch. You do not approve or edit it.

## What works today

| Step | State |
|------|-------|
| `python -m dabao.laptop` runs Codex and writes a bundle | Built, tested with a fake Codex. The live `codex exec` call is untested |
| `dabao attempt-import` validates a bundle and refuses with the flag off | Built |
| Import runs the gates and publishes | Needs a live pipeline: the Debian adapter, scanners and signer are not built (E2). Until then the command exits 4 |

So today you can produce and inspect bundles. A bundle becomes a ledger entry once DAB-9 lands.

## Before you start

- `codex login` done on this machine with your own ChatGPT account. Never copy `auth.json` to
  another machine or a server.
- Docker not required. `git` is.
- The source of the package at the vulnerable version, unpacked, e.g. on Debian:
  `apt-get source nginx=1.22.0-1` then use the `nginx-1.22.0` directory.
- The advisory ID and the exact `stream`, `package` and `version` as the ledger has them. They must
  match an affected row or the import is refused.

## Run

```bash
uv run python -m dabao.laptop \
  --source-dir ./nginx-1.22.0 --advisory CVE-2024-1234 \
  --package nginx --version 1.22.0-1 --network \
  --out /tmp/cve-2024-1234.json
```

- `--network` lets the Codex sandbox reach the web so it can read the upstream fix. Leave it off
  for a first dry run. Whether `workspace-write` honours it on your Codex version is unverified: if
  Codex says it cannot fetch, that is why.
- `--model` is passed to `codex -m`; the default is whatever Codex uses.
- Exit 1 with `codex made no change` means no upstream fix was found. That is a valid outcome:
  the advisory stays `UNPATCHED`. Do not nudge Codex into writing its own fix (ADR-0003).

What the script does: copies the source to a scratch directory, gives Codex only `PATH`, `LANG`, `TERM`
and a throwaway `HOME`, copies your Codex login into a throwaway `CODEX_HOME`, runs
`codex exec --sandbox workspace-write`, builds the diff against a baseline commit, and deletes the
scratch directory. Your shell's other variables (GHCR, cosign, database, LLM keys) never reach Codex.

## Review (read only)

Open the bundle JSON. Check that `patch.upstream_ref` is a real upstream commit or advisory you can open,
the diff touches what you expect, and `run_log` shows no surprises (credential reads, odd hosts).
If something is wrong, discard the bundle and run again. Editing the diff makes it something other than
a Codex run, and the ledger label would be false.

## Import

```bash
MANUAL_ATTEMPTS_ENABLED=1 DATABASE_URL=... uv run dabao attempt-import /tmp/cve-2024-1234.json
```

Exit codes: 0 done (outcomes printed), 1 no matching affected row, 4 no live pipeline, 5 flag off,
6 invalid bundle. The gates decide. If they fail, the advisory is `UNPATCHED` with the verdict in the
attempt record. Read it there, do not override it.

## Do not

- Run this on a server, in CI or on a shared machine, or script it on a timer.
- Run it in a directory that holds secrets, or with `--dangerously-bypass-approvals-and-sandbox`.
- Paste `auth.json`, tokens or advisory text into chat tools.
- Ship a patch the gates rejected.

## Known risks

- Codex reads untrusted advisory and upstream text. The scrubbed environment and the workspace-write
  sandbox limit the damage; they do not remove it. The one secret in reach is your Codex login, which
  sits in scratch space for the run.
- Subscription usage limits apply. Each run is your usage.
- OpenAI's Terms of Use have not been read for this use (DAB-46). Do that before relying on this.
