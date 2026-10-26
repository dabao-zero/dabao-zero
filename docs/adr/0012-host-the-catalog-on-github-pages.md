# ADR-0012: Host the public catalog on GitHub Pages, from a static snapshot

- Status: Accepted 2026-10-27
- Date: 2026-10-27
- Deciders: Jian Rong Lee

## Context

The site is a place to discover the patched images: landing page, catalog, image and advisory pages.
It is read-only. The frontend reads the ledger through `/v1` (`frontend/src/lib/api.ts`, base URL from
`VITE_API_URL`), so a host with no backend would show an empty catalog. Patching runs on the owner's
machine for now (ADR-0009), so the ledger changes a few times a day at most, and nothing
the public does writes to it.

## Decision

1. **Host on GitHub Pages under the `dabao-zero` organisation**, on the default `github.io` address. No
   domain is bought yet. Cost: zero.
2. **Serve a static snapshot of the ledger.** A build step exports the `/v1` responses the frontend
   uses (`images`, `images/<name>`, `advisories/<id>`, `stats`, `runs`) to JSON files, and the frontend
   fetches those. Routing is already hash-based, which Pages needs.
3. **Deploy after green CI on `main`**, behind a repo variable that defaults off (DAB-60).
4. **Revisit when a live API is needed.** If the site needs live data or any writes, the plan is Fly.io
   for the API and Neon for Postgres, with the frontend pointed at it through `VITE_API_URL`. Not built, not
   costed.

## Alternatives considered

| Option | Why not now |
|--------|-------------|
| Fly.io API + Neon from day one | A running service, a database and secrets to protect for a read-only page that changes a few times a day |
| Pages plus a public API on the owner's machine | Puts a home machine on the public internet |

## Consequences

- Gets: a public site with no servers, nothing to keep patched, and no credentials in the deploy.
- Costs: an export step (new work, tracked in DAB-60); the page is as fresh as the last export, so
  the site must show its "as of" time.
- Public data only: the snapshot must contain nothing the ledger API would not already serve publicly.
- DNS and a custom domain are left until one is bought.
