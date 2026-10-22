# Landing page brief

For DAB-56. Copy and structure for the `#/` landing page (DAB-57). Visual design follows the existing
Material 3 tokens and the open takeaway box in `frontend/`; this note is about what the page says.

## What exists already

The site's home is the catalog. It already has a hero ("Images with the CVEs already fixed."), a search box,
a distro filter, a copyable pull command and image cards. `#/about` already explains the six steps, five checks
and what the agent cannot do. So the landing page is not the catalog with a new coat of paint: it is the page
that comes before it, for someone who does not yet know what dabao-zero is. The catalog moves to `#/images`.

## The one claim that must stay true

No image is published yet (README status: early alpha). The page may describe the product and show the
catalog with demo data, but must not say or imply that real, signed images exist until E3's publish workflow
ships. Until then the primary call to action is "See how it works" and "Follow on GitHub", and any pull command
is labelled as an example.

## Audience

Engineers and platform teams who run `nginx`, `postgres`, `redis`, `python` or `node` images and whose scanner
keeps flagging them. They want the same image with fewer findings and are wary of a free project they cannot
call for support. Honesty about limits is what earns them.

## Structure

1. **Hero.** Headline: "The official images you already run, with the CVEs fixed." One sentence under it: fixes come
   from upstream, agents backport them, machines check the result. Buttons: Browse images, How it works.
2. **The swap.** Two lines side by side, with a copy button on the second:
   `FROM nginx:1.27` becomes `FROM ghcr.io/dabao-zero/nginx:1.27`. Caption: same image, quieter scanner.
3. **The problem.** Three short points. Known CVEs sit in images people run. Chainguard is paid. Docker's free hardened
   images remove functionality, so they are not drop-in.
4. **How a fix is made.** Four steps, one line each: an advisory lands, an agent finds the upstream fix and backports it,
   deterministic gates check it, only then is it signed and published. Link to `#/about` for the full six steps.
5. **Why you can trust it, and why you should check.** Gates decide, not the agent. Every image is signed, with SBOM and
   VEX. Every patch diff and agent run is public. Show the `cosign verify` line.
6. **Honest limits.** No SLA, no warranty, use at your own risk. A failed fix is shown as unpatched, not hidden.
   Fixes only come from upstream; the project does not write its own.
7. **The catalog.** A live strip of three image cards from the API with a link to all images. If the API is
   unreachable, say so plainly instead of showing an empty strip.
8. **Footer.** GitHub, About, security policy, the disclaimer.

## Voice

Plain and specific. No "revolutionary", no "AI-powered", no urgency. Say "fixed" only where the ledger says fixed.
Say "agents" and "gates" the way the About page does. Where a number appears (open CVEs, time to fix), it comes from
the API, never typed in.

## Not in scope

Pricing, accounts, a docs site, testimonials, logos of other companies, and any comparison table that names a
competitor's CVE counts.
