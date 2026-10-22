<script lang="ts">
  import { api } from "../lib/api";
  import { REGISTRY } from "../lib/config";
  import Async from "../components/Async.svelte";
  import CopyCode from "../components/CopyCode.svelte";
  import ImageCard from "../components/ImageCard.svelte";
  import OpenBox from "../components/OpenBox.svelte";

  const before = "FROM nginx:1.27";
  const after = `FROM ${REGISTRY}/nginx:1.27`;

  const problems = [
    ["Known CVEs ship in images people run.", "Scanners flag them, and patching them is slow, manual work."],
    ["Chainguard images are paid.", "That is fair for a company, and out of reach for many teams."],
    ["Docker's free hardened images are not drop-in.", "They get small by removing functionality, so your app may stop working."],
  ];
  const steps = [
    ["An advisory lands", "We read public feeds and note which images are affected."],
    ["An agent finds the upstream fix", "It backports the fix the upstream project already shipped. It does not invent patches."],
    ["Machines check it", "Scanners, the image's own tests, a build diff and a provenance check decide. The agent has no say."],
    ["Only then is it signed and published", "A failed fix is shown as unpatched. Nothing partial goes out."],
  ];
</script>

<section class="hero">
  <div style="flex: 1 1 420px; min-width: 0;">
    <h1 class="ts-display-small hero-title">The official images you already run, with the CVEs fixed.</h1>
    <p class="ts-body-large muted" style="margin-top: 16px; max-width: 54ch;">
      Fixes come from upstream. Agents backport them, and deterministic checks decide whether the result is signed
      and published. Free, open source, and early alpha.
    </p>
    <div style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 28px;">
      <a class="btn btn-filled sl" href="#/images">Browse images</a>
      <a class="btn btn-outlined sl" href="#/about">How it works</a>
    </div>
  </div>
  <div style="flex: 0 1 380px; min-width: 0;"><OpenBox /></div>
</section>

<section aria-labelledby="swap-h" style="margin-top: 16px;">
  <h2 id="swap-h" class="ts-title-large">One line to change</h2>
  <p class="ts-body-medium muted" style="margin: 4px 0 16px;">Example. Same image, quieter scanner.</p>
  <div style="display: flex; flex-direction: column; gap: 8px; max-width: 640px;">
    <div class="code"><code style="opacity: 0.6;"><s>{before}</s></code></div>
    <CopyCode text={after} label="Copy the new FROM line" />
  </div>
</section>

<section aria-labelledby="problem-h" style="margin-top: 48px;">
  <h2 id="problem-h" class="ts-title-large">The problem</h2>
  <ul style="margin: 12px 0 0; padding-left: 24px; display: flex; flex-direction: column; gap: 10px; max-width: 64ch;">
    {#each problems as [title, body]}<li><strong>{title}</strong> <span class="muted">{body}</span></li>{/each}
  </ul>
</section>

<section aria-labelledby="how-h" style="margin-top: 48px;">
  <h2 id="how-h" class="ts-title-large">How a fix is made</h2>
  <ol style="margin: 12px 0 0; padding-left: 24px; display: flex; flex-direction: column; gap: 10px; max-width: 64ch;">
    {#each steps as [title, body]}<li><strong>{title}.</strong> <span class="muted">{body}</span></li>{/each}
  </ol>
  <p class="ts-body-medium" style="margin-top: 12px;"><a class="link" href="#/about">The full six steps and five checks</a></p>
</section>

<section aria-labelledby="trust-h" class="card-filled" style="margin-top: 48px; padding: 24px;">
  <h2 id="trust-h" class="ts-title-large" style="margin: 0;">Trust it a little, then check</h2>
  <p style="margin: 8px 0 0; max-width: 64ch;">
    Every image is meant to be signed and ship with a bill of materials. Every patch diff and agent run is public on
    this site. You can verify a signature yourself:
  </p>
  <pre class="code-block" style="margin-top: 12px;">cosign verify {REGISTRY}/nginx@sha256:… \
  --certificate-identity-regexp 'https://github.com/dabao-zero/dabao-zero/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com</pre>
</section>

<section aria-labelledby="limits-h" style="margin-top: 48px;">
  <h2 id="limits-h" class="ts-title-large">The honest limits</h2>
  <ul style="margin: 12px 0 0; padding-left: 24px; display: flex; flex-direction: column; gap: 8px; max-width: 64ch;">
    <li>There is no warranty and no SLA. Use it at your own risk.</li>
    <li>Fixes come from upstream only. If upstream has no fix, the CVE stays open and the ledger says so.</li>
    <li>This is an early alpha. The catalog below can show demo data until the first images are published.</li>
  </ul>
</section>

<section aria-labelledby="catalog-h" style="margin-top: 48px;">
  <div style="display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap;">
    <h2 id="catalog-h" class="ts-title-large">From the catalog</h2>
    <a class="link" href="#/images">All images</a>
  </div>
  <Async load={api.images}>
    {#snippet children(images)}
      <div class="landing-grid">
        {#each images.slice(0, 3) as image (image.name)}<ImageCard {image} />{/each}
      </div>
    {/snippet}
  </Async>
</section>

<style>
  .hero { display: flex; flex-wrap: wrap; align-items: center; gap: 24px 56px; padding: 48px 0 40px; }
  .hero-title { font-size: 3.25rem; line-height: 3.5rem; letter-spacing: -0.01em; max-width: 16ch; }
  @media (max-width: 600px) { .hero-title { font-size: 2.25rem; line-height: 2.75rem; } .hero { padding-top: 24px; } }
  .landing-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-top: 16px; }
</style>
